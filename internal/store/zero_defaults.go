package store

import (
	"context"
	"reflect"
	"sync"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// 解析模型 schema 用的缓存与命名策略。
//
// schema.Parse 不需要数据库连接，因此 ApplyModelDefaults 可以在 admin handler
// 这类拿不到 *gorm.DB 的地方使用。命名策略保持 GORM 默认，与建表时一致。
var (
	modelSchemaCache sync.Map
	modelSchemaNamer = schema.NamingStrategy{}
)

/**
 * ApplyModelDefaults 把模型上 `gorm:"default:..."` 声明的默认值填入结构体的零值字段。
 *
 * 用在「反序列化请求体之前」：先填默认值，再让 JSON 覆盖。`json.Unmarshal` 只写
 * 请求体里出现过的字段，于是「用户没提供」保留默认值、「用户显式传 false / 0」
 * 如实生效——单靠 Go 的值类型区分不了这两种情况，这是唯一不引入 `*bool` 就能
 * 表达意图的位置。
 *
 * 默认值取自模型标签本身，不在 handler 里另抄一份，避免出现第二个数据源。
 * 只填零值字段，已有值一律不动。
 *
 * @param item 指向模型结构体的指针。
 * @return 解析 schema 失败时返回错误；item 非指针时直接返回 nil。
 */
func ApplyModelDefaults(item any) error {
	rv := reflect.ValueOf(item)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil
	}

	sch, err := schema.Parse(item, &modelSchemaCache, modelSchemaNamer)
	if err != nil {
		return err
	}

	elem := rv.Elem()
	ctx := context.Background()
	for _, f := range sch.Fields {
		// DefaultValueInterface 为 nil 表示默认值由数据库生成（如自增主键），
		// 这类字段没有可在 Go 侧填入的具体值。
		if f.PrimaryKey || !f.HasDefaultValue || f.DefaultValueInterface == nil {
			continue
		}
		if f.AutoCreateTime > 0 || f.AutoUpdateTime > 0 {
			continue
		}
		if _, isZero := f.ValueOf(ctx, elem); !isZero {
			continue
		}
		if err := f.Set(ctx, elem, f.DefaultValueInterface); err != nil {
			return err
		}
	}
	return nil
}

/**
 * CreateWithZeroDefaults 插入一条记录，并回写被数据库默认值顶替掉的零值字段。
 *
 * GORM 在 INSERT 时把「带 default 标签、当前又是零值」的字段当作「调用方没设」，
 * 转而写入默认值（`callbacks/create.go` 里用 `field.DefaultValueInterface` 顶替，
 * 并且会 `field.Set` 就地改写传入的结构体）。这在本项目里是会出事故的：
 *
 *   - 新建一个「先不启用」的站点 → 站点立刻接受流量并代理到上游
 *   - 新建 `priority = 0` 的规则 → 变成 100，规则按 priority ASC 排序，
 *     本该抢先拦截的规则被挤到所有默认优先级规则之后
 *   - 新建停用的 IP 名单条目、订阅源、监听器 → 全部立刻生效
 *
 * 用「先快照、后回写」而不是「插入前把零值改成非零」：前者不改变 GORM 对
 * 「调用方真的没设过这个字段」的判断，未显式赋值的字段仍能拿到数据库默认值。
 *
 * 之所以做成通用函数而不是在每个 repository 里手写补偿：手写方案在本仓库
 * 已重复 5 次并漏掉 5 处，且每一份都只处理 `Enabled`，覆盖不了 `Priority`
 * 这类数值字段。
 *
 * @param db   数据库句柄。
 * @param item 指向模型结构体的指针；非指针时退化为普通插入（无法回写）。
 * @return 插入或回写失败时返回错误。
 */
func CreateWithZeroDefaults(db *gorm.DB, item any) error {
	rv := reflect.ValueOf(item)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return db.Create(item).Error
	}
	elem := rv.Elem()

	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(item); err != nil {
		// 解析不了 schema 就没法判断哪些字段带默认值，按原样插入而不是让调用失败。
		return db.Create(item).Error
	}
	sch := stmt.Schema
	if sch == nil || sch.PrioritizedPrimaryField == nil {
		return db.Create(item).Error
	}

	candidates := ZeroDefaultCandidates(sch)
	ctx := context.Background()

	// 必须在 Create 之前快照：GORM 会就地把这些字段改写成默认值。
	zeroed := make(map[string]any, len(candidates))
	for _, f := range candidates {
		if _, isZero := f.ValueOf(ctx, elem); isZero {
			zeroed[f.DBName] = reflect.Zero(f.FieldType).Interface()
		}
	}

	if err := db.Create(item).Error; err != nil {
		return err
	}
	if len(zeroed) == 0 {
		return nil
	}

	pkField := sch.PrioritizedPrimaryField
	pk, pkIsZero := pkField.ValueOf(ctx, elem)
	if pkIsZero {
		// 拿不到主键就无法定位这一行，跳过好过发出无条件 UPDATE。
		return nil
	}
	if err := db.Model(item).Where(pkField.DBName+" = ?", pk).
		UpdateColumns(zeroed).Error; err != nil {
		return err
	}

	// 把结构体也改回零值：GORM 已经把它改成默认值了，不还原的话调用方
	// 手里的对象与库里的行不一致，后续基于它做判断就会出错。
	for _, f := range candidates {
		if _, ok := zeroed[f.DBName]; ok {
			if err := f.Set(ctx, elem, reflect.Zero(f.FieldType).Interface()); err != nil {
				return err
			}
		}
	}
	return nil
}

/**
 * ZeroDefaultCandidates 返回需要「插入后回写零值」的字段。
 *
 * 收两类带默认值的字段：`DefaultValueInterface` 已解析出具体值的（bool、数值、
 * 字符串），以及交给数据库生成的。主键与自动时间戳由 GORM 自行管理，排除在外。
 *
 * @param sch 已解析的模型 schema。
 * @return 候选字段，顺序与 schema.Fields 一致。
 */
func ZeroDefaultCandidates(sch *schema.Schema) []*schema.Field {
	if sch == nil {
		return nil
	}
	out := make([]*schema.Field, 0, len(sch.Fields))
	for _, f := range sch.Fields {
		if f.PrimaryKey || !f.HasDefaultValue || f.AutoCreateTime > 0 || f.AutoUpdateTime > 0 {
			continue
		}
		out = append(out, f)
	}
	return out
}
