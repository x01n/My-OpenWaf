pub const PROTOCOL_VERSION: u32 = 2;

/// AAD purpose 枚举值（规范集合，勿散落字面量）。
pub const PURPOSE_CHALLENGE_DATA: &str = "challenge-data";
pub const PURPOSE_SHIELD: &str = "shield";
pub const PURPOSE_CAPTCHA: &str = "captcha";
pub const PURPOSE_BROWSERSIGN: &str = "browsersign";
pub const PURPOSE_PASS: &str = "pass";
pub const PURPOSE_DYN_PROTECT: &str = "dyn-protect";

/// 统一拼接模型：`envelope_label("env", PROTOCOL_VERSION)` 输出 `owaf-env:v2`。
pub fn envelope_label(category: &str, version: u32) -> String {
    format!("owaf-{}:v{}", category, version)
}

/// 信封前缀：`prefix(PROTOCOL_VERSION, "owaf-env:v2")` 输出 `v2.owaf-env:v2`。
pub fn prefix(version: u32, label: &str) -> String {
    format!("v{}.{}", version, label)
}

/// AAD 拼接：`aad("owaf-captcha:v2", PURPOSE_CHALLENGE_DATA)` 输出
/// `owaf-captcha:v2|challenge-data`。
pub fn aad(label: &str, purpose: &str) -> String {
    format!("{}|{}", label, purpose)
}

/// [`sm3_kdf`] SM3-HKDF 式密钥派生：`kdf(key, category) =
/// SM3(key ‖ label(category, PROTOCOL_VERSION))` 截 32 字节。
/// key 为会话主密钥的原始字节；category 走标签生成函数做域分离。
/// 与 Go 端 b1 同规则。
pub fn sm3_kdf(key: &[u8], category: &str) -> [u8; 32] {
    let info = envelope_label(category, PROTOCOL_VERSION);
    let mut buf = Vec::with_capacity(key.len() + info.len());
    buf.extend_from_slice(key);
    buf.extend_from_slice(info.as_bytes());
    crate::sm3::sm3_digest(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_generation_matches_spec() {
        assert_eq!(envelope_label("env", PROTOCOL_VERSION), "owaf-env:v2");
        assert_eq!(
            envelope_label("captcha", PROTOCOL_VERSION),
            "owaf-captcha:v2"
        );
        assert_eq!(envelope_label("gm", PROTOCOL_VERSION), "owaf-gm:v2");
    }

    #[test]
    fn prefix_generation_matches_spec() {
        let label = envelope_label("env", PROTOCOL_VERSION);
        assert_eq!(prefix(PROTOCOL_VERSION, &label), "v2.owaf-env:v2");
        // 前缀的构成元素由生成函数提供，不是内联常量。
        assert_eq!(
            prefix(
                PROTOCOL_VERSION,
                &envelope_label("captcha", PROTOCOL_VERSION)
            ),
            "v2.owaf-captcha:v2"
        );
    }

    #[test]
    fn aad_generation_matches_spec() {
        let captcha = envelope_label("captcha", PROTOCOL_VERSION);
        assert_eq!(
            aad(&captcha, PURPOSE_CHALLENGE_DATA),
            "owaf-captcha:v2|challenge-data"
        );
        let gm = envelope_label("gm", PROTOCOL_VERSION);
        assert_eq!(aad(&gm, PURPOSE_SHIELD), "owaf-gm:v2|shield");
        assert_eq!(
            aad(
                &envelope_label("env", PROTOCOL_VERSION),
                PURPOSE_BROWSERSIGN
            ),
            "owaf-env:v2|browsersign"
        );
        // purpose 枚举与拼接模型一致性：泛化遍历。
        for purpose in [
            PURPOSE_CHALLENGE_DATA,
            PURPOSE_SHIELD,
            PURPOSE_CAPTCHA,
            PURPOSE_BROWSERSIGN,
            PURPOSE_PASS,
            PURPOSE_DYN_PROTECT,
        ] {
            assert_eq!(
                aad(&captcha, purpose),
                format!("owaf-captcha:v2|{}", purpose)
            );
        }
    }

    #[test]
    fn kdf_matches_arbitration_definition() {
        // kdf(key, category) = SM3(key || owaf-<category>:v2) 截 32 字节。
        let key = b"0123456789abcdef0123456789abcdef";
        let derived = sm3_kdf(key, "server-sign");
        let mut buf = key.to_vec();
        buf.extend_from_slice(b"owaf-server-sign:v2");
        assert_eq!(
            crate::hex_encode(&derived),
            crate::hex_encode(&crate::sm3::sm3_digest(&buf))
        );
        // 不同 category 域分离。
        let other = sm3_kdf(key, "browsersign");
        assert_ne!(derived, other);
        // 空键与空 category 也走同一拼接规则。
        let empty = sm3_kdf(b"", "x");
        let mut buf2 = b"".to_vec();
        buf2.extend_from_slice(b"owaf-x:v2");
        assert_eq!(
            crate::hex_encode(&empty),
            crate::hex_encode(&crate::sm3::sm3_digest(&buf2))
        );
    }
}
