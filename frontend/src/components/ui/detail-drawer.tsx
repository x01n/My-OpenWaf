"use client";

import { Drawer } from "@heroui/react";
import type { ReactNode } from "react";
import { useI18n } from "@/i18n";

/**
 * 通用详情抽屉：右侧滑出，承载只读详情或中型表单。
 * 传入 useOverlayState() 的返回值以受控打开。
 */
export function DetailDrawer({
  state,
  title,
  description,
  children,
  footer,
  width = "w-[520px]",
}: {
  state: ReturnType<typeof import("@heroui/react").useOverlayState>;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  const { t } = useI18n();
  return (
    <Drawer state={state}>
      <Drawer.Backdrop>
        <Drawer.Content placement="right" className={width}>
          <Drawer.Dialog>
            <Drawer.Header>
              <div>
                <Drawer.Heading>{title}</Drawer.Heading>
                {description && <div className="text-muted mt-1 text-xs">{description}</div>}
              </div>
              <Drawer.CloseTrigger aria-label={t("common.close")} />
            </Drawer.Header>
            <Drawer.Body className="gap-3">{children}</Drawer.Body>
            {footer && <Drawer.Footer>{footer}</Drawer.Footer>}
          </Drawer.Dialog>
        </Drawer.Content>
      </Drawer.Backdrop>
    </Drawer>
  );
}

/** 详情抽屉中的键值行 */
export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[120px_1fr] items-start gap-3 border-b border-separator py-2 text-sm last:border-0">
      <span className="text-muted">{label}</span>
      <span className="min-w-0 break-all">{children}</span>
    </div>
  );
}
