"use client";

import { useOverlayState, Button, Modal } from "@heroui/react";
import { useState, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { useI18n } from "@/i18n";

type ConfirmDialogProps = {
  /** 触发按钮文案；不传则使用受控 state */
  trigger?: ReactNode;
  state?: ReturnType<typeof useOverlayState>;
  title: string;
  description?: ReactNode;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
};

/**
 * 确认弹窗：危险操作统一入口。
 * 受控用法：const state = useOverlayState(); <ConfirmDialog state={state} ... />
 * 非受控用法：<ConfirmDialog trigger={<Button/>} ... />
 */
export function ConfirmDialog({
  trigger,
  state: externalState,
  title,
  description,
  confirmText = "确认",
  cancelText = "取消",
  danger,
  onConfirm,
}: ConfirmDialogProps) {
  const internalState = useOverlayState();
  const state = externalState ?? internalState;
  const { t } = useI18n();
  const [pending, setPending] = useState(false);

  async function handleConfirm() {
    setPending(true);
    try {
      await onConfirm();
      state.close();
    } finally {
      setPending(false);
    }
  }

  return (
    <Modal state={state}>
      {trigger ? <Modal.Trigger>{trigger}</Modal.Trigger> : null}
      <Modal.Backdrop>
        <Modal.Container size="sm">
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Icon className={danger ? "bg-danger-soft text-danger" : undefined}>
                <AlertTriangle className="size-5" />
              </Modal.Icon>
              <Modal.Heading>{title}</Modal.Heading>
              <Modal.CloseTrigger aria-label={t("common.close")} />
            </Modal.Header>
            {description ? (
              <Modal.Body className="text-muted text-sm">{description}</Modal.Body>
            ) : null}
            <Modal.Footer>
              <Button variant="ghost" onPress={state.close}>
                {cancelText}
              </Button>
              <Button
                variant={danger ? "danger" : "primary"}
                isPending={pending}
                onPress={handleConfirm}
              >
                {confirmText}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}

/** 局部 useState 别名，避免与外部命名冲突 */

/** 通用表单弹窗壳：统一标题、说明与底部操作区 */
export function FormDialog({
  state,
  title,
  description,
  children,
  footer,
  size = "lg",
}: {
  state: ReturnType<typeof useOverlayState>;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg" | "cover";
}) {
  const { t } = useI18n();
  return (
    <Modal state={state}>
      <Modal.Backdrop>
        <Modal.Container size={size}>
          <Modal.Dialog>
            <Modal.Header>
              <Modal.Heading>{title}</Modal.Heading>
              <Modal.CloseTrigger aria-label={t("common.close")} />
            </Modal.Header>
            {description ? (
              <div className="text-muted px-5 pb-1 text-sm">{description}</div>
            ) : null}
            <Modal.Body className="gap-3">{children}</Modal.Body>
            {footer ? <Modal.Footer>{footer}</Modal.Footer> : null}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  );
}
