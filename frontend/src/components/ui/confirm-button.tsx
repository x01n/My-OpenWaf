"use client";

import { useOverlayState, Button, Modal } from "@heroui/react";
import { useState, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { ApiError } from "@/lib/api/client";
import { showSuccess, showError } from "@/components/ui/toast-host";
import { useI18n } from "@/i18n";

/**
 * 危险操作确认按钮：内置二次确认弹窗 + 执行反馈。
 * 用法：<ConfirmButton onConfirm={() => apiPost(...)} confirmText={t("...")}>删除</ConfirmButton>
 *
 * `title` / `confirmText` 未传时回退到通用文案，避免英文界面下出现中文。
 */
export function ConfirmButton({
  children,
  onConfirm,
  confirmText,
  title,
  successText,
  variant = "danger",
  size = "sm",
  isDisabled,
}: {
  children: ReactNode;
  onConfirm: () => Promise<unknown> | unknown;
  confirmText?: string;
  title?: string;
  successText?: string;
  /** 按钮风格：danger 红色危险操作，primary 主色，ghost 弱化 */
  variant?: "danger" | "primary" | "ghost";
  size?: "sm" | "md" | "lg";
  isDisabled?: boolean;
}) {
  const { t } = useI18n();
  const state = useOverlayState();
  const [pending, setPending] = useState(false);

  async function handleConfirm() {
    setPending(true);
    try {
      await onConfirm();
      showSuccess(successText ?? t("common.success"));
      state.close();
    } catch (err) {
      showError(t("common.operationFailed"), err instanceof ApiError ? err.message : undefined);
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <Button size={size} variant={variant} isDisabled={isDisabled} onPress={state.open}>
        {children}
      </Button>
      <Modal state={state}>
        <Modal.Backdrop>
          <Modal.Container size="sm">
            <Modal.Dialog>
              <Modal.Header>
                <Modal.Icon className="bg-danger-soft text-danger">
                  <AlertTriangle className="size-5" />
                </Modal.Icon>
                <Modal.Heading>{title ?? t("common.confirmTitle")}</Modal.Heading>
                <Modal.CloseTrigger aria-label={t("common.close")} />
              </Modal.Header>
              <Modal.Body className="text-muted text-sm">
                {confirmText ?? t("common.confirmText")}
              </Modal.Body>
              <Modal.Footer>
                <Button variant="ghost" onPress={state.close}>
                  {t("common.cancel")}
                </Button>
                <Button variant="danger" isPending={pending} onPress={handleConfirm}>
                  {t("common.confirm")}
                </Button>
              </Modal.Footer>
            </Modal.Dialog>
          </Modal.Container>
        </Modal.Backdrop>
      </Modal>
    </>
  );
}
