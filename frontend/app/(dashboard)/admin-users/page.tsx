"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  useAdminUsers,
  useAdminUserCreate,
  useAdminUserUpdateRole,
  useAdminUserUpdatePassword,
  useAdminUserDelete,
} from "@/hooks/use-api";
import { DataTable } from "@/components/data-table";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { IconPlus, IconTrash, IconLock } from "@tabler/icons-react";
import type { AdminUser } from "@/lib/types";

function formatTime(t: string | undefined | null): string {
  if (!t) return "-";
  return new Date(t).toLocaleString();
}

function roleBadgeVariant(role: string): "default" | "secondary" | "outline" {
  switch (role) {
    case "admin":
      return "default";
    case "operator":
      return "secondary";
    default:
      return "outline";
  }
}

export default function AdminUsersPage() {
  const { t } = useTranslation();
  const { data, isLoading, mutate } = useAdminUsers();
  const { execute: createUser, loading: createLoading } = useAdminUserCreate();
  const { execute: updateRole } = useAdminUserUpdateRole();
  const { execute: updatePassword, loading: pwdLoading } = useAdminUserUpdatePassword();
  const { execute: deleteUser, loading: deleteLoading } = useAdminUserDelete();

  const [createOpen, setCreateOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<number | null>(null);
  const [passwordTarget, setPasswordTarget] = useState<AdminUser | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [form, setForm] = useState({
    username: "",
    password: "",
    role: "operator",
  });

  const users: AdminUser[] = data || [];

  const currentUser = (() => {
    if (typeof window === "undefined") return null;
    try {
      const token = localStorage.getItem("token");
      if (!token) return null;
      const payload = JSON.parse(atob(token.split(".")[1]));
      return payload.username || payload.sub;
    } catch {
      return null;
    }
  })();

  const handleCreate = async () => {
    if (!form.username.trim() || !form.password.trim()) return;
    try {
      await createUser({
        username: form.username.trim(),
        password: form.password.trim(),
        role: form.role,
      });
      toast.success(t("adminUsers.createSuccess"));
      setCreateOpen(false);
      setForm({ username: "", password: "", role: "operator" });
      mutate();
    } catch {
      toast.error(t("adminUsers.createFailed"));
    }
  };

  const handleRoleChange = async (user: AdminUser, newRole: string) => {
    try {
      await updateRole({ id: user.id, role: newRole });
      toast.success(t("adminUsers.updateRoleSuccess"));
      mutate();
    } catch {
      toast.error(t("adminUsers.updateRoleFailed"));
    }
  };

  const handlePasswordChange = async () => {
    if (!passwordTarget || !newPassword.trim()) return;
    try {
      await updatePassword({ id: passwordTarget.id, password: newPassword.trim() });
      toast.success(t("adminUsers.updatePasswordSuccess"));
      setPasswordOpen(false);
      setPasswordTarget(null);
      setNewPassword("");
    } catch {
      toast.error(t("adminUsers.updatePasswordFailed"));
    }
  };

  const handleDeleteClick = (user: AdminUser) => {
    if (user.username === currentUser) {
      toast.error(t("adminUsers.cannotDeleteSelf"));
      return;
    }
    setDeleteId(user.id);
  };

  const confirmDelete = async () => {
    if (!deleteId) return;
    try {
      await deleteUser(deleteId);
      toast.success(t("common.deleteSuccess"));
      setDeleteId(null);
      mutate();
    } catch {
      toast.error(t("common.deleteFailed"));
    }
  };

  const roleLabel = (role: string) => {
    switch (role) {
      case "admin":
        return t("adminUsers.roleAdmin");
      case "operator":
        return t("adminUsers.roleOperator");
      case "readonly":
        return t("adminUsers.roleReadonly");
      default:
        return role;
    }
  };

  const columns = [
    {
      key: "username",
      title: t("adminUsers.username"),
      render: (row: AdminUser) => (
        <span className="font-medium">{row.username}</span>
      ),
    },
    {
      key: "role",
      title: t("adminUsers.role"),
      render: (row: AdminUser) => (
        <Select
          value={row.role}
          onValueChange={(val) => handleRoleChange(row, val)}
          disabled={row.username === currentUser}
        >
          <SelectTrigger className="h-8 w-28">
            <SelectValue>
              <Badge variant={roleBadgeVariant(row.role)}>
                {roleLabel(row.role)}
              </Badge>
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="admin">{t("adminUsers.roleAdmin")}</SelectItem>
            <SelectItem value="operator">{t("adminUsers.roleOperator")}</SelectItem>
            <SelectItem value="readonly">{t("adminUsers.roleReadonly")}</SelectItem>
          </SelectContent>
        </Select>
      ),
    },
    {
      key: "created_at",
      title: t("adminUsers.createdAt"),
      render: (row: AdminUser) => (
        <span className="text-sm text-muted-foreground">
          {formatTime(row.created_at)}
        </span>
      ),
    },
    {
      key: "last_login",
      title: t("adminUsers.lastLogin"),
      render: (row: AdminUser) => (
        <span className="text-sm text-muted-foreground">
          {row.last_login ? formatTime(row.last_login) : t("adminUsers.never")}
        </span>
      ),
    },
    {
      key: "actions",
      title: t("common.action"),
      width: "120px",
      render: (row: AdminUser) => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => {
              setPasswordTarget(row);
              setPasswordOpen(true);
            }}
            title={t("adminUsers.changePassword")}
          >
            <IconLock className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => handleDeleteClick(row)}
            className="text-destructive hover:text-destructive"
            disabled={row.username === currentUser}
          >
            <IconTrash className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t("adminUsers.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("adminUsers.description")}</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <IconPlus className="mr-2 h-4 w-4" />
          {t("adminUsers.create")}
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={users}
        loading={isLoading}
        rowKey={(row) => row.id}
        emptyText={t("adminUsers.empty")}
      />

      {/* 创建管理员对话框 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("adminUsers.create")}</DialogTitle>
            <DialogDescription>{t("adminUsers.description")}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>{t("adminUsers.username")}</Label>
              <Input
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                placeholder={t("adminUsers.usernamePlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("adminUsers.password")}</Label>
              <Input
                type="password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                placeholder={t("adminUsers.passwordPlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label>{t("adminUsers.role")}</Label>
              <Select
                value={form.role}
                onValueChange={(val) => setForm({ ...form, role: val })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">{t("adminUsers.roleAdmin")}</SelectItem>
                  <SelectItem value="operator">{t("adminUsers.roleOperator")}</SelectItem>
                  <SelectItem value="readonly">{t("adminUsers.roleReadonly")}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handleCreate}
              disabled={createLoading || !form.username.trim() || !form.password.trim()}
            >
              {createLoading ? t("common.submitting") : t("common.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 修改密码对话框 */}
      <Dialog open={passwordOpen} onOpenChange={setPasswordOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t("adminUsers.changePassword")} - {passwordTarget?.username}
            </DialogTitle>
            <DialogDescription>{t("adminUsers.description")}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>{t("adminUsers.newPassword")}</Label>
              <Input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder={t("adminUsers.newPasswordPlaceholder")}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handlePasswordChange();
                }}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPasswordOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handlePasswordChange}
              disabled={pwdLoading || !newPassword.trim()}
            >
              {pwdLoading ? t("common.submitting") : t("common.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除确认 */}
      <ConfirmDialog
        open={deleteId !== null}
        onOpenChange={(open) => !open && setDeleteId(null)}
        title={t("common.confirm")}
        description={t("adminUsers.deleteConfirm")}
        onConfirm={confirmDelete}
        loading={deleteLoading}
      />
    </div>
  );
}
