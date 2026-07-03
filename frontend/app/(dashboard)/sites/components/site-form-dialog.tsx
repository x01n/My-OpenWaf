"use client";

import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useForm, useFieldArray } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import { mutate } from "swr";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { siteApi } from "@/lib/api";
import { useCertificates } from "@/hooks/use-api";
import type { Site } from "@/lib/types";
import {
  IconPlus,
  IconTrash,
} from "@tabler/icons-react";

const siteFormSchema = z.object({
  host: z.string().min(1, "sites.form.hostRequired"),
  name: z.string().optional(),
  listeners: z
    .array(
      z.object({
        port: z
          .string()
          .min(1, "sites.form.portRequired")
          .regex(/^\d+$/, "sites.form.portNumber"),
        tls_enabled: z.boolean(),
      })
    )
    .min(1, "sites.form.listenersRequired"),
  cert_id: z.number().optional(),
  access_mode: z.enum(["proxy", "static", "redirect"]),
  upstreams: z
    .array(
      z.object({
        url: z.string().min(1, "sites.form.upstreamUrlRequired"),
      })
    )
    .min(1, "sites.form.upstreamRequired"),
  upstream_host: z.string().optional(),
});

type SiteFormValues = z.infer<typeof siteFormSchema>;

interface SiteFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  site?: Site | null;
}

/**
 * @description 添加/编辑站点弹窗组件
 * 支持动态监听端口、上游服务器、证书选择、接入方式选择
 */
export function SiteFormDialog({ open, onOpenChange, site }: SiteFormDialogProps) {
  const { t } = useTranslation();
  const isEdit = !!site;
  const { data: certificates } = useCertificates();

  const form = useForm<SiteFormValues>({
    resolver: zodResolver(siteFormSchema),
    defaultValues: {
      host: "",
      name: "",
      listeners: [{ port: "80", tls_enabled: false }],
      cert_id: undefined,
      access_mode: "proxy",
      upstreams: [{ url: "http://127.0.0.1:8080" }],
      upstream_host: "",
    },
  });

  const {
    register,
    handleSubmit,
    control,
    watch,
    setValue,
    reset,
    formState: { errors },
  } = form;

  const listenerArray = useFieldArray({ control, name: "listeners" });
  const upstreamArray = useFieldArray({ control, name: "upstreams" });

  /** @description 当弹窗打开或编辑对象变化时，重置表单数据 */
  useEffect(() => {
    if (open && site) {
      const bind = site.bind || "";
      const portMatch = bind.match(/:(\d+)$/);
      const port = portMatch ? portMatch[1] : "80";
      reset({
        host: site.host,
        name: site.host,
        listeners: [{ port, tls_enabled: site.tls_enabled }],
        cert_id: site.cert_id,
        access_mode: "proxy",
        upstreams: site.upstream_urls
          ? site.upstream_urls.split(",").map((s) => ({ url: s.trim() }))
          : [{ url: "" }],
        upstream_host: site.upstream_host || "",
      });
    } else if (open && !site) {
      reset({
        host: "",
        name: "",
        listeners: [{ port: "80", tls_enabled: false }],
        cert_id: undefined,
        access_mode: "proxy",
        upstreams: [{ url: "http://127.0.0.1:8080" }],
        upstream_host: "",
      });
    }
  }, [open, site, reset]);

  /**
   * @description 表单提交处理
   * 创建时：先创建站点，再创建额外监听器
   * 编辑时：仅更新站点主配置
   */
  const onSubmit = async (values: SiteFormValues) => {
    try {
      const primaryListener = values.listeners[0];
      const bind = `0.0.0.0:${primaryListener.port}`;

      const payload: Partial<Site> = {
        host: values.host,
        bind,
        tls_enabled: primaryListener.tls_enabled,
        cert_id: values.cert_id,
        upstream_urls: values.upstreams.map((u) => u.url).join(","),
        upstream_host: values.upstream_host || undefined,
      };

      if (isEdit && site) {
        await siteApi.update(site.id, payload);
        toast.success(t("sites.updateSuccess"));
        mutate(["sites"]);
        mutate(["site", site.id]);
        onOpenChange(false);
      } else {
        const result = await siteApi.create(payload);
        // 创建额外的监听器
        for (let i = 1; i < values.listeners.length; i++) {
          const l = values.listeners[i];
          await siteApi.createListener(result.id, {
            bind: `0.0.0.0:${l.port}`,
            tls_enabled: l.tls_enabled,
            cert_id: l.tls_enabled ? values.cert_id : undefined,
            enabled: true,
          });
        }
        toast.success(t("sites.createSuccess"));
        mutate(["sites"]);
        onOpenChange(false);
      }
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : t("common.operationFailed"));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? t("sites.form.editTitle") : t("sites.form.addTitle")}</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {/* 域名 */}
          <div className="space-y-1.5">
            <Label htmlFor="host">{t("sites.form.host")} *</Label>
            <Input
              id="host"
              placeholder="example.com"
              {...register("host")}
            />
            {errors.host && (
              <p className="text-xs text-destructive">{t(errors.host.message!)}</p>
            )}
          </div>

          {/* 应用名称 */}
          <div className="space-y-1.5">
            <Label htmlFor="name">{t("sites.form.name")}</Label>
            <Input
              id="name"
              placeholder={t("sites.form.name")}
              {...register("name")}
            />
          </div>

          {/* 监听端口 */}
          <div className="space-y-2">
            <Label>{t("sites.form.listeners")}</Label>
            <div className="space-y-2">
              {listenerArray.fields.map((field, index) => (
                <div key={field.id} className="flex items-center gap-2">
                  <Input
                    placeholder="80"
                    className="w-24"
                    {...register(`listeners.${index}.port` as const)}
                  />
                  <div className="flex items-center gap-2">
              {/* eslint-disable-next-line react-hooks/incompatible-library */}
                    <Switch
                      checked={watch(`listeners.${index}.tls_enabled`)}
                      onCheckedChange={(checked) =>
                        setValue(`listeners.${index}.tls_enabled`, checked)
                      }
                    />
                    <span className="text-xs text-muted-foreground">
                      {watch(`listeners.${index}.tls_enabled`) ? t("sites.https") : t("sites.http")}
                    </span>
                  </div>
                  {listenerArray.fields.length > 1 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      onClick={() => listenerArray.remove(index)}
                    >
                      <IconTrash className="h-4 w-4 text-destructive" />
                    </Button>
                  )}
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  listenerArray.append({ port: "", tls_enabled: false })
                }
              >
                <IconPlus className="h-3.5 w-3.5 mr-1" />
                {t("sites.form.addPort")}
              </Button>
            </div>
            {errors.listeners && (
              <p className="text-xs text-destructive">
                {t(errors.listeners.message!)}
              </p>
            )}
          </div>

          {/* 证书选择 */}
          <div className="space-y-1.5">
            <Label>{t("sites.form.cert")}</Label>
            <Select
              value={watch("cert_id")?.toString() || ""}
              onValueChange={(v) =>
                setValue("cert_id", v ? Number(v) : undefined)
              }
            >
              <SelectTrigger>
                <SelectValue placeholder={t("sites.form.certPlaceholder")} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">{t("sites.form.certNone")}</SelectItem>
                {certificates?.map((cert) => (
                  <SelectItem key={cert.id} value={cert.id.toString()}>
                    {cert.name} ({cert.domain})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* 接入方式 */}
          <div className="space-y-1.5">
            <Label>{t("sites.form.accessMethod")}</Label>
            <RadioGroup
              value={watch("access_mode")}
              onValueChange={(v) => setValue("access_mode", v as SiteFormValues["access_mode"])}
              className="flex flex-col gap-2"
            >
              <div className="flex items-center gap-2">
                <RadioGroupItem value="proxy" id="proxy" />
                <Label htmlFor="proxy" className="cursor-pointer font-normal">
                  {t("sites.form.accessProxy")}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="static" id="static" />
                <Label htmlFor="static" className="cursor-pointer font-normal">
                  {t("sites.form.accessStatic")}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="redirect" id="redirect" />
                <Label htmlFor="redirect" className="cursor-pointer font-normal">
                  {t("sites.form.accessRedirect")}
                </Label>
              </div>
            </RadioGroup>
          </div>

          {/* 上游服务器 */}
          <div className="space-y-2">
            <Label>{t("sites.form.upstreamServers")}</Label>
            <div className="space-y-2">
              {upstreamArray.fields.map((field, index) => (
                <div key={field.id} className="flex items-center gap-2">
                  <Input
                    placeholder="http://127.0.0.1:8080"
                    {...register(`upstreams.${index}.url` as const)}
                  />
                  {upstreamArray.fields.length > 1 && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      onClick={() => upstreamArray.remove(index)}
                    >
                      <IconTrash className="h-4 w-4 text-destructive" />
                    </Button>
                  )}
                </div>
              ))}
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => upstreamArray.append({ url: "" })}
              >
                <IconPlus className="h-3.5 w-3.5 mr-1" />
                {t("sites.form.addUpstream")}
              </Button>
            </div>
            {errors.upstreams && (
              <p className="text-xs text-destructive">
                {t(errors.upstreams.message!)}
              </p>
            )}
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              className="bg-teal-500 hover:bg-teal-600"
            >
              {t("common.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
