"use client";

import { useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import { IconDeviceFloppy, IconRefresh, IconEye } from "@tabler/icons-react";
import {
  usePageTemplate,
  usePageTemplateUpdate,
  usePageTemplateReset,
  usePageTemplatePreview,
} from "@/hooks/use-api";

const TEMPLATE_TYPES = ["captcha", "challenge", "block"] as const;
type TemplateType = (typeof TEMPLATE_TYPES)[number];

interface CommonFields {
  brand_name: string;
  primary_color: string;
  bg_gradient: string;
  logo_url: string;
  title: string;
  footer_text: string;
  custom_css: string;
}

function TemplateEditor({ type }: { type: TemplateType }) {
  const { t } = useTranslation();
  const { data, isLoading, mutate } = usePageTemplate(type);
  const updateTemplate = usePageTemplateUpdate();
  const resetTemplate = usePageTemplateReset();
  const { data: previewData, mutate: refreshPreview } = usePageTemplatePreview(type);

  const [form, setForm] = useState<Record<string, string>>({});
  const [showPreview, setShowPreview] = useState(false);

  useEffect(() => {
    if (data) setForm(data as Record<string, string>);
  }, [data]);

  const setField = (key: string, value: string) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = async () => {
    try {
      await updateTemplate.execute({ type, data: form });
      await mutate();
      await refreshPreview();
      toast.success(t("pageTemplates.saved"));
    } catch {
      toast.error(t("pageTemplates.saveFailed"));
    }
  };

  const handleReset = async () => {
    try {
      await resetTemplate.execute(type);
      await mutate();
      await refreshPreview();
      toast.success(t("pageTemplates.resetSuccess"));
    } catch {
      toast.error(t("pageTemplates.resetFailed"));
    }
  };

  const extraFields: { key: string; label: string }[] = [];
  if (type === "captcha") {
    extraFields.push(
      { key: "subtitle", label: t("pageTemplates.subtitle") },
      { key: "subtitle_zh", label: t("pageTemplates.subtitleZh") },
      { key: "submit_text", label: t("pageTemplates.submitText") }
    );
  } else if (type === "challenge") {
    extraFields.push(
      { key: "checking_text", label: t("pageTemplates.checkingText") },
      { key: "checking_text_zh", label: t("pageTemplates.checkingTextZh") },
      { key: "wait_text", label: t("pageTemplates.waitText") },
      { key: "wait_text_zh", label: t("pageTemplates.waitTextZh") }
    );
  } else if (type === "block") {
    extraFields.push(
      { key: "block_title", label: t("pageTemplates.blockTitle") },
      { key: "block_message", label: t("pageTemplates.blockMessage") },
      { key: "rate_limit_title", label: t("pageTemplates.rateLimitTitle") },
      { key: "rate_limit_message", label: t("pageTemplates.rateLimitMsg") }
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-1">
          <Label>{t("pageTemplates.brandName")}</Label>
          <Input
            value={form.brand_name || ""}
            onChange={(e) => setField("brand_name", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.primaryColor")}</Label>
          <div className="flex gap-2">
            <Input
              value={form.primary_color || ""}
              onChange={(e) => setField("primary_color", e.target.value)}
            />
            <input
              type="color"
              value={form.primary_color || "#14b8a6"}
              onChange={(e) => setField("primary_color", e.target.value)}
              className="h-9 w-9 cursor-pointer rounded border"
            />
          </div>
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.bgGradient")}</Label>
          <Input
            value={form.bg_gradient || ""}
            onChange={(e) => setField("bg_gradient", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.logoUrl")}</Label>
          <Input
            value={form.logo_url || ""}
            onChange={(e) => setField("logo_url", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.pageTitle")}</Label>
          <Input
            value={form.title || ""}
            onChange={(e) => setField("title", e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <Label>{t("pageTemplates.footerText")}</Label>
          <Input
            value={form.footer_text || ""}
            onChange={(e) => setField("footer_text", e.target.value)}
          />
        </div>
        {extraFields.map((f) => (
          <div key={f.key} className="space-y-1">
            <Label>{f.label}</Label>
            <Input
              value={form[f.key] || ""}
              onChange={(e) => setField(f.key, e.target.value)}
            />
          </div>
        ))}
        <div className="space-y-1 md:col-span-2">
          <Label>{t("pageTemplates.customCss")}</Label>
          <Textarea
            rows={4}
            value={form.custom_css || ""}
            onChange={(e) => setField("custom_css", e.target.value)}
            className="font-mono text-sm"
          />
        </div>
      </div>

      <div className="flex gap-2">
        <Button onClick={handleSave} disabled={updateTemplate.loading}>
          <IconDeviceFloppy className="mr-1 h-4 w-4" />
          {t("pageTemplates.save")}
        </Button>
        <Button
          variant="outline"
          onClick={() => setShowPreview(!showPreview)}
        >
          <IconEye className="mr-1 h-4 w-4" />
          {t("pageTemplates.preview")}
        </Button>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="destructive">
              <IconRefresh className="mr-1 h-4 w-4" />
              {t("pageTemplates.reset")}
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("pageTemplates.resetConfirm")}</AlertDialogTitle>
              <AlertDialogDescription>
                {t("pageTemplates.resetConfirmDesc")}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={handleReset}>Confirm</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>

      {showPreview && previewData && (
        <div className="mt-4 rounded-lg border overflow-hidden">
          <iframe
            srcDoc={typeof previewData === "string" ? previewData : (previewData as any).html || ""}
            className="w-full h-[500px]"
            sandbox="allow-same-origin"
            title="Template Preview"
          />
        </div>
      )}
    </div>
  );
}

export default function PageTemplatesPage() {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">
          {t("pageTemplates.title")}
        </h1>
        <p className="text-muted-foreground">
          {t("pageTemplates.description")}
        </p>
      </div>

      <Tabs defaultValue="captcha">
        <TabsList>
          {TEMPLATE_TYPES.map((type) => (
            <TabsTrigger key={type} value={type}>
              {t(`pageTemplates.${type}`)}
            </TabsTrigger>
          ))}
        </TabsList>
        {TEMPLATE_TYPES.map((type) => (
          <TabsContent key={type} value={type}>
            <Card>
              <CardHeader>
                <CardTitle>{t(`pageTemplates.${type}`)}</CardTitle>
                <CardDescription>
                  {t("pageTemplates.description")}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <TemplateEditor type={type} />
              </CardContent>
            </Card>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
