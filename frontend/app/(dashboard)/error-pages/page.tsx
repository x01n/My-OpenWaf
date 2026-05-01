"use client";

import { useEffect, useState } from "react";
import { FileWarning, Eye } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageIntro, Surface, EmptyState } from "@/components/console-shell";
import { listSites, type Site } from "@/lib/api";
import {
  getDefaultErrorPages, getSiteErrorPages, updateSiteErrorPages, previewErrorPage,
  type ErrorPageConfig, type DefaultErrorPagesResponse,
} from "@/lib/rules-api";

const statusCodes = ["403", "404", "429", "500", "502", "503"] as const;
const statusLabels: Record<string, string> = {
  "403": "403 Forbidden",
  "404": "404 Not Found",
  "429": "429 Too Many Requests",
  "500": "500 Internal Error",
  "502": "502 Bad Gateway",
  "503": "503 Unavailable",
};

export default function ErrorPagesPage() {
  const [defaults, setDefaults] = useState<Record<string, ErrorPageConfig>>({});
  const [sites, setSites] = useState<Site[]>([]);
  const [selectedSite, setSelectedSite] = useState<string>("");
  const [activeCode, setActiveCode] = useState("403");
  const [sitePages, setSitePages] = useState<Record<string, ErrorPageConfig>>({});
  const [previewHtml, setPreviewHtml] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getDefaultErrorPages().then((res) => setDefaults(res.defaults ?? {})).catch(() => {});
    listSites().then((res) => {
      const list = res.items ?? [];
      setSites(list);
      if (list.length > 0) setSelectedSite(String(list[0].id));
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedSite) return;
    getSiteErrorPages(Number(selectedSite))
      .then((res) => setSitePages(res.error_pages ?? {}))
      .catch(() => setSitePages({}));
  }, [selectedSite]);

  function getCurrentHtml(): string {
    return sitePages[activeCode]?.html ?? defaults[activeCode]?.html ?? "";
  }

  function setCurrentHtml(html: string) {
    setSitePages((prev) => ({
      ...prev,
      [activeCode]: {
        status_code: Number(activeCode),
        title: statusLabels[activeCode] ?? activeCode,
        html,
        content_type: "text/html",
      },
    }));
  }

  async function handleSave() {
    if (!selectedSite) return;
    setSaving(true);
    try {
      await updateSiteErrorPages(Number(selectedSite), sitePages);
      toast.success("错误页面已保存");
    } catch (e) { toast.error(String(e)); }
    finally { setSaving(false); }
  }

  async function handlePreview() {
    const html = getCurrentHtml();
    if (!html) { toast.error("HTML 内容为空"); return; }
    try {
      const res = await previewErrorPage(html, Number(activeCode));
      setPreviewHtml(res.rendered);
      if (res.parse_error) toast.warning("模板解析警告: " + res.parse_error);
      if (res.execute_error) toast.warning("模板执行警告: " + res.execute_error);
    } catch (e) { toast.error(String(e)); }
  }

  return (
    <div className="space-y-6">
      <PageIntro eyebrow="Error Pages" title="错误页面管理" description="管理默认和站点级自定义错误页面，支持 HTML 编辑和实时预览。" />

      <Surface title="默认错误页面模板" description="系统内置的默认错误页面，当站点未自定义时使用。">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Object.entries(defaults).map(([code, cfg]) => (
            <div key={code} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="mb-2 flex items-center gap-2">
                <FileWarning className="h-4 w-4 text-amber-600" />
                <span className="text-sm font-semibold text-slate-900">{cfg.status_code} {cfg.title}</span>
              </div>
              <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs font-mono text-slate-600 max-h-[120px] overflow-y-auto">{cfg.html?.slice(0, 300)}{(cfg.html?.length ?? 0) > 300 ? "..." : ""}</div>
            </div>
          ))}
        </div>
      </Surface>

      <Surface title="站点自定义错误页面" description="选择站点后为每个状态码编辑自定义 HTML。" action={
        <div className="flex gap-2">
          <Button variant="outline" onClick={handlePreview} className="rounded-xl"><Eye className="mr-2 h-4 w-4" />预览</Button>
          <Button onClick={handleSave} disabled={saving || !selectedSite}>{saving ? "保存中..." : "保存"}</Button>
        </div>
      }>
        <div className="mb-4">
          <Select value={selectedSite} onValueChange={setSelectedSite}>
            <SelectTrigger className="w-[300px] rounded-xl"><SelectValue placeholder="选择站点..." /></SelectTrigger>
            <SelectContent>
              {sites.map((s) => <SelectItem key={s.id} value={String(s.id)}>{s.host} (ID: {s.id})</SelectItem>)}
            </SelectContent>
          </Select>
        </div>

        {!selectedSite ? (
          <EmptyState title="请先选择站点" description="选择一个站点以编辑其自定义错误页面。" />
        ) : (
          <Tabs value={activeCode} onValueChange={setActiveCode}>
            <TabsList className="mb-4">
              {statusCodes.map((code) => <TabsTrigger key={code} value={code}>{code}</TabsTrigger>)}
            </TabsList>

            {statusCodes.map((code) => (
              <TabsContent key={code} value={code}>
                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700">HTML 编辑器 — {statusLabels[code]}</label>
                    <Textarea
                      value={code === activeCode ? getCurrentHtml() : ""}
                      onChange={(e) => setCurrentHtml(e.target.value)}
                      rows={16}
                      className="rounded-xl font-mono text-xs"
                      placeholder={`输入 ${code} 错误页面的 HTML 内容...`}
                    />
                    <p className="text-xs text-slate-400">支持 Go template 变量：{"{{.StatusCode}}"} {"{{.Message}}"} {"{{.ClientIP}}"} {"{{.RequestID}}"}</p>
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700">实时预览</label>
                    <div className="rounded-xl border border-slate-200 bg-white min-h-[350px] overflow-hidden">
                      {previewHtml ? (
                        <iframe srcDoc={previewHtml} className="h-[350px] w-full border-0" sandbox="allow-same-origin" title="错误页面预览" />
                      ) : (
                        <div className="flex h-[350px] items-center justify-center text-sm text-slate-400">点击"预览"按钮查看渲染效果</div>
                      )}
                    </div>
                  </div>
                </div>
              </TabsContent>
            ))}
          </Tabs>
        )}
      </Surface>
    </div>
  );
}