"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Badge } from "@/components/ui/badge";
import {
  IconShield,
  IconClock,
  IconBolt,
  IconAlertTriangle,
  IconBan,
  IconPencil,
  IconPlus,
  IconHelpCircle,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";

interface RateLimitRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
}

interface RuleSection {
  title: string;
  icon: React.ElementType;
  rules: RateLimitRule[];
}

const placeholderRules: RuleSection[] = [
  {
    title: "ccProtection.highFrequencyAccessLimit",
    icon: IconBolt,
    rules: [
      {
        id: "1",
        name: "ccProtection.basicLimit",
        description: "ccProtection.basicLimitDesc",
        enabled: true,
      },
    ],
  },
  {
    title: "ccProtection.highFrequencyAttackLimit",
    icon: IconAlertTriangle,
    rules: [
      {
        id: "2",
        name: "ccProtection.attackLimit",
        description: "ccProtection.attackLimitDesc",
        enabled: true,
      },
    ],
  },
  {
    title: "ccProtection.errorLimit",
    icon: IconBan,
    rules: [
      {
        id: "3",
        name: "ccProtection.basicErrorLimit",
        description: "ccProtection.errorLimitDesc",
        enabled: true,
      },
    ],
  },
];

export default function CCProtectionPage() {
  const { t } = useTranslation();
  const [waitingRoomEnabled, setWaitingRoomEnabled] = useState(false);
  const [rateLimitMode, setRateLimitMode] = useState<"global" | "custom">("global");
  const [sections, setSections] = useState<RuleSection[]>(placeholderRules);
  const [isSaving, setIsSaving] = useState(false);

  const toggleRule = (sectionIndex: number, ruleId: string) => {
    setSections((prev) =>
      prev.map((sec, idx) =>
        idx === sectionIndex
          ? {
              ...sec,
              rules: sec.rules.map((rule) =>
                rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
              ),
            }
          : sec
      )
    );
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      toast.success(t("ccProtection.saveSuccess"));
    } catch {
      toast.error(t("common.saveFailed"));
    } finally {
      setIsSaving(false);
    }
  };

  const handleCancel = () => {
    setWaitingRoomEnabled(false);
    setRateLimitMode("global");
    setSections(placeholderRules);
    toast.info(t("ccProtection.resetSuccess"));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <IconShield className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-semibold">{t("ccProtection.title")}</h1>
      </div>

      {/* 等候室 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconClock className="h-5 w-5 text-primary" />
            {t("ccProtection.waitingRoom")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <Switch
              checked={waitingRoomEnabled}
              onCheckedChange={setWaitingRoomEnabled}
              id="waiting-room"
            />
            <div className="space-y-0.5">
              <Label htmlFor="waiting-room" className="cursor-pointer">
                {t("ccProtection.waitingRoomToggle")}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t("ccProtection.waitingRoomDesc")}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 频率限制 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <IconBolt className="h-5 w-5 text-primary" />
            {t("ccProtection.rateLimit")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center gap-4">
            <RadioGroup
              value={rateLimitMode}
              onValueChange={(v) => setRateLimitMode(v as "global" | "custom")}
              className="flex items-center gap-6"
            >
              <div className="flex items-center gap-2">
                <RadioGroupItem value="global" id="rate-limit-global" />
                <Label htmlFor="rate-limit-global" className="cursor-pointer">
                  {t("ccProtection.followGlobal")}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="custom" id="rate-limit-custom" />
                <Label htmlFor="rate-limit-custom" className="cursor-pointer">
                  {t("ccProtection.customConfig")}
                </Label>
              </div>
            </RadioGroup>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <IconHelpCircle className="h-3.5 w-3.5" />
              <span>{t("ccProtection.rateLimitDesc")}</span>
            </div>
          </div>

          {rateLimitMode === "custom" && (
            <div className="space-y-6">
              {sections.map((section, sectionIndex) => {
                const SectionIcon = section.icon;
                return (
                  <div key={section.title} className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <SectionIcon className="h-4 w-4 text-primary" />
                        <h3 className="text-sm font-medium">{t(section.title)}</h3>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 gap-1 text-xs"
                        onClick={() => toast.info(t("ccProtection.addRuleDeveloping"))}
                      >
                        <IconPlus className="h-3.5 w-3.5" />
                        {t("ccProtection.addRule")}
                      </Button>
                    </div>

                    <div className="space-y-2">
                      {section.rules.map((rule) => (
                        <div
                          key={rule.id}
                          className={cn(
                            "flex items-center gap-4 rounded-lg border p-3 transition-colors",
                            rule.enabled ? "bg-teal-50/50" : "bg-muted/30"
                          )}
                        >
                          <Switch
                            checked={rule.enabled}
                            onCheckedChange={() => toggleRule(sectionIndex, rule.id)}
                            id={`rule-${rule.id}`}
                          />
                          <div className="flex-1 space-y-0.5">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{t(rule.name)}</span>
                              <Badge
                                variant={rule.enabled ? "default" : "secondary"}
                                className="h-4 px-1.5 text-[10px]"
                              >
                                {rule.enabled ? t("common.enable") : t("common.disable")}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              {t(rule.description)}
                            </p>
                          </div>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 shrink-0"
                            onClick={() => toast.info(t("ccProtection.editRuleDeveloping"))}
                          >
                            <IconPencil className="h-4 w-4" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 底部操作按钮 */}
      <div className="flex justify-end gap-3">
        <Button variant="outline" onClick={handleCancel}>
          {t("common.cancel")}
        </Button>
        <Button
          onClick={handleSave}
          disabled={isSaving}
          className="bg-primary hover:bg-primary/90"
        >
          {isSaving ? t("common.saving") : t("common.save")}
        </Button>
      </div>
    </div>
  );
}
