"use client";

import { useTranslation } from "react-i18next";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { useSiteRules, useRuleDelete } from "@/hooks/use-api";
import { ruleApi } from "@/lib/api";
import { DataTable } from "@/components/data-table";
import type { Site } from "@/lib/types";

interface RulesTabProps {
  site: Site;
}

export function RulesTab({ site }: RulesTabProps) {
  const { t } = useTranslation();
  const router = useRouter();
  const { data: rules, mutate } = useSiteRules(site.id);
  const deleteRule = useRuleDelete();

  const handleToggle = async (rule: any) => { // eslint-disable-line @typescript-eslint/no-explicit-any
    try {
      await ruleApi.update(rule.id, { enabled: !rule.enabled });
      toast.success(t("common.updateSuccess"));
      mutate();
    } catch {
      toast.error(t("common.operationFailed"));
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await deleteRule.execute(id);
      toast.success(t("common.deleteSuccess"));
      mutate();
    } catch {
      toast.error(t("common.operationFailed"));
    }
  };

  const columns = [
    { key: "name", title: t("common.name") },
    { key: "phase", title: t("securityEvents.phase") },
    { key: "pattern", title: t("rules.pattern") },
    { key: "action", title: t("rules.action") },
    { key: "priority", title: t("rules.priority") },
    {
      key: "_enabled",
      title: t("common.enabled"),
      render: (row: any) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
        <Switch
          checked={row.enabled}
          onCheckedChange={() => handleToggle(row)}
          className="scale-75"
        />
      ),
    },
    {
      key: "_actions",
      title: "",
      render: (row: any) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7 text-destructive"
          onClick={() => handleDelete(row.id)}
        >
          <IconTrash className="h-3.5 w-3.5" />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <CardTitle className="text-base">{t("sites.detail.rules")}</CardTitle>
          <Button
            size="sm"
            className="h-8"
            onClick={() => router.push("/rules")}
          >
            <IconPlus className="mr-1 h-4 w-4" />
            {t("sites.detail.addRule")}
          </Button>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={rules?.items || []}
            loading={!rules}
            rowKey={(row) => row.id}
            emptyText={t("sites.detail.noRules")}
          />
        </CardContent>
      </Card>
    </div>
  );
}
