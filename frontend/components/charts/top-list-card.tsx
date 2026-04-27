"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Ban, TrendingUp } from "lucide-react";
import { toast } from "sonner";

interface TopItem {
  label: string;
  value: string | number;
  count: number;
  actionable?: boolean;
}

interface TopListCardProps {
  title: string;
  icon?: React.ReactNode;
  items: TopItem[];
  emptyText?: string;
  onAddToBlacklist?: (value: string) => Promise<void>;
}

export function TopListCard({
  title,
  icon,
  items,
  emptyText = "暂无数据",
  onAddToBlacklist,
}: TopListCardProps) {
  const [loading, setLoading] = useState<string | null>(null);

  const handleAddToBlacklist = async (value: string) => {
    if (!onAddToBlacklist) return;

    setLoading(value);
    try {
      await onAddToBlacklist(value);
      toast.success(`已将 ${value} 加入黑名单`);
    } catch (error) {
      toast.error(`加入黑名单失败: ${error instanceof Error ? error.message : "未知错误"}`);
    } finally {
      setLoading(null);
    }
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-4">
            {emptyText}
          </p>
        ) : (
          <div className="space-y-2">
            {items.map((item, index) => (
              <div
                key={index}
                className="flex items-center justify-between p-2 rounded-lg hover:bg-muted/50 transition-colors"
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <Badge variant="outline" className="shrink-0">
                    #{index + 1}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" title={String(item.value)}>
                      {item.label}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {item.value}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge variant="secondary" className="font-mono">
                    <TrendingUp className="h-3 w-3 mr-1" />
                    {item.count}
                  </Badge>
                  {item.actionable && onAddToBlacklist && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0"
                      onClick={() => handleAddToBlacklist(String(item.value))}
                      disabled={loading === String(item.value)}
                    >
                      <Ban className="h-3.5 w-3.5 text-destructive" />
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
