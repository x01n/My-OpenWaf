"use client";

import { useState, useCallback, useMemo } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { IconChevronRight, IconChevronDown } from "@tabler/icons-react";
import { cn } from "@/lib/utils";

export interface RecordedResource {
  id: number;
  site_id: number;
  path: string;
  method: string;
  content_type?: string;
}

interface TreeNode {
  segment: string;
  fullPath: string | null;
  children: TreeNode[];
  resources: RecordedResource[];
  depth: number;
}

/**
 * 将资源路径列表构建为树形结构。
 *
 * @param resources 已记录资源列表
 * @returns 树形节点列表
 */
function buildResourceTree(resources: RecordedResource[]): TreeNode[] {
  const root: { children: Map<string, TreeNode> } = { children: new Map() };

  for (const res of resources) {
    const segments = res.path.split("/").filter((s) => s.length > 0);
    let current = root as unknown as { children: Map<string, TreeNode> };
    let currentPath = "";

    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      currentPath = currentPath + "/" + seg;

      if (!current.children.has(seg)) {
        const node: TreeNode = {
          segment: seg,
          fullPath: i === segments.length - 1 ? currentPath : null,
          children: [],
          resources: [],
          depth: i,
        };
        current.children.set(seg, node);
      }

      const node = current.children.get(seg)!;
      if (i === segments.length - 1) {
        node.resources.push(res);
      }
      current = node as unknown as { children: Map<string, TreeNode> };
    }

    // 处理根路径 "/" 的情况
    if (segments.length === 0 && res.path === "/") {
      if (!current.children.has("/")) {
        const node: TreeNode = {
          segment: "/",
          fullPath: "/",
          children: [],
          resources: [res],
          depth: 0,
        };
        current.children.set("/", node);
      } else {
        current.children.get("/")!.resources.push(res);
      }
    }
  }

  return Array.from(root.children.values()).sort((a, b) =>
    a.segment.localeCompare(b.segment)
  );
}

interface ResourcePathTreeProps {
  resources: RecordedResource[];
  selectedPaths: string[];
  onSelect: (path: string, checked: boolean) => void;
}

/**
 * 资源路径树形组件。
 *
 * 按路径层级树形展示已记录资源，支持展开/折叠与多选。
 */
export function ResourcePathTree({
  resources,
  selectedPaths,
  onSelect,
}: ResourcePathTreeProps) {
  const tree = useMemo(() => buildResourceTree(resources), [resources]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpanded = useCallback((path: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }, []);

  if (tree.length === 0) {
    return null;
  }

  return (
    <div className="rounded-md border p-2 max-h-48 overflow-y-auto">
      <TreeNodeList
        nodes={tree}
        expanded={expanded}
        toggleExpanded={toggleExpanded}
        selectedPaths={selectedPaths}
        onSelect={onSelect}
      />
    </div>
  );
}

interface TreeNodeListProps {
  nodes: TreeNode[];
  expanded: Set<string>;
  toggleExpanded: (path: string) => void;
  selectedPaths: string[];
  onSelect: (path: string, checked: boolean) => void;
}

function TreeNodeList({
  nodes,
  expanded,
  toggleExpanded,
  selectedPaths,
  onSelect,
}: TreeNodeListProps) {
  return (
    <div className="space-y-0.5">
      {nodes.map((node) => (
        <TreeNodeItem
          key={node.segment + node.depth}
          node={node}
          expanded={expanded}
          toggleExpanded={toggleExpanded}
          selectedPaths={selectedPaths}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

interface TreeNodeItemProps {
  node: TreeNode;
  expanded: Set<string>;
  toggleExpanded: (path: string) => void;
  selectedPaths: string[];
  onSelect: (path: string, checked: boolean) => void;
}

function TreeNodeItem({
  node,
  expanded,
  toggleExpanded,
  selectedPaths,
  onSelect,
}: TreeNodeItemProps) {
  const hasChildren = node.children.length > 0;
  const isLeaf = node.fullPath !== null;
  const pathKey = node.fullPath || node.segment + "-" + node.depth;
  const isExpanded = expanded.has(pathKey);

  const checked = isLeaf && node.fullPath ? selectedPaths.includes(node.fullPath) : false;

  const handleToggle = useCallback(() => {
    if (isLeaf && node.fullPath) {
      onSelect(node.fullPath, !checked);
    }
  }, [isLeaf, node.fullPath, checked, onSelect]);

  const handleExpand = useCallback(() => {
    toggleExpanded(pathKey);
  }, [toggleExpanded, pathKey]);

  return (
    <div>
      <div
        className={cn(
          "flex items-center gap-1.5 rounded-sm px-1 py-0.5 hover:bg-muted/60",
          isLeaf && "pl-1"
        )}
        style={{ paddingLeft: `${node.depth * 12 + 4}px` }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={handleExpand}
            className="flex items-center justify-center h-4 w-4 text-muted-foreground hover:text-foreground shrink-0"
          >
            {isExpanded ? (
              <IconChevronDown className="h-3.5 w-3.5" />
            ) : (
              <IconChevronRight className="h-3.5 w-3.5" />
            )}
          </button>
        ) : (
          <span className="h-4 w-4 shrink-0" />
        )}

        {isLeaf ? (
          <>
            <Checkbox
              id={`tree-check-${pathKey}`}
              checked={checked}
              onCheckedChange={handleToggle}
              className="h-3.5 w-3.5"
            />
            <Label
              htmlFor={`tree-check-${pathKey}`}
              className="cursor-pointer text-xs font-normal truncate"
              title={node.fullPath || undefined}
            >
              {node.segment}
              {node.resources.length > 0 && (
                <span className="ml-1 text-[10px] text-muted-foreground">
                  {node.resources.map((r) => r.method).join(",")}
                </span>
              )}
            </Label>
          </>
        ) : (
          <>
            <span className="h-3.5 w-3.5 shrink-0" />
            <button
              type="button"
              onClick={handleExpand}
              className="text-xs font-normal truncate hover:text-foreground text-left"
            >
              {node.segment}
            </button>
          </>
        )}
      </div>

      {hasChildren && isExpanded && (
        <div className="mt-0.5">
          <TreeNodeList
            nodes={node.children}
            expanded={expanded}
            toggleExpanded={toggleExpanded}
            selectedPaths={selectedPaths}
            onSelect={onSelect}
          />
        </div>
      )}
    </div>
  );
}
