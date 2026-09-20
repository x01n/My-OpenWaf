import * as React from "react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
  IconChevronLeft,
  IconChevronRight,
  IconDots,
} from "@tabler/icons-react"

function Pagination({ className, ...props }: React.ComponentProps<"nav">) {
  return (
    <nav
      role="navigation"
      aria-label="pagination"
      data-slot="pagination"
      className={cn("mx-auto flex w-full justify-center", className)}
      {...props}
    />
  )
}

function PaginationContent({
  className,
  ...props
}: React.ComponentProps<"ul">) {
  return (
    <ul
      data-slot="pagination-content"
      className={cn("flex items-center gap-1", className)}
      {...props}
    />
  )
}

function PaginationItem({ ...props }: React.ComponentProps<"li">) {
  return <li data-slot="pagination-item" {...props} />
}

type PaginationLinkSharedProps = {
  isActive?: boolean
} & Pick<React.ComponentProps<typeof Button>, "size">

type PaginationLinkProps = PaginationLinkSharedProps &
  (
    | React.ComponentProps<"a">
    | (Omit<React.ComponentProps<"button">, "type"> & {
        href?: undefined
        type?: "button"
      })
  )

function hasHref(
  props: PaginationLinkProps
): props is PaginationLinkSharedProps & React.ComponentProps<"a"> {
  return "href" in props && props.href !== undefined
}

function PaginationLink(props: PaginationLinkProps) {
  const variant = props.isActive ? "outline" : "ghost"
  if (hasHref(props)) {
    const { className, isActive, size = "icon", ...anchorProps } = props

    return (
      <Button asChild variant={variant} size={size} className={cn(className)}>
        <a
          aria-current={isActive ? "page" : undefined}
          data-slot="pagination-link"
          data-active={isActive}
          {...anchorProps}
        />
      </Button>
    )
  }

  const { className, isActive, size = "icon", ...buttonProps } = props

  return (
    <Button
      variant={variant}
      size={size}
      className={cn(className)}
      aria-current={isActive ? "page" : undefined}
      data-slot="pagination-link"
      data-active={isActive}
      {...buttonProps}
      type="button"
    />
  )
}

function PaginationPrevious({
  className,
  text = "Previous",
  ...props
}: React.ComponentProps<typeof PaginationLink> & { text?: string }) {
  return (
    <PaginationLink
      aria-label="Go to previous page"
      size="default"
      className={cn("ps-2!", className)}
      {...props}
    >
      <IconChevronLeft data-icon="inline-start" className="rtl:rotate-180" />
      <span className="hidden sm:block">{text}</span>
    </PaginationLink>
  )
}

function PaginationNext({
  className,
  text = "Next",
  ...props
}: React.ComponentProps<typeof PaginationLink> & { text?: string }) {
  return (
    <PaginationLink
      aria-label="Go to next page"
      size="default"
      className={cn("pe-2!", className)}
      {...props}
    >
      <span className="hidden sm:block">{text}</span>
      <IconChevronRight data-icon="inline-end" className="rtl:rotate-180" />
    </PaginationLink>
  )
}

function PaginationEllipsis({
  className,
  ...props
}: React.ComponentProps<"span">) {
  return (
    <span
      aria-hidden
      data-slot="pagination-ellipsis"
      className={cn(
        "flex size-9 items-center justify-center [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    >
      <IconDots />
      <span className="sr-only">More pages</span>
    </span>
  )
}

export {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
}
