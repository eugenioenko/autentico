import { Link, NavItem, type LinkProps, type NavItemProps } from "@yarcl/react";
import type { HTMLAttributeAnchorTarget, MouseEvent } from "react";
import { useHref, useLinkClickHandler } from "react-router-dom";

interface RouterProps {
  to: string;
  target?: HTMLAttributeAnchorTarget;
}

function useRouterAnchor({ to, target, onClick }: RouterProps & { onClick?: (event: MouseEvent<HTMLAnchorElement>) => void }) {
  const href = useHref(to);
  const navigate = useLinkClickHandler<HTMLAnchorElement>(to, { target });
  return {
    href,
    target,
    onClick: (event: MouseEvent<HTMLAnchorElement>) => {
      onClick?.(event);
      if (!event.defaultPrevented) navigate(event);
    },
  };
}

export type RouterLinkProps = Omit<LinkProps, "href" | "external"> & RouterProps;

export function RouterLink({ to, target, onClick, ...props }: RouterLinkProps) {
  return <Link {...props} {...useRouterAnchor({ to, target, onClick })} />;
}

export type RouterNavItemProps = Omit<NavItemProps, "href"> & RouterProps;

export function RouterNavItem({ to, target, onClick, ...props }: RouterNavItemProps) {
  return <NavItem {...props} {...useRouterAnchor({ to, target, onClick })} />;
}
