import { Suspense, useState, type ReactNode } from "react";
import { matchPath, Outlet, useLocation } from "react-router-dom";
import {
  IconApi,
  IconApps,
  IconBook,
  IconChevronDown,
  IconDeviceDesktop,
  IconFileSearch,
  IconFileText,
  IconKey,
  IconLayoutDashboard,
  IconIndentDecrease,
  IconIndentIncrease,
  IconLogout,
  IconSettings,
  IconShieldLock,
  IconUser,
  IconUsers,
  IconUsersGroup,
  IconWorld,
} from "@tabler/icons-react";
import { AppLayout, Avatar, Button, Heading, IconButton, Inline, Menu, NavItem, NavSection, Spinner, Stack, Text } from "@yarcl/react";
import { useAuth } from "oidc-js-react";
import ColorSchemeToggle from "../components/ColorSchemeToggle";
import { useGroup } from "../hooks/useGroups";
import { useUser } from "../hooks/useUsers";
import { RouterNavItem } from "../components/RouterLink";
import "./AdminLayout.css";

interface NavEntry {
  to: string;
  icon: ReactNode;
  label: string;
  title?: string;
}

const adminItems: NavEntry[] = [
  { to: "/", icon: <IconLayoutDashboard />, label: "Dashboard" },
  { to: "/users", icon: <IconUser />, label: "Users" },
  { to: "/groups", icon: <IconUsersGroup />, label: "Groups" },
  { to: "/sessions", icon: <IconDeviceDesktop />, label: "Sessions" },
  { to: "/tokens", icon: <IconKey />, label: "Tokens" },
  { to: "/clients", icon: <IconApps />, label: "Clients" },
  { to: "/protected-apps", icon: <IconShieldLock />, label: "Protected Apps", title: "Protected Applications" },
  { to: "/federation", icon: <IconWorld />, label: "Federation", title: "Federation Providers" },
  { to: "/audit-log", icon: <IconFileSearch />, label: "Audit Log" },
  { to: "/cors", icon: <IconApi />, label: "CORS" },
  { to: "/settings", icon: <IconSettings />, label: "Settings", title: "System Settings" },
];

const resourceItems = [
  { href: "/account/", icon: <IconUsers />, label: "Profile" },
  { href: "/api-docs/", icon: <IconFileText />, label: "API Docs" },
  { href: "/swagger/index.html", icon: <IconFileText />, label: "Swagger UI" },
  { href: "https://getautentico.dev/", icon: <IconBook />, label: "Autentico Docs" },
];

function isActive(pathname: string, to: string) {
  return to === "/" ? pathname === "/" : pathname.startsWith(to);
}

function UserMenu() {
  const { user } = useAuth();
  const username = (user?.claims?.preferred_username ?? user?.claims?.email ?? "User") as string;
  const picture = user?.claims?.picture as string | undefined;
  return (
    <Menu placement="bottom-end">
      <Menu.Trigger>
        <Button variant="ghost" color="neutral" data-testid="user-menu" endIcon={<IconChevronDown aria-hidden="true" />}>
          <Inline as="span" gap="sm" wrap={false}>
            <Avatar size="sm" src={picture} name={username} color="brand" />
            <Text as="span" inherit>
              {username}
            </Text>
          </Inline>
        </Button>
      </Menu.Trigger>
      <Menu.Content aria-label="Account">
        <Menu.Item onSelect={() => window.open("/account/", "_blank")}>
          <Inline as="span" gap="sm" wrap={false}>
            <IconUser aria-hidden="true" />
            Profile
          </Inline>
        </Menu.Item>
        <Menu.Separator />
        <Menu.Item color="danger" onSelect={() => (window.location.href = "/oauth2/logout")}>
          <Inline as="span" gap="sm" wrap={false}>
            <IconLogout aria-hidden="true" />
            Logout
          </Inline>
        </Menu.Item>
      </Menu.Content>
    </Menu>
  );
}

export default function AdminLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const { pathname } = useLocation();
  const currentPage = adminItems.find((item) => isActive(pathname, item.to));
  const groupRoute = matchPath("/groups/:groupId/members", pathname);
  const deviceRoute = matchPath("/sessions/:userId/devices/:sessionId", pathname);
  const { data: group } = useGroup(groupRoute?.params.groupId ?? null);
  const { data: sessionUser } = useUser(deviceRoute?.params.userId ?? "");
  const pageTitle = groupRoute
    ? group ? `Members of ${group.name}` : "Group Members"
    : deviceRoute
      ? sessionUser ? `OAuth Sessions for ${sessionUser.username}` : "OAuth Sessions"
      : currentPage?.title ?? currentPage?.label ?? "Autentico";

  const navigation = (
    <>
      <Stack gap="xs">
        {adminItems.map((item) => (
          <RouterNavItem key={item.to} to={item.to} icon={item.icon} active={isActive(pathname, item.to)}>
            {item.label}
          </RouterNavItem>
        ))}
      </Stack>
      <NavSection title="Resources" collapsed={collapsed}>
        {resourceItems.map((item) => (
          <NavItem key={item.href} href={item.href} target="_blank" rel="noreferrer" icon={item.icon}>
            {item.label}
          </NavItem>
        ))}
      </NavSection>
    </>
  );

  const brand = (
    <Inline gap="sm" align="center" wrap={false} className="admin-brand">
      <img src="/admin/favicon.svg" alt="" className="admin-logo" />
      {!collapsed && (
        <Text as="span" textStyle="subheading">
          Autentico
        </Text>
      )}
    </Inline>
  );

  const navbar = (
    <Inline gap="md" justify="between" align="center" wrap={false} className="admin-navbar">
      <Inline gap="sm" align="center" wrap={false} className="admin-navbar-start">
        <IconButton
          variant="ghost"
          color="neutral"
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          className="admin-collapse"
          onClick={() => setCollapsed((c) => !c)}
        >
          {collapsed ? <IconIndentIncrease /> : <IconIndentDecrease />}
        </IconButton>
        <Heading level={1} textStyle="subheading" className="admin-page-title">
          {pageTitle}
        </Heading>
      </Inline>
      <Inline gap="sm" align="center" wrap={false}>
        <ColorSchemeToggle />
        <UserMenu />
      </Inline>
    </Inline>
  );

  return (
    <AppLayout
      desktopBreakpoint="lg"
      sidebarWidth="sidebar"
      navigationLabel="Admin"
      menuLabel="Open navigation"
      skipLabel="Skip to content"
      collapsed={collapsed}
      navigation={navigation}
      navbar={navbar}
      sidebarHeader={brand}
      mainProps={{ className: "admin-main" }}
    >
      <Suspense
        fallback={
          <div className="page-loading">
            <Spinner size="lg" label="Loading" />
          </div>
        }
      >
        <Outlet />
      </Suspense>
    </AppLayout>
  );
}
