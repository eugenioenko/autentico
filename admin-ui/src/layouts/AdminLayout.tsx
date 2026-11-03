import { Suspense, useState, type ReactNode } from "react";
import { Outlet, useLocation } from "react-router-dom";
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
import { AppLayout, Avatar, Button, IconButton, Inline, Menu, NavItem, NavSection, Spinner, Stack, Text } from "@yarcl/react";
import { useAuth } from "oidc-js-react";
import ColorSchemeToggle from "../components/ColorSchemeToggle";
import { RouterNavItem } from "../components/RouterLink";
import "./AdminLayout.css";

interface NavEntry {
  to: string;
  icon: ReactNode;
  label: string;
}

const adminItems: NavEntry[] = [
  { to: "/", icon: <IconLayoutDashboard />, label: "Dashboard" },
  { to: "/users", icon: <IconUser />, label: "Users" },
  { to: "/groups", icon: <IconUsersGroup />, label: "Groups" },
  { to: "/sessions", icon: <IconDeviceDesktop />, label: "Sessions" },
  { to: "/tokens", icon: <IconKey />, label: "Tokens" },
  { to: "/clients", icon: <IconApps />, label: "Clients" },
  { to: "/protected-apps", icon: <IconShieldLock />, label: "Protected Apps" },
  { to: "/federation", icon: <IconWorld />, label: "Federation" },
  { to: "/audit-log", icon: <IconFileSearch />, label: "Audit Log" },
  { to: "/cors", icon: <IconApi />, label: "CORS" },
  { to: "/settings", icon: <IconSettings />, label: "Settings" },
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
      <Inline gap="sm" align="center" wrap={false}>
        <IconButton
          variant="ghost"
          color="neutral"
          aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          className="admin-collapse"
          onClick={() => setCollapsed((c) => !c)}
        >
          {collapsed ? <IconIndentIncrease /> : <IconIndentDecrease />}
        </IconButton>
        <div className="admin-navbar-brand">{brand}</div>
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
