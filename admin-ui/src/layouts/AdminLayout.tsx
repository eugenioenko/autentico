import { useState, Suspense } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { Layout, Menu, Button, Typography, theme, Avatar, Dropdown, ConfigProvider } from "antd";
import {
  DashboardOutlined,
  AppstoreOutlined,
  UserOutlined,
  DesktopOutlined,
  KeyOutlined,
  FileSearchOutlined,
  FileTextOutlined,
  ApiOutlined,
  GlobalOutlined,
  SettingOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  DownOutlined,
  TeamOutlined,
} from "@ant-design/icons";
import { useAuth } from "oidc-js-react";
import { useTranslation } from "react-i18next";
import ThemeToggle from "../components/ThemeToggle";
import LanguageSwitcher from "../components/LanguageSwitcher";

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

function useMenuItems() {
  const { t } = useTranslation();
  const menuItems: any[] = [
    { key: "/", icon: <DashboardOutlined />, label: t("menu.dashboard") },
    { key: "/users", icon: <UserOutlined />, label: t("menu.users") },
    { key: "/groups", icon: <TeamOutlined />, label: t("menu.groups") },
    { key: "/sessions", icon: <DesktopOutlined />, label: t("menu.sessions") },
    { key: "/tokens", icon: <KeyOutlined />, label: t("menu.tokens") },
    { key: "/clients", icon: <AppstoreOutlined />, label: t("menu.clients") },
    { key: "/federation", icon: <GlobalOutlined />, label: t("menu.federation") },
    { key: "/audit-log", icon: <FileSearchOutlined />, label: t("menu.auditLog") },
    { key: "/cors", icon: <ApiOutlined />, label: "CORS" },
    { key: "/settings", icon: <SettingOutlined />, label: t("menu.settings") },
    { type: "divider" },
    {
      type: "group",
      label: t("menu.resources"),
      children: [
        { key: "/account", icon: <UserOutlined />, label: t("menu.profile") },
        { key: "/docs", icon: <FileTextOutlined />, label: t("menu.apiDocs") },
        { key: "/swagger", icon: <FileTextOutlined />, label: "Swagger UI" },
        { key: "/autentico-docs", icon: <FileTextOutlined />, label: "Autentico" },
      ],
    },
  ];
  return menuItems;
}

export default function AdminLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const { user } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const menuItems = useMenuItems();
  const {
    token: { colorBgContainer, borderRadiusLG },
  } = theme.useToken();

  const selectedKey =
    menuItems.find(
      (item) => item.key && item.key !== "/" && location.pathname.startsWith(item.key)
    )?.key ?? "/";

  const handleLogout = () => {
    window.location.href = "/oauth2/logout";
  };

  const userDropdownItems = [
    {
      key: "account",
      label: t("menu.profile"),
      icon: <UserOutlined />,
      onClick: () => window.open("/account/", "_blank"),
    },
    {
      type: "divider" as const,
    },
    {
      key: "logout",
      label: t("menu.logout"),
      icon: <LogoutOutlined />,
      danger: true,
      onClick: handleLogout,
    },
  ];

  const username = (user?.claims?.preferred_username ?? user?.claims?.email ?? "User") as string;
  const siderBg = "#16162a";

  return (
    <Layout style={{ height: "100dvh", overflow: "hidden" }}>
      <ConfigProvider
        theme={{
          components: {
            Menu: {
              darkItemBg: siderBg,
              darkSubMenuItemBg: siderBg,
              darkItemSelectedBg: "rgba(255, 255, 255, 0.1)",
              darkItemSelectedColor: "#ffffff",
              darkItemColor: "rgba(255, 255, 255, 0.55)",
              darkItemHoverColor: "rgba(255, 255, 255, 0.85)",
              darkItemHoverBg: "rgba(255, 255, 255, 0.06)",
              darkGroupTitleColor: "rgba(255, 255, 255, 0.45)",
            },
          },
        }}
      >
        <Sider trigger={null} collapsible collapsed={collapsed} breakpoint="lg" onBreakpoint={setCollapsed} style={{ background: siderBg, overflow: "auto" }}>
          <div
            style={{
              height: 64,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 12,
              color: "white",
              fontWeight: 600,
              fontSize: 18,
              padding: "0 16px",
              overflow: "hidden",
            }}
          >
            <img
              src="/admin/favicon.svg"
              alt="Autentico Logo"
              style={{ width: 32, height: 32, flexShrink: 0 }}
            />
            {!collapsed && <span style={{ whiteSpace: "nowrap" }}>Autentico</span>}
          </div>
          <Menu
            theme="dark"
            mode="inline"
            selectedKeys={[selectedKey]}
            items={menuItems}
            onClick={({ key }) => {
              if (key === "/account") {
                window.open("/account/", "_blank");
              } else if (key === "/docs") {
                window.open("/api-docs/", "_blank");
              } else if (key === "/swagger") {
                window.open("/swagger/index.html", "_blank");
              } else if (key === "/autentico-docs") {
                window.open("https://autentico.top/", "_blank");
              } else {
                navigate(key);
              }
            }}
          />
        </Sider>
      </ConfigProvider>
      <Layout style={{ overflow: "hidden" }}>
        <Header
          style={{
            padding: "0 24px",
            background: colorBgContainer,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <Button
            type="text"
            icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            onClick={() => setCollapsed(!collapsed)}
          />
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <LanguageSwitcher />
            <ThemeToggle />
            <Dropdown menu={{ items: userDropdownItems }} trigger={["click"]} placement="bottomRight">
              <div data-testid="user-menu" style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                <Avatar
                  src={user?.claims?.picture as string | undefined}
                  icon={!user?.claims?.picture && <UserOutlined />}
                  style={{ backgroundColor: "#6366f1" }}
                />
                <Text>{username}</Text>
                <DownOutlined style={{ fontSize: 11, opacity: 0.6 }} />
              </div>
            </Dropdown>
          </div>
        </Header>
        <Content
          style={{
            margin: 24,
            padding: 24,
            background: colorBgContainer,
            borderRadius: borderRadiusLG,
            overflow: "hidden",
            flex: 1,
            display: "flex",
            flexDirection: "column",
          }}
        >
          <Suspense fallback={null}>
            <Outlet />
          </Suspense>
        </Content>
      </Layout>
    </Layout>
  );
}
