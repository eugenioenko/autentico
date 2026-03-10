import { useState, Suspense } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { Layout, Menu, Button, Typography, theme, Avatar, Dropdown } from "antd";
import {
  DashboardOutlined,
  AppstoreOutlined,
  UserOutlined,
  DesktopOutlined,
  FileTextOutlined,
  GlobalOutlined,
  SettingOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
} from "@ant-design/icons";
import { useAuth } from "../context/AuthContext";

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

const menuItems: any[] = [
  { key: "/", icon: <DashboardOutlined />, label: "Dashboard" },
  { key: "/clients", icon: <AppstoreOutlined />, label: "Clients" },
  { key: "/users", icon: <UserOutlined />, label: "Users" },
  { key: "/sessions", icon: <DesktopOutlined />, label: "Sessions" },
  { key: "/federation", icon: <GlobalOutlined />, label: "Federation" },
  { key: "/settings", icon: <SettingOutlined />, label: "Settings" },
  { type: "divider" },
  {
    type: "group",
    label: "Resources",
    children: [
      { key: "/account", icon: <UserOutlined />, label: "Profile" },
      { key: "/docs", icon: <FileTextOutlined />, label: "API Docs" },
      { key: "/swagger", icon: <FileTextOutlined />, label: "Swagger UI" },
      { key: "/autentico-docs", icon: <FileTextOutlined />, label: "Autentico Docs" },
    ],
  },
];

export default function AdminLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const {
    token: { colorBgContainer, borderRadiusLG },
  } = theme.useToken();

  const selectedKey =
    menuItems.find(
      (item) => item.key && item.key !== "/" && location.pathname.startsWith(item.key)
    )?.key ?? "/";

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  const userDropdownItems = [
    {
      key: "account",
      label: "Profile",
      icon: <UserOutlined />,
      onClick: () => window.open("/account/", "_blank"),
    },
    {
      type: "divider" as const,
    },
    {
      key: "logout",
      label: "Logout",
      icon: <LogoutOutlined />,
      danger: true,
      onClick: handleLogout,
    },
  ];

  const username = user?.profile?.preferred_username ?? user?.profile?.email ?? "User";

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider trigger={null} collapsible collapsed={collapsed}>
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
              window.open("/admin/docs/", "_blank");
            } else if (key === "/swagger") {
              window.open("/swagger/index.html", "_blank");
            } else if (key === "/autentico-docs") {
              window.open("https://docs.autentico.top/", "_blank");
            } else {
              navigate(key);
            }
          }}
        />
      </Sider>
      <Layout>
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
            <Dropdown menu={{ items: userDropdownItems }} trigger={["click"]} placement="bottomRight">
              <div style={{ display: "flex", alignItems: "center", gap: 10, cursor: "pointer" }}>
                <Text>{username}</Text>
                <Avatar 
                  src={user?.profile?.picture} 
                  icon={!user?.profile?.picture && <UserOutlined />} 
                  style={{ backgroundColor: "#1677ff" }}
                />
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
            minHeight: 280,
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
