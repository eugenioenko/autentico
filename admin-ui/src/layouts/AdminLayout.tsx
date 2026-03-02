import { useState, Suspense } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { Layout, Menu, Button, Typography, theme } from "antd";
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

const menuItems = [
  { key: "/", icon: <DashboardOutlined />, label: "Dashboard" },
  { key: "/clients", icon: <AppstoreOutlined />, label: "Clients" },
  { key: "/users", icon: <UserOutlined />, label: "Users" },
  { key: "/sessions", icon: <DesktopOutlined />, label: "Sessions" },
  { key: "/federation", icon: <GlobalOutlined />, label: "Federation" },
  { key: "/settings", icon: <SettingOutlined />, label: "Settings" },
  { key: "/docs", icon: <FileTextOutlined />, label: "API Docs" },
  { key: "/swagger", icon: <FileTextOutlined />, label: "Swagger UI" },
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
      (item) => item.key !== "/" && location.pathname.startsWith(item.key)
    )?.key ?? "/";

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

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
            if (key === "/docs") {
              window.open("/admin/docs", "_blank");
            } else if (key === "/swagger") {
              window.open("/swagger/index.html", "_blank");
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
            <Text>{user?.profile?.preferred_username ?? user?.profile?.email}</Text>
            <Button
              type="text"
              icon={<LogoutOutlined />}
              onClick={handleLogout}
            >
              Logout
            </Button>
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
