import { Card, Col, Row, Statistic, Button, Space, Typography, Spin } from "antd";
import {
  UserOutlined,
  AppstoreOutlined,
  DesktopOutlined,
  LoginOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { useStats } from "../hooks/useStats";

export default function DashboardPage() {
  const { data: stats, isLoading } = useStats();
  const navigate = useNavigate();

  if (isLoading) {
    return <Spin style={{ display: "block", marginTop: 80 }} />;
  }

  return (
    <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <Typography.Title level={4} style={{ margin: 0 }}>
        Dashboard
      </Typography.Title>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Total Users"
              value={stats?.total_users ?? 0}
              prefix={<UserOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Active Clients"
              value={stats?.active_clients ?? 0}
              prefix={<AppstoreOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Active Sessions"
              value={stats?.active_sessions ?? 0}
              suffix={`/ ${stats?.total_sessions ?? 0}`}
              prefix={<DesktopOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="Recent Logins (24h)"
              value={stats?.recent_logins ?? 0}
              prefix={<LoginOutlined />}
            />
          </Card>
        </Col>
      </Row>

      <Card title="Quick Actions">
        <Space>
          <Button
            icon={<PlusOutlined />}
            onClick={() => navigate("/users", { state: { create: true } })}
          >
            Create User
          </Button>
          <Button
            icon={<PlusOutlined />}
            onClick={() => navigate("/clients", { state: { create: true } })}
          >
            Create Client
          </Button>
        </Space>
      </Card>
    </Space>
  );
}
