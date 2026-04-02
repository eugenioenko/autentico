import { Card, Col, Row, Statistic, Button, Space, Typography, Spin } from "antd";
import {
  UserOutlined,
  AppstoreOutlined,
  DesktopOutlined,
  LoginOutlined,
  PlusOutlined,
  CopyOutlined,
  CheckOutlined,
  DeleteOutlined,
} from "@ant-design/icons";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useStats } from "../hooks/useStats";
import { useAuth } from "../context/AuthContext";

export default function DashboardPage() {
  const { data: stats, isLoading } = useStats();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);

  const handleCopyToken = () => {
    navigator.clipboard.writeText(user?.access_token ? `Bearer ${user.access_token}` : "").then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  if (isLoading) {
    return <Spin style={{ display: "block", marginTop: 80 }} />;
  }

  return (
    <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <Typography.Title level={4} style={{ margin: 0 }} data-testid="admin-dashboard">
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
        {(stats?.pending_deletion_requests ?? 0) > 0 && (
          <Col xs={24} sm={12} lg={6}>
            <Card
              style={{ cursor: "pointer" }}
              onClick={() => navigate("/deletion-requests")}
            >
              <Statistic
                title="Pending Deletions"
                value={stats?.pending_deletion_requests ?? 0}
                prefix={<DeleteOutlined />}
                valueStyle={{ color: "#cf1322" }}
              />
            </Card>
          </Col>
        )}
      </Row>

      <Card title="Quick Actions">
        <Space direction="vertical" style={{ width: "100%" }}>
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
          <Typography.Text type="secondary">Access token for API / Swagger:</Typography.Text>
          <Button
            icon={copied ? <CheckOutlined /> : <CopyOutlined />}
            onClick={handleCopyToken}
          >
            {copied ? "Copied!" : "Copy access token"}
          </Button>
        </Space>
      </Card>
    </Space>
  );
}
