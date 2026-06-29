import { Card, Col, Row, Statistic, Button, Space, Typography, Spin } from "antd";
import {
  UserOutlined,
  AppstoreOutlined,
  DesktopOutlined,
  KeyOutlined,
  LoginOutlined,
  PlusOutlined,
  CopyOutlined,
  CheckOutlined,
  DeleteOutlined,
  WarningOutlined,
  LockOutlined,
} from "@ant-design/icons";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useStats } from "../hooks/useStats";
import { useAuth } from "oidc-js-react";
import { useTranslation } from "react-i18next";

export default function DashboardPage() {
  const { data: stats, isLoading } = useStats();
  const { tokens } = useAuth();
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);
  const { t } = useTranslation();

  const handleCopyToken = () => {
    navigator.clipboard.writeText(tokens.access ? `Bearer ${tokens.access}` : "").then(() => {
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
        {t("dashboard.title")}
      </Typography.Title>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t("dashboard.totalUsers")}
              value={stats?.total_users ?? 0}
              prefix={<UserOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t("dashboard.activeClients")}
              value={stats?.active_clients ?? 0}
              prefix={<AppstoreOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t("dashboard.activeDevices")}
              value={stats?.active_devices ?? 0}
              prefix={<DesktopOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t("dashboard.activeTokens")}
              value={stats?.active_tokens ?? 0}
              prefix={<KeyOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t("dashboard.recentLogins24h")}
              value={stats?.recent_logins ?? 0}
              prefix={<LoginOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t("dashboard.failedLogins24h")}
              value={stats?.failed_logins_24h ?? 0}
              prefix={<WarningOutlined />}
              valueStyle={(stats?.failed_logins_24h ?? 0) > 0 ? { color: "#cf1322" } : undefined}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t("dashboard.lockedAccounts")}
              value={stats?.locked_accounts ?? 0}
              prefix={<LockOutlined />}
              valueStyle={(stats?.locked_accounts ?? 0) > 0 ? { color: "#cf1322" } : undefined}
            />
          </Card>
        </Col>
        {(stats?.pending_deletion_requests ?? 0) > 0 && (
          <Col xs={24} sm={12} lg={6}>
            <Card
              style={{ cursor: "pointer" }}
              onClick={() => navigate("/users?tab=deletions")}
            >
              <Statistic
                title={t("dashboard.pendingDeletions")}
                value={stats?.pending_deletion_requests ?? 0}
                prefix={<DeleteOutlined />}
                valueStyle={{ color: "#cf1322" }}
              />
            </Card>
          </Col>
        )}
      </Row>

      <Card title={t("dashboard.quickActions")}>
        <Space direction="vertical" style={{ width: "100%" }}>
          <Space>
            <Button
              icon={<PlusOutlined />}
              onClick={() => navigate("/users", { state: { create: true } })}
            >
              {t("dashboard.createUser")}
            </Button>
            <Button
              icon={<PlusOutlined />}
              onClick={() => navigate("/clients", { state: { create: true } })}
            >
              {t("dashboard.createClient")}
            </Button>
          </Space>
          <Typography.Text type="secondary">{t("dashboard.apiSwaggerToken")}:</Typography.Text>
          <Button
            icon={copied ? <CheckOutlined /> : <CopyOutlined />}
            onClick={handleCopyToken}
          >
            {copied ? t("dashboard.copiedExcl") : t("dashboard.copyAccessToken")}
          </Button>
        </Space>
      </Card>
    </Space>
  );
}
