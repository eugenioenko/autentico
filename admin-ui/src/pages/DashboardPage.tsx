import { Button, Card, Grid, Heading, Inline, Spinner, Stack, Text } from "@yarcl/react";
import {
  IconAlertTriangle,
  IconApps,
  IconCheck,
  IconCopy,
  IconDeviceDesktop,
  IconKey,
  IconLock,
  IconLogin,
  IconPlus,
  IconTrash,
  IconUser,
} from "@tabler/icons-react";
import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useStats } from "../hooks/useStats";
import { useAuth } from "oidc-js-react";
import { RouterLink } from "../components/RouterLink";
import "./DashboardPage.css";

interface StatCardProps {
  title: string;
  value: number;
  icon: ReactNode;
  alert?: boolean;
  children?: ReactNode;
}

function StatCard({ title, value, icon, alert, children }: StatCardProps) {
  return (
    <Card>
      <Stack gap="xs">
        <Text textStyle="caption" muted>
          {title}
        </Text>
        <Inline gap="sm" align="center" wrap={false} className="dashboard-stat-value">
          {icon}
          <Text textStyle="display" color={alert ? "danger" : undefined}>
            {value}
          </Text>
        </Inline>
        {children}
      </Stack>
    </Card>
  );
}

export default function DashboardPage() {
  const { data: stats, isLoading } = useStats();
  const { tokens } = useAuth();
  const navigate = useNavigate();
  const [copied, setCopied] = useState(false);

  const handleCopyToken = () => {
    navigator.clipboard.writeText(tokens.access ? `Bearer ${tokens.access}` : "").then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  if (isLoading) {
    return (
      <div className="page-loading">
        <Spinner size="lg" label="Loading" />
      </div>
    );
  }

  const failedLogins = stats?.failed_logins_24h ?? 0;
  const lockedAccounts = stats?.locked_accounts ?? 0;
  const pendingDeletions = stats?.pending_deletion_requests ?? 0;

  return (
    <Stack gap="lg" data-testid="admin-dashboard">


      <Grid columns={{ base: 1, sm: 2, lg: 4 }} gap="md">
        <StatCard title="Total Users" value={stats?.total_users ?? 0} icon={<IconUser aria-hidden="true" />} />
        <StatCard title="Active Clients" value={stats?.active_clients ?? 0} icon={<IconApps aria-hidden="true" />} />
        <StatCard title="Active Devices" value={stats?.active_devices ?? 0} icon={<IconDeviceDesktop aria-hidden="true" />} />
        <StatCard title="Active Tokens" value={stats?.active_tokens ?? 0} icon={<IconKey aria-hidden="true" />} />
        <StatCard title="Recent Logins (24h)" value={stats?.recent_logins ?? 0} icon={<IconLogin aria-hidden="true" />} />
        <StatCard
          title="Failed Logins (24h)"
          value={failedLogins}
          alert={failedLogins > 0}
          icon={<IconAlertTriangle aria-hidden="true" />}
        />
        <StatCard
          title="Locked Accounts"
          value={lockedAccounts}
          alert={lockedAccounts > 0}
          icon={<IconLock aria-hidden="true" />}
        />
        {pendingDeletions > 0 && (
          <StatCard title="Pending Deletions" value={pendingDeletions} alert icon={<IconTrash aria-hidden="true" />}>
            <RouterLink to="/users?tab=deletions">Review requests</RouterLink>
          </StatCard>
        )}
      </Grid>

      <Card>
        <Stack gap="md">
          <Heading level={2} textStyle="subheading">
            Quick Actions
          </Heading>
          <Stack gap="sm" align="start">
            <Inline gap="sm">
              <Button
                variant="outline"
                color="neutral"
                startIcon={<IconPlus />}
                onClick={() => navigate("/users", { state: { create: true } })}
              >
                Create User
              </Button>
              <Button
                variant="outline"
                color="neutral"
                startIcon={<IconPlus />}
                onClick={() => navigate("/clients", { state: { create: true } })}
              >
                Create Client
              </Button>
            </Inline>
            <Text muted>Access token for API / Swagger:</Text>
            <Button
              variant="outline"
              color={copied ? "success" : "neutral"}
              startIcon={copied ? <IconCheck /> : <IconCopy />}
              onClick={handleCopyToken}
            >
              {copied ? "Copied!" : "Copy access token"}
            </Button>
          </Stack>
        </Stack>
      </Card>
    </Stack>
  );
}
