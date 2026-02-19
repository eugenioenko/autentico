import { useState, useMemo } from "react";
import { 
  Layout, 
  Menu, 
  Typography, 
  Card, 
  Descriptions, 
  Tag, 
  Button, 
  Space, 
  Divider, 
  Tabs,
  Collapse
} from "antd";
import { 
  LogoutOutlined, 
  ReloadOutlined, 
  UserOutlined, 
  KeyOutlined, 
  InfoCircleOutlined 
} from "@ant-design/icons";
import { useAuth } from "../context/AuthContext";

const { Header, Content } = Layout;
const { Title, Text, Paragraph } = Typography;

function parseJwt(token: string) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

export default function DashboardPage() {
  const { user, logout, renewToken } = useAuth();
  const [loading, setLoading] = useState(false);

  const idTokenPayload = useMemo(() => user?.id_token ? parseJwt(user.id_token) : null, [user]);
  const accessTokenPayload = useMemo(() => user?.access_token ? parseJwt(user.access_token) : null, [user]);

  const handleRefresh = async () => {
    setLoading(true);
    await renewToken();
    setLoading(false);
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ color: 'white', fontSize: '1.5rem', fontWeight: 'bold' }}>Token Debugger</div>
        <Menu theme="dark" mode="horizontal" selectable={false}>
          <Menu.Item key="user" icon={<UserOutlined />}>
            {user?.profile?.preferred_username || user?.profile?.email || 'User'}
          </Menu.Item>
          <Menu.Item key="logout" icon={<LogoutOutlined />} onClick={logout}>
            Logout
          </Menu.Item>
        </Menu>
      </Header>
      <Content style={{ padding: '24px' }}>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Card 
            title={<span><InfoCircleOutlined /> Session Overview</span>}
            extra={
              <Button 
                icon={<ReloadOutlined />} 
                loading={loading} 
                onClick={handleRefresh}
              >
                Refresh Token (Silent)
              </Button>
            }
          >
            <Descriptions bordered column={1}>
              <Descriptions.Item label="Expires In">
                {user?.expires_in ? `${user.expires_in} seconds` : 'N/A'}
              </Descriptions.Item>
              <Descriptions.Item label="Expired">
                <Tag color={user?.expired ? 'red' : 'green'}>
                  {user?.expired ? 'Yes' : 'No'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Scopes">
                {user?.scope?.split(' ').map(s => <Tag key={s} color="blue">{s}</Tag>)}
              </Descriptions.Item>
              <Descriptions.Item label="Token Type">
                <Tag color="purple">{user?.token_type}</Tag>
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Tabs defaultActiveKey="1" items={[
            {
              key: '1',
              label: 'ID Token',
              children: (
                <Card>
                   <Title level={4}>Raw ID Token</Title>
                   <Paragraph copyable ellipsis={{ rows: 2, expandable: true }}>
                     {user?.id_token}
                   </Paragraph>
                   <Divider />
                   <Title level={4}>Payload</Title>
                   <pre style={{ background: '#f5f5f5', padding: '10px', borderRadius: '4px', overflow: 'auto' }}>
                     {JSON.stringify(idTokenPayload, null, 2)}
                   </pre>
                </Card>
              )
            },
            {
              key: '2',
              label: 'Access Token',
              children: (
                <Card>
                   <Title level={4}>Raw Access Token</Title>
                   <Paragraph copyable ellipsis={{ rows: 2, expandable: true }}>
                     {user?.access_token}
                   </Paragraph>
                   <Divider />
                   <Title level={4}>Payload</Title>
                   {accessTokenPayload ? (
                     <pre style={{ background: '#f5f5f5', padding: '10px', borderRadius: '4px', overflow: 'auto' }}>
                       {JSON.stringify(accessTokenPayload, null, 2)}
                     </pre>
                   ) : (
                     <Text type="secondary">Access token is not a readable JWT (might be opaque)</Text>
                   )}
                </Card>
              )
            },
            {
              key: '3',
              label: 'Refresh Token',
              children: (
                <Card>
                   <Title level={4}>Raw Refresh Token</Title>
                   <Paragraph copyable={user?.refresh_token ? { text: user.refresh_token } : false}>
                     {user?.refresh_token || <Text type="secondary">No refresh token provided (request 'offline_access' scope)</Text>}
                   </Paragraph>
                </Card>
              )
            }
          ]} />

          <Collapse items={[
            {
              key: 'raw_user',
              label: 'Raw User Object (oidc-client-ts)',
              children: (
                <pre style={{ background: '#f5f5f5', padding: '10px', borderRadius: '4px', overflow: 'auto' }}>
                  {JSON.stringify(user, null, 2)}
                </pre>
              )
            }
          ]} />
        </Space>
      </Content>
    </Layout>
  );
}
