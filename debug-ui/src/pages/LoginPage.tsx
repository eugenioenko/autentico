import { useEffect } from "react";
import { Button, Card, Typography, Space, Divider } from "antd";
import { LoginOutlined, MobileOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const { Title, Text } = Typography;

export default function LoginPage() {
  const { startLogin, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      window.location.href = "/debug/";
    }
  }, [isAuthenticated]);

  return (
    <div style={{ 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center', 
      height: '100vh',
      backgroundColor: '#f0f2f5'
    }}>
      <Card style={{ width: 400, textAlign: 'center' }}>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Title level={2}>Debug UI</Title>
          <Text>Welcome to the Token Debugger. Please log in to view and test your tokens.</Text>
          <Button
            type="primary"
            icon={<LoginOutlined />}
            size="large"
            onClick={() => startLogin()}
            block
          >
            Log In with Autentico
          </Button>
          <Divider>or</Divider>
          <Button
            icon={<MobileOutlined />}
            size="large"
            onClick={() => navigate("/device")}
            block
          >
            Test Device Flow
          </Button>
        </Space>
      </Card>
    </div>
  );
}
