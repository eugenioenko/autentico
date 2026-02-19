import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Spin, Result, Button } from "antd";
import { useAuth } from "../context/AuthContext";

export default function CallbackPage() {
  const { handleCallback } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;

    handleCallback()
      .then(() => navigate("/"))
      .catch((err) => {
        console.error(err);
        setError(err instanceof Error ? err.message : "Authentication failed");
      });
  }, [handleCallback, navigate]);

  if (error) {
    return (
      <Result
        status="error"
        title="Authentication Error"
        subTitle={error}
        extra={[
          <Button type="primary" key="login" onClick={() => navigate("/login")}>
            Back to Login
          </Button>,
        ]}
      />
    );
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <Spin size="large" tip="Processing authentication..." />
    </div>
  );
}
