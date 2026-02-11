import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Spin } from "antd";
import { useAuth } from "../context/AuthContext";

export default function CallbackPage() {
  const navigate = useNavigate();
  const { handleCallback } = useAuth();
  const processed = useRef(false);

  useEffect(() => {
    if (processed.current) return;
    processed.current = true;

    handleCallback()
      .then(() => {
        navigate("/", { replace: true });
      })
      .catch((err: Error) => {
        navigate(`/login?error=${encodeURIComponent(err.message)}`, {
          replace: true,
        });
      });
  }, [navigate, handleCallback]);

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
      }}
    >
      <Spin size="large" tip="Signing in..." />
    </div>
  );
}
