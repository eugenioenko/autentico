import { useEffect, useRef } from "react";
import { useAuth } from "oidc-js-react";
import { setAuth } from "../api/client";

export default function AuthBridge() {
  const { tokens, actions } = useAuth();
  const tokenRef = useRef(tokens.access);
  tokenRef.current = tokens.access;

  useEffect(() => {
    setAuth(() => tokenRef.current, actions.login, actions.refresh);
  }, [actions]);

  return null;
}
