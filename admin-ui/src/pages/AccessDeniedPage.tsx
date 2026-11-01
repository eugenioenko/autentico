import { Button, EmptyState } from "@yarcl/react";
import { IconShieldX } from "@tabler/icons-react";
import "./AuthScreen.css";

export default function AccessDeniedPage() {
  return (
    <div className="auth-screen">
      <EmptyState
        headingLevel={1}
        color="danger"
        icon={<IconShieldX aria-hidden="true" />}
        title="Unauthorized"
        description="Your account does not have administrator privileges."
        actions={<Button href="/account/">Go to Account Portal</Button>}
      />
    </div>
  );
}
