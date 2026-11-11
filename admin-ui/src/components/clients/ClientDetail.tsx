import { Badge, Drawer, Heading, Inline, Stack, Text } from "@yarcl/react";
import type { ClientInfoResponse } from "../../types/client";
import { useGroupsByIds } from "../../hooks/useGroups";
import { useUsersByIds } from "../../hooks/useUsers";
import DescriptionList from "../DescriptionList";

interface ClientDetailProps {
  open: boolean;
  client: ClientInfoResponse | null;
  onClose: () => void;
}

function Chips({ items }: { items: string[] | undefined }) {
  return (
    <Inline gap="xs">
      {items?.map((item) => (
        <Badge key={item} variant="soft" color="neutral">
          {item}
        </Badge>
      ))}
    </Inline>
  );
}

function UriList({ uris }: { uris: string[] }) {
  return (
    <Stack gap="xs">
      {uris.map((uri) => (
        <span key={uri}>{uri}</span>
      ))}
    </Stack>
  );
}

function AccessDetails({ client }: { client: ClientInfoResponse }) {
  const groupIds = client.allowed_groups ?? [];
  const userIds = client.allowed_users ?? [];
  const groups = useGroupsByIds(groupIds);
  const { data: users } = useUsersByIds(userIds);
  const groupNames = groupIds.map((id) => groups.find((g) => g.id === id)?.name ?? id);
  const usernames = userIds.map((id) => users?.find((u) => u.id === id)?.username ?? id);
  const restricted = !!client.restrict_access;

  return (
    <>
      <DescriptionList.Item label="Restrict Access">
        <Stack gap="xs">
          <Inline gap="xs">
            <Badge variant="soft" color={restricted ? "warning" : "neutral"}>
              {restricted ? "On" : "Off"}
            </Badge>
          </Inline>
          {restricted && groupIds.length === 0 && userIds.length === 0 && (
            <Text color="danger">Nobody can sign in to this client</Text>
          )}
        </Stack>
      </DescriptionList.Item>
      {(restricted || groupIds.length > 0) && (
        <DescriptionList.Item label="Allowed Groups">
          {groupNames.length > 0 ? <Chips items={groupNames} /> : <Text muted>None</Text>}
        </DescriptionList.Item>
      )}
      {(restricted || userIds.length > 0) && (
        <DescriptionList.Item label="Allowed Users">
          {usernames.length > 0 ? <Chips items={usernames} /> : <Text muted>None</Text>}
        </DescriptionList.Item>
      )}
    </>
  );
}

export default function ClientDetail({ open, client, onClose }: ClientDetailProps) {
  if (!client) return null;

  const hasOverrides =
    client.access_token_expiration ||
    client.refresh_token_expiration ||
    client.authorization_code_expiration ||
    client.allowed_audiences?.length ||
    client.allow_self_signup !== undefined ||
    client.sso_session_idle_timeout ||
    client.trust_device_enabled !== undefined ||
    client.trust_device_expiration;

  return (
    <Drawer title={`Client: ${client.client_name}`} open={open} onOpenChange={(next) => !next && onClose()} side="right" size="md">
      <Stack gap="lg">
        <DescriptionList>
          <DescriptionList.Item label="Client ID">{client.client_id}</DescriptionList.Item>
          <DescriptionList.Item label="Client Name">{client.client_name}</DescriptionList.Item>
          <DescriptionList.Item label="Client Type">
            <Badge variant="soft" color={client.client_type === "confidential" ? "info" : "success"}>
              {client.client_type}
            </Badge>
          </DescriptionList.Item>
          <DescriptionList.Item label="Status">
            <Badge variant="soft" color={client.is_active ? "success" : "danger"}>
              {client.is_active ? "Active" : "Inactive"}
            </Badge>
          </DescriptionList.Item>
          <DescriptionList.Item label="Redirect URIs">
            <UriList uris={client.redirect_uris ?? []} />
          </DescriptionList.Item>
          <DescriptionList.Item label="Post-Logout Redirect URIs">
            {client.post_logout_redirect_uris && client.post_logout_redirect_uris.length > 0 ? (
              <UriList uris={client.post_logout_redirect_uris} />
            ) : (
              <Text muted>None</Text>
            )}
          </DescriptionList.Item>
          <DescriptionList.Item label="Grant Types">
            <Chips items={client.grant_types} />
          </DescriptionList.Item>
          <DescriptionList.Item label="Response Types">
            <Chips items={client.response_types} />
          </DescriptionList.Item>
          <DescriptionList.Item label="Scopes">
            <Chips items={client.scopes?.split(" ").filter(Boolean)} />
          </DescriptionList.Item>
          <DescriptionList.Item label="Auth Method">{client.token_endpoint_auth_method}</DescriptionList.Item>
        </DescriptionList>

        <Stack gap="sm">
          <Heading level={3} textStyle="subheading">
            Access
          </Heading>
          <DescriptionList>
            <AccessDetails client={client} />
          </DescriptionList>
        </Stack>

        {hasOverrides && (
          <Stack gap="sm">
            <Heading level={3} textStyle="subheading">
              Overrides
            </Heading>
            <DescriptionList>
              {client.access_token_expiration && (
                <DescriptionList.Item label="Access Token TTL">{client.access_token_expiration}</DescriptionList.Item>
              )}
              {client.refresh_token_expiration && (
                <DescriptionList.Item label="Refresh Token TTL">{client.refresh_token_expiration}</DescriptionList.Item>
              )}
              {client.authorization_code_expiration && (
                <DescriptionList.Item label="Auth Code TTL">{client.authorization_code_expiration}</DescriptionList.Item>
              )}
              {client.allowed_audiences?.length ? (
                <DescriptionList.Item label="Allowed Audiences">{client.allowed_audiences.join(", ")}</DescriptionList.Item>
              ) : null}
              {client.allow_self_signup !== undefined && (
                <DescriptionList.Item label="Self Signup">{client.allow_self_signup ? "Allowed" : "Disabled"}</DescriptionList.Item>
              )}
              {client.sso_session_idle_timeout && (
                <DescriptionList.Item label="SSO Idle Timeout">{client.sso_session_idle_timeout}</DescriptionList.Item>
              )}
              {client.trust_device_enabled !== undefined && (
                <DescriptionList.Item label="Trust Device">{client.trust_device_enabled ? "Enabled" : "Disabled"}</DescriptionList.Item>
              )}
              {client.trust_device_expiration && (
                <DescriptionList.Item label="Trust Device TTL">{client.trust_device_expiration}</DescriptionList.Item>
              )}
            </DescriptionList>
          </Stack>
        )}
      </Stack>
    </Drawer>
  );
}
