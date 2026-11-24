import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { Alert, Button, Drawer, Inline, Input, Stack, Text, toast } from "@yarcl/react";
import apiClient from "../../api/client";
import CopyText from "../CopyText";

const path = "/admin/api/signup-invites";
interface Invite {
  id: string;
  kind: "personal" | "shared";
  delivery_method: "link" | "email";
  email?: string;
  max_uses: number | null;
  use_count: number;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}
interface InviteList { items: Invite[]; smtp_available: boolean }

function status(invite: Invite) {
  if (invite.revoked_at) return "Revoked";
  if (invite.max_uses !== null && invite.use_count >= invite.max_uses) return "Used";
  if (invite.expires_at && Date.parse(invite.expires_at) <= Date.now()) return "Expired";
  return "Active";
}

export default function SignupInvitesTab() {
  const list = useQuery({
    queryKey: ["signup-invites"],
    queryFn: async () => (await apiClient.get<{ data: InviteList }>(path)).data.data,
  });
  const [open, setOpen] = useState(false);
  const [shared, setShared] = useState(false);
  const [sendEmail, setSendEmail] = useState(false);
  const [unlimited, setUnlimited] = useState(false);
  const [neverExpires, setNeverExpires] = useState(false);
  const [link, setLink] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try { await action(); }
    catch (err) {
      if (isAxiosError(err) && err.response?.data?.data?.id) setOpen(false);
      setError((isAxiosError(err) && err.response?.data?.error?.message) || "Invitation request failed.");
    } finally {
      await list.refetch();
      setBusy(false);
    }
  }
  function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const expiry = fields.get("expires");
    void run(async () => {
      const response = await apiClient.post(path, {
        kind: shared ? "shared" : "personal",
        delivery_method: !shared && sendEmail ? "email" : "link",
        email: shared ? "" : fields.get("email"),
        max_uses: shared && !unlimited ? Number(fields.get("uses")) : undefined,
        unlimited: shared && unlimited,
        never_expires: shared && neverExpires,
        expires_at: expiry ? new Date(String(expiry)).toISOString() : undefined,
      });
      setLink(response.data.data.url ?? "");
      setOpen(false);
      if (!response.data.data.url) toast({ title: "Invitation emailed", color: "success" });
    });
  }

  return <Stack gap="md">
    <Inline><Button onClick={() => {
      setShared(false); setSendEmail(false); setUnlimited(false); setNeverExpires(false);
      setError(""); setLink(""); setOpen(true);
    }}>Create invite</Button></Inline>
    {error && !open && <Alert color="danger">{error}</Alert>}
    {link && <Stack gap="xs"><Text>Copy this signup link before leaving this page.</Text>
      <CopyText text={link} /><Inline><Button variant="ghost" onClick={() => setLink("")}>Dismiss link</Button></Inline></Stack>}
    {list.isLoading && <Text>Loading invitations…</Text>}
    {list.isError && <Alert color="danger">Could not load invitations.</Alert>}
    {list.data?.items.length === 0 && <Text>No signup invitations yet.</Text>}
    {list.data?.items.map(invite => <Stack key={invite.id} gap="xs">
      <Inline><strong>{invite.kind === "shared" ? "Shared link" : "Personal invitation"}</strong>
        {invite.email && <Text>{invite.email}</Text>}<Text>{status(invite)}</Text></Inline>
      <Text>Created {new Date(invite.created_at).toLocaleString()} · {invite.use_count} of {invite.max_uses ?? "unlimited"} used · {invite.expires_at ? "Expires " + new Date(invite.expires_at).toLocaleString() : "No expiration"}</Text>
      {status(invite) === "Active" && <Inline>
        {invite.delivery_method === "email" && list.data.smtp_available && <Button disabled={busy} variant="ghost" onClick={() => void run(async () => {
          await apiClient.post(path + "/" + invite.id + "/retry"); toast({title: "New invitation emailed", color: "success"});
        })}>Resend email</Button>}
        <Button disabled={busy} color="danger" variant="ghost" onClick={() => void run(async () => {
          await apiClient.delete(path + "/" + invite.id); setLink("");
        })}>Revoke</Button>
      </Inline>}
    </Stack>)}
    <Drawer title="Create invite" open={open} onOpenChange={setOpen} side="right" size="md">
      {open && <form onSubmit={create}><Stack gap="md">
        <label>Invitation type <select value={shared ? "shared" : "personal"} onChange={e => setShared(e.target.value === "shared")}>
          <option value="personal">Personal · one use</option><option value="shared">Shared link</option>
        </select></label>
        {shared ? <>
          <label><input type="checkbox" checked={unlimited} onChange={e => setUnlimited(e.target.checked)} /> Unlimited uses</label>
          {!unlimited && <label>Maximum signups<Input type="number" name="uses" min="1" step="1" required defaultValue="10" /></label>}
          <label><input type="checkbox" checked={neverExpires} onChange={e => setNeverExpires(e.target.checked)} /> No expiration</label>
          {unlimited && neverExpires && <Text>Anyone with this link can register until you revoke it.</Text>}
        </> : <>
          {list.data?.smtp_available && <label><input type="checkbox" checked={sendEmail} onChange={e => setSendEmail(e.target.checked)} /> Send email invite</label>}
          <label>{sendEmail ? "Recipient email" : "Restrict to email (optional)"}<Input type="email" name="email" required={sendEmail} /></label>
        </>}
        {!(shared && neverExpires) && <label>Expires at (defaults to 7 days)<Input type="datetime-local" name="expires" /></label>}
        {error && <Alert color="danger">{error}</Alert>}
        <Button loading={busy} type="submit">{!shared && sendEmail ? "Send invite" : "Generate link"}</Button>
      </Stack></form>}
    </Drawer>
  </Stack>;
}
