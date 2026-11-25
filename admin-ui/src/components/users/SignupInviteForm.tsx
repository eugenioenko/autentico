import { useId, useState, type FormEvent } from "react";
import { Alert, Button, Checkbox, DatePicker, Drawer, Field, Input, NumberInput, Select, Stack } from "@yarcl/react";
import dayjs from "dayjs";

export interface InviteRequest {
  kind: "personal" | "shared";
  delivery_method: "email" | "link";
  email: string;
  unlimited: boolean;
  max_uses?: number;
  never_expires: boolean;
  expires_at?: string;
}

interface Props {
  smtp: boolean;
  busy: boolean;
  error: string;
  onClose: () => void;
  onCreate: (request: InviteRequest) => void;
}

export default function SignupInviteForm({ smtp, busy, error, onClose, onCreate }: Props) {
  const formId = useId();
  const [shared, setShared] = useState(false);
  const [sendEmail, setSendEmail] = useState(false);
  const [unlimited, setUnlimited] = useState(false);
  const [neverExpires, setNeverExpires] = useState(false);
  const [uses, setUses] = useState<number | null>(10);
  const [email, setEmail] = useState("");
  const [expiry, setExpiry] = useState<Date | null>(() => dayjs().add(7, "day").toDate());
  const [time, setTime] = useState(() => dayjs().format("HH:mm"));
  const expires = !shared || !neverExpires;
  const emailDelivery = !shared && smtp && sendEmail;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (expires && !expiry) return;
    const [hour, minute] = time.split(":").map(Number);
    onCreate({
      kind: shared ? "shared" : "personal",
      delivery_method: emailDelivery ? "email" : "link",
      email: shared ? "" : email,
      unlimited: shared && unlimited,
      max_uses: shared && !unlimited ? uses ?? undefined : undefined,
      never_expires: !expires,
      expires_at: expires ? dayjs(expiry).hour(hour).minute(minute).second(0).millisecond(0).toISOString() : undefined,
    });
  }

  return (
    <Drawer title="Create invite" open onOpenChange={next => !next && !busy && onClose()} side="right" size="md"
      footer={<>
        <Button color="neutral" variant="ghost" disabled={busy} onClick={onClose}>Cancel</Button>
        <Button form={formId} type="submit" loading={busy} disabled={(expires && !expiry) || (shared && !unlimited && !uses)}>
          {emailDelivery ? "Send invite" : "Generate link"}
        </Button>
      </>}>
      <form id={formId} onSubmit={submit}>
        <Stack gap="md">
          <Field label="Invitation type">
            <Select value={shared ? "shared" : "personal"} onValueChange={v => setShared(v === "shared")}
              options={[{label: "Personal · one use", value: "personal"}, {label: "Shared link", value: "shared"}]} />
          </Field>
          {shared ? <>
            <Checkbox checked={unlimited} onChange={e => setUnlimited(e.target.checked)}>Unlimited uses</Checkbox>
            {!unlimited && <Field label="Maximum signups" required>
              <NumberInput min={1} step={1} value={uses} onValueChange={setUses} />
            </Field>}
            <Checkbox checked={neverExpires} onChange={e => setNeverExpires(e.target.checked)}>No expiration</Checkbox>
            {unlimited && neverExpires && <Alert color="warning">Anyone with this link can register until you revoke it.</Alert>}
          </> : <>
            {smtp && <Checkbox checked={sendEmail} onChange={e => setSendEmail(e.target.checked)}>Send email invite</Checkbox>}
            <Field label={emailDelivery ? "Recipient email" : "Restrict to email (optional)"} required={emailDelivery}>
              <Input type="email" value={email} onChange={e => setEmail(e.target.value)} />
            </Field>
          </>}
          {expires && <>
            <Field label="Expiration date"><DatePicker min={new Date()} value={expiry} onValueChange={setExpiry} /></Field>
            <Field label="Expiration time" required><Input type="time" value={time} onChange={e => setTime(e.target.value)} /></Field>
          </>}
          {error && <Alert color="danger" live="assertive">{error}</Alert>}
        </Stack>
      </form>
    </Drawer>
  );
}
