import { useEffect, useRef, useState } from "react";
import { Alert, Button, Dialog, Field, Inline, Input, Select, Stack, Text, Textarea } from "@yarcl/react";
import type { ClaimRequirement, ClaimTestResult } from "../../types/federation";
import { testClaimRequirements } from "../../api/federation";
import "./ClaimRequirementsEditor.css";

type Props = { value?: ClaimRequirement[]; onChange?: (rules: ClaimRequirement[]) => void };

const MATCH_OPTIONS = (["equals", "not_equals", "regex", "not_regex"] as const).map((value) => ({
  value,
  label: value.split("_").join(" "),
}));
const TYPE_OPTIONS = [
  { value: "string", label: "String" },
  { value: "boolean", label: "Boolean" },
];
const BOOLEAN_OPTIONS = [
  { value: "true", label: "true" },
  { value: "false", label: "false" },
];

export default function ClaimRequirementsEditor({ value = [], onChange }: Props) {
  const [open, setOpen] = useState(false);
  const [sample, setSample] = useState('{"email":"member@mycompany.com","email_verified":true,"hd":"mycompany.com"}');
  const [result, setResult] = useState<ClaimTestResult>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const generation = useRef(0);
  useEffect(() => {
    generation.current++;
    setResult(undefined);
    setError("");
  }, [value, sample]);
  const change = (index: number, patch: Partial<ClaimRequirement>) =>
    onChange?.(value.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  const test = async () => {
    // A local parse error starts no request and must leave the tester usable.
    try {
      JSON.parse(sample);
    } catch {
      setError("Sample claims must be valid JSON.");
      setResult(undefined);
      return;
    }
    const version = generation.current;
    setLoading(true);
    setError("");
    setResult(undefined);
    try {
      const answer = await testClaimRequirements(value, sample);
      if (version === generation.current) setResult(answer);
    } catch (err) {
      if (version === generation.current)
        setError(
          err instanceof SyntaxError
            ? "Sample claims must be valid JSON."
            : "Unable to test: check the claims object, rule limits and configuration.",
        );
    } finally {
      setLoading(false);
    }
  };
  return (
    <Stack gap="sm">
      <Text muted>
        Every row must pass. Missing, null and wrong-type claims fail all operators. An empty list adds no restrictions. Names refer
        to literal top-level claims.
      </Text>
      {value.map((rule, index) => {
        const regex = rule.match === "regex" || rule.match === "not_regex";
        const n = index + 1;
        return (
          <Inline key={index} gap="sm" align="center" className="claim-rule">
            <Text>Row {n}</Text>
            <Input
              className="claim-rule-claim"
              aria-label={`Rule ${n} claim`}
              placeholder="Claim name"
              maxLength={256}
              value={rule.claim}
              onChange={(e) => change(index, { claim: e.target.value })}
            />
            <Select
              className="claim-rule-operator"
              aria-label={`Rule ${n} operator`}
              value={rule.match}
              options={MATCH_OPTIONS}
              onValueChange={(match) =>
                match &&
                change(index, {
                  match,
                  ...((match === "regex" || match === "not_regex") && typeof rule.value !== "string" ? { value: "" } : {}),
                })
              }
            />
            <Select
              className="claim-rule-type"
              aria-label={`Rule ${n} type`}
              value={typeof rule.value === "boolean" ? "boolean" : "string"}
              disabled={regex}
              options={TYPE_OPTIONS}
              onValueChange={(type) => type && change(index, { value: type === "boolean" ? true : "" })}
            />
            {typeof rule.value === "boolean" ? (
              <Select
                className="claim-rule-value"
                aria-label={`Rule ${n} value`}
                value={String(rule.value)}
                options={BOOLEAN_OPTIONS}
                onValueChange={(v) => v && change(index, { value: v === "true" })}
              />
            ) : (
              <Input
                className="claim-rule-value"
                aria-label={`Rule ${n} value`}
                placeholder={regex ? "Go regex, e.g. ^[^@]+@mycompany\\.com$" : "Expected value"}
                maxLength={regex ? 1024 : 4096}
                value={rule.value}
                onChange={(e) => change(index, { value: e.target.value })}
              />
            )}
            <Button
              variant="outline"
              color="danger"
              aria-label={`Remove rule ${n}`}
              onClick={() => onChange?.(value.filter((_, i) => i !== index))}
            >
              Remove
            </Button>
          </Inline>
        );
      })}
      <Inline gap="sm">
        <Button
          variant="outline"
          color="neutral"
          disabled={value.length >= 32}
          onClick={() => onChange?.([...value, { claim: "", match: "equals", value: "" }])}
        >
          Add requirement
        </Button>
        <Button variant="outline" color="neutral" onClick={() => setOpen(true)}>
          Test rules
        </Button>
      </Inline>
      <Text muted>
        Regex uses Go syntax and searches within a string; use ^ and $ for whole-value matching. For Google Workspace use hd equals
        mycompany.com; add email_verified equals boolean true when required.
      </Text>
      <Dialog
        open={open}
        onOpenChange={setOpen}
        title="Test claim requirements"
        size="lg"
        footer={
          <Button aria-label="Run test" disabled={loading} loading={loading} onClick={test}>
            Run test
          </Button>
        }
      >
        <Stack gap="md">
          <Alert color="info" title="Claims matcher only">
            This tests the current draft without saving it. It does not verify a JWT signature or prove token authenticity. Samples
            are not stored.
          </Alert>
          <Field label="Sample claims JSON">
            <Textarea rows={8} value={sample} onChange={(e) => setSample(e.target.value)} maxLength={65536} />
          </Field>
          {error && <Alert color="danger" title={error} live="assertive" />}
          {result && (
            <Stack gap="xs" role="group" aria-label="Claim test results">
              <Alert
                color={result.passed ? "success" : "danger"}
                title={result.passed ? "All requirements pass" : "Requirements failed"}
              />
              {result.results.map((row) => (
                <Text key={row.index} color={row.passed ? "success" : "danger"}>
                  Row {row.index + 1} ({row.claim || "missing name"}): {row.reason.split("_").join(" ")}
                </Text>
              ))}
            </Stack>
          )}
        </Stack>
      </Dialog>
    </Stack>
  );
}
