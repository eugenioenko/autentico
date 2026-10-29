import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Input, Modal, Select, Space, Typography } from 'antd';
import type { ClaimRequirement, ClaimTestResult } from '../../types/federation';
import { testClaimRequirements } from '../../api/federation';

type Props = { value?: ClaimRequirement[]; onChange?: (rules: ClaimRequirement[]) => void };

export default function ClaimRequirementsEditor({ value = [], onChange }: Props) {
  const [open, setOpen] = useState(false);
  const [sample, setSample] = useState('{"email":"member@mycompany.com","email_verified":true,"hd":"mycompany.com"}');
  const [result, setResult] = useState<ClaimTestResult>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const generation = useRef(0);
  useEffect(() => { generation.current++; setResult(undefined); setError(''); }, [value, sample]);
  const change = (index: number, patch: Partial<ClaimRequirement>) => onChange?.(value.map((rule, i) => i === index ? { ...rule, ...patch } : rule));
  const test = async () => {
    const version = generation.current;
    setLoading(true); setError(''); setResult(undefined);
    try {
      const answer = await testClaimRequirements(value, sample);
      if (version === generation.current) setResult(answer);
    } catch (err) {
      if (version === generation.current) setError(err instanceof SyntaxError ? 'Sample claims must be valid JSON.' : 'Unable to test: check the claims object, rule limits and configuration.');
    } finally { setLoading(false); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text type="secondary">Every row must pass. Missing, null and wrong-type claims fail all operators. An empty list adds no restrictions. Names refer to literal top-level claims.</Typography.Text>
    {value.map((rule, index) => {
      const regex = rule.match === 'regex' || rule.match === 'not_regex';
      return <Space key={index} wrap style={{ borderBottom: '1px solid #ddd', paddingBottom: 8 }}>
        <Typography.Text>Row {index + 1}</Typography.Text>
        <Input aria-label={`Rule ${index + 1} claim`} placeholder="Claim name" maxLength={256} value={rule.claim} style={{ width: 150 }} onChange={e => change(index, { claim: e.target.value })} />
        <Select aria-label={`Rule ${index + 1} operator`} value={rule.match} style={{ width: 130 }} options={['equals', 'not_equals', 'regex', 'not_regex'].map(value => ({ value, label: value.split('_').join(' ') }))} onChange={match => change(index, { match, ...((match === 'regex' || match === 'not_regex') && typeof rule.value !== 'string' ? { value: '' } : {}) })} />
        <Select aria-label={`Rule ${index + 1} type`} value={typeof rule.value} disabled={regex} style={{ width: 100 }} options={[{ value: 'string', label: 'String' }, { value: 'boolean', label: 'Boolean' }]} onChange={type => change(index, { value: type === 'boolean' ? true : '' })} />
        {typeof rule.value === 'boolean'
          ? <Select aria-label={`Rule ${index + 1} value`} value={String(rule.value)} options={[{ value: 'true', label: 'true' }, { value: 'false', label: 'false' }]} onChange={v => change(index, { value: v === 'true' })} style={{ width: 150 }} />
          : <Input aria-label={`Rule ${index + 1} value`} placeholder={regex ? 'Go regex, e.g. ^[^@]+@mycompany\\.com$' : 'Expected value'} maxLength={regex ? 1024 : 4096} value={rule.value} onChange={e => change(index, { value: e.target.value })} style={{ width: 200 }} />}
        <Button danger aria-label={`Remove rule ${index + 1}`} onClick={() => onChange?.(value.filter((_, i) => i !== index))}>Remove</Button>
      </Space>;
    })}
    <Space><Button disabled={value.length >= 32} onClick={() => onChange?.([...value, { claim: '', match: 'equals', value: '' }])}>Add requirement</Button><Button onClick={() => setOpen(true)}>Test rules</Button></Space>
    <Typography.Text type="secondary">Regex uses Go syntax and searches within a string; use ^ and $ for whole-value matching. For Google Workspace use hd equals mycompany.com; add email_verified equals boolean true when required.</Typography.Text>
    <Modal open={open} title="Test claim requirements" onCancel={() => setOpen(false)} footer={<Button type="primary" loading={loading} onClick={test}>Run test</Button>} width={640}>
      <Alert type="info" showIcon title="Claims matcher only" description="This tests the current draft without saving it. It does not verify a JWT signature or prove token authenticity. Samples are not stored." />
      <Typography.Paragraph>Sample claims JSON</Typography.Paragraph>
      <Input.TextArea aria-label="Sample claims JSON" rows={8} value={sample} onChange={e => setSample(e.target.value)} maxLength={65536} />
      {error && <Alert type="error" title={error} role="alert" />}
      {result && <Space direction="vertical" aria-label="Claim test results">
        <Alert type={result.passed ? 'success' : 'error'} title={result.passed ? 'All requirements pass' : 'Requirements failed'} />
        {result.results.map(row => <Typography.Text key={row.index} type={row.passed ? 'success' : 'danger'}>Row {row.index + 1} ({row.claim || 'missing name'}): {row.reason.split('_').join(' ')}</Typography.Text>)}
      </Space>}
    </Modal>
  </Space>;
}
