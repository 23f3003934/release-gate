const assert = require('assert');
const { evaluateReleaseGate } = require('./server');

function safePreviewPayload() {
  return {
    target: 'preview',
    event: 'pull_request',
    ref: 'refs/heads/feature-1',
    workflow: {
      trigger: 'pull_request',
      permissions: { contents: 'read', packages: 'write', 'id-token': 'none' },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        { owner: 'actions', name: 'checkout', ref: 'v4' },
        { owner: 'octocat', name: 'some-action', ref: 'a'.repeat(40) },
      ],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: 'buildkit',
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
  };
}

// 1. A fully safe preview payload should promote.
{
  const result = evaluateReleaseGate(safePreviewPayload());
  assert.strictEqual(result.decision, 'promote');
  assert.deepStrictEqual(result.violations, []);
}

// 2. Excess permission should block.
{
  const payload = safePreviewPayload();
  payload.workflow.permissions = {
    contents: 'read',
    packages: 'write',
    'id-token': 'none',
    actions: 'write',
  };
  const result = evaluateReleaseGate(payload);
  assert.strictEqual(result.decision, 'block');
  assert.ok(result.violations.includes('EXCESS_PERMISSION'));
}

// 3. pull_request_target should be flagged.
{
  const payload = safePreviewPayload();
  payload.workflow.trigger = 'pull_request_target';
  const result = evaluateReleaseGate(payload);
  assert.ok(result.violations.includes('UNSAFE_PR_TRIGGER'));
}

// 4. Unpinned third-party action should be flagged, but actions/* with a tag is fine.
{
  const payload = safePreviewPayload();
  payload.workflow.actions = [
    { owner: 'actions', name: 'checkout', ref: 'v4' },
    { owner: 'someone', name: 'other-action', ref: 'main' },
  ];
  const result = evaluateReleaseGate(payload);
  assert.ok(result.violations.includes('MUTABLE_ACTION'));
}

// 5. Root runtime + secret leak + critical CVE combined.
{
  const payload = safePreviewPayload();
  payload.image.runsAsRoot = true;
  payload.image.secretMode = 'copy';
  payload.image.criticalVulnerabilities = 2;
  const result = evaluateReleaseGate(payload);
  assert.ok(result.violations.includes('ROOT_RUNTIME'));
  assert.ok(result.violations.includes('SECRET_IN_LAYER'));
  assert.ok(result.violations.includes('CRITICAL_CVE'));
}

// 6. Production requires push to main + approval.
{
  const payload = safePreviewPayload();
  payload.target = 'production';
  payload.event = 'push';
  payload.ref = 'refs/heads/develop'; // wrong branch
  payload.workflow.environmentApproval = false;
  const result = evaluateReleaseGate(payload);
  assert.ok(result.violations.includes('INVALID_PRODUCTION_REF'));
  assert.ok(result.violations.includes('APPROVAL_REQUIRED'));
}

// 7. A fully compliant production release should promote.
{
  const payload = safePreviewPayload();
  payload.target = 'production';
  payload.event = 'push';
  payload.ref = 'refs/heads/main';
  payload.workflow.environmentApproval = true;
  const result = evaluateReleaseGate(payload);
  assert.strictEqual(result.decision, 'promote');
  assert.deepStrictEqual(result.violations, []);
}

console.log('All release-gate tests passed.');
