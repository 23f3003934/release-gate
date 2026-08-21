const express = require('express');

const app = express();
app.use(express.json());

// --- helpers -----------------------------------------------------------

const REQUIRED_PERMISSIONS = {
  contents: 'read',
  packages: 'write',
  'id-token': 'none',
};

function hasExactLeastPrivilegePermissions(permissions) {
  if (!permissions || typeof permissions !== 'object') return false;
  const keys = Object.keys(permissions);
  const requiredKeys = Object.keys(REQUIRED_PERMISSIONS);

  // No extra scopes, no missing scopes.
  if (keys.length !== requiredKeys.length) return false;

  return requiredKeys.every((key) => permissions[key] === REQUIRED_PERMISSIONS[key]);
}

const FULL_SHA_REGEX = /^[0-9a-f]{40}$/;

function isPinnedToFullSha(ref) {
  return typeof ref === 'string' && FULL_SHA_REGEX.test(ref);
}

function usesMutableAction(actions) {
  if (!Array.isArray(actions)) return false;
  return actions.some((action) => {
    // Actions owned by "actions" (e.g. actions/checkout) may use a version tag.
    if (action && action.owner === 'actions') return false;
    // Every third-party action must be pinned to a full 40-char lowercase hex SHA.
    return !isPinnedToFullSha(action && action.ref);
  });
}

// --- core policy logic ---------------------------------------------------

function evaluateReleaseGate(body) {
  const violations = [];

  const target = body && body.target;
  const event = body && body.event;
  const ref = body && body.ref;
  const workflow = (body && body.workflow) || {};
  const image = (body && body.image) || {};

  // 1. Least-privilege permissions.
  if (!hasExactLeastPrivilegePermissions(workflow.permissions)) {
    violations.push('EXCESS_PERMISSION');
  }

  // 2. Pull request safety.
  if (event === 'pull_request') {
    if (workflow.trigger !== 'pull_request') {
      violations.push('UNSAFE_PR_TRIGGER');
    }
    if (
      workflow.testsPassed !== true ||
      workflow.matrixComplete !== true ||
      workflow.failFast !== false
    ) {
      violations.push('TESTS_INCOMPLETE');
    }
  }

  // 3. Action pinning.
  if (usesMutableAction(workflow.actions)) {
    violations.push('MUTABLE_ACTION');
  }

  // 4. Image hardening.
  if (image.multiStage !== true) {
    violations.push('SINGLE_STAGE_IMAGE');
  }
  if (image.runsAsRoot !== false) {
    violations.push('ROOT_RUNTIME');
  }
  if (image.secretMode !== 'none' && image.secretMode !== 'buildkit') {
    violations.push('SECRET_IN_LAYER');
  }
  if (typeof image.criticalVulnerabilities !== 'number' || image.criticalVulnerabilities > 0) {
    violations.push('CRITICAL_CVE');
  }
  if (image.digestPinned !== true) {
    violations.push('UNPINNED_IMAGE');
  }

  // 5. Production-only rules.
  if (target === 'production') {
    if (!(event === 'push' && ref === 'refs/heads/main')) {
      violations.push('INVALID_PRODUCTION_REF');
    }
    if (workflow.environmentApproval !== true) {
      violations.push('APPROVAL_REQUIRED');
    }
  }

  return {
    decision: violations.length === 0 ? 'promote' : 'block',
    violations,
  };
}

// --- route -----------------------------------------------------------

app.post('/release-gate', (req, res) => {
  const result = evaluateReleaseGate(req.body);
  res.status(200).json(result);
});

app.get('/', (_req, res) => {
  res.status(200).send('release-gate service is running');
});

// Only start listening if this file is run directly (not when imported by tests).
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`release-gate listening on port ${PORT}`);
  });
}

module.exports = { app, evaluateReleaseGate };
