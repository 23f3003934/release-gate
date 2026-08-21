# release-gate

Deterministic policy endpoint (`POST /release-gate`) for a CI/CD container
release gate. See `server.js` for the full rule set and `test.js` for
example payloads.

## Run locally

```bash
npm install
npm start
# in another terminal:
curl -X POST http://localhost:3000/release-gate \
  -H "Content-Type: application/json" \
  -d @sample-payload.json
```

## Run tests

```bash
npm test
```

## How to submit this assignment (step by step)

1. **Create a new public GitHub repository** (e.g. `release-gate`).
2. **Push these files to it**, keeping the folder structure:
   - `server.js`
   - `package.json`
   - `test.js`
   - `.github/workflows/release-gate.yml`
   - this `README.md`

   ```bash
   git init
   git add .
   git commit -m "Add release gate service"
   git branch -M main
   git remote add origin https://github.com/<your-username>/release-gate.git
   git push -u origin main
   ```

3. **Check the Actions tab** on GitHub. Pushing to `main` automatically
   triggers the `TDS GA7 Release Gate` workflow. Make sure it goes green
   (all steps pass, including `npm test`).
4. **Deploy the server somewhere reachable** (e.g. Render, Railway, Fly.io,
   a VM, etc.) so the grader can `POST` to `/release-gate` on the live
   hidden test cases — this is worth 75% of the marks. Any host that runs
   `npm install && npm start` (listening on the `PORT` env var, which the
   code already does) will work.
5. **Submit the workflow page URL**, which looks like:
   `https://github.com/<your-username>/release-gate/actions/workflows/release-gate.yml`
   — not a URL to a specific run.

## Rule summary

| Check | Violation code |
|---|---|
| Permissions must be exactly `contents:read`, `packages:write`, `id-token:none` | `EXCESS_PERMISSION` |
| PR must use `pull_request`, not `pull_request_target` | `UNSAFE_PR_TRIGGER` |
| PR must have `testsPassed`, `matrixComplete` true and `failFast` false | `TESTS_INCOMPLETE` |
| Third-party actions must be pinned to a 40-char lowercase hex SHA | `MUTABLE_ACTION` |
| Image must be multi-stage | `SINGLE_STAGE_IMAGE` |
| Image must not run as root | `ROOT_RUNTIME` |
| Build secrets must use `none` or `buildkit` mode | `SECRET_IN_LAYER` |
| Zero critical vulnerabilities | `CRITICAL_CVE` |
| Image must be digest-pinned | `UNPINNED_IMAGE` |
| Production must be `push` to `refs/heads/main` | `INVALID_PRODUCTION_REF` |
| Production must have `environmentApproval: true` | `APPROVAL_REQUIRED` |
