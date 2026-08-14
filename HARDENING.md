<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2026.417.125702

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2026.417.125702** was hardened automatically. 4 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Three workflow files use mutable branch refs (`@master`) instead of pinned full 40-character SHA commit hashes for their `uses:` references, making them vulnerable to supply-chain attacks if the referenced repository is compromised.

- `.github/workflows/_codeql.yml`: `uses: LizardByte/.github/.github/workflows/__call-codeql.yml@master`
- `.github/workflows/_common-lint.yml`: `uses: LizardByte/.github/.github/workflows/__call-common-lint.yml@master`
- `.github/workflows/_top-issues.yml`: `uses: LizardByte/.github/.github/workflows/__call-top-issues.yml@master`

Locations:

- `.github/workflows/_codeql.yml:18`
- `.github/workflows/_common-lint.yml:15`
- `.github/workflows/_top-issues.yml:18`

### script-injection (severity: high)

Rule (a): The 'Install dependencies' step in action.yml directly interpolates `${{ steps.setup-python.outputs.python-path }}` inside a `run:` shell command. The `steps.*.outputs.*` context is a workflow-controllable value that flows through YAML template substitution before the shell processes it, enabling script injection. Offending lines:
  `${{ steps.setup-python.outputs.python-path }} -m pip install --upgrade pip setuptools wheel`
  `${{ steps.setup-python.outputs.python-path }} -m pip install -r requirements.txt`

The fix is to capture the python path into an env var and reference it as `"$PYTHON_PATH"` in the shell.

Locations:

- `action.yml:118`

### script-injection (severity: high)

Rule (a): The 'JPRM repo' step in action.yml directly interpolates multiple `${{ steps.inputs.outputs.* }}` expressions inside `run:` shell commands. These outputs are derived from user-controlled `inputs.*` and `github.*` values (branch, action, gh_pages_url, plugin_url, zipfile_path, plugin_name, release_version), enabling script injection. Example offending lines:
  `${{ steps.setup-python.outputs.python-path }} -m jprm repo init ${{ steps.inputs.outputs.branch }}`
  `if [ "${{ steps.inputs.outputs.action }}" == "add" ]; then`
  `--url ${{ steps.inputs.outputs.gh_pages_url }}`
  `--plugin-url ${{ steps.inputs.outputs.plugin_url }}`
  `${{ steps.inputs.outputs.zipfile_path }}`

All these values should be passed via `env:` variables and referenced as quoted shell variables (e.g., `"$BRANCH"`).

Locations:

- `action.yml:131`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from user-controlled `inputs.*` and `github.*` contexts to `$GITHUB_OUTPUT` without sanitization. The env vars INPUTS_ACTION, INPUTS_BRANCH, INPUTS_GH_PAGES_URL, INPUTS_REPOSITORY, INPUTS_RELEASE_TAG, INPUTS_PLUGIN_URL, INPUTS_ZIPFILE (from `inputs.*`) and SOURCE_REPOSITORY_NAME, SOURCE_REPOSITORY_URL (from `github.event.repository.*`) are written directly to `$GITHUB_OUTPUT` via a heredoc block:

```
{
  echo "action=${INPUTS_ACTION}"
  echo "branch=${INPUTS_BRANCH}"
  echo "gh_pages_url=${INPUTS_GH_PAGES_URL}"
  ...
} >> "${GITHUB_OUTPUT}"
```

None of these writes are preceded by the required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`). An attacker-controlled newline in any of these values can inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:100`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection

**Notes:**

Fixed all four findings: (1) unpinned-uses: Pinned all three workflow uses references from @master to full SHA 4d902c4ebbda3f214bd644b12f0f97fcae3a40ea with # master comment in _codeql.yml, _common-lint.yml, and _top-issues.yml. (2) script-injection in Install dependencies step: moved python-path expression into env block as PYTHON_PATH and referenced as $PYTHON_PATH in shell. (3) script-injection in JPRM repo step: moved all steps.setup-python.outputs.python-path and steps.inputs.outputs.* expressions into env block with named vars and referenced as quoted shell variables. (4) github-env-injection in Setup inputs step: added sanitization for all values written to GITHUB_OUTPUT using printf and tr -d to strip newlines before writing.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed all 6 unquoted variable expansions in the 'Setup inputs' step of action.yml:
1. `case ${INPUTS_ACTION} in` → `case "${INPUTS_ACTION}" in`
2. `echo ${SOURCE_REPOSITORY_NAME}}` → `echo "${SOURCE_REPOSITORY_NAME}"` (also fixed extra `}` typo)
3. `echo ${SOURCE_REPOSITORY_NAME}` (else branch) → `echo "${SOURCE_REPOSITORY_NAME}"`
4. `echo ${INPUTS_RELEASE_TAG}` → `echo "${INPUTS_RELEASE_TAG}"`
5. `echo ${SOURCE_REPOSITORY_NAME}` (repository_name) → `echo "${SOURCE_REPOSITORY_NAME}"`
6. `basename ${INPUTS_ZIPFILE}` → `basename "${INPUTS_ZIPFILE}"`
All variables holding untrusted inputs are now properly double-quoted to prevent shell metacharacter injection.

