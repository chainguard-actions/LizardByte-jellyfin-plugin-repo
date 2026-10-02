<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2024.919.151635

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2024.919.151635** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Multiple `run:` blocks in action.yml directly interpolate `${{ ... }}` expressions inside shell commands, enabling script injection. An attacker-controlled value (e.g. a crafted `inputs.action`, `inputs.zipfile`, `inputs.plugin_url`, `github.event.repository.name`, or `github.workspace`) can break out of the shell context and execute arbitrary commands.

Affected steps and representative offending lines:

**Step: 'Setup inputs'** — direct interpolation of inputs and github context:
  - `action=${{ inputs.action }}`
  - `branch=${{ inputs.branch }}`
  - `gh_pages_url=${{ inputs.gh_pages_url }}`
  - `repository=${{ inputs.repository }}`
  - `release_tag=${{ inputs.release_tag }}`
  - `source_repository=${{ github.event.repository.name }}`
  - `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]`
  - `zipfile_path=${{ github.workspace }}/...`
  - `zipfile_name=$(basename ${{ inputs.zipfile }})`
  - `zipfile_path=${{ inputs.zipfile }}`
  - `plugin_url=${{ github.event.repository.html_url }}/...`
  - `plugin_url=${{ inputs.plugin_url }}`

**Step: 'Install dependencies'** — interpolation of step output:
  - `${{ steps.setup-python.outputs.python-path }} -m pip install ...`

**Step: 'JPRM repo'** — interpolation of step outputs derived from untrusted inputs:
  - `${{ steps.setup-python.outputs.python-path }} ...`
  - `if [ "${{ steps.inputs.outputs.action }}" == "add" ]`
  - `--url ${{ steps.inputs.outputs.gh_pages_url }}`
  - `--plugin-url ${{ steps.inputs.outputs.plugin_url }}`
  - `${{ steps.inputs.outputs.branch }}`
  - `${{ steps.inputs.outputs.zipfile_path }}`
  - `${{ steps.inputs.outputs.release_version }}`

All `${{ ... }}` expressions must be moved to `env:` blocks and the env vars must be double-quoted in the shell script.

Locations:

- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:53`
- `action.yml:57`
- `action.yml:58`
- `action.yml:75`
- `action.yml:80`
- `action.yml:83`
- `action.yml:84`
- `action.yml:86`
- `action.yml:89`
- `action.yml:96`
- `action.yml:107`
- `action.yml:118`
- `action.yml:127`
- `action.yml:131`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted `inputs.*` and `github.*` context expressions to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`). An attacker can inject newlines into these values to smuggle additional key=value pairs into GITHUB_OUTPUT, potentially overwriting outputs consumed by later steps.

Affected writes (all in the 'Setup inputs' step):
  - `echo "action=${action}" >> $GITHUB_OUTPUT`  (action sourced from `${{ inputs.action }}`)
  - `echo "branch=${branch}" >> $GITHUB_OUTPUT`  (branch sourced from `${{ inputs.branch }}`)
  - `echo "gh_pages_url=${gh_pages_url}" >> $GITHUB_OUTPUT`  (sourced from `${{ inputs.gh_pages_url }}`)
  - `echo "repository=${repository}" >> $GITHUB_OUTPUT`  (sourced from `${{ inputs.repository }}`)
  - `echo "release_tag=${release_tag}" >> $GITHUB_OUTPUT`  (sourced from `${{ inputs.release_tag }}`)
  - `echo "release_version=${release_version}" >> $GITHUB_OUTPUT`  (derived from release_tag)
  - `echo "source_repository=${source_repository}" >> $GITHUB_OUTPUT`  (sourced from `${{ github.event.repository.name }}`)
  - `echo "plugin_url=${plugin_url}" >> $GITHUB_OUTPUT`  (sourced from `${{ github.event.repository.html_url }}` or `${{ inputs.plugin_url }}`)
  - `echo "zipfile_name=${zipfile_name}" >> $GITHUB_OUTPUT`  (derived from source_repository or `${{ inputs.zipfile }}`)
  - `echo "zipfile_path=${zipfile_path}" >> $GITHUB_OUTPUT`  (sourced from `${{ github.workspace }}` or `${{ inputs.zipfile }}`)

Each write must be preceded by: `safe=$(printf '%s' "$VAR" | tr -d '\n\r')` and then write `$safe`.

Locations:

- `action.yml:96`
- `action.yml:97`
- `action.yml:98`
- `action.yml:99`
- `action.yml:100`
- `action.yml:101`
- `action.yml:103`
- `action.yml:105`
- `action.yml:106`
- `action.yml:107`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable version tags instead of pinned 40-character commit SHA digests. This exposes the action to supply-chain attacks: a compromised upstream action tag can silently deliver malicious code.

Failing references:
  1. `uses: actions/setup-python@v5` — should be pinned to a full SHA, e.g. `actions/setup-python@<sha> # v5`
  2. `uses: actions/checkout@v4` — should be pinned to a full SHA, e.g. `actions/checkout@<sha> # v4`
  3. `uses: actions-js/push@v1.5` — should be pinned to a full SHA, e.g. `actions-js/push@<sha> # v1.5`

Locations:

- `action.yml:110`
- `action.yml:116`
- `action.yml:160`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.action }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:51`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.branch }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:52`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.gh_pages_url }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:53`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.repository }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:54`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.release_tag }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:55`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.zipfile }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:83`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.zipfile }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:89`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.zipfile }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:90`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.plugin-url }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:93`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.plugin_url }}" appears directly in run: block of step "Setup inputs"; move to env: map

Locations:

- `action.yml:96`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, static-inline-injection

**Notes:**

Fixed all findings in action.yml:

1. **script-injection / static-inline-injection**: Moved all `${{ inputs.* }}`, `${{ github.* }}`, and `${{ steps.*.outputs.* }}` expressions out of `run:` blocks into `env:` blocks. Shell scripts now reference double-quoted environment variables (`"$VAR_NAME"`) instead of inline expressions. Applied to 'Setup inputs', 'Install dependencies', and 'JPRM repo' steps.

2. **github-env-injection**: All values written to `$GITHUB_OUTPUT` are now sanitized with `safe_X=$(printf '%s' "$X" | tr -d '\n\r')` before writing, preventing newline injection attacks that could smuggle additional key=value pairs.

3. **unpinned-uses**: Pinned all three action references to full 40-character commit SHAs:
   - `actions/setup-python@v5` → `@a26af69be951a213d495a4c3e4e4022e16d87065 # v5`
   - `actions/checkout@v4` → `@11d5960a326750d5838078e36cf38b85af677262 # v4`
   - `actions-js/push@v1.5` → `@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5`

Note: `${{ github.event.repository }}` (used for the LizardByte org check) was replaced with `${{ github.event.repository.full_name }}` (the correct field for `owner/repo` string). The `with:` blocks for checkout and push actions retain `${{ steps.inputs.outputs.* }}` expressions as these are processed by the Actions engine, not a shell, and are not subject to shell injection.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted variable expansion in the 'Setup inputs' step's case statement. Changed `case $action in` to `case "$action" in` at line 69 of action.yml. The variable `$action` holds a caller-controlled value from `inputs.action`, and quoting it prevents word splitting and glob expansion before the shell processes the case statement.

