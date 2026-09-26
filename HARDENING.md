<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.426.154020

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.426.154020** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple ${{ }} expressions are directly interpolated inside run: shell command strings across three steps, violating rule (a). This allows an attacker to inject arbitrary shell commands via controlled inputs or github context values.

**Step: 'Setup inputs' (lines 47–88):** `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]`, `if [ -z "${{ inputs.zipfile }}" ]`, `zipfile_path=${{ github.workspace }}/...`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `if [ -z "${{ inputs.plugin-url }}" ]`, `plugin_url=${{ github.event.repository.html_url }}/...`, `plugin_url=${{ inputs.plugin_url }}`.

**Step: 'Install dependencies' (lines 109–110):** `${{ steps.setup-python.outputs.python-path }} -m pip install ...` (twice).

**Step: 'JPRM repo' (lines 124–145):** `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.branch }}`, `${{ steps.inputs.outputs.action }}`, `${{ steps.inputs.outputs.gh_pages_url }}`, `${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, `${{ steps.inputs.outputs.release_version }}`. All of these ultimately trace back to attacker-controlled inputs or github context. Fix: move all expressions into env: variables and reference them as quoted shell variables (e.g., "$ACTION").

Locations:

- `action.yml:47`
- `action.yml:48`
- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:63`
- `action.yml:65`
- `action.yml:75`
- `action.yml:79`
- `action.yml:81`
- `action.yml:82`
- `action.yml:85`
- `action.yml:86`
- `action.yml:88`
- `action.yml:109`
- `action.yml:110`
- `action.yml:124`
- `action.yml:127`
- `action.yml:131`
- `action.yml:133`
- `action.yml:135`
- `action.yml:136`
- `action.yml:137`
- `action.yml:138`
- `action.yml:141`
- `action.yml:144`
- `action.yml:145`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs and github context directly to $GITHUB_OUTPUT without the required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`). An attacker can inject newlines into any of these values to smuggle additional key=value pairs into GITHUB_OUTPUT, potentially overwriting outputs consumed by later steps.

Affected writes (lines 91–100):
- `echo "action=${action}" >> $GITHUB_OUTPUT` — `action` was set from `${{ inputs.action }}`
- `echo "branch=${branch}" >> $GITHUB_OUTPUT` — `branch` was set from `${{ inputs.branch }}`
- `echo "gh_pages_url=${gh_pages_url}" >> $GITHUB_OUTPUT` — set from `${{ inputs.gh_pages_url }}`
- `echo "repository=${repository}" >> $GITHUB_OUTPUT` — set from `${{ inputs.repository }}`
- `echo "release_tag=${release_tag}" >> $GITHUB_OUTPUT` — set from `${{ inputs.release_tag }}`
- `echo "release_version=${release_version}" >> $GITHUB_OUTPUT` — derived from `release_tag`
- `echo "source_repository=${source_repository}" >> $GITHUB_OUTPUT` — set from `${{ github.event.repository.name }}`
- `echo "plugin_url=${plugin_url}" >> $GITHUB_OUTPUT` — derived from `${{ github.event.repository.html_url }}` or `${{ inputs.plugin_url }}`
- `echo "zipfile_name=${zipfile_name}" >> $GITHUB_OUTPUT` — derived from `${{ inputs.zipfile }}`
- `echo "zipfile_path=${zipfile_path}" >> $GITHUB_OUTPUT` — derived from `${{ inputs.zipfile }}` or `${{ github.workspace }}`

Fix: sanitize each variable before writing, e.g. `safe=$(printf '%s' "$action" | tr -d '\n\r'); echo "action=${safe}" >> $GITHUB_OUTPUT`.

Locations:

- `action.yml:91`
- `action.yml:92`
- `action.yml:93`
- `action.yml:94`
- `action.yml:95`
- `action.yml:96`
- `action.yml:98`
- `action.yml:100`
- `action.yml:101`
- `action.yml:102`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable version tags instead of pinned 40-character commit SHA digests. This exposes the action to supply-chain attacks: if any of these upstream actions is compromised or the tag is moved, malicious code could be silently injected into every workflow that calls this action.

Failing references:
- `uses: actions/setup-python@v5` (line 104) — tag `v5` is mutable
- `uses: actions/checkout@v4` (line 116) — tag `v4` is mutable
- `uses: actions-js/push@v1.5` (line 148) — tag `v1.5` is mutable

Fix: pin each to its full 40-character commit SHA, e.g. `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `action.yml:104`
- `action.yml:116`
- `action.yml:148`

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

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses

**Notes:**

Fixed all findings in action.yml:

1. **script-injection / static-inline-injection**: Moved all ${{ }} expressions from run: shell strings into env: blocks. The 'Setup inputs' step now declares INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, INPUT_PLUGIN_DASH_URL, GITHUB_REPO_NAME, GITHUB_REPO_FULL, GITHUB_REPO_HTML_URL, and GITHUB_WORKSPACE_PATH as env vars. The 'Install dependencies' step uses PYTHON_PATH env var. The 'JPRM repo' step uses PYTHON_PATH, STEP_BRANCH, STEP_ACTION, STEP_GH_PAGES_URL, STEP_PLUGIN_URL, STEP_ZIPFILE_PATH, STEP_PLUGIN_NAME, and STEP_RELEASE_VERSION env vars. All shell references use quoted "$VAR" form.

2. **github-env-injection**: All values written to $GITHUB_OUTPUT are sanitized with `printf '%s' "$var" | tr -d '\n\r'` before writing. Each variable has a safe_* version that strips newlines and carriage returns.

3. **unpinned-uses**: Pinned all three actions to full 40-character commit SHAs:
   - actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: ${{ }} expressions in with: blocks (not run: blocks) are left as-is since they are action input parameters, not shell strings, and are not subject to shell injection.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted variable expansion in the 'Setup inputs' step of action.yml. Changed `case $action in` to `case "$action" in` on line 71. The variable `$action` holds the value of `inputs.action` (a workflow-controllable input) via the env var `INPUT_ACTION`, and must be double-quoted to prevent script injection.

