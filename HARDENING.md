<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.426.154020

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **LizardByte--jellyfin-plugin-repo/v2025.426.154020** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable tags instead of full 40-character SHA commit hashes, making the action vulnerable to supply-chain attacks if the referenced tag is moved:
- `actions/setup-python@v5` (line ~97)
- `actions/checkout@v4` (line ~109)
- `actions-js/push@v1.5` (line ~155)
All should be pinned to a full SHA digest, e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `action.yml:97`
- `action.yml:109`
- `action.yml:155`

### script-injection (severity: high)

Multiple `${{ ... }}` expressions are directly interpolated inside `run:` shell command strings in action.yml, violating sub-rule (a). This allows an attacker to inject arbitrary shell commands via attacker-controlled inputs or github context values before the shell ever sees the string.

Affected expressions in the 'Setup inputs' run block:
- `action=${{ inputs.action }}` — attacker-controlled input directly assigned in shell
- `branch=${{ inputs.branch }}` — attacker-controlled input directly assigned in shell
- `gh_pages_url=${{ inputs.gh_pages_url }}` — attacker-controlled input directly assigned in shell
- `repository=${{ inputs.repository }}` — attacker-controlled input directly assigned in shell
- `release_tag=${{ inputs.release_tag }}` — attacker-controlled input directly assigned in shell
- `source_repository=${{ github.event.repository.name }}` — github context directly in shell
- `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]` — github context directly in shell
- `zipfile_path=${{ github.workspace }}/${repository_name}.zip` — github context directly in shell
- `zipfile_name=$(basename ${{ inputs.zipfile }})` — attacker-controlled input directly in shell
- `zipfile_path=${{ inputs.zipfile }}` — attacker-controlled input directly in shell
- `plugin_url=${{ github.event.repository.html_url }}/releases/download/...` — github context directly in shell
- `plugin_url=${{ inputs.plugin_url }}` — attacker-controlled input directly in shell

Affected expressions in the 'Install dependencies' run block:
- `${{ steps.setup-python.outputs.python-path }} -m pip install ...` — step output directly in shell

Affected expressions in the 'JPRM repo' run block:
- `${{ steps.setup-python.outputs.python-path }}` — step output directly in shell
- `if [ "${{ steps.inputs.outputs.action }}" == "add" ]` — step output directly in shell
- `--url ${{ steps.inputs.outputs.gh_pages_url }}` — step output directly in shell (unquoted)
- `--plugin-url ${{ steps.inputs.outputs.plugin_url }}` — step output directly in shell (unquoted)
- `${{ steps.inputs.outputs.branch }}` — step output directly in shell (unquoted)
- `${{ steps.inputs.outputs.zipfile_path }}` — step output directly in shell (unquoted)
- `${{ steps.inputs.outputs.plugin_name }}` — step output directly in shell (unquoted)
- `${{ steps.inputs.outputs.release_version }}` — step output directly in shell (unquoted)

All `${{ ... }}` expressions must be moved to `env:` blocks and the env vars must be double-quoted in the shell script.

Locations:

- `action.yml:51`
- `action.yml:52`
- `action.yml:53`
- `action.yml:54`
- `action.yml:55`
- `action.yml:63`
- `action.yml:65`
- `action.yml:75`
- `action.yml:77`
- `action.yml:78`
- `action.yml:82`
- `action.yml:84`
- `action.yml:103`
- `action.yml:121`
- `action.yml:128`

### github-env-injection (severity: high)

The 'Setup inputs' run block writes values derived from `inputs.*` and `github.*` context directly to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker can inject newlines into these values to smuggle additional key=value pairs into GITHUB_OUTPUT, potentially overwriting subsequent step outputs or injecting environment variables.

Affected writes (all in the 'Setup inputs' step):
- `echo "action=${action}" >> $GITHUB_OUTPUT` — action is set from `${{ inputs.action }}`
- `echo "branch=${branch}" >> $GITHUB_OUTPUT` — branch is set from `${{ inputs.branch }}`
- `echo "gh_pages_url=${gh_pages_url}" >> $GITHUB_OUTPUT` — set from `${{ inputs.gh_pages_url }}`
- `echo "repository=${repository}" >> $GITHUB_OUTPUT` — set from `${{ inputs.repository }}`
- `echo "release_tag=${release_tag}" >> $GITHUB_OUTPUT` — set from `${{ inputs.release_tag }}`
- `echo "release_version=${release_version}" >> $GITHUB_OUTPUT` — derived from release_tag (inputs)
- `echo "source_repository=${source_repository}" >> $GITHUB_OUTPUT` — set from `${{ github.event.repository.name }}`
- `echo "plugin_url=${plugin_url}" >> $GITHUB_OUTPUT` — derived from github context and inputs
- `echo "zipfile_name=${zipfile_name}" >> $GITHUB_OUTPUT` — derived from github context and inputs
- `echo "zipfile_path=${zipfile_path}" >> $GITHUB_OUTPUT` — derived from github context and inputs

Each write must be preceded by sanitization, e.g.:
`safe=$(printf '%s' "$branch" | tr -d '\n\r')`
`echo "branch=${safe}" >> $GITHUB_OUTPUT`

Locations:

- `action.yml:86`
- `action.yml:87`
- `action.yml:88`
- `action.yml:89`
- `action.yml:90`
- `action.yml:91`
- `action.yml:93`
- `action.yml:95`
- `action.yml:96`
- `action.yml:97`

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

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all findings in action.yml:

1. **unpinned-uses**: Pinned all three actions to full SHA digests:
   - actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
   - actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

2. **script-injection / static-inline-injection**: Moved all ${{ }} expressions from run: blocks into env: blocks. The 'Setup inputs' step now uses env vars (INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, GITHUB_REPO_NAME, GITHUB_REPO_FULL, GITHUB_REPO_HTML_URL, GITHUB_WORKSPACE_PATH). The 'Install dependencies' and 'JPRM repo' steps use PYTHON_PATH and STEP_* env vars. All env vars are double-quoted in shell scripts.

3. **github-env-injection**: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$var" | tr -d '\n\r'` before writing, preventing newline injection. Also added missing plugin_name output that was computed but never written in the original.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted shell variable in the case statement on line 72 of action.yml. Changed `case $action in` to `case "$action" in` to prevent shell metacharacter interpretation from the caller-controlled `inputs.action` value.

