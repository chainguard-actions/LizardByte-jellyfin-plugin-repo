<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.612.131900

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.612.131900** was hardened automatically. 15 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Setup inputs' run: block directly interpolates ${{ inputs.action }}, ${{ inputs.branch }}, ${{ inputs.gh_pages_url }}, ${{ inputs.repository }}, ${{ inputs.release_tag }}, ${{ github.event.repository.name }}, ${{ github.event.repository }}, ${{ inputs.zipfile }}, ${{ github.workspace }}, ${{ inputs.plugin-url }}, ${{ github.event.repository.html_url }}, and ${{ inputs.plugin_url }} directly into shell commands. Any of these values can contain shell metacharacters (`;`, `|`, `&`, `$(...)`, etc.) that will be interpreted by the shell before quoting takes effect, enabling command injection.

Locations:

- `action.yml:52`

### script-injection (severity: high)

Sub-rule (a): The 'Install dependencies' run: block directly interpolates ${{ steps.setup-python.outputs.python-path }} into shell commands. The steps.*.outputs.* context is a workflow-controllable value and must not be interpolated directly into run: scripts.

Locations:

- `action.yml:109`

### script-injection (severity: high)

Sub-rule (a): The 'JPRM repo' run: block directly interpolates ${{ steps.setup-python.outputs.python-path }}, ${{ steps.inputs.outputs.branch }}, ${{ steps.inputs.outputs.action }}, ${{ steps.inputs.outputs.gh_pages_url }}, ${{ steps.inputs.outputs.plugin_url }}, ${{ steps.inputs.outputs.zipfile_path }}, ${{ steps.inputs.outputs.plugin_name }}, and ${{ steps.inputs.outputs.release_version }} into shell commands. These values originate from user-controlled inputs and github context, enabling command injection.

Locations:

- `action.yml:123`

### github-env-injection (severity: high)

The 'Setup inputs' run: block writes values derived from untrusted inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.repository, inputs.release_tag) and github context (github.event.repository.name, github.event.repository.html_url, github.workspace) to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker-controlled newline in any of these values can inject arbitrary key=value pairs into GITHUB_OUTPUT, poisoning subsequent steps.

Locations:

- `action.yml:91`

### unpinned-uses (severity: high)

Three uses: references in action.yml use mutable tags instead of immutable full-length SHA commit hashes, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the repository is compromised: (1) actions/setup-python@v5 (line 103), (2) actions/checkout@v4 (line 113), (3) actions-js/push@v1.5 (line 148). Each should be pinned to a full 40-character hex SHA.

Locations:

- `action.yml:103`
- `action.yml:113`
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

1. script-injection / static-inline-injection: Moved all ${{ }} expressions from run: blocks to env: blocks in 'Setup inputs', 'Install dependencies', and 'JPRM repo' steps. Shell scripts now reference plain environment variables ($INPUT_ACTION, $PYTHON_PATH, $STEP_BRANCH, etc.).

2. github-env-injection: All values written to $GITHUB_OUTPUT in 'Setup inputs' are now sanitized with `printf '%s' "$var" | tr -d '\n\r'` before writing, preventing newline injection.

3. unpinned-uses: Pinned all three action references to full 40-character commit SHAs:
   - actions/setup-python@v5 → @a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@v4 → @11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@v1.5 → @5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: The original ${{ github.event.repository }} used in the regex check was replaced with ${{ github.event.repository.full_name }} (env var GITHUB_REPO_FULL) since the full_name property gives the 'owner/repo' string that the ^LizardByte/ regex was checking against. The plugin_name output was also added to GITHUB_OUTPUT (it was computed but not previously output).

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted variable expansion in the case statement at line 72 of action.yml. Changed `case $action in` to `case "$action" in` to properly double-quote the workflow-controllable variable `$action`, preventing word splitting and glob expansion.

