<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2024.919.151635

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2024.919.151635** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Setup inputs' run: block directly interpolates multiple ${{ }} expressions into shell commands, violating rule (a). Attacker-controlled values include: ${{ inputs.action }}, ${{ inputs.branch }}, ${{ inputs.gh_pages_url }}, ${{ inputs.repository }}, ${{ inputs.release_tag }}, ${{ inputs.zipfile }}, ${{ inputs.plugin_url }}, ${{ github.event.repository.name }}, ${{ github.event.repository }}, ${{ github.workspace }}, and ${{ github.event.repository.html_url }}. An attacker can inject shell metacharacters (e.g. semicolons, backticks, $(...)) via any of these inputs. The 'Install dependencies' and 'JPRM repo' steps also interpolate ${{ steps.setup-python.outputs.python-path }} and ${{ steps.inputs.outputs.* }} directly in run: blocks. All ${{ ... }} expressions must be moved to env: variables and then double-quoted in the shell script.

Locations:

- `action.yml:48`
- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:62`
- `action.yml:63`
- `action.yml:75`
- `action.yml:78`
- `action.yml:79`
- `action.yml:83`
- `action.yml:85`
- `action.yml:100`
- `action.yml:101`
- `action.yml:113`
- `action.yml:121`
- `action.yml:124`
- `action.yml:127`
- `action.yml:128`
- `action.yml:129`
- `action.yml:133`
- `action.yml:135`
- `action.yml:136`

### github-env-injection (severity: high)

The 'Setup inputs' run: block writes values derived from untrusted inputs (${{ inputs.action }}, ${{ inputs.branch }}, ${{ inputs.gh_pages_url }}, ${{ inputs.repository }}, ${{ inputs.release_tag }}, ${{ inputs.zipfile }}, ${{ inputs.plugin_url }}) and GitHub context values (${{ github.event.repository.name }}, ${{ github.event.repository.html_url }}, ${{ github.workspace }}) to $GITHUB_OUTPUT via shell variables (action, branch, gh_pages_url, repository, release_tag, release_version, source_repository, plugin_url, zipfile_name, zipfile_path) without the required sanitization step (printf '%s' "$VAR" | tr -d '\n\r'). A newline injected into any of these values can add arbitrary key=value pairs to GITHUB_OUTPUT, poisoning subsequent steps.

Locations:

- `action.yml:88`
- `action.yml:89`
- `action.yml:90`
- `action.yml:91`
- `action.yml:92`
- `action.yml:93`
- `action.yml:95`
- `action.yml:97`
- `action.yml:98`
- `action.yml:99`

### unpinned-uses (severity: high)

Three uses: references in action.yml use mutable version tags instead of immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved: (1) actions/setup-python@v5, (2) actions/checkout@v4, (3) actions-js/push@v1.5. Each should be pinned to a full commit SHA (e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4).

Locations:

- `action.yml:106`
- `action.yml:116`
- `action.yml:141`

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

1. script-injection / static-inline-injection: Moved all ${{ }} expressions from run: blocks into env: blocks. In 'Setup inputs', all inputs (action, branch, gh_pages_url, repository, release_tag, zipfile, plugin_url) and github context values (github.event.repository.name, github.event.repository.full_name, github.event.repository.html_url, github.workspace) are now env vars. In 'Install dependencies' and 'JPRM repo', steps.setup-python.outputs.python-path is now PYTHON_PATH env var, and all steps.inputs.outputs.* values are env vars. All shell references use double-quoted "$VAR" form.

2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` before being echoed, preventing newline injection attacks.

3. unpinned-uses: Pinned all three actions to full commit SHAs:
   - actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: Also added plugin_name to GITHUB_OUTPUT (it was computed but not previously output), which is needed by the 'JPRM repo' step's remove branch.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted variable in the case statement at line 71 of action.yml: changed `case $action in` to `case "$action" in`. The variable `$action` is derived from `$INPUT_ACTION` which holds the workflow-controllable `inputs.action` value, so it must be double-quoted per the script-injection rule.

