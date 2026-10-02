<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.612.131900

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.612.131900** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ ... }} expressions are directly interpolated inside run: shell command strings in action.yml. In the 'Setup inputs' step, attacker-controlled inputs such as ${{ inputs.action }}, ${{ inputs.branch }}, ${{ inputs.gh_pages_url }}, ${{ inputs.repository }}, ${{ inputs.release_tag }}, ${{ inputs.zipfile }}, ${{ inputs.plugin_url }}, and github context values ${{ github.event.repository.name }}, ${{ github.event.repository }}, ${{ github.workspace }}, ${{ github.event.repository.html_url }} are all interpolated directly into shell commands before the shell ever sees them, enabling command injection. The 'Install dependencies' step interpolates ${{ steps.setup-python.outputs.python-path }} as the executable path. The 'JPRM repo' step interpolates multiple ${{ steps.inputs.outputs.* }} values (which themselves derive from untrusted inputs) directly into shell commands without quoting.

Locations:

- `action.yml:48`
- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:60`
- `action.yml:62`
- `action.yml:72`
- `action.yml:76`
- `action.yml:78`
- `action.yml:80`
- `action.yml:83`
- `action.yml:96`
- `action.yml:97`
- `action.yml:107`
- `action.yml:116`
- `action.yml:121`
- `action.yml:126`

### github-env-injection (severity: high)

The 'Setup inputs' step assigns untrusted values from ${{ inputs.* }} and ${{ github.* }} contexts to shell variables (action, branch, gh_pages_url, repository, release_tag, release_version, source_repository, plugin_url, zipfile_name, zipfile_path) and then writes them directly to $GITHUB_OUTPUT using echo "key=${var}" >> $GITHUB_OUTPUT without the required sanitization step (printf '%s' "$VAR" | tr -d '\n\r'). An attacker-controlled newline in any of these values can inject arbitrary key=value pairs into GITHUB_OUTPUT, poisoning subsequent steps.

Locations:

- `action.yml:100`
- `action.yml:101`
- `action.yml:102`
- `action.yml:103`
- `action.yml:104`
- `action.yml:105`
- `action.yml:107`
- `action.yml:109`
- `action.yml:110`
- `action.yml:111`

### unpinned-uses (severity: high)

Three uses: references in action.yml are pinned to mutable version tags rather than immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved or compromised: (1) actions/setup-python@v5, (2) actions/checkout@v4, (3) actions-js/push@v1.5. All should be pinned to full SHA digests (e.g. uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4).

Locations:

- `action.yml:113`
- `action.yml:131`
- `action.yml:155`

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

Rewrote action.yml to fix all findings:

1. script-injection / static-inline-injection: Moved all ${{ }} expressions out of run: shell strings into env: blocks for the 'Setup inputs', 'Install dependencies', and 'JPRM repo' steps. Shell scripts now reference plain environment variables ($VAR_NAME) instead of inline expressions.

2. github-env-injection: Added sanitization for all values written to $GITHUB_OUTPUT using `printf '%s' "$VAR" | tr -d '\n\r'` to strip attacker-controlled newlines before writing key=value pairs.

3. unpinned-uses: Pinned all three actions to full commit SHAs:
   - actions/setup-python@v5 → @a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@v4 → @11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@v1.5 → @5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: ${{ }} expressions in with: blocks (action inputs, not shell commands) are intentionally left as-is since they are not subject to shell injection.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed unquoted variable expansion in the 'Setup inputs' step's case statement. Changed `case $action in` to `case "$action" in` at line 68 of action.yml. This prevents word splitting and glob expansion on the untrusted `inputs.action` value before it is matched against the case patterns.

