<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2024.919.151635

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2024.919.151635** was hardened automatically. 13 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple `${{ ... }}` expressions are directly interpolated inside `run:` shell command strings across three steps.

**Setup inputs step (line 49–91):** User-controlled inputs and github context values are interpolated directly into shell:
- `action=${{ inputs.action }}` (line 49)
- `branch=${{ inputs.branch }}` (line 50)
- `gh_pages_url=${{ inputs.gh_pages_url }}` (line 51)
- `repository=${{ inputs.repository }}` (line 52)
- `release_tag=${{ inputs.release_tag }}` (line 53)
- `source_repository=${{ github.event.repository.name }}` (line 66)
- `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]` (line 68)
- `zipfile_path=${{ github.workspace }}/...` (line 82)
- `zipfile_name=$(basename ${{ inputs.zipfile }})` (line 84)
- `zipfile_path=${{ inputs.zipfile }}` (line 85)
- `plugin_url=${{ github.event.repository.html_url }}/...` (line 89)
- `plugin_url=${{ inputs.plugin_url }}` (line 91)

**Install dependencies step (line 113–114):** `${{ steps.setup-python.outputs.python-path }}` is interpolated directly as a shell command.

**JPRM repo step (line 126–146):** Multiple `${{ steps.inputs.outputs.* }}` and `${{ steps.setup-python.outputs.python-path }}` expressions are interpolated directly into shell commands, including as command arguments and in conditional strings.

Locations:

- `action.yml:49`
- `action.yml:113`
- `action.yml:126`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from `inputs.*` and `github.*` context directly to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). The variables `action`, `branch`, `gh_pages_url`, `repository`, `release_tag`, `release_version`, `source_repository`, `plugin_url`, `zipfile_name`, and `zipfile_path` are all assigned from `${{ inputs.* }}` or `${{ github.* }}` expressions earlier in the same script, then written unsanitized to `$GITHUB_OUTPUT` (e.g., `echo "action=${action}" >> $GITHUB_OUTPUT`). An attacker-controlled newline in any of these values could inject arbitrary key=value pairs into the output context.

Locations:

- `action.yml:94`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable tag refs instead of full 40-character commit SHA digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the upstream repository is compromised:
- `uses: actions/setup-python@v5` (line 108) — should be pinned to a full SHA
- `uses: actions/checkout@v4` (line 118) — should be pinned to a full SHA
- `uses: actions-js/push@v1.5` (line 148) — should be pinned to a full SHA

Locations:

- `action.yml:108`
- `action.yml:118`
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

Rewrote action.yml to fix all findings:

1. script-injection / static-inline-injection: Moved all ${{ }} expressions from run: blocks to env: blocks for all three affected steps (Setup inputs, Install dependencies, JPRM repo). Shell scripts now reference plain environment variables.

2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` before being echoed, preventing newline injection attacks.

3. unpinned-uses: Pinned all three action references to full 40-character commit SHAs:
   - actions/setup-python@v5 → @a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@v4 → @11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@v1.5 → @5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: ${{ }} expressions in with: blocks (action inputs, not shell) are not subject to shell injection and were left as-is.

