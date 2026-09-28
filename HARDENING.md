<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.426.154020

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.426.154020** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Setup inputs' run block directly interpolates ${{ inputs.* }} and ${{ github.* }} expressions into shell commands (sub-rule a), enabling script injection. Examples: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `source_repository=${{ github.event.repository.name }}`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `plugin_url=${{ github.event.repository.html_url }}/...`. These values are also used unquoted as shell variables (sub-rule b), e.g. `case $action in`. The 'Install dependencies' step uses `${{ steps.setup-python.outputs.python-path }}` directly in a run block. The 'JPRM repo' step uses `${{ steps.setup-python.outputs.python-path }}` and `${{ steps.inputs.outputs.* }}` directly in a run block, all without quoting.

Locations:

- `action.yml:47`
- `action.yml:48`
- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:67`
- `action.yml:68`
- `action.yml:79`
- `action.yml:83`
- `action.yml:84`
- `action.yml:88`
- `action.yml:89`
- `action.yml:101`
- `action.yml:102`
- `action.yml:113`
- `action.yml:114`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs (${{ inputs.action }}, ${{ inputs.branch }}, ${{ inputs.gh_pages_url }}, ${{ inputs.repository }}, ${{ inputs.release_tag }}, ${{ github.event.repository.name }}, ${{ inputs.zipfile }}, ${{ inputs.plugin_url }}, ${{ github.event.repository.html_url }}) to $GITHUB_OUTPUT via shell variables (e.g. `echo "action=${action}" >> $GITHUB_OUTPUT`) without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker-controlled newline in any of these values can inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:95`
- `action.yml:96`
- `action.yml:97`
- `action.yml:98`
- `action.yml:99`
- `action.yml:100`
- `action.yml:102`
- `action.yml:104`
- `action.yml:105`
- `action.yml:106`

### unpinned-uses (severity: high)

Three 'uses:' references in action.yml use mutable version tags instead of full 40-character commit SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved: (1) `actions/setup-python@v5`, (2) `actions/checkout@v4`, (3) `actions-js/push@v1.5`.

Locations:

- `action.yml:110`
- `action.yml:118`
- `action.yml:152`

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

1. script-injection / static-inline-injection: Moved all ${{ inputs.* }} and ${{ github.* }} expressions from run: blocks into env: blocks for the 'Setup inputs', 'Install dependencies', and 'JPRM repo' steps. Shell variables now use proper double-quoting throughout.

2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$var" | tr -d '\n\r'` before being echoed, preventing newline injection attacks.

3. unpinned-uses: Pinned all three actions to full 40-character commit SHAs:
   - actions/setup-python@v5 → @a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@v4 → @11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@v1.5 → @5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Also fixed: the original `${{ github.event.repository }}` (whole object) used in a regex check was replaced with `${{ github.event.repository.full_name }}` (the owner/repo string) which is what the ^LizardByte/ regex was designed to match.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted `$action` variable in the `case` statement on line 68 of action.yml. Changed `case $action in` to `case "$action" in` to prevent shell metacharacter interpretation (glob expansion, word splitting) before the pattern match occurs. The variable was already safely assigned from `$INPUT_ACTION` (which is set via the env block from `inputs.action`), but the unquoted use in the case statement was the specific finding.

