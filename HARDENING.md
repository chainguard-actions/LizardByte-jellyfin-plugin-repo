<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.612.131900

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.612.131900** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ ... }} expressions are interpolated directly inside run: shell command strings in the 'Setup inputs' step. Attacker-controlled inputs such as `${{ inputs.action }}`, `${{ inputs.branch }}`, `${{ inputs.gh_pages_url }}`, `${{ inputs.repository }}`, `${{ inputs.release_tag }}`, `${{ inputs.zipfile }}`, `${{ inputs.plugin_url }}`, `${{ github.event.repository.name }}`, `${{ github.event.repository }}`, `${{ github.workspace }}`, and `${{ github.event.repository.html_url }}` are substituted into the shell script before the shell parses it, enabling arbitrary command injection. Similarly, the 'Install dependencies' step interpolates `${{ steps.setup-python.outputs.python-path }}` directly as a command, and the 'JPRM repo' step interpolates multiple `${{ steps.inputs.outputs.* }}` values as unquoted shell arguments.

Locations:

- `action.yml:48`
- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:68`
- `action.yml:70`
- `action.yml:80`
- `action.yml:84`
- `action.yml:86`
- `action.yml:87`
- `action.yml:90`
- `action.yml:91`
- `action.yml:93`
- `action.yml:113`
- `action.yml:114`
- `action.yml:122`
- `action.yml:125`
- `action.yml:128`
- `action.yml:130`
- `action.yml:131`
- `action.yml:132`
- `action.yml:133`
- `action.yml:135`
- `action.yml:137`
- `action.yml:138`
- `action.yml:139`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs directly to $GITHUB_OUTPUT without sanitization. Variables `action`, `branch`, `gh_pages_url`, `repository`, `release_tag`, `release_version`, `source_repository`, `plugin_url`, `zipfile_name`, and `zipfile_path` are all populated from `${{ inputs.* }}` or `${{ github.* }}` expressions and then echoed to $GITHUB_OUTPUT (e.g. `echo "action=${action}" >> $GITHUB_OUTPUT`). No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before any of these writes, allowing a newline-injection attack to smuggle arbitrary key=value pairs into the output file.

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

Three `uses:` references in action.yml are pinned to mutable version tags rather than immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if those tags are moved or hijacked: (1) `uses: actions/setup-python@v5`, (2) `uses: actions/checkout@v4`, (3) `uses: actions-js/push@v1.5`.

Locations:

- `action.yml:110`
- `action.yml:118`
- `action.yml:143`

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

1. **script-injection / static-inline-injection**: Moved all ${{ inputs.* }} and ${{ github.* }} expressions from run: shell strings into env: maps. The 'Setup inputs' step now receives all inputs via environment variables (INPUT_ACTION, INPUT_BRANCH, etc.) and references them as $VAR_NAME. The 'Install dependencies' step uses PYTHON_PATH env var instead of inline ${{ steps.setup-python.outputs.python-path }}. The 'JPRM repo' step uses env vars for all step outputs.

2. **github-env-injection**: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$var" | tr -d '\n\r'` before writing, preventing newline injection attacks.

3. **unpinned-uses**: Pinned all three actions to full commit SHAs:
   - actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: The original code used ${{ github.event.repository }} in a regex check but this is the full repository object; replaced with ${{ github.event.repository.full_name }} which gives the 'owner/repo' string needed for the LizardByte/ prefix check. Also added plugin_name to GITHUB_OUTPUT (it was computed but not previously output, yet referenced in the remove branch).

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted shell variable expansion in the 'Setup inputs' step at line 68 of action.yml. Changed `case $action in` to `case "$action" in` to properly double-quote the workflow-controllable variable `$action` (derived from `inputs.action` via the `INPUT_ACTION` env var). While bash's `case` subject does not undergo word splitting, the security rules require all expansions of workflow-controllable data to be double-quoted.

