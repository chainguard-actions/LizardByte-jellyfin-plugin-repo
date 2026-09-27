<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.426.154020

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.426.154020** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `${{ }}` expressions are interpolated directly inside `run:` shell command strings across three steps, violating rule (a). This allows an attacker to inject arbitrary shell commands via controlled inputs or github context values.

**Step 'Setup inputs'** (lines ~48–90): `${{ inputs.action }}`, `${{ inputs.branch }}`, `${{ inputs.gh_pages_url }}`, `${{ inputs.repository }}`, `${{ inputs.release_tag }}`, `${{ github.event.repository.name }}`, `${{ github.event.repository }}`, `${{ inputs.zipfile }}`, `${{ github.workspace }}`, `${{ inputs.zipfile }}`, `${{ inputs.plugin-url }}`, `${{ github.event.repository.html_url }}`, `${{ inputs.plugin_url }}` are all interpolated directly into shell.

**Step 'Install dependencies'** (lines ~105–108): `${{ steps.setup-python.outputs.python-path }}` is interpolated directly as the shell command prefix.

**Step 'JPRM repo'** (lines ~116–145): `${{ steps.setup-python.outputs.python-path }}` and multiple `${{ steps.inputs.outputs.* }}` values are interpolated directly into shell commands.

All of these should be moved to `env:` variables and referenced as quoted `"$VAR"` shell variables instead.

Locations:

- `action.yml:48`
- `action.yml:105`
- `action.yml:116`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted `inputs.*` and `github.*` context expressions to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). Specifically, variables `action`, `branch`, `gh_pages_url`, `repository`, `release_tag`, `release_version`, `source_repository`, `plugin_url`, `zipfile_name`, and `zipfile_path` — all sourced from attacker-controllable inputs or github context — are echoed directly to `$GITHUB_OUTPUT`. A malicious value containing a newline could inject arbitrary key=value pairs into the output environment, affecting downstream steps.

Locations:

- `action.yml:92`
- `action.yml:93`
- `action.yml:94`
- `action.yml:95`
- `action.yml:96`
- `action.yml:97`
- `action.yml:99`
- `action.yml:101`
- `action.yml:102`
- `action.yml:103`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable tag refs instead of full 40-character commit SHA digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the upstream repository is compromised:
- `uses: actions/setup-python@v5` (should be pinned to a full SHA)
- `uses: actions/checkout@v4` (should be pinned to a full SHA)
- `uses: actions-js/push@v1.5` (should be pinned to a full SHA)

Locations:

- `action.yml:104`
- `action.yml:112`
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

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, static-inline-injection

**Notes:**

Fixed all findings in action.yml:

1. **script-injection / static-inline-injection**: Moved all ${{ }} expressions from run: blocks to env: maps in three steps:
   - 'Setup inputs': 12 expressions (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.repository, inputs.release_tag, inputs.zipfile, inputs.plugin-url, inputs.plugin_url, github.event.repository.name, github.event.repository.full_name, github.event.repository.html_url, github.workspace) moved to env: block
   - 'Install dependencies': steps.setup-python.outputs.python-path moved to env: PYTHON_PATH
   - 'JPRM repo': steps.setup-python.outputs.python-path and all steps.inputs.outputs.* moved to env: block

2. **github-env-injection**: All 10 values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` before being echoed, preventing newline injection attacks.

3. **unpinned-uses**: Pinned all three action references to full commit SHAs:
   - actions/setup-python@v5 → @a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@v4 → @11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@v1.5 → @5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: The original code used inputs.plugin-url (hyphen) for the empty check and inputs.plugin_url (underscore) for the value — this logic was preserved by mapping them to separate env vars (INPUT_PLUGIN_URL and INPUT_PLUGIN_URL_ALT respectively). The ${{ }} expressions in the 'Publish gh-pages' step's with: block were left as-is since those are action inputs, not shell run: commands, and are not subject to shell injection.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted variable in the `case` statement on line 68 of action.yml. Changed `case $action in` to `case "$action" in` to prevent shell metacharacter interpretation of the attacker-controlled `inputs.action` value. The variable was already properly routed through an `env:` block, but the unquoted expansion in the `case` statement still allowed shell parsing of metacharacters.

