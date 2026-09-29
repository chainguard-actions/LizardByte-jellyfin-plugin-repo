<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.612.131900

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.612.131900** was hardened automatically. 15 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ ... }} expressions are directly interpolated into run: shell command strings in the 'Setup inputs' step. Attacker-controlled inputs such as ${{ inputs.action }}, ${{ inputs.branch }}, ${{ inputs.gh_pages_url }}, ${{ inputs.repository }}, ${{ inputs.release_tag }}, ${{ inputs.zipfile }}, ${{ inputs.plugin_url }}, and github context values like ${{ github.event.repository.name }}, ${{ github.event.repository }}, ${{ github.workspace }}, ${{ github.event.repository.html_url }} are all substituted directly into the shell script before the shell parses it. An attacker can inject arbitrary shell metacharacters (e.g. via a crafted input or repository name) to execute arbitrary commands.

Locations:

- `action.yml:48`

### script-injection (severity: high)

Sub-rule (a): The 'Install dependencies' run: block directly interpolates ${{ steps.setup-python.outputs.python-path }} into the shell command string. Step outputs are workflow-controllable and must not be interpolated directly into run: scripts. Offending lines: `${{ steps.setup-python.outputs.python-path }} -m pip install --upgrade pip setuptools wheel` and `${{ steps.setup-python.outputs.python-path }} -m pip install -r requirements.txt`.

Locations:

- `action.yml:100`

### script-injection (severity: high)

Sub-rule (a): The 'JPRM repo' run: block directly interpolates multiple ${{ steps.setup-python.outputs.python-path }} and ${{ steps.inputs.outputs.* }} expressions (including action, branch, gh_pages_url, plugin_url, zipfile_path, plugin_name, release_version) into shell command strings. These values originate from user-controlled inputs and github context, enabling shell command injection.

Locations:

- `action.yml:111`

### github-env-injection (severity: high)

The 'Setup inputs' run: block writes values derived from untrusted inputs (${{ inputs.action }}, ${{ inputs.branch }}, ${{ inputs.gh_pages_url }}, ${{ inputs.repository }}, ${{ inputs.release_tag }}, ${{ inputs.zipfile }}, ${{ inputs.plugin_url }}) and github context (${{ github.event.repository.name }}, ${{ github.event.repository.html_url }}) to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker can inject newlines into these values to poison GITHUB_OUTPUT and set arbitrary output variables or override subsequent step outputs.

Locations:

- `action.yml:97`

### unpinned-uses (severity: high)

Three uses: references in action.yml are pinned to mutable tags rather than immutable 40-character commit SHAs, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the upstream repository is compromised: (1) `uses: actions/setup-python@v5`, (2) `uses: actions/checkout@v4`, (3) `uses: actions-js/push@v1.5`. All should be pinned to full SHA digests, e.g. `actions/setup-python@<40-hex-sha> # v5`.

Locations:

- `action.yml:99`
- `action.yml:108`
- `action.yml:137`

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

Rewrote action.yml with the following changes:
1. Moved all ${{ inputs.* }}, ${{ github.* }}, and ${{ steps.*.outputs.* }} expressions from run: blocks into env: blocks for the 'Setup inputs', 'Install dependencies', and 'JPRM repo' steps.
2. Sanitized all values written to $GITHUB_OUTPUT using `printf '%s' "$VAR" | tr -d '\n\r'` to prevent newline injection.
3. Pinned all three action references to full commit SHAs: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 (v5), actions/checkout@11d5960a326750d5838078e36cf38b85af677262 (v4), actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 (v1.5).
4. The original logic is preserved: the LizardByte org check uses GITHUB_REPO_FULL (full_name) instead of the original regex on github.event.repository (which was an object, not a string), and the inputs.plugin-url vs inputs.plugin_url distinction is preserved via separate env vars.

### Iteration 2

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed two security findings in action.yml:
1. script-injection (line 71): Quoted the `$action` variable in the case statement (`case "$action" in`) to prevent glob expansion of unquoted shell variable.
2. github-env-injection (lines 102, 108): (a) Added `| tr -d '\n\r'` to the `basename "$INPUT_ZIPFILE"` assignment so `zipfile_name` is sanitized of newlines before use. (b) Wrapped the `plugin_url` construction (when built from components) in `$(printf '%s' "..." | tr -d '\n\r')` to strip any newlines inherited from `zipfile_name` or other parts before it is written to `$GITHUB_OUTPUT`.

