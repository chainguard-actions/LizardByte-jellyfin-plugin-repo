<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.612.131900

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **LizardByte--jellyfin-plugin-repo/v2025.612.131900** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ ... }} expressions are interpolated directly inside run: shell command strings in action.yml. In the 'Setup inputs' step, attacker-controlled inputs are expanded inline: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `${{ github.event.repository }}`, `${{ inputs.zipfile }}`, `zipfile_path=${{ github.workspace }}/...`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `${{ inputs.plugin-url }}`, `plugin_url=${{ github.event.repository.html_url }}/...`, `plugin_url=${{ inputs.plugin_url }}`. In the 'Install dependencies' step: `${{ steps.setup-python.outputs.python-path }}` is used directly in run:. In the 'JPRM repo' step: `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.branch }}`, `${{ steps.inputs.outputs.action }}`, `${{ steps.inputs.outputs.gh_pages_url }}`, `${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, `${{ steps.inputs.outputs.release_version }}` are all interpolated directly into shell commands. Any of these values can contain shell metacharacters that will be interpreted by the shell before quoting takes effect.

Locations:

- `action.yml:52`
- `action.yml:53`
- `action.yml:54`
- `action.yml:55`
- `action.yml:56`
- `action.yml:63`
- `action.yml:65`
- `action.yml:75`
- `action.yml:78`
- `action.yml:79`
- `action.yml:82`
- `action.yml:84`
- `action.yml:107`
- `action.yml:116`
- `action.yml:122`
- `action.yml:127`
- `action.yml:130`
- `action.yml:133`
- `action.yml:136`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.repository, inputs.release_tag, inputs.zipfile, inputs.plugin_url, github.event.repository.name, github.event.repository.html_url, github.workspace) to $GITHUB_OUTPUT via intermediate shell variables (action, branch, gh_pages_url, repository, release_tag, release_version, source_repository, plugin_url, zipfile_name, zipfile_path) without applying the required sanitization step (`printf '%s' ... | tr -d '\n\r'`) before each write. An attacker can inject newlines into these values to poison subsequent steps that read from $GITHUB_OUTPUT.

Locations:

- `action.yml:89`
- `action.yml:90`
- `action.yml:91`
- `action.yml:92`
- `action.yml:93`
- `action.yml:94`
- `action.yml:96`
- `action.yml:98`
- `action.yml:99`
- `action.yml:100`

### unpinned-uses (severity: high)

Three uses: references in action.yml use mutable version tags instead of pinned 40-character SHA commit digests, making the action vulnerable to supply-chain attacks if those tags are moved: (1) `actions/setup-python@v5`, (2) `actions/checkout@v4`, (3) `actions-js/push@v1.5`. Each should be replaced with a full SHA, e.g. `actions/setup-python@<40-char-sha> # v5`.

Locations:

- `action.yml:104`
- `action.yml:112`
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

Rewrote action.yml to fix all findings:

1. script-injection / static-inline-injection: Moved all ${{ }} expressions from run: shell strings into env: blocks for the 'Setup inputs', 'Install dependencies', and 'JPRM repo' steps. All shell references now use double-quoted "$VAR" form to prevent shell metacharacter interpretation.

2. github-env-injection: Added sanitization of all values before writing to $GITHUB_OUTPUT using `printf '%s' "$var" | tr -d '\n\r'` to strip newlines that could inject additional key=value pairs.

3. unpinned-uses: Pinned all three action references to full 40-character SHA digests:
   - actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
   - actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: The original code used `${{ github.event.repository }}` in a regex check (checking if it starts with 'LizardByte/'). This was changed to use `${{ github.event.repository.full_name }}` which is the correct field for the full repository name (owner/repo format), mapped to EVENT_REPO_FULL_NAME env var. Also added plugin_name to GITHUB_OUTPUT since it was referenced in the JPRM repo step but was missing from the original outputs.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted `$action` variable in the `case` statement at line 68 of action.yml. Changed `case $action in` to `case "$action" in` to ensure the untrusted caller-controlled value (derived from `inputs.action` via `INPUT_ACTION` env var) is always double-quoted when expanded in the shell script.

