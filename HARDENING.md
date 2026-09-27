<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2024.919.151635

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2024.919.151635** was hardened automatically. 13 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ ... }} expressions are directly interpolated inside run: shell command strings in the 'Setup inputs' step. Attacker-controlled values from inputs.* and github.* contexts are expanded by the YAML template engine before the shell ever sees them, enabling command injection. Offending lines include:
- `action=${{ inputs.action }}`
- `branch=${{ inputs.branch }}`
- `gh_pages_url=${{ inputs.gh_pages_url }}`
- `repository=${{ inputs.repository }}`
- `release_tag=${{ inputs.release_tag }}`
- `source_repository=${{ github.event.repository.name }}`
- `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]`
- `if [ -z "${{ inputs.zipfile }}" ]`
- `zipfile_path=${{ github.workspace }}/${repository_name}.zip`
- `zipfile_name=$(basename ${{ inputs.zipfile }})`
- `zipfile_path=${{ inputs.zipfile }}`
- `if [ -z "${{ inputs.plugin-url }}" ]`
- `plugin_url=${{ github.event.repository.html_url }}/releases/download/...`
- `plugin_url=${{ inputs.plugin_url }}`

The 'Install dependencies' step also interpolates `${{ steps.setup-python.outputs.python-path }}` and `${{ github.action_path }}` directly in run:.

The 'JPRM repo' step interpolates `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.action }}`, `${{ steps.inputs.outputs.gh_pages_url }}`, `${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.branch }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, and `${{ steps.inputs.outputs.release_version }}` directly in run:.

All ${{ ... }} expressions must be moved to env: blocks and the shell variables must be double-quoted.

Locations:

- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:53`
- `action.yml:63`
- `action.yml:65`
- `action.yml:73`
- `action.yml:76`
- `action.yml:78`
- `action.yml:79`
- `action.yml:82`
- `action.yml:83`
- `action.yml:85`
- `action.yml:107`
- `action.yml:108`
- `action.yml:120`
- `action.yml:124`
- `action.yml:125`
- `action.yml:128`
- `action.yml:129`
- `action.yml:130`
- `action.yml:131`
- `action.yml:133`
- `action.yml:134`
- `action.yml:135`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.repository, inputs.release_tag, github.event.repository.name, inputs.zipfile, inputs.plugin_url, github.workspace, github.event.repository.html_url) to $GITHUB_OUTPUT without any sanitization. The required sanitization step `printf '%s' "$VAR" | tr -d '\n\r'` is never applied before any of the echo ... >> $GITHUB_OUTPUT writes. A malicious input containing newlines could inject arbitrary key=value pairs into GITHUB_OUTPUT, poisoning subsequent steps. Affected writes:
- `echo "action=${action}" >> $GITHUB_OUTPUT`
- `echo "branch=${branch}" >> $GITHUB_OUTPUT`
- `echo "gh_pages_url=${gh_pages_url}" >> $GITHUB_OUTPUT`
- `echo "repository=${repository}" >> $GITHUB_OUTPUT`
- `echo "release_tag=${release_tag}" >> $GITHUB_OUTPUT`
- `echo "release_version=${release_version}" >> $GITHUB_OUTPUT`
- `echo "source_repository=${source_repository}" >> $GITHUB_OUTPUT`
- `echo "plugin_url=${plugin_url}" >> $GITHUB_OUTPUT`
- `echo "zipfile_name=${zipfile_name}" >> $GITHUB_OUTPUT`
- `echo "zipfile_path=${zipfile_path}" >> $GITHUB_OUTPUT`

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

Three uses: references in action.yml are pinned to mutable version tags instead of immutable 40-character commit SHAs. This exposes the action to supply-chain attacks if any of these upstream actions are compromised or their tags are moved:
- `uses: actions/setup-python@v5` (line 101)
- `uses: actions/checkout@v4` (line 113)
- `uses: actions-js/push@v1.5` (line 139)

Each should be replaced with the full SHA digest of the intended commit, e.g. `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `action.yml:101`
- `action.yml:113`
- `action.yml:139`

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
1. unpinned-uses: Pinned actions/setup-python to SHA a26af69be951a213d495a4c3e4e4022e16d87065 (v5), actions/checkout to SHA 11d5960a326750d5838078e36cf38b85af677262 (v4), and actions-js/push to SHA 5a7cbd780d82c0c937b5977586e641b2fd94acc5 (v1.5).
2. script-injection / static-inline-injection: Moved all ${{ inputs.* }}, ${{ github.* }}, and ${{ steps.*.outputs.* }} expressions out of run: shell strings and into env: blocks. Shell variables are now double-quoted throughout. Affected steps: 'Setup inputs', 'Install dependencies', and 'JPRM repo'.
3. github-env-injection: All GITHUB_OUTPUT writes now sanitize values using `printf '%s' "$VAR" | tr -d '\n\r'` before writing, preventing newline injection attacks that could poison subsequent steps.

