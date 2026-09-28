<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2024.919.151635

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2024.919.151635** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `run:` blocks in action.yml directly interpolate `${{ ... }}` expressions inside shell commands, violating rule (a). In the 'Setup inputs' step, attacker-controlled inputs are interpolated directly: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `${{ github.event.repository }}`, `${{ inputs.zipfile }}`, `zipfile_path=${{ github.workspace }}/...`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `plugin_url=${{ github.event.repository.html_url }}/...`, and `plugin_url=${{ inputs.plugin_url }}`. In the 'Install dependencies' step, `${{ steps.setup-python.outputs.python-path }}` and `${{ github.action_path }}` are interpolated in `run:`. In the 'JPRM repo' step, `${{ steps.setup-python.outputs.python-path }}` and multiple `${{ steps.inputs.outputs.* }}` values are interpolated directly into shell commands. Any of these can allow command injection by a caller supplying malicious input values.

Locations:

- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:53`
- `action.yml:65`
- `action.yml:67`
- `action.yml:76`
- `action.yml:80`
- `action.yml:82`
- `action.yml:83`
- `action.yml:86`
- `action.yml:87`
- `action.yml:89`
- `action.yml:113`
- `action.yml:114`
- `action.yml:128`
- `action.yml:131`
- `action.yml:135`
- `action.yml:136`
- `action.yml:137`
- `action.yml:138`

### github-env-injection (severity: high)

The 'Setup inputs' step in action.yml assigns attacker-controlled `inputs.*` and `github.*` values to shell variables via direct expression interpolation (e.g., `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `plugin_url=${{ github.event.repository.html_url }}/...`, `zipfile_path=${{ inputs.zipfile }}`), then writes those variables to `$GITHUB_OUTPUT` without any sanitization (`printf '%s' ... | tr -d '\n\r'`). For example: `echo "action=${action}" >> $GITHUB_OUTPUT`, `echo "branch=${branch}" >> $GITHUB_OUTPUT`, `echo "plugin_url=${plugin_url}" >> $GITHUB_OUTPUT`, `echo "zipfile_path=${zipfile_path}" >> $GITHUB_OUTPUT`, etc. A malicious caller can inject newlines into these values to poison subsequent steps' environment or outputs.

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

Three `uses:` references in action.yml use mutable version tags instead of full 40-character commit SHA digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the repository is compromised: `actions/setup-python@v5` (line 107), `actions/checkout@v4` (line 118), and `actions-js/push@v1.5` (line 155). Each should be pinned to a full SHA, e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `action.yml:107`
- `action.yml:118`
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

Fixed all security findings in hardened/action/action.yml:

1. script-injection / static-inline-injection: Moved all ${{ }} expressions from run: blocks to env: maps. In 'Setup inputs': INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, GITHUB_WORKSPACE_PATH, GITHUB_REPO_NAME, GITHUB_REPO_FULL_NAME, GITHUB_REPO_HTML_URL. In 'Install dependencies': PYTHON_PATH. In 'JPRM repo': PYTHON_PATH, JPRM_BRANCH, JPRM_ACTION, JPRM_GH_PAGES_URL, JPRM_PLUGIN_URL, JPRM_ZIPFILE_PATH, JPRM_PLUGIN_NAME, JPRM_RELEASE_VERSION. Shell scripts now reference only plain env vars.

2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with 'printf "%s" "$var" | tr -d "\n\r"' before writing, preventing newline injection.

3. unpinned-uses: Pinned all three actions to full commit SHAs: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 (v5), actions/checkout@11d5960a326750d5838078e36cf38b85af677262 (v4), actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 (v1.5).

Note: The 'Publish gh-pages' step's 'with:' block still uses ${{ }} expressions, but those are action input parameters (not run: shell commands), so they are not subject to shell injection.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted shell variable in the case statement on line 68 of action.yml. Changed `case $action in` to `case "$action" in` to properly quote the variable derived from the workflow-controllable input `inputs.action` (via `$INPUT_ACTION` env var).

