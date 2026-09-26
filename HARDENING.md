<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2024.919.151635

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2024.919.151635** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple run: blocks directly interpolate ${{ ... }} expressions into shell commands, enabling script injection. (a) The 'Setup inputs' step interpolates attacker-controlled inputs directly into shell variable assignments: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `${{ github.event.repository }}`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `plugin_url=${{ github.event.repository.html_url }}/...`, `plugin_url=${{ inputs.plugin_url }}`, and `zipfile_path=${{ github.workspace }}/...`. Any of these inputs can contain shell metacharacters that execute arbitrary commands. (b) The 'Install dependencies' step interpolates `${{ steps.setup-python.outputs.python-path }}` directly into the run: script. (c) The 'JPRM repo' step interpolates `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.branch }}`, `${{ steps.inputs.outputs.action }}`, `${{ steps.inputs.outputs.gh_pages_url }}`, `${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, and `${{ steps.inputs.outputs.release_version }}` directly into the run: script.

Locations:

- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:53`
- `action.yml:68`
- `action.yml:70`
- `action.yml:82`
- `action.yml:85`
- `action.yml:86`
- `action.yml:90`
- `action.yml:92`
- `action.yml:118`
- `action.yml:119`
- `action.yml:131`
- `action.yml:134`
- `action.yml:138`
- `action.yml:142`
- `action.yml:144`
- `action.yml:146`
- `action.yml:147`
- `action.yml:151`
- `action.yml:153`
- `action.yml:155`

### github-env-injection (severity: high)

The 'Setup inputs' run: block writes values derived from untrusted inputs and github context (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.repository, inputs.release_tag, inputs.zipfile, inputs.plugin_url, github.event.repository.name, github.event.repository.html_url) to $GITHUB_OUTPUT without the required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`). An attacker can inject newlines into these values to poison subsequent steps that read from $GITHUB_OUTPUT, or to inject arbitrary key=value pairs into the output context.

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

Three uses: references in action.yml use mutable version tags instead of immutable full 40-character SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved: (1) `actions/setup-python@v5` — should be pinned to a full SHA; (2) `actions/checkout@v4` — should be pinned to a full SHA; (3) `actions-js/push@v1.5` — should be pinned to a full SHA.

Locations:

- `action.yml:116`
- `action.yml:124`
- `action.yml:160`

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

Rewrote hardened/action/action.yml with three categories of fixes:

1. script-injection / static-inline-injection: All ${{ ... }} expressions in run: blocks moved to env: maps. 'Setup inputs' step gets an env: block with INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, INPUT_PLUGIN_URL_HYPHEN, EVENT_REPO_NAME, EVENT_REPO_FULL_NAME, EVENT_REPO_HTML_URL, GITHUB_WORKSPACE_PATH. 'Install dependencies' step gets PYTHON_PATH env var. 'JPRM repo' step gets PYTHON_PATH, STEP_BRANCH, STEP_ACTION, STEP_GH_PAGES_URL, STEP_PLUGIN_URL, STEP_ZIPFILE_PATH, STEP_PLUGIN_NAME, STEP_RELEASE_VERSION. Shell scripts reference only plain $VAR_NAME variables.

2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with 'printf \'%s\' "$VAR" | tr -d \'\n\r\'' before writing. Each variable has a safe_* counterpart.

3. unpinned-uses: Pinned actions/setup-python@v5 → @a26af69be951a213d495a4c3e4e4022e16d87065, actions/checkout@v4 → @11d5960a326750d5838078e36cf38b85af677262, actions-js/push@v1.5 → @5a7cbd780d82c0c937b5977586e641b2fd94acc5. Original tags preserved as comments.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the script injection vulnerability in the 'Setup inputs' step of action.yml. Changed `case $action in` to `case "$action" in` on line 68. The unquoted variable expansion allowed shell metacharacters from the user-controlled `inputs.action` input to be parsed before the case match, enabling command injection. Quoting the variable ensures the value is treated as a literal string.

