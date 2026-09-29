<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.426.154020

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.426.154020** was hardened automatically. 13 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `run:` blocks in action.yml directly interpolate `${{ ... }}` expressions inside shell command strings, violating sub-rule (a). In the 'Setup inputs' step (line 50), attacker-controlled inputs are interpolated unquoted directly into shell assignments: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `${{ github.event.repository }}` in a regex test, `${{ github.workspace }}`, `${{ inputs.zipfile }}`, `${{ inputs.plugin_url }}`, `${{ github.event.repository.html_url }}`. Additionally, shell variables like `$action` and `$source_repository` are used unquoted in shell constructs (sub-rule b). In the 'Install dependencies' step (line 122), `${{ steps.setup-python.outputs.python-path }}` is interpolated directly into the run script. In the 'JPRM repo' step (line 137), numerous `${{ steps.inputs.outputs.* }}` expressions are interpolated directly into shell commands including as unquoted CLI arguments.

Locations:

- `action.yml:50`
- `action.yml:122`
- `action.yml:137`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs and github context directly to `$GITHUB_OUTPUT` without sanitization. Variables `action`, `branch`, `gh_pages_url`, `repository`, `release_tag`, `release_version`, `source_repository`, `plugin_url`, `zipfile_name`, and `zipfile_path` are all populated from `inputs.*` or `github.*` expressions (e.g. `inputs.action`, `inputs.branch`, `github.event.repository.name`, `github.event.repository.html_url`) and then written via `echo "key=${var}" >> $GITHUB_OUTPUT` without the required `printf '%s' "$VAR" | tr -d '\n\r'` sanitization step. A newline injected into any of these values could allow an attacker to inject arbitrary key-value pairs into the step outputs.

Locations:

- `action.yml:99`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml are pinned to mutable version tags rather than immutable 40-character SHA commit digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the upstream repository is compromised: (1) `uses: actions/setup-python@v5` (line 114), (2) `uses: actions/checkout@v4` (line 127), (3) `uses: actions-js/push@v1.5` (line 162). Each should be pinned to a full SHA, e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `action.yml:114`
- `action.yml:127`
- `action.yml:162`

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

1. **script-injection & static-inline-injection**: Moved all ${{ }} expressions from run: blocks into env: maps. 'Setup inputs' step now uses INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, INPUT_PLUGIN_URL_HYPHEN, GITHUB_REPO_NAME, GITHUB_REPO_FULL_NAME, GITHUB_REPO_HTML_URL, GITHUB_WORKSPACE_PATH env vars. 'Install dependencies' uses PYTHON_PATH. 'JPRM repo' uses PYTHON_PATH, JPRM_ACTION, JPRM_BRANCH, JPRM_GH_PAGES_URL, JPRM_PLUGIN_URL, JPRM_ZIPFILE_PATH, JPRM_PLUGIN_NAME, JPRM_RELEASE_VERSION. All shell variables are now properly double-quoted.

2. **github-env-injection**: All values written to $GITHUB_OUTPUT are sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` before writing. The $GITHUB_OUTPUT reference is also properly quoted.

3. **unpinned-uses**: Pinned all three actions to full commit SHAs:
   - actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

Note: The original `${{ github.event.repository }}` regex check (which tested the whole repository object) was replaced with `${{ github.event.repository.full_name }}` (GITHUB_REPO_FULL_NAME) which correctly provides the 'org/repo' string for the LizardByte/ prefix check.

