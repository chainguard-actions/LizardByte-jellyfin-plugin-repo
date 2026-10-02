<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.426.154020

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.426.154020** was hardened automatically. 13 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Setup inputs' run block directly interpolates ${{ inputs.* }} and ${{ github.* }} expressions into shell commands without routing through env vars. This allows an attacker to inject arbitrary shell commands. Offending lines include:
- `action=${{ inputs.action }}` (rule a)
- `branch=${{ inputs.branch }}` (rule a)
- `gh_pages_url=${{ inputs.gh_pages_url }}` (rule a)
- `repository=${{ inputs.repository }}` (rule a)
- `release_tag=${{ inputs.release_tag }}` (rule a)
- `source_repository=${{ github.event.repository.name }}` (rule a)
- `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]` (rule a)
- `zipfile_path=${{ github.workspace }}/${repository_name}.zip` (rule a)
- `zipfile_name=$(basename ${{ inputs.zipfile }})` (rule a)
- `zipfile_path=${{ inputs.zipfile }}` (rule a)
- `plugin_url=${{ github.event.repository.html_url }}/releases/download/...` (rule a)
- `plugin_url=${{ inputs.plugin_url }}` (rule a)
The 'Install dependencies' step also interpolates `${{ steps.setup-python.outputs.python-path }}` directly in the run block. The 'JPRM repo' step interpolates multiple `${{ steps.inputs.outputs.* }}` values directly into shell commands.

Locations:

- `action.yml:52`
- `action.yml:53`
- `action.yml:54`
- `action.yml:55`
- `action.yml:56`
- `action.yml:71`
- `action.yml:73`
- `action.yml:84`
- `action.yml:87`
- `action.yml:88`
- `action.yml:92`
- `action.yml:95`
- `action.yml:113`
- `action.yml:131`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs directly to $GITHUB_OUTPUT without sanitization (no `printf '%s' ... | tr -d '\n\r'` step). Variables such as `action`, `branch`, `gh_pages_url`, `repository`, `release_tag`, `release_version`, `source_repository`, `plugin_url`, `zipfile_name`, and `zipfile_path` are all derived from `${{ inputs.* }}` or `${{ github.* }}` expressions and written unsanitized to $GITHUB_OUTPUT. A newline injection in any of these values could allow an attacker to inject arbitrary key=value pairs into the output context.

Locations:

- `action.yml:99`
- `action.yml:100`
- `action.yml:101`
- `action.yml:102`
- `action.yml:103`
- `action.yml:104`
- `action.yml:106`
- `action.yml:108`
- `action.yml:109`
- `action.yml:110`

### unpinned-uses (severity: high)

Three `uses:` references in action.yml use mutable version tags instead of pinned full-length SHA digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the upstream repository is compromised:
- `actions/setup-python@v5` (should be pinned to a 40-char SHA)
- `actions/checkout@v4` (should be pinned to a 40-char SHA)
- `actions-js/push@v1.5` (should be pinned to a 40-char SHA)

Locations:

- `action.yml:117`
- `action.yml:123`
- `action.yml:163`

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

1. script-injection / static-inline-injection: Moved all ${{ inputs.* }} and ${{ github.* }} expressions from run: blocks into env: maps. The 'Setup inputs' step now uses INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, GITHUB_REPO_NAME, GITHUB_REPO_FULL_NAME, GITHUB_REPO_HTML_URL, GITHUB_WORKSPACE_PATH env vars. The 'Install dependencies' step uses PYTHON_PATH. The 'JPRM repo' step uses PYTHON_PATH, JPRM_ACTION, JPRM_BRANCH, JPRM_GH_PAGES_URL, JPRM_PLUGIN_URL, JPRM_ZIPFILE_PATH, JPRM_PLUGIN_NAME, JPRM_RELEASE_VERSION.

2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$var" | tr -d '\n\r'` before being echoed, preventing newline injection attacks.

3. unpinned-uses: Pinned all three action references to full 40-char SHAs:
   - actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
   - actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
   - actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 # v1.5

