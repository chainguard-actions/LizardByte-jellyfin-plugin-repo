<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.612.131900

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.612.131900** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `run:` blocks in action.yml directly interpolate GitHub Actions expressions (`${{ ... }}`) inside shell command strings, violating rule (a). In the 'Setup inputs' step: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]`, `zipfile_path=${{ github.workspace }}/...`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `plugin_url=${{ github.event.repository.html_url }}/...`, and `plugin_url=${{ inputs.plugin_url }}` are all interpolated directly into the shell. In the 'Install dependencies' step: `${{ steps.setup-python.outputs.python-path }}` is interpolated directly. In the 'JPRM repo' step: `${{ steps.setup-python.outputs.python-path }}` and multiple `${{ steps.inputs.outputs.* }}` values are interpolated directly into shell commands. All `${{ ... }}` expressions inside `run:` blocks are script-injection risks regardless of context.

Locations:

- `action.yml:52`
- `action.yml:53`
- `action.yml:54`
- `action.yml:55`
- `action.yml:56`
- `action.yml:64`
- `action.yml:66`
- `action.yml:75`
- `action.yml:79`
- `action.yml:81`
- `action.yml:84`
- `action.yml:86`
- `action.yml:100`
- `action.yml:107`
- `action.yml:116`
- `action.yml:122`
- `action.yml:125`
- `action.yml:127`
- `action.yml:129`
- `action.yml:131`
- `action.yml:137`
- `action.yml:140`
- `action.yml:143`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted `inputs.*` and `github.*` context directly to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). Variables written include: `action` (from `inputs.action`), `branch` (from `inputs.branch`), `gh_pages_url` (from `inputs.gh_pages_url`), `repository` (from `inputs.repository`), `release_tag` (from `inputs.release_tag`), `release_version` (derived from `inputs.release_tag`), `source_repository` (from `github.event.repository.name`), `plugin_url` (from `github.event.repository.html_url` or `inputs.plugin_url`), `zipfile_name` (derived from `github.event.repository.name` or `inputs.zipfile`), and `zipfile_path` (from `github.workspace` or `inputs.zipfile`). None of these writes are preceded by the required sanitization pipeline.

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

Three `uses:` references in action.yml are pinned to mutable version tags instead of immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if those tags are moved: (1) `actions/setup-python@v5`, (2) `actions/checkout@v4`, (3) `actions-js/push@v1.5`. These should be replaced with their corresponding full commit SHAs.

Locations:

- `action.yml:105`
- `action.yml:111`
- `action.yml:145`

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
1. script-injection / static-inline-injection: Moved all ${{ inputs.* }}, ${{ github.* }}, and ${{ steps.*.outputs.* }} expressions from run: blocks into env: maps. Shell scripts now reference environment variables ($INPUT_ACTION, $PYTHON_PATH, etc.) instead of inline expressions.
2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` before writing, preventing newline injection attacks.
3. unpinned-uses: Pinned all three actions to full commit SHAs: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 (v5), actions/checkout@11d5960a326750d5838078e36cf38b85af677262 (v4), actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 (v1.5). The with: blocks for checkout and push actions retain ${{ }} expressions as those are action inputs (not shell-executed) and are safe.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed unquoted variable expansion in the 'Setup inputs' step's case statement. Changed `case $action in` to `case "$action" in` at line 63 of action.yml. This prevents glob-pattern metacharacters (e.g., `*`, `?`, `[...]`) in the caller-controlled `inputs.action` value from being interpreted by the shell during the case statement evaluation.

