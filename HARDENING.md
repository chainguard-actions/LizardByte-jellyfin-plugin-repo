<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.612.131900

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.612.131900** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The 'Setup inputs' run: block (sub-rule a) directly interpolates multiple untrusted ${{ }} expressions into shell commands before the shell ever sees them, enabling arbitrary command injection. Offending lines include: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]`, `zipfile_path=${{ github.workspace }}/...`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `plugin_url=${{ github.event.repository.html_url }}/...`, and `plugin_url=${{ inputs.plugin_url }}`. The 'Install dependencies' step also interpolates `${{ steps.setup-python.outputs.python-path }}` directly into the run: script. The 'JPRM repo' step interpolates `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.* }}` values directly into shell commands.

Locations:

- `action.yml:48`
- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:52`
- `action.yml:64`
- `action.yml:66`
- `action.yml:75`
- `action.yml:78`
- `action.yml:79`
- `action.yml:82`
- `action.yml:84`
- `action.yml:85`
- `action.yml:108`
- `action.yml:109`
- `action.yml:120`
- `action.yml:123`
- `action.yml:127`
- `action.yml:129`
- `action.yml:130`
- `action.yml:131`
- `action.yml:132`
- `action.yml:134`
- `action.yml:138`
- `action.yml:139`
- `action.yml:140`

### github-env-injection (severity: high)

The 'Setup inputs' run: block writes values derived from untrusted inputs (${{ inputs.* }}, ${{ github.* }}) to $GITHUB_OUTPUT without sanitization. Variables such as `action`, `branch`, `gh_pages_url`, `repository`, `release_tag`, `release_version`, `source_repository`, `plugin_url`, `zipfile_name`, and `zipfile_path` are all populated from attacker-controlled expressions and then echoed directly to $GITHUB_OUTPUT (e.g., `echo "action=${action}" >> $GITHUB_OUTPUT`). No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before any of these writes, allowing newline injection to poison the output context.

Locations:

- `action.yml:93`
- `action.yml:94`
- `action.yml:95`
- `action.yml:96`
- `action.yml:97`
- `action.yml:98`
- `action.yml:100`
- `action.yml:102`
- `action.yml:103`
- `action.yml:104`

### unpinned-uses (severity: high)

Three uses: references are pinned to mutable tags rather than immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if the upstream tag is moved or compromised: (1) `actions/setup-python@v5` — should be pinned to a full SHA; (2) `actions/checkout@v4` — should be pinned to a full SHA; (3) `actions-js/push@v1.5` — should be pinned to a full SHA.

Locations:

- `action.yml:106`
- `action.yml:113`
- `action.yml:146`

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

1. script-injection / static-inline-injection: Moved all ${{ inputs.* }} and ${{ github.* }} expressions from run: blocks into env: blocks. The 'Setup inputs' step now uses INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, GITHUB_REPO_NAME, GITHUB_REPO_FULL, GITHUB_REPO_HTML_URL, and GITHUB_WORKSPACE_PATH env vars. The 'Install dependencies' and 'JPRM repo' steps use PYTHON_PATH env var instead of inline ${{ steps.setup-python.outputs.python-path }}. The 'JPRM repo' step uses INPUTS_ACTION, INPUTS_BRANCH, INPUTS_GH_PAGES_URL, INPUTS_PLUGIN_URL, INPUTS_ZIPFILE_PATH, INPUTS_PLUGIN_NAME, and INPUTS_RELEASE_VERSION env vars.

2. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with `printf '%s' "$VAR" | tr -d '\n\r'` before writing, preventing newline injection attacks.

3. unpinned-uses: Pinned all three actions to full commit SHAs:
   - actions/setup-python@v5 → @a26af69be951a213d495a4c3e4e4022e16d87065
   - actions/checkout@v4 → @11d5960a326750d5838078e36cf38b85af677262
   - actions-js/push@v1.5 → @5a7cbd780d82c0c937b5977586e641b2fd94acc5

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted shell variable in the `case` statement at line 68 of action.yml. Changed `case $action in` to `case "$action" in` to prevent word splitting and glob expansion on the caller-controlled `$INPUT_ACTION` value.

