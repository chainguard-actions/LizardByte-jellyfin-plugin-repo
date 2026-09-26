<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2026.602.212143

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2026.602.212143** was hardened automatically. 3 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

The 'Setup inputs' step writes multiple values derived from untrusted inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.plugin_url, inputs.repository, inputs.release_tag, inputs.zipfile, github.event.repository.full_name, github.event.repository.name, github.event.repository.html_url) to $GITHUB_OUTPUT via `echo "key=${VAR}" >> "${GITHUB_OUTPUT}"` without the required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`). A newline injected into any of these values could allow an attacker to inject arbitrary key=value pairs into GITHUB_OUTPUT, potentially overwriting outputs consumed by later steps.

Locations:

- `action.yml:100`

### script-injection (severity: high)

Sub-rule (a): The 'Install dependencies' step interpolates `${{ steps.setup-python.outputs.python-path }}` directly inside a `run:` shell command string. `steps.*.outputs.*` is a workflow-controllable context; any `${{ ... }}` expression inside a `run:` block is a script-injection risk because the value is substituted by the template engine before the shell ever sees it. Offending lines: `${{ steps.setup-python.outputs.python-path }} -m pip install --upgrade pip setuptools wheel` and `${{ steps.setup-python.outputs.python-path }} -m pip install -r requirements.txt`.

Locations:

- `action.yml:120`
- `action.yml:121`

### script-injection (severity: high)

Sub-rule (a): The 'JPRM repo' step interpolates multiple `${{ steps.inputs.outputs.* }}` and `${{ steps.setup-python.outputs.python-path }}` expressions directly inside a `run:` shell command string. These values originate from `inputs.*` and `github.*` contexts (forwarded through the first step's outputs), making them attacker-controllable. Offending expressions include: `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.branch }}`, `${{ steps.inputs.outputs.action }}`, `${{ steps.inputs.outputs.gh_pages_url }}`, `${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, `${{ steps.inputs.outputs.release_version }}`. An attacker controlling any of these values (e.g. via inputs.branch, inputs.plugin_url, inputs.release_tag, or the repository name) can inject arbitrary shell commands.

Locations:

- `action.yml:128`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, script-injection

**Notes:**

Fixed three findings in action.yml: (1) github-env-injection: Added printf '%s' | tr -d '\n\r' sanitization for all 11 values written to GITHUB_OUTPUT in the 'Setup inputs' step, preventing newline injection attacks. (2) script-injection in 'Install dependencies': Moved ${{ steps.setup-python.outputs.python-path }} into an env var PYTHON_PATH and referenced it as "$PYTHON_PATH" in the shell script. (3) script-injection in 'JPRM repo': Moved all ${{ steps.setup-python.outputs.python-path }} and ${{ steps.inputs.outputs.* }} expressions into env vars (PYTHON_PATH, JPRM_ACTION, JPRM_BRANCH, JPRM_GH_PAGES_URL, JPRM_PLUGIN_URL, JPRM_ZIPFILE_PATH, JPRM_PLUGIN_NAME, JPRM_RELEASE_VERSION) and referenced them as quoted shell variables in the run script.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed 5 unquoted variable expansions in the 'Setup inputs' run block of action.yml:
1. `echo ${SOURCE_REPOSITORY_NAME} | sed 's/-jellyfin$//'` → `echo "${SOURCE_REPOSITORY_NAME}" | sed ...`
2. `echo ${SOURCE_REPOSITORY_NAME} | tr '[:upper:]' '[:lower:]'` (else branch) → `echo "${SOURCE_REPOSITORY_NAME}" | tr ...`
3. `echo ${INPUTS_RELEASE_TAG} | sed 's/^v//'` → `echo "${INPUTS_RELEASE_TAG}" | sed ...`
4. `echo ${SOURCE_REPOSITORY_NAME} | tr '[:upper:]' '[:lower:]'` (zipfile branch) → `echo "${SOURCE_REPOSITORY_NAME}" | tr ...`
5. `basename ${INPUTS_ZIPFILE}` → `basename "${INPUTS_ZIPFILE}"`

All variables were already loaded from the env block (not inline ${{ }} expressions), but the unquoted expansions allowed word splitting and glob expansion from attacker-controlled values. Double-quoting prevents shell metacharacters from being interpreted.

### Iteration 3

**Fixes applied:** script-injection

**Notes:**

Fixed the unquoted case statement subject in the 'Setup inputs' step of action.yml. Changed `case ${INPUTS_ACTION} in` to `case "${INPUTS_ACTION}" in` at line 63. While bash's case statement doesn't perform word-splitting on the subject, it does perform glob expansion on unquoted values, and the security rules require all env vars holding workflow-controllable data to be double-quoted inside run: scripts.

