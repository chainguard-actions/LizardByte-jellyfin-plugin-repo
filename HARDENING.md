<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2026.602.212143

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2026.602.212143** was hardened automatically. 3 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.plugin_url, inputs.repository, inputs.release_tag, inputs.zipfile) and GitHub context values (github.event.repository.name, github.event.repository.html_url) to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker-controlled input containing newline characters could inject arbitrary key=value pairs into GITHUB_OUTPUT, potentially overwriting subsequent step outputs.

Locations:

- `action.yml:51`

### script-injection (severity: high)

Sub-rule (a): The 'Install dependencies' run: block directly interpolates ${{ steps.setup-python.outputs.python-path }} as the shell interpreter path. Step outputs are workflow-controllable contexts and must not be interpolated directly into run: scripts. The expression is substituted by the Actions runner before the shell parses the command, allowing injection of arbitrary shell metacharacters.

Locations:

- `action.yml:121`

### script-injection (severity: high)

Sub-rule (a): The 'JPRM repo' run: block directly interpolates multiple ${{ steps.inputs.outputs.* }} expressions (branch, action, gh_pages_url, plugin_url, zipfile_path, plugin_name, release_version, python-path) into shell commands. These step outputs are derived from attacker-controllable inputs.* and github.* values. Direct interpolation allows an attacker to inject shell metacharacters (e.g. via inputs.branch, inputs.plugin_url, inputs.zipfile) to achieve arbitrary command execution.

Locations:

- `action.yml:134`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, script-injection

**Notes:**

Fixed three security findings in action.yml: (1) github-env-injection: sanitized all 11 values written to $GITHUB_OUTPUT in the 'Setup inputs' step using `printf '%s' ... | tr -d '\n\r'` to strip newlines before writing; (2) script-injection in 'Install dependencies': moved `${{ steps.setup-python.outputs.python-path }}` into an env block as PYTHON_PATH and referenced it as "$PYTHON_PATH" in the shell; (3) script-injection in 'JPRM repo': moved all ${{ steps.setup-python.outputs.python-path }} and ${{ steps.inputs.outputs.* }} expressions into an env block (PYTHON_PATH, JPRM_ACTION, JPRM_BRANCH, JPRM_GH_PAGES_URL, JPRM_PLUGIN_URL, JPRM_ZIPFILE_PATH, JPRM_PLUGIN_NAME, JPRM_RELEASE_VERSION) and referenced them as properly double-quoted environment variables in the shell script.

### Iteration 2

**Fixes applied:** script-injection, unpinned-uses

**Notes:**

Fixed script-injection in action.yml by adding double quotes around all unquoted variable expansions in the 'Setup inputs' run block: `case "${INPUTS_ACTION}"`, `echo "${SOURCE_REPOSITORY_NAME}"` (3 occurrences), `echo "${INPUTS_RELEASE_TAG}"`, and `basename "${INPUTS_ZIPFILE}"`. Fixed unpinned-uses by resolving LizardByte/.github@master to SHA 4e4aa17193e825a20773bb38157b86186129d579 and pinning all three reusable workflow references in _codeql.yml, _common-lint.yml, and _top-issues.yml.

