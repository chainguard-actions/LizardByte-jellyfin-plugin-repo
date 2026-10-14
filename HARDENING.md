<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2026.417.125702

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2026.417.125702** was hardened automatically. 3 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): The 'Install dependencies' run: block directly interpolates `${{ steps.setup-python.outputs.python-path }}` into the shell command string. `steps.*.outputs.*` is a workflow-controllable context that flows through YAML template substitution before the shell sees it, enabling script injection. Example offending line: `${{ steps.setup-python.outputs.python-path }} -m pip install --upgrade pip setuptools wheel`

Locations:

- `action.yml:118`

### script-injection (severity: high)

Rule (a): The 'JPRM repo' run: block directly interpolates multiple `${{ steps.setup-python.outputs.python-path }}` and `${{ steps.inputs.outputs.* }}` expressions (branch, action, gh_pages_url, plugin_url, zipfile_path, plugin_name, release_version) into shell command strings. These `steps.inputs.outputs.*` values are derived from user-controlled `inputs.*` and `github.event.*` values, enabling script injection. Example offending lines: `${{ steps.setup-python.outputs.python-path }} -m jprm repo init ${{ steps.inputs.outputs.branch }}` and `if [ "${{ steps.inputs.outputs.action }}" == "add" ]`

Locations:

- `action.yml:133`

### github-env-injection (severity: high)

The 'Setup inputs' run: block writes multiple values derived from untrusted inputs to $GITHUB_OUTPUT without sanitization (no `printf '%s' ... | tr -d '\n\r'` applied before each write). The env: block maps `inputs.action`, `inputs.branch`, `inputs.gh_pages_url`, `inputs.plugin_url`, `inputs.repository`, `inputs.release_tag`, `inputs.zipfile`, `github.event.repository.name`, and `github.event.repository.html_url` into shell variables, which are then written unsanitized to $GITHUB_OUTPUT via a heredoc block (e.g., `echo "action=${INPUTS_ACTION}"`, `echo "branch=${INPUTS_BRANCH}"`, `echo "plugin_url=${plugin_url}"`, etc.). A newline injected into any of these values could poison subsequent GITHUB_OUTPUT entries.

Locations:

- `action.yml:51`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed three security findings in action.yml:

1. github-env-injection (line 51): Added sanitization for all 10 values written to $GITHUB_OUTPUT. Each value is now processed through `printf '%s' "${VAR}" | tr -d '\n\r'` before being written, preventing newline injection attacks that could poison subsequent GITHUB_OUTPUT entries.

2. script-injection (line 118 - Install dependencies): Moved `${{ steps.setup-python.outputs.python-path }}` out of the run: shell string into an `env:` block as `PYTHON_PATH`, then referenced it as `"$PYTHON_PATH"` in the shell script.

3. script-injection (line 133 - JPRM repo): Moved all `${{ steps.setup-python.outputs.python-path }}` and `${{ steps.inputs.outputs.* }}` expressions (action, branch, gh_pages_url, plugin_url, zipfile_path, plugin_name, release_version) out of the run: shell string into an `env:` block with JPRM_* prefixed names, then referenced them as shell variables in the shell script.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed 6 unquoted variable expansions in the 'Setup inputs' run block of action.yml:
1. Line 68: `case ${INPUTS_ACTION} in` → `case "${INPUTS_ACTION}" in`
2. Line 82: `echo ${SOURCE_REPOSITORY_NAME}}` → `echo "${SOURCE_REPOSITORY_NAME}"` (also removed stray extra `}`)
3. Line 84: `echo ${SOURCE_REPOSITORY_NAME}` → `echo "${SOURCE_REPOSITORY_NAME}"`
4. Line 88: `echo ${INPUTS_RELEASE_TAG}` → `echo "${INPUTS_RELEASE_TAG}"`
5. Line 92: `echo ${SOURCE_REPOSITORY_NAME}` → `echo "${SOURCE_REPOSITORY_NAME}"`
6. Line 96: `basename ${INPUTS_ZIPFILE}` → `basename "${INPUTS_ZIPFILE}"`

All variables holding caller-controlled values (inputs.* and github.*) are now properly double-quoted to prevent shell metacharacter injection.

