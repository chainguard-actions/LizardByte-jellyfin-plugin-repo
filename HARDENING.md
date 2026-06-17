<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2026.417.125702

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **LizardByte--jellyfin-plugin-repo/v2026.417.125702** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

The 'Setup inputs' step writes multiple values derived from user-controlled inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.plugin_url, inputs.repository, inputs.release_tag, inputs.zipfile) and github context (github.event.repository.name, github.event.repository.html_url) to $GITHUB_OUTPUT without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker-controlled newline in any of these values can inject arbitrary key=value pairs into GITHUB_OUTPUT, potentially overwriting outputs consumed by later steps. The block `{ echo "action=${INPUTS_ACTION}"; echo "branch=${INPUTS_BRANCH}"; ... } >> "${GITHUB_OUTPUT}"` is the unsanitized write.

Locations:

- `action.yml:64`

### script-injection (severity: high)

Rule (a): The 'Install dependencies' step directly interpolates `${{ steps.setup-python.outputs.python-path }}` and `${{ github.action_path }}` inside a `run:` shell command. Any `${{ ... }}` expression inside a run block is a script-injection risk because YAML template substitution occurs before the shell sees the value. Offending lines: `working-directory: ${{ github.action_path }}` and `${{ steps.setup-python.outputs.python-path }} -m pip install ...`.

Locations:

- `action.yml:120`
- `action.yml:122`
- `action.yml:123`

### script-injection (severity: high)

Rule (a): The 'JPRM repo' step directly interpolates numerous `${{ steps.inputs.outputs.* }}` expressions inside a `run:` shell command. These outputs are derived from user-controlled inputs (action, branch, gh_pages_url, plugin_url, zipfile_path, plugin_name, release_version) and are substituted by the YAML template engine before the shell parses them, enabling command injection. Offending lines include: `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.branch }}`, `if [ "${{ steps.inputs.outputs.action }}" == "add" ]`, `--url ${{ steps.inputs.outputs.gh_pages_url }}`, `--plugin-url ${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, `${{ steps.inputs.outputs.release_version }}`.

Locations:

- `action.yml:135`
- `action.yml:137`
- `action.yml:141`
- `action.yml:144`
- `action.yml:148`
- `action.yml:149`
- `action.yml:150`
- `action.yml:151`
- `action.yml:153`
- `action.yml:157`
- `action.yml:158`
- `action.yml:159`

### script-injection (severity: high)

Rule (b): The 'Setup inputs' step uses unquoted shell variable expansions of untrusted data inside the `run:` block. Variables holding user-controlled input values are expanded without double-quoting, allowing shell metacharacter injection. Offending lines include: `case ${INPUTS_ACTION} in` (unquoted), `plugin_name=$(echo ${SOURCE_REPOSITORY_NAME}} | ...)` (unquoted), `plugin_name=$(echo ${SOURCE_REPOSITORY_NAME} | ...)` (unquoted), `release_version=$(echo ${INPUTS_RELEASE_TAG} | ...)` (unquoted), `repository_name=$(echo ${SOURCE_REPOSITORY_NAME} | ...)` (unquoted), `zipfile_name=$(basename ${INPUTS_ZIPFILE})` (unquoted).

Locations:

- `action.yml:66`
- `action.yml:77`
- `action.yml:79`
- `action.yml:82`
- `action.yml:86`
- `action.yml:89`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, script-injection

**Notes:**

Fixed all four findings in action.yml:

1. github-env-injection: All values written to $GITHUB_OUTPUT are now sanitized using `printf '%s' "${VAR}" | tr -d '\n\r'` before being echoed. Each output variable is stored in a `safe_*` variable first.

2. script-injection (Install dependencies): Removed `working-directory: ${{ github.action_path }}` and replaced with `cd "${ACTION_PATH}"` in the run block. Both `github.action_path` and `steps.setup-python.outputs.python-path` moved to the `env:` block.

3. script-injection (JPRM repo): All `${{ steps.setup-python.outputs.python-path }}` and `${{ steps.inputs.outputs.* }}` expressions moved to the `env:` block as named variables (PYTHON_PATH, JPRM_ACTION, JPRM_BRANCH, JPRM_GH_PAGES_URL, JPRM_PLUGIN_URL, JPRM_ZIPFILE_PATH, JPRM_PLUGIN_NAME, JPRM_RELEASE_VERSION). Run block uses properly double-quoted shell variables.

4. script-injection (Setup inputs - unquoted variables): All shell variable expansions are now properly double-quoted throughout the Setup inputs run block (case statement, echo pipes, basename call, etc.). Also fixed the typo `${SOURCE_REPOSITORY_NAME}}` (extra `}`) in the original.

