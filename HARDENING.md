<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2026.417.125702

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2026.417.125702** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### github-env-injection (severity: high)

The 'Setup inputs' step writes values derived from untrusted inputs (inputs.action, inputs.branch, inputs.gh_pages_url, inputs.plugin_url, inputs.repository, inputs.release_tag, inputs.zipfile, github.event.repository.name, github.event.repository.html_url) to $GITHUB_OUTPUT using bare `echo "key=${VAR}" >> "${GITHUB_OUTPUT}"` without the required sanitization step (`printf '%s' "$VAR" | tr -d '\n\r'`). An attacker-controlled newline in any of these values can inject arbitrary key=value pairs into GITHUB_OUTPUT, poisoning subsequent steps.

Locations:

- `action.yml:100`

### script-injection (severity: high)

Rule (a): The 'Install dependencies' step directly interpolates `${{ steps.setup-python.outputs.python-path }}` (a steps.*.outputs.* expression) inside a `run:` shell command. Any `${{ ... }}` expression in a run block is subject to template substitution before the shell sees it, enabling script injection. Offending lines: `${{ steps.setup-python.outputs.python-path }} -m pip install --upgrade pip setuptools wheel` and `${{ steps.setup-python.outputs.python-path }} -m pip install -r requirements.txt`.

Locations:

- `action.yml:120`

### script-injection (severity: high)

Rule (a): The 'JPRM repo' step directly interpolates multiple `${{ ... }}` expressions inside a `run:` shell command, including `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.branch }}`, `${{ steps.inputs.outputs.action }}`, `${{ steps.inputs.outputs.gh_pages_url }}`, `${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, and `${{ steps.inputs.outputs.release_version }}`. The steps.inputs.outputs.* values are derived from caller-controlled inputs.* and github.event.* values, making this a direct script injection vector. An attacker can supply a malicious input value containing shell metacharacters that will be executed by the runner shell.

Locations:

- `action.yml:132`

### script-injection (severity: high)

Rule (b): The 'Setup inputs' run block expands multiple shell variables holding untrusted data without double-quoting: `${SOURCE_REPOSITORY_NAME}` (from github.event.repository.name), `${INPUTS_RELEASE_TAG}` (from inputs.release_tag), `${INPUTS_ZIPFILE}` (from inputs.zipfile), `${INPUTS_PLUGIN_URL}` (from inputs.plugin_url), and `${SOURCE_REPOSITORY_URL}` (from github.event.repository.html_url) are all used unquoted in command substitutions and variable assignments. Unquoted expansions allow shell metacharacter injection (word splitting, glob expansion, command injection via backticks or $(...)).

Locations:

- `action.yml:75`

## Iteration Notes

### Iteration 1

**Fixes applied:** github-env-injection, script-injection

**Notes:**

Fixed all four security findings in hardened/action/action.yml:

1. github-env-injection: Replaced bare `echo "key=${VAR}"` writes to GITHUB_OUTPUT with `printf 'key=%s\n' "$(printf '%s' "${VAR}" | tr -d '\n\r')"` for all 10+ output values, preventing newline injection attacks.

2. script-injection (Install dependencies step): Moved `${{ steps.setup-python.outputs.python-path }}` from the run block into an env var `PYTHON_PATH`, referenced as `"$PYTHON_PATH"` in the shell script.

3. script-injection (JPRM repo step): Moved all 8 `${{ ... }}` expressions (python-path, action, branch, gh_pages_url, plugin_url, zipfile_path, plugin_name, release_version) from the run block into env vars, referenced as properly double-quoted shell variables.

4. script-injection (Setup inputs step): Added double-quotes around all unquoted variable expansions (`${SOURCE_REPOSITORY_NAME}`, `${INPUTS_RELEASE_TAG}`, `${INPUTS_ZIPFILE}`, `${INPUTS_PLUGIN_URL}`, `${SOURCE_REPOSITORY_URL}`, etc.) to prevent word splitting and glob expansion. Also fixed a typo `${SOURCE_REPOSITORY_NAME}}` (extra `}`) in the original.

