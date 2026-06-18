<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2026.602.212143

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **LizardByte--jellyfin-plugin-repo/v2026.602.212143** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): The 'Install dependencies' step directly interpolates ${{ steps.setup-python.outputs.python-path }} inside the run: shell command. The steps.*.outputs.* context is workflow-controllable and flows through YAML template substitution before the shell processes it, enabling command injection.

Locations:

- `action.yml:121`
- `action.yml:122`

### script-injection (severity: high)

Rule (a): The 'JPRM repo' step directly interpolates multiple ${{ }} expressions inside the run: shell command, including ${{ steps.setup-python.outputs.python-path }}, ${{ steps.inputs.outputs.branch }}, ${{ steps.inputs.outputs.action }}, ${{ steps.inputs.outputs.gh_pages_url }}, ${{ steps.inputs.outputs.plugin_url }}, ${{ steps.inputs.outputs.zipfile_path }}, ${{ steps.inputs.outputs.plugin_name }}, and ${{ steps.inputs.outputs.release_version }}. These are derived from user-controlled inputs.* and github.* contexts and are interpolated directly into shell commands, enabling command injection.

Locations:

- `action.yml:135`
- `action.yml:138`
- `action.yml:141`
- `action.yml:144`
- `action.yml:145`
- `action.yml:147`
- `action.yml:148`
- `action.yml:152`
- `action.yml:153`
- `action.yml:154`

### script-injection (severity: high)

Rule (b): The 'Setup inputs' step expands untrusted env vars without double-quoting in multiple shell commands: `case ${INPUTS_ACTION} in` (unquoted), `echo ${SOURCE_REPOSITORY_NAME}` (unquoted, used in command substitution), `echo ${INPUTS_RELEASE_TAG}` (unquoted), `basename ${INPUTS_ZIPFILE}` (unquoted). These env vars hold values from inputs.* and github.* contexts. Unquoted expansions allow shell metacharacters (spaces, globs, semicolons) to be interpreted by the shell.

Locations:

- `action.yml:66`
- `action.yml:75`
- `action.yml:76`
- `action.yml:79`
- `action.yml:83`
- `action.yml:87`

### github-env-injection (severity: high)

The 'Setup inputs' step writes multiple values derived from untrusted inputs.* and github.* contexts to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). The following values are written unsanitized: action (from inputs.action), branch (from inputs.branch), gh_pages_url (from inputs.gh_pages_url), plugin_name (derived from github.event.repository.name), plugin_url (derived from inputs.plugin_url and github.event.repository.html_url), repository (from inputs.repository), release_tag (from inputs.release_tag), release_version (derived from inputs.release_tag), source_repository (from github.event.repository.name), zipfile_name and zipfile_path (derived from inputs.zipfile and github.event.repository.name). A newline in any of these values could inject arbitrary key=value pairs into GITHUB_OUTPUT, poisoning subsequent steps.

Locations:

- `action.yml:100`
- `action.yml:101`
- `action.yml:102`
- `action.yml:103`
- `action.yml:104`
- `action.yml:105`
- `action.yml:106`
- `action.yml:107`
- `action.yml:108`
- `action.yml:109`
- `action.yml:110`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all four security findings in action.yml:

1. script-injection (Install dependencies): Moved `${{ steps.setup-python.outputs.python-path }}` into an `env:` block as `PYTHON_PATH` and referenced it as `"$PYTHON_PATH"` in the shell script.

2. script-injection (JPRM repo): Moved all `${{ steps.setup-python.outputs.python-path }}` and `${{ steps.inputs.outputs.* }}` expressions into an `env:` block with named variables (`PYTHON_PATH`, `JPRM_ACTION`, `JPRM_BRANCH`, `JPRM_GH_PAGES_URL`, `JPRM_PLUGIN_URL`, `JPRM_ZIPFILE_PATH`, `JPRM_PLUGIN_NAME`, `JPRM_RELEASE_VERSION`) and referenced them as properly double-quoted `"$VAR"` in the shell script.

3. script-injection (Setup inputs): Added double-quotes around all unquoted env var expansions in the shell script (case statement, echo commands, basename call).

4. github-env-injection (Setup inputs): Replaced all `echo "key=value"` writes to `$GITHUB_OUTPUT` with `printf 'key=%s\n' "$(printf '%s' "${VAR}" | tr -d '\n\r')"` to sanitize newlines and carriage returns before writing, preventing newline injection attacks.

