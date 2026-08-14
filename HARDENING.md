<!-- markdownlint-disable -->

# Hardening Report: LizardByte--jellyfin-plugin-repo/v2025.426.154020

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **LizardByte--jellyfin-plugin-repo/v2025.426.154020** was hardened automatically. 22 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Setup inputs' run: block in action.yml directly interpolates multiple untrusted ${{ }} expressions into shell commands without routing through env: variables. Offending lines include: `action=${{ inputs.action }}`, `branch=${{ inputs.branch }}`, `gh_pages_url=${{ inputs.gh_pages_url }}`, `repository=${{ inputs.repository }}`, `release_tag=${{ inputs.release_tag }}`, `source_repository=${{ github.event.repository.name }}`, `if [[ "${{ github.event.repository }}" =~ ^LizardByte/ ]]`, `zipfile_path=${{ github.workspace }}/${repository_name}.zip`, `zipfile_name=$(basename ${{ inputs.zipfile }})`, `zipfile_path=${{ inputs.zipfile }}`, `plugin_url=${{ github.event.repository.html_url }}/releases/download/...`, and `plugin_url=${{ inputs.plugin_url }}`. An attacker controlling any of these inputs can inject arbitrary shell commands.

Locations:

- `action.yml:52`

### script-injection (severity: high)

Sub-rule (a): The 'Install dependencies' run: block in action.yml directly interpolates `${{ steps.setup-python.outputs.python-path }}` into the shell command string. Any ${{ }} expression inside a run: block is a script-injection risk regardless of context.

Locations:

- `action.yml:107`

### script-injection (severity: high)

Sub-rule (a): The 'JPRM repo' run: block in action.yml directly interpolates multiple ${{ steps.inputs.outputs.* }} and ${{ steps.setup-python.outputs.python-path }} expressions into shell commands. Offending lines include: `${{ steps.setup-python.outputs.python-path }}`, `${{ steps.inputs.outputs.branch }}`, `if [ "${{ steps.inputs.outputs.action }}" == "add" ]`, `--url ${{ steps.inputs.outputs.gh_pages_url }}`, `--plugin-url ${{ steps.inputs.outputs.plugin_url }}`, `${{ steps.inputs.outputs.zipfile_path }}`, `${{ steps.inputs.outputs.plugin_name }}`, `${{ steps.inputs.outputs.release_version }}`. These values originate from user-controlled inputs and github context.

Locations:

- `action.yml:120`

### script-injection (severity: high)

Sub-rule (a): The 'Prebuild' run: block in .github/workflows/codeql.yml directly interpolates `${{ matrix.language }}` and `${{ runner.os }}` into a shell variable assignment: `filename=".codeql-prebuild-${{ matrix.language }}-${{ runner.os }}.sh"`. Any ${{ }} expression inside a run: block is a script-injection risk.

Locations:

- `.github/workflows/codeql.yml:147`

### script-injection (severity: high)

Sub-rule (a): The 'CMake - cmake-lint' run: block in .github/workflows/common-lint.yml directly interpolates `${{ steps.cmake_files.outputs.found_files }}` into a shell command: `cmake-lint --line-width 120 --tab-size 4 ${{ steps.cmake_files.outputs.found_files }}`. This value is derived from filesystem discovery but flows through a step output, making it a script-injection risk.

Locations:

- `.github/workflows/common-lint.yml:82`

### script-injection (severity: high)

Sub-rule (a): The 'Docker - hadolint' run: block in .github/workflows/common-lint.yml directly interpolates `${{ steps.dokcer_files.outputs.found_files }}` into a shell for-loop: `for file in ${{ steps.dokcer_files.outputs.found_files }}; do`. This value flows through a step output and is unquoted, enabling shell metacharacter injection.

Locations:

- `.github/workflows/common-lint.yml:107`

### github-env-injection (severity: high)

The 'Setup inputs' run: block in action.yml assigns values from untrusted sources (inputs.* and github.*) to shell variables and then writes them to $GITHUB_OUTPUT without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). For example: `action=${{ inputs.action }}` ... `echo "action=${action}" >> $GITHUB_OUTPUT`; `branch=${{ inputs.branch }}` ... `echo "branch=${branch}" >> $GITHUB_OUTPUT`; `source_repository=${{ github.event.repository.name }}` ... `echo "source_repository=${source_repository}" >> $GITHUB_OUTPUT`; and similarly for gh_pages_url, repository, release_tag, release_version, plugin_url, zipfile_name, zipfile_path. A newline injected into any of these values can poison subsequent steps via GITHUB_OUTPUT.

Locations:

- `action.yml:88`

### unpinned-uses (severity: high)

Multiple uses: references in action.yml are pinned to mutable version tags rather than immutable 40-character SHA digests, making the action vulnerable to supply-chain attacks if the referenced tag is moved or the repository is compromised. Failing references: `actions/setup-python@v5`, `actions/checkout@v4`, `actions-js/push@v1.5`.

Locations:

- `action.yml:103`
- `action.yml:113`
- `action.yml:148`

### unpinned-uses (severity: high)

Multiple uses: references in .github/workflows/ci.yml are pinned to mutable version tags rather than immutable SHA digests. Failing references: `actions/checkout@v4`, `LizardByte/setup-release-action@v2025.426.225`, `LizardByte/create-release-action@v2025.426.1549`.

Locations:

- `.github/workflows/ci.yml:26`
- `.github/workflows/ci.yml:31`
- `.github/workflows/ci.yml:37`

### unpinned-uses (severity: high)

Multiple uses: references in .github/workflows/codeql.yml are pinned to mutable version tags rather than immutable SHA digests. Failing references: `actions/checkout@v4`, `actions/github-script@v7` (×2), `easimon/maximize-build-space@v10`, `msys2/setup-msys2@v2`, `github/codeql-action/init@v3`, `github/codeql-action/autobuild@v3`, `github/codeql-action/analyze@v3`, `advanced-security/filter-sarif@v1`, `github/codeql-action/upload-sarif@v3`, `actions/upload-artifact@v4`.

Locations:

- `.github/workflows/codeql.yml:31`
- `.github/workflows/codeql.yml:37`
- `.github/workflows/codeql.yml:96`
- `.github/workflows/codeql.yml:113`
- `.github/workflows/codeql.yml:121`
- `.github/workflows/codeql.yml:127`
- `.github/workflows/codeql.yml:134`
- `.github/workflows/codeql.yml:155`
- `.github/workflows/codeql.yml:158`
- `.github/workflows/codeql.yml:163`
- `.github/workflows/codeql.yml:172`
- `.github/workflows/codeql.yml:179`

### unpinned-uses (severity: high)

Multiple uses: references in .github/workflows/common-lint.yml are pinned to mutable version tags rather than immutable SHA digests. Failing references: `actions/checkout@v4`, `actions/setup-python@v5`, `DoozyX/clang-format-lint-action@v0.20`, `dtolnay/rust-toolchain@stable`, `ibiqlik/action-yamllint@v3`.

Locations:

- `.github/workflows/common-lint.yml:26`
- `.github/workflows/common-lint.yml:30`
- `.github/workflows/common-lint.yml:60`
- `.github/workflows/common-lint.yml:162`
- `.github/workflows/common-lint.yml:181`

### unpinned-uses (severity: high)

The uses: reference in .github/workflows/issues.yml is pinned to a mutable version tag rather than an immutable SHA digest. Failing reference: `dessant/label-actions@v4`.

Locations:

- `.github/workflows/issues.yml:24`

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

Fixed all findings across action.yml, .github/workflows/ci.yml, .github/workflows/codeql.yml, .github/workflows/common-lint.yml, and .github/workflows/issues.yml.

1. action.yml - Setup inputs step: Moved all ${{ inputs.* }} and ${{ github.* }} expressions into env: block (INPUT_ACTION, INPUT_BRANCH, INPUT_GH_PAGES_URL, INPUT_REPOSITORY, INPUT_RELEASE_TAG, INPUT_ZIPFILE, INPUT_PLUGIN_URL, INPUT_PLUGIN_URL_DASH, GITHUB_REPO_NAME, GITHUB_REPO_FULL, GITHUB_REPO_HTML_URL, GITHUB_WORKSPACE_PATH). All GITHUB_OUTPUT writes now sanitize values with `printf '%s' | tr -d '\n\r'`.

2. action.yml - Install dependencies step: Moved ${{ steps.setup-python.outputs.python-path }} into env: PYTHON_PATH.

3. action.yml - JPRM repo step: Moved all ${{ steps.setup-python.outputs.python-path }} and ${{ steps.inputs.outputs.* }} into env: block (PYTHON_PATH, JPRM_BRANCH, JPRM_ACTION, JPRM_GH_PAGES_URL, JPRM_PLUGIN_URL, JPRM_ZIPFILE_PATH, JPRM_PLUGIN_NAME, JPRM_RELEASE_VERSION).

4. action.yml - Pinned actions/setup-python@v5 → SHA a26af69, actions/checkout@v4 → SHA 11d5960, actions-js/push@v1.5 → SHA 5a7cbd7.

5. codeql.yml - Prebuild step: Moved ${{ matrix.language }} and ${{ runner.os }} into env: MATRIX_LANGUAGE and RUNNER_OS_VAL. Pinned all 11 action references to full SHAs.

6. common-lint.yml - CMake cmake-lint step: Moved ${{ steps.cmake_files.outputs.found_files }} into env: CMAKE_FOUND_FILES. Docker hadolint step: Moved ${{ steps.dokcer_files.outputs.found_files }} into env: DOCKER_FOUND_FILES. Pinned all 5 action references to full SHAs.

7. issues.yml - Pinned dessant/label-actions@v4 → SHA 102faf4.

8. ci.yml - Pinned all 3 action references to full SHAs.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed two script-injection findings: (1) In action.yml, quoted the unquoted `$action` variable in the `case` statement: changed `case $action in` to `case "$action" in`. (2) In .github/workflows/common-lint.yml, moved the `${{ steps.yamllint.outputs.logfile }}` expression from the `run:` shell command into an `env:` block as `YAMLLINT_LOGFILE`, then referenced it as `"$YAMLLINT_LOGFILE"` in the shell command.

### Iteration 3

**Fixes applied:** script-injection

**Notes:**

Fixed two script injection findings in .github/workflows/common-lint.yml:
1. CMake - cmake-lint step (line ~100): Replaced unquoted `$CMAKE_FOUND_FILES` expansion with `mapfile -t cmake_files_array <<< "$CMAKE_FOUND_FILES"` followed by `"${cmake_files_array[@]}"` to safely pass file paths as individual quoted arguments.
2. Docker - hadolint step (line ~128): Replaced unquoted `for file in $DOCKER_FOUND_FILES` with `mapfile -t docker_files_array <<< "$DOCKER_FOUND_FILES"` and `for file in "${docker_files_array[@]}"` to safely iterate over file paths without word-splitting or glob expansion.

