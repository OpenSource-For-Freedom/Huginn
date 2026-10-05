# MITRE CVE requests — form answers (cveform.mitre.org → "Report Vulnerability/Request CVE ID")

Prepared 2026-10-03; versions rechecked against the latest releases on 2026-10-05. Tim submits each form himself. The CVE ID is assigned by MITRE (CNA of last resort);
NVD scores and indexes the record after it is published to the CVE List. NVD does not take submissions.

**Existing-CVE check (2026-10-03):** none found for any finding below.
- Huginn's scan-time OSV and GitHub Advisory lookups returned no match.
- A web search found nothing.
- NVD and cve.org could not be queried from the analyst environment. Search https://www.cve.org for the
  package name before each submission.

Fields common to every form:
- **Request type:** Report Vulnerability/Request CVE ID
- **Discoverer:** Tim Burns
- **Attack type:** Remote unless stated otherwise
- **References:** use the package page below. MITRE reserves the ID and publishes the record once a public
  reference exists (your advisory, a write-up, or the vendor's fix).

Already handled: **agento-core** (submitted 2026-10-01; awaiting the ID). **filterbymodel**: answers are in
`filterbymodel.md` (now v1.0.0 through 1.3.5; config and controllers unchanged in 1.3.5).

---

## 1. archilence-ubuntu-connector (PyPI)

- **Vulnerability type:** Missing Authentication for Critical Function (CWE-306)
- **Vendor / product:** Archilence / archilence-ubuntu-connector
- **Versions:** 1.0.0 through 2.7.0 (all releases; the inbound tool server is still unauthenticated in 2.7.0, whose api_key is only sent on outbound calls)
- **Vendor confirmed:** No (no-details contact request to hello@archilence.com; no reply)
- **Impact:** Information Disclosure; Code Execution (when `control.allow_exec` is enabled); Denial of Service
  (when `control.enabled`)
- **Affected component:** `archilence_connector/tool_server.py` (all routes), `archilence_connector/main.py`
  (binds 0.0.0.0:8990)
- **Attack vector:** A network attacker sends HTTP requests to the connector's tool server, which binds all
  interfaces and authenticates no inbound request.
- **Suggested description:**
  > archilence-ubuntu-connector 1.0.0 through 2.7.0 exposes a Flask tool server on 0.0.0.0:8990 without
  > authentication. A remote unauthenticated attacker can read host process, container (including
  > environment variables), port, network and systemd journal information. When control features are
  > enabled, the attacker can restart systemd units and restart or stop Docker containers. When
  > control.allow_exec is enabled, the attacker can execute arbitrary shell commands through
  > /tools/exec_command.
- **CVSS 4.0:**
  - default configuration: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (8.7 High);
  - with allow_exec: `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.2 Critical).
- **Reference:** https://pypi.org/project/archilence-ubuntu-connector/

## 2. layrz-sdk (PyPI)

- **Vulnerability type:** OS Command Injection (CWE-78); Insertion of Sensitive Information into Log File
  (CWE-532)
- **Vendor / product:** Golden M / layrz-sdk
- **Versions:** 4.7.0 through 4.10.0 (latest; still affected)
- **Vendor confirmed:** No
- **Impact:** Code Execution; Information Disclosure (password logged)
- **Affected component:** `layrz_sdk/entities/report/report.py`, `Report._export_xlsx()` (called from
  `Report.export()`)
- **Attack vector:** An application that passes a user-chosen report password or report name to
  `Report.export()` with `msoffice_crypt_path` set lets that user inject shell syntax, because the values are
  interpolated into a command string run with `shell=True`.
- **Suggested description:**
  > In layrz-sdk 4.7.0 through 4.10.0, Report._export_xlsx() in layrz_sdk/entities/report/report.py builds
  > an msoffice-crypt command line by interpolating the export password and report filename into a string
  > executed with subprocess.call(shell=True), allowing OS command injection by anyone who controls either
  > value. The full command, including the plaintext password, is also written to the debug log.
- **CVSS 4.0:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (9.2 Critical)
- **Reference:** https://pypi.org/project/layrz-sdk/

## 3. nontainer (PyPI) — fixed upstream

- **Vulnerability type:** Deserialization of Untrusted Data (CWE-502)
- **Vendor / product:** Adam Ashenfelter / nontainer
- **Versions:** 0.1.2 through 0.8.2; fixed in 0.8.3 (the `dir` backend was removed)
- **Vendor confirmed:** Yes (maintainer replied 2026-09-30 and removed the backend in 0.8.3)
- **Attack type:** Local (code running inside the sandbox)
- **Impact:** Code Execution; Escalation of Privileges (sandbox / microVM escape)
- **Affected component:** `nontainer/providers/dir.py` (`_FileKV`, `DirProvider`); `executor_dud.py`
  (workspace push and harvest)
- **Attack vector:** Code running in a nontainer session that uses the `dir` backend, including inside the
  DudExecutor microVM, rewrites the agent-visible `.nontainer/kv.pkl`. The host process unpickles it the
  next time the session is opened.
- **Suggested description:**
  > In nontainer 0.1.2 through 0.8.2, the dir storage backend keeps its key-value cache as a pickle file
  > (.nontainer/kv.pkl) inside the agent-visible workspace and unpickles it on the host whenever a session is
  > opened. Code executing in the sandbox, including inside the DudExecutor microVM whose changes are synced
  > back to the host, can replace this file and obtain arbitrary code execution in the host process. Fixed in
  > 0.8.3 by removing the dir backend.
- **CVSS 4.0:** `CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (7.3 High)
- **Reference:** https://pypi.org/project/nontainer/0.8.3/ (fixed release; public, so the CVE can publish now)

## 4. pipulate (PyPI)

- **Vulnerability type:** Missing Authentication for Critical Function (CWE-306); OS Command Injection
  (CWE-78)
- **Vendor / product:** Mike Levin / pipulate
- **Versions:** 1.2.0 through 2.78 (latest; checked 2026-10-05)
- **Vendor confirmed:** No
- **Attack type:** Remote (adjacent network)
- **Impact:** Code Execution
- **Affected component:** `server.py` (uvicorn bound to 0.0.0.0:5001; `POST /mcp-tool-executor`),
  `tools/system_tools.py` (`execute_shell_command`)
- **Attack vector:** An attacker who can reach port 5001 sends an unauthenticated POST to
  /mcp-tool-executor naming the registered shell tool. The command runs through
  asyncio.create_subprocess_shell.
- **Suggested description:**
  > pipulate 1.2.0 through 2.78 starts its web server on 0.0.0.0:5001 with no authentication. The
  > /mcp-tool-executor endpoint dispatches to a tool registry that by default includes
  > execute_shell_command, which runs the supplied command with asyncio.create_subprocess_shell. A remote
  > attacker on the same network can execute arbitrary OS commands as the user running pipulate.
- **CVSS 4.0:** `CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (8.7 High)
- **Reference:** https://pypi.org/project/pipulate/

## 5. polyglav (PyPI)

- **Vulnerability type:** OS Command Injection (CWE-78); Incomplete List of Disallowed Inputs (CWE-184)
- **Vendor / product:** Evgenij Myasnikov / polyglav (bundled plugin polyglav-core-exec)
- **Versions:** 0.37.0 through 0.42.0 (latest, checked 2026-10-05; 0.42.0 added newline/heredoc rejection but still prefix-matches and runs with shell=True)
- **Vendor confirmed:** No
- **Impact:** Code Execution
- **Affected component:** `plugins/polyglav-core-exec/src/plugin.py` (`run_command`, `_command_allowed`)
- **Attack vector:** Content processed by the agent (for example a web page) steers the model to run a
  command that begins with an allow-listed prefix but contains shell substitution or redirection. The
  allow-list check splits only on command separators and matches string prefixes, and the command then runs
  with shell=True.
- **Suggested description:**
  > In polyglav 0.37.0 through 0.42.0, the bash_allow command allow-list in the bundled polyglav-core-exec
  > plugin (_command_allowed in plugin.py) checks only that each separator-delimited segment starts with an
  > allowed prefix, then runs the command with subprocess.run(shell=True). Command substitution,
  > redirection and prefix extension are not rejected, so when tool_permission.bash is set to allow with a
  > bash_allow list, attacker-influenced model output can execute arbitrary commands.
- **CVSS 4.0:** `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (7.7 High)
- **Reference:** https://pypi.org/project/polyglav/

## 6. ResolveSpec (Go module github.com/bitechdev/ResolveSpec)

- **Vulnerability type:** SQL Injection (CWE-89)
- **Vendor / product:** bitechdev / ResolveSpec (`pkg/funcspec`)
- **Versions:** v0.0.63 through v1.3.3 (latest tag; ValidSQL and the ORDER BY path unchanged, checked 2026-10-05)
- **Vendor confirmed:** No (asked for a private channel via PR #24; no details sent)
- **Impact:** Information Disclosure
- **Affected component:** `pkg/funcspec/function_api.go` (`Handler.SqlQueryList`); `ValidSQL` "select"
  mode
- **Attack vector:** A client of an application route built on funcspec SqlQueryList supplies the `sort`
  query parameter or `x-sort` header. The value is appended to the query's ORDER BY clause after only a
  keyword denylist.
- **Suggested description:**
  > In ResolveSpec v0.0.63 through v1.3.3, funcspec Handler.SqlQueryList appends the client-supplied sort
  > value (sort query parameter or x-sort header) to the SQL ORDER BY clause after filtering it only with a
  > keyword denylist (ValidSQL "select" mode), allowing blind SQL injection against the application
  > database on any route built with SqlQueryList.
- **CVSS 4.0:**
  - public route: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (8.7 High);
  - authenticated route: PR:L, 7.1.
- **Reference:** https://github.com/bitechdev/ResolveSpec
