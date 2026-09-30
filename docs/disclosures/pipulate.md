# Disclosure — pipulate: unauthenticated server on 0.0.0.0 runs shell commands via `/mcp-tool-executor`

**Status:** VALIDATED (static), NOT DISCLOSED. Send only after owner approval.  
**Report to:** Mike Levin (`miklevin`) at `pipulate@gmail.com`, the package `Author-email`. The
repository has no SECURITY.md and no private vulnerability reporting (checked 2026-09-30), and no
matching issue or advisory exists. Do not open a public issue.  
**Package:** `pipulate` (PyPI), `server.py`  
**Affected:** 1.2.0 (2025-09-25) through 2.72 (2026-09-30). Checked 1.2.0, 1.2.3, 1.5, 1.96, 2.0, 2.3,
2.41, 2.50, 2.60, 2.71 and 2.72. 1.1.1 already binds `0.0.0.0` and has the executor route, but
has no shell tool.  
**Evidence artifact:** `pipulate-2.72.tar.gz` sha256
`e0fdc264a681f19c5e1f6fe2631449c6616e85ceb9f46086833529ad221dfb99`  
**Weaknesses:** CWE-306 (missing authentication for critical function), CWE-78 (OS command
execution)  
**Suggested CVSS 3.1:** `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (8.8) for an attacker on the same
network. If a browser delivers the cross-site request (see below), the vector becomes network
with user interaction, `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` (8.8).

---

## Report text (ready to send)

**Subject:** Security: pipulate's server runs shell commands for unauthenticated network requests (1.2.0–2.72)

Hi Mike,

While reviewing recent PyPI releases, I found that pipulate's local server lets anyone who can
reach it run shell commands on the machine. It affects every release I checked from 1.2.0
through the current 2.72. I'm reporting it privately; please don't discuss it in a public issue.

**Details**

- `server.py` starts uvicorn with `host='0.0.0.0', port=5001`. The startup log says
  `http://localhost:5001`, but the server listens on every interface. No route requires
  authentication.
- `POST /mcp-tool-executor` reads `{"tool": ..., "params": ...}` from the request body and
  dispatches to `MCP_TOOL_REGISTRY`, which is `get_all_tools()`.
- By default that registry includes the `@auto_tool` `execute_shell_command` in
  `tools/system_tools.py`, which passes `params["command"]` to `asyncio.create_subprocess_shell`.
  Only the opt-in `PIPULATE_TOOL_DENY` environment variable removes it.
- The cwd check limits the working directory, not the command.
- `GET /open-folder` is on the same unauthenticated surface. It runs `open` / `xdg-open` /
  `explorer` on any existing directory. On macOS, `.app` bundles are directories, so this also
  launches applications.

**Impact:** anyone on the same network as a machine running pipulate can execute arbitrary
commands as the user who started it. Because `request.json()` parses the body whatever its
`Content-Type`, a cross-site `text/plain` POST from a web page may also reach the endpoint in
browsers that allow requests from public sites to local addresses. I did not test this in a
browser.

**Suggested fix**

- Bind to `127.0.0.1` by default and make LAN exposure an explicit opt-in.
- Require a per-install secret (a token in a header or an `HttpOnly` cookie) on
  `/mcp-tool-executor` and other state-changing routes.
- Reject requests whose `Origin` or `Host` isn't the local app, and require
  `Content-Type: application/json`.
- Consider leaving `execute_shell_command` out of the HTTP-reachable registry unless it's
  explicitly enabled.

I have not published this and did not test it against any system I do not own. My review was
static; I did not run the package. Let me know how you'd like to coordinate a fix. If you enable
GitHub private vulnerability reporting, we can handle it as a GitHub Security Advisory and
request a CVE there, or I can request one if you prefer. My default is to disclose 90 days after
this report, or once a fixed release is published, whichever comes first.

Tim Burns
https://github.com/OpenSource-For-Freedom
