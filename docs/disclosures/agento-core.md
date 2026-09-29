# Disclosure — agento-core: toolbox Jira proxy sends stored credentials to a caller-chosen host

**Status:** VALIDATED (static), NOT DISCLOSED. Send only after owner approval.  
**Report to:** GitHub private vulnerability reporting on `https://github.com/agento-cc/agento`
(Security → Report a vulnerability). Do not open a public issue. The package names Marcin Klauza as
author and publishes no security email.  
**Package:** `agento-core` (PyPI)  
**Affected:** 0.6.0 (2026-04-15) through 0.16.3 (2026-09-29, current stable), 39 releases.  
**Fixed in:** 0.17.0rc2 (pre-release, 2026-09-22), which ignores `jira_host` and requires a
host-relative `path`. The fix has not reached a stable release: 0.16.3 was published a week after it
and is still vulnerable.  
**Evidence artifacts:** `agento_core-0.16.3.tar.gz` sha256
`1800b8306048a7de4f59db89c1ab1778c8ebb2f9538883821336bdea3bcc0ad9`;
`agento_core-0.6.0.tar.gz` sha256 `ad59d2cc0dfa597fa88f162705999ee9340359fcd3b9f229497ebbb0cd572703`;
fixed `agento_core-0.17.0rc2.tar.gz` sha256
`029ed192c0b649a1f8d1cadcb0c6b9e3739020bbcdc18406d81a1939298ba202`  
**Weaknesses:** CWE-522 (Insufficiently Protected Credentials), CWE-918 (SSRF)  
**Suggested CVSS 3.1:** `AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` (8.2). The attacker is any code on the
Compose network, such as the agent sandbox. Scope changes because the stolen credential grants access
to the Jira tenant.

---

## Report text (ready to send)

**Subject:** Toolbox `/api/jira/request` sends stored Jira credentials to a caller-supplied host (0.6.0–0.16.3)

Hello,

While reviewing recent PyPI releases, we found that the toolbox's Jira proxy in `agento-core` can be
made to send the configured Jira credentials to a host the caller chooses. We saw that 0.17.0rc2
already contains a fix. We're reporting because every stable release from 0.6.0 through the current
0.16.3 is still affected, and we couldn't find a published advisory.

**Details** (0.16.3, `agento/modules/jira/toolbox/jira-proxy.js`, registered as
`POST /api/jira/request` in `modules/jira/toolbox/api.js`):

```js
const config = await configResolver(req.body.agent_view_id || null);   // global Jira config when omitted
...
const host = req.body.jira_host || config.host;
const user = req.body.auth_user || config.user;
const token = req.body.auth_token || config.token;
...
const response = await fetch(`${host}${path}`, { headers: { Authorization: `Basic ${auth}`, ... } });
```

A request that sets only `jira_host`, `method` and `path` makes the toolbox send
`Authorization: Basic base64(jira_user:jira_token)` for the configured account to that host. The
response body is returned to the caller.

**Why this crosses a boundary:** the toolbox does not authenticate callers. The comment in
`toolbox/server.js` says "the internal Docker network IS its boundary". The Express server listens on
`0.0.0.0:3001`. The generated `docker-compose.yml` puts the agent sandbox on the same `agento-net`
network. The README describes the sandbox as holding no tool credentials and talking to the toolbox
only through MCP tool calls. Nothing enforces that, though: code running in the sandbox can call this
REST route directly. That includes an agent steered by prompt injection from the Jira tickets, emails
or web pages it processes. Such a call hands the long-lived Jira API token to an external host. The
same route also works as a general-purpose HTTP client from inside the credential broker.

**Suggested fix:** release the 0.17.0rc2 change in a 0.16.x patch release. That change ignores
`jira_host` and rejects any `path` that is not host-relative. Please also consider requiring a
shared-secret or caller-identity check on the toolbox's non-MCP REST routes, so the
network-as-boundary assumption no longer covers the sandbox.

We have not published this, and we did not test it against any deployment we do not own. Please let
us know whether you would like to open a GitHub Security Advisory and request a CVE for the stable
range, and when a patched stable release is expected. Our default is to disclose after 90 days or
once a fixed stable release is published, whichever comes first.

— OpenSource-For-Freedom / Huginn
