# Disclosure — archilence-ubuntu-connector: missing authentication on the connector tool server

**Status:** VALIDATED (static), NOT DISCLOSED. Send only after owner approval.  
**Package:** `archilence-ubuntu-connector` (PyPI)  
**Affected:** every published release, 1.0.0 (2026-04-11) through 2.5.0 (2026-09-29). 2.4.0 and
2.5.0 changed only packaging metadata; `tool_server.py` and `main.py` are identical to 2.3.0.  
**Evidence artifacts:** `archilence_ubuntu_connector-2.3.0.tar.gz` sha256
`f12479e58d894df25fb65a6e57e7dd7a77cc59e5097b57668d7e1f56cfa86996`;
`archilence_ubuntu_connector-2.5.0.tar.gz` sha256
`ba90ac7f42f113dcff7d2fd2c9b7edd4c332431ebe043b5aa0fc06f9af3c9220`  
**Weakness:** CWE-306 (Missing Authentication for Critical Function)  
**Suggested CVSS 3.1:**
- default configuration (information disclosure): `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5)
- `control.enabled` (unauthenticated service/container restart and stop): `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H` (9.4)
- `control.enabled` + `control.allow_exec` (unauthenticated command execution): 9.8

**Report to:** the package metadata names no author, maintainer, homepage or repository, so the
right channel has to be found before sending:
1. The Archilence vendor's published security contact: `https://archilence.com/.well-known/security.txt`
   or a security page on `archilence.com`. The README installs from and registers with
   `cockpit.archilence.com`. (This domain could not be reached from the Huginn review environment;
   check it from a browser.)
2. Otherwise the vendor's general support contact, asking for a security contact first and
   sending no details until one is given.
3. If no contact responds within 14 days, ask PyPI security (`security@pypi.org`) to help
   reach the project owner.

---

## Report text (ready to send once a contact is confirmed)

**Subject:** Unauthenticated access to archilence-ubuntu-connector tool server (1.0.0–2.5.0)

Hello Archilence team,

While reviewing newly published PyPI releases, we found that the tool server in
`archilence-ubuntu-connector` accepts requests from anyone who can reach it. This affects every
published release, 1.0.0 through 2.5.0.

**Details**

- `archilence_connector/main.py` serves the Flask app from `tool_server.create_app()` with
  `app.run(host="0.0.0.0", port=config.port)` (default port 8990). The README documents this
  port as the callback URL that Archilence Core calls, so it is expected to be reachable over
  the network.
- None of the routes in `tool_server.py` authenticate the caller. The module defines
  `_is_loopback_request()`, but only `/analysis/full` uses it. The connector holds an Archilence
  API key for its own outbound calls to Core. It never checks one on inbound requests.

**Impact**

- **Default configuration:** anyone on the network can read the host's processes, containers
  (including environment variables), listening ports and network configuration. They can read
  the systemd journal of any unit through `POST /tools/get_logs` (service logs often contain
  credentials), and trigger `/sync`.
- **With `control.enabled: true`:** anyone can restart any systemd unit through
  `sudo systemctl`, and restart or stop any Docker container.
- **With `control.allow_exec: true`:** `POST /tools/exec_command` passes the request's `cmd`
  field to `subprocess.run(..., shell=True)`. Anyone who can reach the port can run arbitrary
  commands as the connector's user. The configuration labels this option dangerous, but it
  gives no warning that the endpoint is unauthenticated.

**Suggested fix**

- Require authentication on every tool-server route. For example, verify a shared secret or
  HMAC from Core on each request, or use mutual TLS.
- Bind to `127.0.0.1` by default, and make network exposure an explicit opt-in.
- Apply the existing loopback check, or the new authentication, before any `control` route.

We have not published this, and we did not test it against any system we do not own. Please
tell us how you would like to coordinate a fix and a CVE request. Our default is to disclose
after 90 days or once a fixed release is published, whichever comes first.

— OpenSource-For-Freedom / Huginn
