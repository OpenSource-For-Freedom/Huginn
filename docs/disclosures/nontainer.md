# Disclosure — nontainer: agent-writable `.nontainer/kv.pkl` is unpickled on the host (DirProvider)

**Status:** VALIDATED (static), NOT DISCLOSED. Send only after owner approval.  
**Report to:** maintainer `ashenfad` (github.com/ashenfad). The repository has no SECURITY.md and
private vulnerability reporting is not enabled (checked 2026-09-30). Ask for a private channel
first, either by email if the GitHub profile lists one, or with a minimal issue that contains no
details, and suggest they enable private vulnerability reporting.  
**Package:** `nontainer` (PyPI), `store(..., backend="dir")` / `DirProvider`  
**Affected:** every release, 0.1.2 (2026-07-19) through 0.8.2 (2026-09-29). `dir.py`'s pickle
store and `executor_dud.py` exist in every checked release (0.1.2, 0.2.0, 0.3.0, 0.5.0, 0.6.0, 0.7.0,
0.8.2). The default `kvgit` backend does not use this code path.  
**Evidence artifact:** `nontainer-0.8.2.tar.gz` sha256
`7e54bebb1e35823bc9871c9033c486365259aa74711b629ef4ee99e2ca3ad419`; harvest behaviour from
`dud-0.4.1` (`dud/diffscan.py`, `_IGNORE_DIRS = {"__pycache__"}`).  
**Weakness:** CWE-502 (deserialization of untrusted data)  
**Suggested CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0) for the DudExecutor microVM
case, where the crossed boundary is the one documented for "actively untrusted code". For
LocalExecutor with `isolation="process"`/`"kernel"`, `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (8.8).
The final score depends on how the maintainer frames the local executors.

---

## Report text (ready to send once a private channel is confirmed)

**Subject:** Agent code can escape nontainer's sandbox via `.nontainer/kv.pkl` with the `dir` backend (0.1.2–0.8.2)

Hello,

While reviewing recent PyPI releases, I found a way for agent code to run arbitrary code in
the host process when a nontainer store uses the `dir` backend. It also works from inside the
DudExecutor microVM. It affects every release I checked, 0.1.2 through 0.8.2.

**Details**

- `nontainer/providers/dir.py`: `_FileKV.__init__` runs `pickle.load()` on
  `<root>/.nontainer/kv.pkl` whenever a `DirProvider` is constructed. `Store._session_provider()`
  does that for each session open with `backend="dir"`.
- The module docstring says `.nontainer` is "framework-internal but visible to the agent
  (documented, not hidden)" and treats the worst case as the agent corrupting its own cache.
  Because the file is unpickled, the worst case is code execution in the host process the next
  time the session is opened.
- **DudExecutor:** `_push_tree()` sends the whole workspace root, including `.nontainer/`, to the
  guest. `diff()` / `_apply_diff()` write the guest's changes back into the provider fs. dud's
  harvest ignores only `__pycache__` and `*.pyc`/`*.pyo`. So a guest that rewrites
  `.nontainer/kv.pkl` gets it copied to the host, where it is unpickled on the next open. This
  breaks the rule stated in `executor_dud.py` ("the host stores bytes and never unpickles guest
  bytes") and crosses the microVM boundary that the README recommends for actively untrusted
  code.
- **LocalExecutor:** the same file is writable from the terminal or `run_python`, so
  `isolation="process"` / `"kernel"` does not contain the effect either.

**Impact:** with `backend="dir"`, code the agent runs, including code steered by prompt
injection, can execute arbitrary code as the host user the next time the session is opened.
Under DudExecutor, that is an escape from the microVM.

**Suggested fix:** keep the kv store outside the agent-visible tree (for example
`<store>/<session>.kv` next to the workspace root rather than under it), or refuse and strip
`.nontainer/` in `_push_tree` and in the harvest before `_apply_diff`. Consider replacing
pickle for the dir kv with a format that can't execute code (JSON plus the bytes-only rule the
Dud path already uses).

I have not published this and did not test it against any system I do not own. My review was
static; I did not run the package. Let me know how you'd like to coordinate a fix and a CVE
request. My default is to disclose 90 days after this report, or once a fixed release is
published, whichever comes first.

Tim Burns
https://github.com/OpenSource-For-Freedom
