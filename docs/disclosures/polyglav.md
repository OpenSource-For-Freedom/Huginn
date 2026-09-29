# Disclosure — polyglav: `bash_allow` command allow-list bypass in `run_command`

**Status:** VALIDATED (static), NOT DISCLOSED. Send only after owner approval.  
**Report to:** the maintainer directly. The repository's SECURITY.md offers a public issue with the
`security` label, or direct contact with the maintainer. Private vulnerability reporting is not
enabled (checked 2026-09-29). Do not put details in a public issue. If no private address can be
found, open a minimal `security` issue asking for one, with no details. Author per PyPI metadata:
Evgenij Myasnikov.  
**Package:** `polyglav` (PyPI), bundled plugin `polyglav-core-exec`  
**Affected:** 0.37.0 (2026-09-27) and 0.38.0 (2026-09-29), every release on PyPI. The plugin
source is identical in both.  
**Evidence artifacts:** `polyglav-0.38.0.tar.gz` sha256
`7cfb87c81ec9d98c5051186f40572c1d8b86763d3c9d33847dd5a2b8a157b4df`;
`polyglav-0.37.0.tar.gz` sha256 `a3e557549cf8fab3c57a5991693e534475274f78e23e9b8b5bc98331c496b0f9`  
**Weaknesses:** CWE-78 (OS command injection), CWE-184 (incomplete list of disallowed inputs)  
**Suggested CVSS 3.1:** `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H` (7.5). The attacker is content that
reaches the agent, such as a web page or a file it reads. It only works when the operator has set
`tool_permission.bash = allow` with a `bash_allow` list, which is the configuration the list
exists for. With the default `bash = ask`, the user is still prompted.

---

## Report text (ready to send)

**Subject:** `bash_allow` allow-list in polyglav-core-exec can be bypassed with shell substitution (0.37.0–0.38.0)

Hello,

While reviewing recent PyPI releases, I found that the `bash_allow` command allow-list in
polyglav's bundled `polyglav-core-exec` plugin can be bypassed. A command that starts with an
allowed prefix can still run arbitrary other commands. This affects 0.37.0 and 0.38.0.

**Location:** `plugins/polyglav-core-exec/src/plugin.py`

- `run_command` executes the model-supplied `command` with `subprocess.run(command, shell=True, ...)`.
- When `tool_permission.bash` is `allow`, the only restriction is `_run_command_permission()`,
  which calls `_command_allowed(command, bash_allow)`.
- `_command_allowed()` rejects newlines and `<<`, splits the string on `&&`, `||`, `;`, `|` and
  `&`, and checks that each segment `startswith()` an allowed prefix.

**The gap:** the check never looks inside a segment, so the shell still interprets:

- command substitution: `$(...)` and backticks;
- redirection: `>` and `<`;
- prefixes without a word boundary: `pytest` also matches `pytestx`.

With `bash_allow: ["pytest"]`, a command such as `pytest $(<other command>)` passes the check,
and the shell runs the substituted command before `pytest` starts. `pytest > ~/.bashrc` also
passes and overwrites the file. The package's own tests (`test_bash_allow_denies_other`,
`test_bash_allow_chain_denies_unlisted_segment`) show the list is meant to stop unlisted
commands, and the README describes tools as running "behind permissions you control".

**Impact:** an operator who enables `bash: allow` and relies on `bash_allow` to limit the agent
to a few commands can still get arbitrary command execution with their privileges. This happens
whenever the model is steered by prompt injection from content it processes. For example, the
`web` tool is allowed by default.

**Suggested fix:** don't pass allow-listed commands to a shell. Parse the command with
`shlex.split()`, match the allow-list against the parsed argv (whole tokens, not string
prefixes), and run it with `shell=False`. If shell operators must be supported, reject `$(`,
backticks, `>`, `<` and subshell parentheses before matching, and require a word boundary
after each prefix.

I have not published this and did not test it against any system I do not own. Let me know
whether you want to handle it as a GitHub Security Advisory and request a CVE there, or whether
you'd prefer that I request one. My default is to disclose 90 days from the report date, or once
a fixed release is published, whichever comes first.

Tim Burns
https://github.com/OpenSource-For-Freedom
