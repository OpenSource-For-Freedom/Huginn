# Disclosure — layrz-sdk: OS command injection in `Report` Excel encryption

**Status:** VALIDATED (static), NOT DISCLOSED. Send only after owner approval.  
**Report to:** email `software@goldenm.com` (package `Author-email`), cc the listed maintainer
`kenny@goldenm.com`. GitHub private vulnerability reporting is not enabled on
`goldenm-software/layrz-sdk` and the repository has no SECURITY.md (checked 2026-09-29). Do not
open a public issue.  
**Package:** `layrz-sdk` (PyPI)  
**Affected:** 4.7.0 – 4.10.0 (every release since 4.7.0, published 2026-09-24; 4.10.0, published
2026-09-29 21:12 UTC, is the latest and still contains the same `call(..., shell=True)` at
`report.py:363`). 4.6.4 and earlier are not affected.  
**Evidence artifacts:** `layrz_sdk-4.7.0.tar.gz` sha256
`180631984040f98e635447a816518dac0f22b86f10ec62ebd6489096f7c81b57`;
`layrz_sdk-4.8.2.tar.gz` sha256 `48b3b05730d5eba8dad4c5f4cd66b90879e23e4b3b75a7ce269edfcea19c9691`;
`layrz_sdk-4.9.0.tar.gz` sha256 `32d0be4d2a5c6a53a4930e3d000b3a0c9a4085555b6bf14fdc6966198e3f17bc`;
`layrz_sdk-4.10.0.tar.gz` sha256 `cec1d1bb1d69ad4f38be0bd2e344ff51f744a9b16f9a83fb3117b19ce790235f`  
**Weaknesses:** CWE-78 (OS command injection), CWE-532 (password written to log)  
**Suggested CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8) when an application passes a
user-chosen report password or name to `export()`. Lower (for example `AV:L/PR:L`) when both
values are fully controlled by the operator. The maintainer's usage decides the final score.

---

## Report text (ready to send)

**Subject:** Command injection in `layrz_sdk.entities.Report` xlsx password encryption (4.7.0–4.10.0)

Hello Golden M team,

While reviewing newly published PyPI releases, we found an OS command injection in
`layrz-sdk`. It affects 4.7.0 through the current 4.10.0.

**Location:** `layrz_sdk/entities/report/report.py`, `Report._export_xlsx()` (line 363 in 4.8.2 and 4.10.0):

```python
if password and msoffice_crypt_path:
  new_path = os.path.join(path, f'encrypted_{self.filename}')
  log.debug(f'Executing `{msoffice_crypt_path} -e -p "{password}" "{full_path}" "{new_path}"`')
  call(f'{msoffice_crypt_path} -e -p "{password}" "{full_path}" "{new_path}"', shell=True)
```

`password` is the public `Report.export(..., password=..., msoffice_crypt_path=...)` argument.
`full_path` and `new_path` contain `self.filename`. All three are interpolated into a string that
`subprocess.call` runs through `/bin/sh` without quoting or escaping.

**Impact:** A password or report name containing a double quote, `$(...)` or backticks ends the
quoted argument and runs arbitrary shell commands with the privileges of the process calling
`export()`. The feature exists so that end users can choose a report password, and an
application that forwards that password gets remote code execution from any user who can set
one. Separately, the full command, including the plaintext password, is written to the
`log.debug` stream.

**Proof of concept (benign; run in a throwaway environment):** Call `export()` on any `Report`
with `msoffice_crypt_path` set and
`password='x" ; id > /tmp/layrz_poc ; echo "'`. After the call, `/tmp/layrz_poc` contains the
output of `id`, which shows the command executed. We did not run this against any system we
do not own.

**Suggested fix:** Pass an argument list and drop the shell. For example:
`subprocess.run([msoffice_crypt_path, "-e", "-p", password, full_path, new_path], check=True)`.
Also stop logging the password. msoffice-crypt also accepts the password without it appearing
in the process list, via stdin or an environment variable if supported; that avoids exposing it
to other local users through `ps`.

We have not published this. Please let us know whether you want to request a CVE through
GitHub's advisory process, or whether you would prefer that we request one. We are happy to
coordinate on a disclosure date; our default is 90 days or when a fixed release is published,
whichever comes first.

— OpenSource-For-Freedom / Huginn
