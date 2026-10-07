"""Malicious-package analyzer: git_warden's Tier-2 rules, vendored.

The scanning modules here are copied byte-for-byte from git_warden by
scripts/sync_analyzer.py (see SOURCE.json), so Huginn, Warden and Knorr judge
code with the same rules without Huginn depending on the private git_warden
repository at hunt time. package_entry.py is Huginn's own and is not synced.
Standard library only: the analyzer image needs nothing but Python and yara.
"""
