"""Huginn private static-analysis capture pipeline."""

import csv as _csv

__version__ = "0.1.0"

# Scanner evidence (for example a line from a minified bundle) can exceed the csv module's
# default 128 KiB field limit; every Huginn CSV reader imports this package first.
_csv.field_size_limit(2**31 - 1)
