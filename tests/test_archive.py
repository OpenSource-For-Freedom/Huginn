from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from huginn.archive import UnsafeArchive, extract


class ArchiveSafetyTests(unittest.TestCase):
    def test_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                data = b"bad"
                info = tarfile.TarInfo("../../escape.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            with self.assertRaises(UnsafeArchive):
                extract(archive, Path(td) / "out")

    def test_extracts_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "ok.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                data = b"print('ok')\n"
                info = tarfile.TarInfo("pkg/a.py")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            out = Path(td) / "out"
            extract(archive, out)
            self.assertEqual((out / "pkg" / "a.py").read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
