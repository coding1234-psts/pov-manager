"""Tests for integrated CTU threat report helpers."""
import os
import tempfile
import zipfile

import pytest

from vdr.integrated_threat_report import _find_zip_member_by_suffix


@pytest.mark.unit
class TestFindZipMemberBySuffix:
    def test_returns_none_when_no_match(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            path = f.name
        try:
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("other.txt", b"x")
            with zipfile.ZipFile(path, "r") as zf:
                assert _find_zip_member_by_suffix(zf, "_credentials.xlsx") is None
        finally:
            os.unlink(path)

    def test_prefers_longest_matching_path(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            path = f.name
        try:
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("a/foo_credentials.xlsx", b"x")
                zf.writestr("nested/longer_name_credentials.xlsx", b"y")
            with zipfile.ZipFile(path, "r") as zf:
                got = _find_zip_member_by_suffix(zf, "_credentials.xlsx")
                assert got == "nested/longer_name_credentials.xlsx"
        finally:
            os.unlink(path)

    def test_case_insensitive_suffix(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            path = f.name
        try:
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("rpt_SUSPICIOUS_DOMAINS.XLSX", b"x")
            with zipfile.ZipFile(path, "r") as zf:
                got = _find_zip_member_by_suffix(zf, "_suspicious_domains.xlsx")
                assert got == "rpt_SUSPICIOUS_DOMAINS.XLSX"
        finally:
            os.unlink(path)
