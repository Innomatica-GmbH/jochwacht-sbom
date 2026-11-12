"""A purl the text cleaning would change is emptied, never repaired
(measured 12.11.2026: pkg:npm/pkg<U+200B>-a became pkg-a)."""

from __future__ import annotations

import pytest

from jochwacht_sbom.sbom.classify import clean_dependency
from jochwacht_sbom.sbom.scanner import Dependency


@pytest.mark.parametrize("purl", [
    "pkg:npm/pkg\u200b-a@1.0.0", "pkg:npm/pkg-a@1.0.0\u202e", "pkg:npm/pkg%E2%80%8B-a@1.0.0",
])
def test_a_purl_the_cleaning_would_change_is_emptied(purl: str) -> None:
    dep = Dependency(name="pkg-a", version="1.0.0", ecosystem="npm", purl=purl)
    clean_dependency(dep)
    assert not dep.purl


def test_a_clean_purl_stays() -> None:
    dep = Dependency(name="pkg-a", version="1.0.0", ecosystem="npm", purl="pkg:npm/pkg-a@1.0.0")
    clean_dependency(dep)
    assert dep.purl == "pkg:npm/pkg-a@1.0.0"
