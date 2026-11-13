"""Shared fixtures — every test starts with an empty diagnosis record."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from jochwacht_sbom import diagnosis


@pytest.fixture(autouse=True)
def _fresh_diagnosis() -> Iterator[None]:
    diagnosis.reset()
    yield
    diagnosis.reset()


@pytest.fixture(autouse=True)
def _release_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """--send needs a release label (contract of 27). Tests that send name one
    through the environment; the tests of the missing label remove it. It also
    keeps a label from the developer's own shell out of the tests."""
    monkeypatch.setenv("JOCHWACHT_RELEASE", "test-1.0")
