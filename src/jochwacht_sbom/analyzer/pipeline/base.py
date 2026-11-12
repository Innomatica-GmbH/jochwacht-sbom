"""Base types for the multi-tier scanner pipeline.

Defines the ``TierScanner`` protocol that all scanner implementations must
follow, and the ``ScanResult`` container for scanner output.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel

from jochwacht_sbom.analyzer.models import (  # noqa: TC001
    BuildFileArtifact,
    BuildFileDependency,
    BuildFileInternalDep,
)

if TYPE_CHECKING:
    from pathlib import Path


@runtime_checkable
class TierScanner(Protocol):
    """Protocol for a tier scanner in the multi-tier pipeline."""

    tier: int
    name: str

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        """Check if this scanner can handle the given file type."""
        ...

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        """Scan a file or project and return detected dependencies.

        Args:
            file_type: Build file type (e.g. "cmake", "cargo", "_project").
            file_path: Path to the build file (or project root for project-wide scans).
            project_path: Root directory of the project.

        Returns:
            ScanResult with detected dependencies and artifacts.
        """
        ...


class ScanResult(BaseModel):
    """Result from a single scanner invocation."""

    tier: int
    scanner_name: str
    dependencies: list[BuildFileDependency] = []
    artifacts: list[BuildFileArtifact] = []
    internal_deps: list[BuildFileInternalDep] = []
    #: Ökosysteme, für die DIESES Ergebnis vollständig ist und andere Tiers
    #: verdrängt: go list -deps liefert die gelinkte
    #: Go-Menge; tier4 gomod (go.mod-require, auch nicht importierte) darf sie
    #: dann nicht wieder auffüllen. Der Merge streicht Deps dieser Ökosysteme,
    #: die NICHT aus einem autoritativen Ergebnis stammen.
    authoritative_for: list[str] = []
