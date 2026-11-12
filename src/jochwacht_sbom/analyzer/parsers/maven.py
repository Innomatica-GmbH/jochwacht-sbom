"""Deterministic Maven pom.xml parser.

Extracts dependency coordinates (groupId:artifactId) from pom.xml files.
"""

from __future__ import annotations

import re

from jochwacht_sbom.core import xmlsafe
from jochwacht_sbom.core.xmlsafe import Element, ParseError

_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


def _get_own_group_id(root: Element, ns: str) -> str:
    """Return the project's own groupId (or parent groupId as fallback)."""
    group_el = root.find(f"{ns}groupId")
    if group_el is not None and group_el.text:
        return group_el.text.strip()
    parent_el = root.find(f"{ns}parent")
    if parent_el is not None:
        parent_group_el = parent_el.find(f"{ns}groupId")
        if parent_group_el is not None and parent_group_el.text:
            return parent_group_el.text.strip()
    return ""


def parse(content: str) -> list[str]:
    """Extract dependency coordinates from pom.xml content.

    Skips dependencies with unresolved ``${...}`` placeholders and
    self-references (groupId matching the project's own groupId).
    """
    deps: set[str] = set()

    try:
        root = xmlsafe.fromstring(content, what="pom.xml")   # no DOCTYPE, no entities
    except ParseError:
        # Fall back to regex
        return _parse_regex(content)

    # Try with namespace first, then without
    for ns in (_MAVEN_NS, ""):
        own_group_id = _get_own_group_id(root, ns)
        for dep in root.iter(f"{ns}dependency"):
            group_el = dep.find(f"{ns}groupId")
            artifact_el = dep.find(f"{ns}artifactId")
            if group_el is not None and artifact_el is not None:
                group = (group_el.text or "").strip()
                artifact = (artifact_el.text or "").strip()
                if not group or not artifact:
                    continue
                # Skip unresolved property placeholders
                if "${" in group or "${" in artifact:
                    continue
                # Skip self-references (internal submodules)
                if own_group_id and group == own_group_id:
                    continue
                deps.add(f"{group}:{artifact}")

    return sorted(deps)


def _parse_regex(content: str) -> list[str]:
    """Fallback regex parser for malformed XML."""
    deps: set[str] = set()

    # Match <dependency> blocks
    dep_pattern = re.compile(
        r"<dependency>\s*"
        r"<groupId>\s*([^<]+)\s*</groupId>\s*"
        r"<artifactId>\s*([^<]+)\s*</artifactId>",
        re.DOTALL,
    )

    for m in dep_pattern.finditer(content):
        group = m.group(1).strip()
        artifact = m.group(2).strip()
        if group and artifact and not group.startswith("$"):
            deps.add(f"{group}:{artifact}")

    return sorted(deps)
