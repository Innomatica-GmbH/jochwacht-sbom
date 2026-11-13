"""XML from a customer's tree is parsed only without DOCTYPE and entities.

ElementTree expands an internal entity (measured below). The collector read
pom.xml, MSBuild projects, packages.config and Directory.Packages.props
with ``ET.parse`` directly; a pom.xml with ``<!ENTITY x "lolEXPANDED">``
produced the component "org.x:lolEXPANDED", a .csproj the component
"lolEXPANDED", in UTF-8 and in UTF-16. Every such parse now goes through
``jochwacht_sbom.core.xmlsafe``, and no other module may import an XML
parser (checked by AST, the same rule as in the suite).
"""

from __future__ import annotations

import ast
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from click.testing import CliRunner

from jochwacht_sbom.cli import main

SRC = Path(__file__).resolve().parents[1] / "src" / "jochwacht_sbom"
BANNED_IMPORTS = {"xml", "lxml"}

POM = """<?xml version="1.0" encoding="{enc}"?>
<!DOCTYPE project [<!ENTITY x "lolEXPANDED">]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.own</groupId><artifactId>app</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>org.x</groupId><artifactId>&x;</artifactId>
      <version>1.2.3</version></dependency>
    <dependency><groupId>org.y</groupId><artifactId>plain</artifactId>
      <version>4.5.6</version></dependency>
  </dependencies>
</project>
"""

CSPROJ = """<?xml version="1.0" encoding="{enc}"?>
<!DOCTYPE Project [<!ENTITY x "lolEXPANDED">]>
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="&x;" Version="1.2.3" />
    <PackageReference Include="Plain.Package" Version="4.5.6" />
  </ItemGroup>
</Project>
"""


def test_measured_premise_elementtree_expands_internal_entities() -> None:
    root = ET.fromstring('<!DOCTYPE a [<!ENTITY x "lol">]><a>&x;</a>')  # noqa: S314 — the premise
    assert root.text == "lol"


def _run(tmp_path: Path, filename: str, template: str, encoding: str) -> str:
    proj = tmp_path / "proj"
    proj.mkdir()
    py_enc = {"UTF-8": "utf-8", "UTF-16": "utf-16"}[encoding]
    (proj / filename).write_bytes(template.format(enc=encoding).encode(py_enc))
    res = CliRunner().invoke(main, [str(proj), "--no-send"])
    bill = proj / "sbom.cdx.json"
    return res.output + (bill.read_text(encoding="utf-8") if bill.is_file() else "")


@pytest.mark.parametrize("encoding", ["UTF-8", "UTF-16"])
@pytest.mark.parametrize(("filename", "template"), [
    ("pom.xml", POM),
    ("app.csproj", CSPROJ),
])
def test_an_entity_in_a_build_file_is_never_expanded(
    filename: str, template: str, encoding: str, tmp_path: Path,
) -> None:
    out = _run(tmp_path, filename, template, encoding)
    assert "lolEXPANDED" not in out


@pytest.mark.parametrize(("filename", "template", "name"), [
    ("pom.xml", POM, "plain"),
    ("app.csproj", CSPROJ, "Plain.Package"),
])
def test_counter_check_the_same_file_without_doctype_is_read(
    filename: str, template: str, name: str, tmp_path: Path,
) -> None:
    clean = template.replace('<!DOCTYPE project [<!ENTITY x "lolEXPANDED">]>\n', "")
    clean = clean.replace('<!DOCTYPE Project [<!ENTITY x "lolEXPANDED">]>\n', "")
    clean = clean.replace("&x;", "entityfree")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / filename).write_text(clean.format(enc="UTF-8"), encoding="utf-8")
    res = CliRunner().invoke(main, [str(proj), "--no-send"])
    assert res.exit_code == 0, res.output
    bill = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))
    names = {c["name"] for c in bill["components"]}
    assert any(name in n for n in names), names


def banned_xml_imports(source: str) -> list[str]:
    """Every import of an XML parser package in *source*, by AST: ``import
    x``, ``import x as y``, ``from x import …``, at module level or inside a
    function. Only ``jochwacht_sbom.core.xmlsafe`` may have one."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in BANNED_IMPORTS:
                    found.append(f"import {alias.name} (line {node.lineno})")
        elif (isinstance(node, ast.ImportFrom) and node.module
              and node.module.split(".")[0] in BANNED_IMPORTS):
            names = ", ".join(a.name for a in node.names)
            found.append(f"from {node.module} import {names} (line {node.lineno})")
    return found


@pytest.mark.parametrize("snippet", [
    "import xml.etree.ElementTree as ET",
    "from xml.etree.ElementTree import fromstring",
    "from xml.etree import ElementTree",
    "import xml",
    "from xml.dom import minidom",
    "import xml.sax",
    "from xml.parsers import expat",
    "import lxml.etree",
    "from lxml import etree",
    "def f():\n    import xml.etree.ElementTree as ET\n    return ET",
])
def test_every_form_of_an_xml_parser_import_is_found(snippet: str) -> None:
    assert banned_xml_imports(snippet), snippet


def test_counter_check_the_safe_way_passes() -> None:
    assert banned_xml_imports(
        "from jochwacht_sbom.core import xmlsafe\n"
        "from jochwacht_sbom.core.xmlsafe import Element, ParseError\n"
        "import json\n"
    ) == []
    assert banned_xml_imports("x = 'import xml.etree.ElementTree'") == []


def test_only_xmlsafe_imports_an_xml_parser() -> None:
    offenders: dict[str, list[str]] = {}
    for p in sorted(SRC.rglob("*.py")):
        rel = p.relative_to(SRC).as_posix()  # "core/xmlsafe.py" on Windows too
        if rel == "core/xmlsafe.py":
            continue
        hits = banned_xml_imports(p.read_text(encoding="utf-8"))
        if hits:
            offenders[rel] = hits
    assert offenders == {}
    assert banned_xml_imports((SRC / "core" / "xmlsafe.py").read_text(encoding="utf-8"))
