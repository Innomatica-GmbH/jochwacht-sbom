"""A pom.xml dependency is one component with a valid purl.

Measured 11.11.2026: the collector wrote log4j-core twice — as
"org.apache.logging.log4j/log4j-core" from the lockfile path and as
"org.apache.logging.log4j:log4j-core" from the build-file pipeline, the
second with the invalid purl pkg:maven/org.apache.logging.log4j:log4j-core@2.14.1.
In the service that is two entries for one OSV key.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from jochwacht_sbom.cli import main

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
      <version>2.14.1</version></dependency>
  </dependencies>
</project>
"""


def test_one_component_with_a_valid_purl(tmp_path: Path) -> None:
    proj = tmp_path / "demo"
    proj.mkdir()
    (proj / "pom.xml").write_text(POM, encoding="utf-8")
    res = CliRunner().invoke(main, [str(proj), "--no-send"])
    assert res.exit_code == 0, res.output
    comps = [c for c in json.loads((proj / "sbom.cdx.json").read_text())["components"]
             if "log4j" in c["name"]]
    assert len(comps) == 1, comps
    assert comps[0]["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert comps[0]["version"] == "2.14.1"
