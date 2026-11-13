# jochwacht-sbom

> **Renamed on 01.10.2026** — same tool, same code line, new name: the old one
> collided with a registered trademark. `pipx install jochwacht-sbom`. From
> 0.9.0 on, GPL-3.0-or-later; releases up to 0.8.6 stay MIT. Every release
> under the earlier names is withdrawn from PyPI.

### Only what you actually ship

A Python lockfile holds the resolution for *every* environment the resolver
considered — `uv.lock` writes one entry per resolution, each with its own
markers. Tell the tool what you ship and the rest stops counting as yours:

```bash
jochwacht-sbom . --target-env "python=3.10;platform=linux;arch=aarch64,x86_64"
```

Comma multiplies, semicolon separates the axes. Keys: `python`, `platform`,
`arch`, `system`, `os`, `implementation`. Resolutions no target reaches are
kept in the bill as `scope="excluded"` with the reason — nothing is deleted,
so your bill still agrees with your lockfile. Without the flag nothing is
evaluated and the output is unchanged.

Both places a condition can sit are read: the package entry and the
dependency edge (`uv.lock` writes it in either). A package that only a false
edge leads to is not shipped either.

A marker that needs something you did not declare is **not** guessed: it
counts as shipped, with a note. Otherwise the answer would depend on the
machine that ran the scan.

One thing to get right yourself: `--target-env` must be the environment you
really ship. Nothing checks it against your `requires-python`, so declaring
3.10 while shipping 3.12 produces an exclusion that is simply wrong.

### If you installed this tool under its earlier name

Remove that installation and install this one — there is no forwarding
command and no alias package, so the move is a clean swap rather than a
layer:

```bash
pipx uninstall <the old package>   # whichever name you installed
pipx install jochwacht-sbom
```

One thing does carry over, because it is about a file you already have: a
bill written by **any** earlier release is still recognised as yours, so it
is overwritten in place instead of being refused as somebody else's evidence.
The module path (`jochwacht_sbom`), the exception class and the `JOCHWACHT_*`
environment variables all use the current name.

**Reads your build, writes your bill of materials — locally.** One command in
your project folder produces a CycloneDX SBOM, including from **configured
builds** (`CMakeCache.txt`) and **Yocto/Buildroot build output** that generic
scanners cannot read. The bill is the component inventory the
[EU Cyber Resilience Act](https://jochwacht.dev/en/cra-nis2-guide.html) asks for.

## SBOM generation for embedded builds

Most SBOM tools catalog package registries — npm, PyPI, Go, Cargo. Embedded software
is built differently: CMake, Make, Meson and Autotools source trees, Yocto images,
Buildroot, Zephyr modules, vcpkg manifests. That is what jochwacht-sbom reads.

**What you get:**

- A CycloneDX bill of materials from your **build**, not just from lockfiles —
  1.6 by default, `--cyclonedx 1.7` for the current specification —
  including the C/C++ worlds that have no package manager. Versions of system
  libraries come from the linked system (pkg-config), never guessed.
- **License and supplier** as your build and your `jochwacht-deps.yaml` state them.
  Jochwacht subscribers get them completed from a curated knowledge base on the
  server.
- Test material, examples and build tools **marked as excluded** instead of counted
  as product components. Conditional dependencies are marked **optional** instead
  of being guessed into the product.
- **Nothing leaves your machine by default.** The standard run writes `sbom.cdx.json`
  next to your project and transmits nothing.

**Why not a generic scanner?** Measured on 2026-09-09 against syft 1.51.1 across six
embedded projects (CMake, Zephyr, Yocto, Buildroot): the generic scanner produced
zero product components for these builds. For registry ecosystems (npm, PyPI, Go),
generic scanners work well — embedded builds are the gap this tool exists for.

```
pipx install jochwacht-sbom
jochwacht-sbom .         # writes sbom.cdx.json, sends nothing
```

## Quickstart

```bash
pipx install jochwacht-sbom          # or: pip install jochwacht-sbom,
                                    #     or download the standalone binary
jochwacht-sbom .                     # reads your build, writes sbom.cdx.json
                                    # — and transmits NOTHING
```

You now have your own CycloneDX SBOM. An existing `sbom.cdx.json` is never
silently overwritten.

More options: `jochwacht-sbom --help` — including `--sbom PATH` (write the
SBOM elsewhere) and `--with-tools` to additionally use native package-manager
CLIs for higher-fidelity results.

**Nothing leaves your machine.** The default run transmits nothing.

### Sending it to your Jochwacht subscription

With a subscription, `--send` sends the SBOM written here to Jochwacht, and
`jochwacht-sbom status` reads the result of that version — for example as two
steps of a CI pipeline:

```bash
export JOCHWACHT_API_KEY=…            # from a secret of your pipeline, never on the command line
jochwacht-sbom . --send --yes --release 1.4.2   # writes sbom.cdx.json and sends it
jochwacht-sbom status --wait 600                 # 0 green/yellow/waiting for a person, 1 red, 2 error
```

- The key comes from `JOCHWACHT_API_KEY`, the address from `JOCHWACHT_API_URL`
  (default `https://api.jochwacht.dev`). Only https, no redirect is followed,
  the key is never printed or saved.
- When your key reaches several products, name one with `--product` or
  `JOCHWACHT_PRODUCT`: its name as in the portal, or its id `prd_…`. The product
  must exist in the portal; the upload never creates one. A key can be limited
  to some products; another product is then refused.
- `--send` needs the release of the version you send: `--release` or
  `JOCHWACHT_RELEASE` (for example your tag), at most 100 characters; a longer
  one is refused, never shortened. It is written as the version into the bill
  and the upload. The same label replaces the previous version of that
  release; a new label is a new release with a full check. When the releases
  of your subscription are used up, the oldest fully checked one goes into
  watch, and you get a mail.
- The answer of the send is kept in `.jochwacht/last-upload.json` (without the
  key). `status` must run in the same directory, or get `--status-href`.
- `status` asks again while the comparison still runs (`--wait`, seconds) and
  always prints the ready line of the answer. `--preliminary` asks for the
  result before a person looked (Premium).
- You can send your own SBOM with `curl` instead; the setup page in the portal
  shows the two lines.

The old `--email`, `--voucher` and `--code` belonged to the free report, which
is no longer offered; with `--send` they end with a message.

## What it reads

- dependencies from lockfiles and build files: Conan, vcpkg, CMake, Cargo,
  npm/yarn/pnpm, Python incl. uv, Go, Maven/Gradle, Meson, Alire, .NET/NuGet
  (`packages.lock.json`, `<PackageReference>` in project files,
  `packages.config`) and more,
- **Zephyr workspaces**: the `west.yml` module manifest — every module
  with its pinned revision,
- **Yocto and Buildroot BUILD OUTPUT**: run the tool in your build
  directory — it reads `deploy/images/**/*.manifest` (what is actually
  in your image) resp. `legal-info/manifest.csv`. The recipe source
  tree only says what *could* be built, so the build output is what
  counts,
- names and versions of FPGA IP cores
  (AMD/Xilinx Vivado `.hwh`/`.xci`, Microchip Libero Tcl/`.cxf`,
  Intel/Altera Quartus `*_hw.tcl`),
- your own declarations in `jochwacht-deps.yaml` (supplier, license, purl,
  CPE).

Build outputs (`dist/`, `build/`, `node_modules/`, …) and hidden
directories are never scanned. Project-specific excludes go into a
committed `.jochwachtignore` at the project root — one glob pattern per
line, `#` comments.

**Quality rules** (v0.6.0): component identity is (name, version,
ecosystem) — nested second versions of one package are kept as own rows
(the older nested version is often the vulnerable one); build tools and
system libraries (`Doxygen`, `-lanl`, `find_package(Git)`, …) are
dropped via a curated 950-name skip list — your own `jochwacht-deps.yaml`
declarations are never skipped; `*` and guessed versions are never
reported — a missing version is shown as honestly missing. If no
supported build system is found, no SBOM is written and the tool tells
you exactly what it looks for and where.

This collector is open source so that you can verify that nothing leaves
your machine.

## When the tool fails: the diagnosis file

A defect in jochwacht-sbom must not be a silent gap in your bill, and it
must not phone home either. When a reader crashes (or the tool crashes
elsewhere), the run

- continues with the other readers and still writes the SBOM,
- says in red which reader failed (`pom.xml (KeyError)`), that the bill is
  **incomplete**, and that this is a defect in the tool, not in your project,
- writes `jochwacht-sbom-diagnosis.json` next to the SBOM, names the path,
  and asks you to mail it to <support@innomatica.de>,
- ends with exit code 1.

Nothing is sent automatically — the file leaves your machine only if you
send it. Open it first. It contains: tool version, Python version, operating
system, which reader failed, the exception *type*, the call chain inside
jochwacht-sbom, and the file *pattern* the reader was called for (a name from
the tool's own tables, e.g. `pom.xml` or `*.csproj`). It never contains
package names, versions, licenses, file paths, file contents, environment
variables, host names — or the exception message (a `KeyError`'s message is
a key, and a key is often a package name). The boundary is one function,
`own_frames()` in `src/jochwacht_sbom/diagnosis.py`, and `tests/test_diagnosis.py`
runs a fabricated crash against canary data to prove nothing gets through.

A build system the tool does not read yet is **not** a defect: if nothing
readable is found but markers of a known-but-unread build system are
(Bazel, SCons, Keil, IAR, PlatformIO, Swift PM, Composer, …), the run keeps
exit code 2, names the markers by label and count (`bazel (2), keil (1)`),
and writes the same file with `"kind": "unsupported_build"` — labels and
counts only, no file names. Next to a build system it does read, an unread
one is named in a dim line and no file is written. Developers who want the
plain traceback set `JOCHWACHT_SBOM_TRACEBACK=1` (the pre-rename
`JOCHWACHT_SBOM_TRACEBACK` is still read, so existing setups keep working).

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | success |
| 1    | error (network, a crashed reader — the bill is incomplete, diagnosis file written, …) |
| 2    | no supported build system found — declare dependencies manually in `jochwacht-deps.yaml`; markers of unread build systems are named |

## Privacy

The tool works locally and transmits nothing. Innomatica's privacy policy:
<https://jochwacht.dev/en/privacy.html>.

## About

`jochwacht-sbom` is the free entry point to
[Jochwacht](https://jochwacht.dev) — the CRA/NIS2 compliance toolchain for
embedded software teams by [Innomatica GmbH](https://jochwacht.dev/impressum.html).
The server side (enrichment, vulnerability monitoring, reports) is a
commercial product; this repository contains the complete client.

Maintained by Innomatica; the roadmap follows the product. Issues and PRs are
welcome — please report security topics per [SECURITY.md](SECURITY.md).

## License

GPL-3.0-or-later, Copyright (C) 2026 Innomatica GmbH — see [LICENSE](LICENSE).
Releases up to and including jochwacht-sbom 0.8.6 were published under the MIT
License and remain available under it. The GPL keeps the one argument this
tool is published for intact: anyone can read, run and verify what it does,
and improvements to it stay open.
