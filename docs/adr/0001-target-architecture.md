# ADR 0001: Target architecture of the collector

Status: accepted on 16 November 2026 (rule of the maintainer: object-oriented code, code files of at most 350 lines). It applies to every new change from that day.

## Context
The collector is a command line tool. A run reads a source tree, detects the build systems, builds a model of the components and writes an SBOM, optionally uploads it. The public interfaces are the command line, the output format and the data of the upload. Part of the code lives in long modules with free functions (the parsers, the analyzer pipeline, the CLI). It is rebuilt step by step, whenever a file is touched, not in one big change.

## Decision
1. **Direction of dependencies, downwards only:** command line entry → pipeline (one class per task) → readers (one class per build system) and writers (SBOM output, upload) → model (data classes, value objects). Readers and writers do not import each other; the model imports nothing from the layers above it. No module imports upwards, no cycles.
2. **Classes behind interfaces:** readers, the pipeline stages and writers are classes. Between layers there is a `typing.Protocol` that is small and shaped for its user. The user knows the Protocol, not the implementation. Each package keeps its Protocols in a module `ports.py`.
3. **Dependencies come through the constructor.** No instance created at import time, no hidden global state. The parts are put together in one place, the entry point of the command line.
4. **Free functions:** only the command line entry points. Pure formatting and pure parsers without domain logic, state or access to a layer are allowed in a module with a clear name; the guard counts them and their number may only go down. Anything that decides something belongs in a class.
5. **File size:** a new code file has at most 350 lines, split by responsibility, not by line count. Existing files above 350 lines must not grow. Excluded: tests, generated files and configuration.
6. **Names in English**, classes named for their task, no `Manager` or `Helper`.
7. **A rebuild step changes no behaviour:** the same tests stay green, and the command line, the output format and the upload data stay as they are. Small steps, one responsibility each.

## Rebuild from 20 November 2026
Step by step, whenever a file is touched. Whoever changes a file on the frozen list splits it. A file that falls under 350 lines leaves the list and does not return.

## Checks (to be added to `tests.yml` from 20 November 2026)
- A frozen list of the files above 350 lines: a line count may not rise, a new file above 350 lines fails.
- Free functions outside the command line: the count may only go down.
- Import cycles and the direction of the layers: `import-linter` with contracts; the count may not rise.

## Review of a change
The rule is checked as a separate point at every merge, apart from the security review. Until 20 November 2026 a fix in a large file is allowed if it only fixes the defect; new logic with a task of its own goes into a new class in a new file of at most 350 lines.
