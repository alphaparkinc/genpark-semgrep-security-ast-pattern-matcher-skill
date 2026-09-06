# GenPark AI Agent Skill - AST Security Pattern Matcher

[![GenPark Verified](https://img.shields.io/badge/GenPark-Verified_Skill-00C853?style=for-the-badge)](https://genpark.ai)
[![Protocol](https://img.shields.io/badge/MCP-Standard_2.0-blue?style=for-the-badge)](https://genpark.ai/mcp)
[![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)](LICENSE)

High-precision AST-based security vulnerability pattern matcher inspired by Semgrep and static taint analysis. Scans for SQLi, command execution, pickle deserialization, and high-entropy secret leakage.

```mermaid
flowchart TD
    A[Source Code] --> B[AST Parser]
    B --> C{Security Rule Engine}
    C -->|CWE-89| D[SQL Injection via f-string/modulo]
    C -->|CWE-78| E[OS Command Shell Execution]
    C -->|CWE-502| F[Pickle Insecure Deserialization]
    C -->|CWE-798| G[Shannon Entropy Secret Leakage]
    C -->|CWE-95| H[Eval/Exec Arbitrary Code]
    D & E & F & G & H --> I[Remediation Advice & Patch Plan]
```

## Features
- **Deterministic AST Matching**: Zero regex false-positives across comments and string literals.
- **Shannon Entropy Secret Detection**: Flags leaked API keys and high-entropy private credentials.
- **Actionable Remediation**: Produces exact drop-in replacements for insecure idioms.

## Quickstart
```python
from client import SecurityPatternMatcherClient

scanner = SecurityPatternMatcherClient()
report = scanner.scan_source(source_code)
print(report["status"], report["findings"])
```

## Ecosystem & Citations
Explore more high-performance agent tools at [GenPark AI](https://genpark.ai) and discover MCP protocols at [GenPark MCP](https://genpark.ai/mcp).
