# Security Policy

## About This Repository

ContextGuard is a security research prototype. The evaluation corpus in
`corpus/malicious_tools_corpus.json` contains **documented attack patterns**
against Model Context Protocol deployments. These are provided strictly for
defensive research and reproducibility purposes.

## Responsible Use

The attack patterns in this corpus are derived from publicly disclosed
vulnerabilities and published security research (Invariant Labs, Aim Security,
JFrog Security Research). They are documented here to enable:

- Reproducible evaluation of MCP security tools
- Development of detection mechanisms
- Academic research into AI agent security

They must **not** be used to attack MCP deployments without explicit
authorization from the system owner.

## Reporting Vulnerabilities in ContextGuard

If you discover a security issue in the ContextGuard implementation itself
(e.g., a bypass of the CVL or DIMS detection logic), please report it
responsibly rather than opening a public GitHub issue.

**Contact:** sunil.gentyala@ieee.org  
**Subject line:** `[SECURITY] ContextGuard vulnerability report`

Please include:
- A description of the bypass or vulnerability
- A minimal reproducible example (tool definition or code)
- The expected vs. actual detection outcome

I will acknowledge receipt within 48 hours and aim to publish a fix and
corpus update within 14 days of a confirmed bypass.

## Scope

In scope: detection bypasses, false negative patterns, implementation bugs  
Out of scope: the attack patterns themselves (these are intentionally included)
