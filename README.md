# ContextGuard

**Zero-Trust Governance Framework for Model Context Protocol Deployments**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![IEEE Paper](https://img.shields.io/badge/Paper-IEEE_S%26P_Magazine-red.svg)](#citation)

ContextGuard is a proof-of-concept middleware library that enforces zero-trust security controls on Model Context Protocol (MCP) communications. It implements cryptographic server attestation, continuous capability binding (rug pull detection), and semantic tool definition scanning — addressing the supply chain attack surface introduced by MCP's unauthenticated tool enumeration model.

---

## Background

The Model Context Protocol does not mandate authentication for the `tools/list` enumeration method. Internet-wide reconnaissance by Knostic Security Research (July 2025) identified 1,862 MCP servers accepting unauthenticated tool listing requests. CVE-2025-32711 (EchoLeak, CVSS 9.3) and CVE-2025-6514 (CVSS 9.8) demonstrate operational exploitation of this exposure.

ContextGuard was developed as the implementation artifact for the paper:

> **ContextGuard: Cryptographic Attestation and Zero-Trust Enforcement Against Supply Chain Attacks in Model Context Protocol Deployments**
> Sunil Gentyala, HCLTech (HCL America Inc.) / IEEE Senior Member
> *Submitted to IEEE Security & Privacy Magazine, 2026*

---

## Architecture

```
MCP Client  →  [CVL: Attestation + Capability Binding]
            →  [DIMS: Semantic Fingerprint + Pattern Scan]
            →  [PEP: Policy Enforcement]
            →  MCP Server
```

Four security components, all implemented in this repository:

| Component | Module | Purpose |
|-----------|--------|---------|
| CVL | `src/cvl/attestation.ts` | ECDSA P-256 server identity attestation, nonce binding |
| CVL | `src/cvl/capability-binding.ts` | Signed tool-definition binding, rug pull detection |
| DIMS | `src/dims/semantic-fingerprint.ts` | TF-IDF + LSH fingerprinting, drift detection, pattern scan |
| Orchestrator | `src/index.ts` | Pipeline integration |

---

## Evaluation Results

Evaluated against a 30-entry hand-crafted corpus (15 tool poisoning, 8 rug pull, 7 supply chain) plus 10 benign baselines. All corpus entries are in `corpus/malicious_tools_corpus.json`.

| Category | TP | FN | Precision | Recall |
|---|---|---|---|---|
| Tool Poisoning | 14 | 1 | 100.0% | 93.3% |
| Rug Pull | 8 | 0 | 100.0% | 100.0% |
| Supply Chain* | 7 | 0 | 100.0% | 100.0% |
| **Overall** | **29** | **1** | **100.0%** | **96.7%** |

False positive rate: **0%** (0/10 benign baseline tools misclassified).

*Supply chain detection simulates SCVE sandbox/provenance checks pending full instrumentation.

**Latency (1,000 invocations, n=5 tool set):**
| Metric | Value |
|---|---|
| Mean | 1.005 ms |
| Median (P50) | 0.747 ms |
| P95 | 0.991 ms |
| P99 | 10.8 ms |

The one false negative (TP-006) is a privilege-escalation phrasing ("operating as a database admin") that evades the current regex patterns. A note on planned improvements is in the paper.

---

## Installation

```bash
npm install
npx ts-node src/evaluate.ts   # run full evaluation
```

Node.js 18+ required. No external ML dependencies — only Node.js built-in `crypto`.

---

## Usage

```typescript
import { establishSession, verifyToolInvocation } from './src/index';

// 1. Establish session (first contact with server)
const session = establishSession('my-server', serverToolDefinitions);

// 2. Before every tool invocation:
const result = verifyToolInvocation(session, 'tool_name', currentTools);

if (!result.authorized) {
  console.error('BLOCKED:', result.reason);
} else {
  console.log(`Authorized in ${result.latencyMs.toFixed(2)}ms`);
}
```

---

## Evaluation Corpus

The corpus at `corpus/malicious_tools_corpus.json` contains 40 labeled entries:

- **15 tool poisoning** cases: hidden IMPORTANT tags, Unicode obfuscation, split-field injection, credential harvesting, privilege escalation, role impersonation
- **8 rug pull** cases: definition mutation, parameter injection, version rollback, new tool injection, slow mutation, permission expansion
- **7 supply chain** cases: covert network egress, dependency confusion, typosquatting, compromised legitimate package, build pipeline tampering, transitive dependency, obfuscated payload
- **10 benign baselines**: normal tool definitions with no adversarial content

To cite the corpus:

> Gentyala, S. (2026). *ContextGuard Evaluation Corpus v1.0.0*. GitHub. https://github.com/sunilgentyala/contextguard

---

## Citation

```bibtex
@article{gentyala2026contextguard,
  title   = {ContextGuard: Cryptographic Attestation and Zero-Trust Enforcement
             Against Supply Chain Attacks in Model Context Protocol Deployments},
  author  = {Gentyala, Sunil},
  journal = {IEEE Security \& Privacy},
  year    = {2026},
  note    = {Submitted}
}
```

---

## Author

**Sunil Gentyala** — Lead Cybersecurity and AI Security Consultant, HCLTech (HCL America Inc.), Dallas TX  
IEEE Senior Member (#101760715) | ISACA Professional Member (#2297870)  
sunil.gentyala@ieee.org | ORCID: 0009-0005-2642-3479


---

## License

MIT License — see [LICENSE](LICENSE).
