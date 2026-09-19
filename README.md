# domain-radar

[![npm version](https://img.shields.io/npm/v/domain-radar.svg)](https://www.npmjs.com/package/domain-radar)
[![Powered by insight.surf](https://img.shields.io/badge/Powered%20by-insight.surf-blue.svg)](https://insight.surf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Domain Radar** is a production-grade Model Context Protocol (MCP) server powered by **[insight.surf](https://insight.surf)**. Built for domain investors, founders, and autonomous AI research agents, it performs authoritative multi-TLD RDAP registry auditing, keyword combination generation, and real-time live website activity probing.

## Core Capabilities

- **1,200+ Global TLD Dynamic IANA Bootstrap**: Queries authoritative registries across over 1,200 top-level domains (`.com`, `.net`, `.org`, `.ai`, `.io`, `.xyz`, `.tech`, `.app`, `.cloud`, `.co`, `.de`, etc.).
- **Live Activity Radar (In-Use vs Inactive/Parked)**: Probes registered domains in real-time via DNS and HTTP/HTTPS to classify them into:
  - 🟢 **`UNREGISTERED`**: Not found in registry at audit time (available to register).
  - 🔵 **`ACTIVE_IN_USE`**: Actively operating website/service (proof of commercial adoption).
  - ⚪ **`INACTIVE_OR_PARKED`**: Registered but dormant (no DNS) or parked on domain aftermarket marketplaces (Dan, Sedo, HugeDomains, Afternic).
- **Flexible Keyword Positioning**: Generate combinations with keyword as `prefix` (`kw+word`), `suffix` (`word+kw`), or `inside` (`mod+kw+word`).
- **Hyphen & Numeric Pattern Controls**:
  - Hyphen: `none` (unhyphenated), `hyphen_only` (hyphenated), or `both`.
  - Numbers: `none` (letters only), `include` (with high-value commercial patterns like `24`, `365`, `360`, `247`, `101`, `88`), or `numbers_only`.
- **Autonomous Agent-Ready (`readOnlyHint: true`)**: Properly encapsulated in the official MCP `annotations` object so AI clients (Claude Desktop, Cursor) execute automated research loops without permission prompts.
- **Polite Rate Limiting & Zero API Keys**: Batch-throttled to avoid HTTP 429 rate limits. Runs locally via stdio at $0 operational cost.

## Quick Start

### Run Directly with npx
```bash
npx domain-radar
```

### Add to Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "domain-radar": {
      "command": "npx",
      "args": ["-y", "domain-radar"]
    }
  }
}
```

## Tools Included

1. `search_keyword_domains`: Full DotDB-equivalent search engine. Supports keyword positioning (`beginning`, `end`, `any`), character filters (`include_alphabets`, `include_digits`, `include_hyphens`), live site status probing (`active`, `parked`, `inactive`, `unregistered`), and custom TLD lists across 1,200+ IANA extensions.
2. `scan_keyword_tlds`: Audits exact keyword registration coverage across 1,200+ authoritative TLDs and probes real-time web activity.
3. `search_keyword_combinations` & `find_available_combinations`: Backward-compatible aliases for legacy workflows.

## Official Namespace
Namespace Identifier: `surf.insight/domain-radar`

## License
MIT © [datutu / insight.surf](https://insight.surf)
