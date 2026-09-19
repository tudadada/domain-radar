# domain-radar

[![npm version](https://img.shields.io/npm/v/domain-radar.svg)](https://www.npmjs.com/package/domain-radar)
[![Powered by insight.surf](https://img.shields.io/badge/Powered%20by-insight.surf-blue.svg)](https://insight.surf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Domain Radar** is a production-grade Model Context Protocol (MCP) server powered by **[insight.surf](https://insight.surf)**. Built for domain investors, founders, and autonomous AI research agents, it performs authoritative multi-TLD RDAP registry auditing and intelligent keyword combination discovery.

## Core Capabilities

- **Authoritative Multi-TLD RDAP Matrix**: Directly audits keyword registration status across major authoritative registry RDAP endpoints (`.com`, `.net`, `.org`, `.info`, `.biz`, `.ca`, `.de`, `.io`, `.ai`).
- **Polite Rate Limiting & Throttling**: Queries registry endpoints in controlled batches with polite headers and backoff to prevent HTTP 429 throttling and IP blocks.
- **Agent-Ready Metadata (`readOnlyHint: true`)**: Configured with official MCP annotations so autonomous agents (Claude Desktop, Cursor, etc.) can safely execute scans in automated loops without prompting for approval.
- **No Overclaiming**: Reports exact ICANN RDAP status (`TAKEN` vs `NOT_FOUND_IN_REGISTRY`) rather than misleading DNS resolution guesses.
- **Zero API Keys & $0 Operational Cost**: Runs locally via stdio. Connects directly to authoritative registry endpoints.

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

1. `scan_keyword_tlds`: Scans keyword registration density and commercial saturation across 9+ premier TLDs using official RDAP endpoints.
2. `find_available_combinations`: Generates industry-targeted domain combinations (arctic, energy, tech, finance, security) and identifies candidates not found in the registry at time of check.

## Official Namespace
Namespace Identifier: `surf.insight/domain-radar`

## License
MIT © [datutu / insight.surf](https://insight.surf)
