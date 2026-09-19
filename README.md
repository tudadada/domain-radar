# domain-radar

[![npm version](https://img.shields.io/npm/v/domain-radar.svg)](https://www.npmjs.com/package/domain-radar)
[![Powered by insight.surf](https://img.shields.io/badge/Powered%20by-insight.surf-blue.svg)](https://insight.surf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Domain Radar** is a high-speed Model Context Protocol (MCP) server powered by **[insight.surf](https://insight.surf)**. It provides real-time keyword TLD coverage matrix scanning and Verisign RDAP availability discovery for domain investors, founders, and AI agents.

## Core Capabilities

- **TLD Matrix Scan**: Audits keyword registration density across 9+ premier TLDs (`.com`, `.net`, `.org`, `.ai`, `.io`, etc.).
- **Available Combination Discovery**: Matches keywords against curated industry dictionaries (arctic, energy, tech, finance) and verifies 100% unregistered status via official Verisign RDAP.
- **Privacy & $0 Operational Cost**: Runs locally via stdio. Zero third-party API keys required.

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

1. `scan_keyword_tlds`: Checks keyword registration across all major global TLDs.
2. `find_available_combinations`: Generates industry-targeted domain names and filters out taken ones in real time.

## Verified Namespace
Official Registry Identifier: `surf.insight/domain-radar`

## License
MIT © [tudadada](https://github.com/tudadada)
