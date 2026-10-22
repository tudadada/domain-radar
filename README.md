# domain-radar

[![npm version](https://img.shields.io/npm/v/domain-radar.svg)](https://www.npmjs.com/package/domain-radar)
[![Powered by insight.surf](https://img.shields.io/badge/Powered%20by-insight.surf-blue.svg)](https://insight.surf)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Domain Radar** is a production-grade Model Context Protocol (MCP) server powered by **[insight.surf](https://insight.surf)**. Built for domain investors, founders, and autonomous AI research agents, it performs authoritative multi-TLD RDAP registry auditing, historical timeline sorting, keyword combination generation, and real-time live website activity probing.

## Core Capabilities

- **1,400+ Global IANA TLD Full-Spectrum Scanning**: Audits exact keywords across the entire directory of over 1,400 top-level domains (`.com`, `.net`, `.org`, `.ai`, `.io`, `.xyz`, `.tech`, `.app`, `.cloud`, `.co`, `.de`, ccTLDs, and new gTLDs).
- **Registration Year & Historical Timeline Analysis**: Extracts authoritative creation dates / registration years from official RDAP registries and socket WHOIS fallbacks.
- **Chronological Sorting (Oldest $\rightarrow$ Newest)**: Instantly presents the domain registration history from the earliest legacy registration to the newest active brand.
- **Two-Phase High-Speed Pipeline**:
  - *Phase 1 (DNS Pre-scan)*: Multi-worker asynchronous DNS query sweeps all 1,400+ extensions in seconds.
  - *Phase 2 (RDAP/WHOIS Deep Inspection)*: Authoritative extraction of creation date, expiry date, and sponsoring registrar.
- **Live Activity Radar**: Probes registered domains in real-time via HTTP/HTTPS to classify them into `ACTIVE_IN_USE`, `PARKED_FOR_SALE`, or `INACTIVE_DORMANT`.
- **Autonomous Agent-Ready (`readOnlyHint: true`)**: Zero API keys required, running locally via stdio with $0 operational cost.

## Tools Included

### 1. `scan_keyword_tlds` (TLD Timeline & Coverage Radar)
Audits an exact keyword across all registered TLDs (over 1,400+ extensions), extracts registration year and creation date for each registered domain, and returns all results sorted chronologically from oldest to newest registration year.

**Parameters:**
- `keyword` (*string*, required): The core keyword to search (e.g. `"openai"`, `"anthropic"`, `"crypto"`).
- `scope` (*string*, optional, default: `"all"`):
  - `"all"`: All 1,400+ IANA top-level domains.
  - `"popular"`: Top 80–100 commercial extensions.
  - `"gtld"`: New gTLD extensions.
  - `"cctld"`: 2-letter country-code extensions.
- `sort_by` (*string*, optional, default: `"year_asc"`):
  - `"year_asc"`: Oldest registration year to newest.
  - `"year_desc"`: Newest to oldest.
  - `"alphabetical"`: Alphabetical by extension.
- `concurrency` (*integer*, optional, default: 40): Parallel DNS worker count.
- `probe_activity` (*boolean*, optional, default: false): Also probe live HTTP/HTTPS status.

### 2. `get_domain_whois`
Retrieve detailed RDAP/WHOIS information for any specific domain including creation date, expiry date, registrar, status codes, and live website status.

### 3. `search_keyword_domains`
Full DotDB-style domain search engine. Supports keyword placement (`beginning`, `end`, `any`), character filters (`include_alphabets`, `include_digits`, `include_hyphens`), live site status filtering, and custom extension sets.

## Installation & MCP Configuration

Add to your MCP configuration file (`mcp_config.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "domain-radar": {
      "command": "node",
      "args": ["/path/to/domain-radar/index.js"]
    }
  }
}
```

Or run via npx:
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

## License
MIT © [datutu / insight.surf](https://insight.surf)
