#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import dns from "dns/promises";
import https from "https";

const server = new Server(
  {
    name: "surf.insight/domain-radar",
    version: "1.0.2",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const USER_AGENT = "domain-radar/1.0.1 (https://insight.surf; support@insight.surf)";

const INDUSTRY_DICTIONARIES = {
  tech: ["ai", "data", "cloud", "core", "labs", "systems", "tech", "protocol", "intel", "node"],
  energy: ["power", "energy", "oil", "gas", "marine", "subsea", "grid", "clean", "battery"],
  finance: ["capital", "fund", "ventures", "invest", "holdings", "group", "wealth", "trust"],
  arctic: ["geo", "drilling", "permafrost", "risk", "ice", "polar", "climate", "carbon"],
  security: ["sec", "defense", "audit", "guard", "safe", "shield", "auth", "trust"],
  general: ["pro", "hub", "central", "point", "base", "network", "direct", "online"],
};

const IANA_RDAP_BASES = {
  com: "https://rdap.verisign.com/com/v1/domain/",
  net: "https://rdap.verisign.com/net/v1/domain/",
  org: "https://rdap.publicinterestregistry.org/rdap/domain/",
  info: "https://rdap.identitydigital.services/rdap/domain/",
  biz: "https://rdap.nic.biz/domain/",
  ca: "https://rdap.ca.fury.ca/rdap/domain/",
  de: "https://rdap.denic.de/domain/",
  io: "https://rdap.identitydigital.services/rdap/domain/",
  ai: "https://rdap.identitydigital.services/rdap/domain/",
};

function queryRdap(url) {
  return new Promise((resolve) => {
    const req = https.get(
      url,
      {
        headers: { "User-Agent": USER_AGENT },
        timeout: 4500,
      },
      (res) => {
        const code = res.statusCode;
        res.resume();
        if (code === 200) resolve("TAKEN");
        else if (code === 404) resolve("NOT_FOUND_IN_REGISTRY");
        else if (code === 429) resolve("RATE_LIMITED");
        else resolve("UNKNOWN");
      }
    );
    req.on("error", () => resolve("UNKNOWN"));
    req.on("timeout", () => {
      req.destroy();
      resolve("TIMEOUT");
    });
  });
}

async function checkDomainStatus(domain, tld) {
  const base = IANA_RDAP_BASES[tld];
  if (base) {
    const rdapStatus = await queryRdap(base + domain);
    if (rdapStatus === "TAKEN" || rdapStatus === "NOT_FOUND_IN_REGISTRY") {
      return rdapStatus;
    }
  }

  // Authoritative DNS Name Server delegation fallback (for ccTLDs or RDAP timeouts)
  try {
    const ns = await dns.resolveNs(domain);
    if (ns && ns.length > 0) return "TAKEN";
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      return "NOT_FOUND_IN_REGISTRY";
    }
  }

  return "UNKNOWN";
}

async function batchProcess(items, fn, batchSize = 3, delayMs = 120) {
  const results = [];
  for (let i = 0; i < items.length; i += batchSize) {
    const chunk = items.slice(i, i + batchSize);
    const chunkResults = await Promise.all(chunk.map(fn));
    results.push(...chunkResults);
    if (i + batchSize < items.length && delayMs > 0) {
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  return results;
}

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "scan_keyword_tlds",
        title: "Scan Keyword TLD Coverage",
        description:
          "Audits a core keyword across major authoritative RDAP registries (.com, .net, .org, .info, .biz, .ca, .de, .io, .ai) to measure commercial registration density and identify extensions not found in registry at time of check.",
        annotations: {
          readOnlyHint: true,
          idempotentHint: true,
          openWorldHint: true,
        },
        inputSchema: {
          type: "object",
          properties: {
            keyword: {
              type: "string",
              description: "The root keyword to audit (e.g. permafrost, subsea, agent)",
            },
          },
          required: ["keyword"],
        },
      },
      {
        name: "find_available_combinations",
        title: "Find Industry Keyword Combinations",
        description:
          "Generates industry-specific combinations (prefix/suffix) with a target keyword and queries authoritative RDAP registries with polite rate-limiting to discover candidate domains not found in registry at time of check.",
        annotations: {
          readOnlyHint: true,
          idempotentHint: true,
          openWorldHint: true,
        },
        inputSchema: {
          type: "object",
          properties: {
            keyword: {
              type: "string",
              description: "Target keyword",
            },
            position: {
              type: "string",
              enum: ["prefix", "suffix", "both"],
              description: "Position of keyword: prefix (keyword+word) or suffix (word+keyword)",
            },
            industry: {
              type: "string",
              enum: ["tech", "energy", "finance", "arctic", "security", "general"],
              description: "Target industry dictionary",
            },
          },
          required: ["keyword"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const kw = (args?.keyword || "").toLowerCase().replace(/[^a-z0-9]/g, "");

  if (!kw) throw new Error("A valid keyword is required");

  if (name === "scan_keyword_tlds") {
    const tlds = ["com", "net", "org", "info", "biz", "ca", "de", "io", "ai"];
    const results = {};

    await batchProcess(
      tlds,
      async (t) => {
        const domain = `${kw}.${t}`;
        results[domain] = await checkDomainStatus(domain, t);
      },
      3,
      100
    );

    const takenCount = Object.values(results).filter((v) => v === "TAKEN").length;
    const commercialDensity =
      takenCount >= 7 ? "ULTRA_HIGH" : takenCount >= 4 ? "HIGH" : "MODERATE";

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              keyword: kw,
              source: "insight.surf Domain Radar",
              total_tlds_scanned: tlds.length,
              registered_count: takenCount,
              commercial_density_score: commercialDensity,
              status_legend: {
                TAKEN: "Domain is registered in authoritative registry / delegated",
                NOT_FOUND_IN_REGISTRY: "Domain not found in authoritative registry at time of check (candidate for registration)",
                RATE_LIMITED: "Registry rate limit reached, recheck later",
                UNKNOWN: "Could not be determined authoritatively"
              },
              matrix: results,
              audited_at: new Date().toISOString(),
              notice: "Domains reported as NOT_FOUND_IN_REGISTRY were unregistered at time of check. Please verify registrar pricing, premium tiers, or trademark restrictions prior to purchase."
            },
            null,
            2
          ),
        },
      ],
    };
  }

  if (name === "find_available_combinations") {
    const pos = args?.position || "prefix";
    const ind = args?.industry || "general";
    const dict = INDUSTRY_DICTIONARIES[ind] || INDUSTRY_DICTIONARIES.general;

    const candidates = [];
    for (const w of dict) {
      if (pos === "prefix" || pos === "both") candidates.push(`${kw}${w}.com`);
      if (pos === "suffix" || pos === "both") candidates.push(`${w}${kw}.com`);
    }

    const rdapResults = {};
    await batchProcess(
      candidates,
      async (dom) => {
        rdapResults[dom] = await checkDomainStatus(dom, "com");
      },
      3,
      120
    );

    const availableList = Object.keys(rdapResults).filter(
      (d) => rdapResults[d] === "NOT_FOUND_IN_REGISTRY"
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              keyword: kw,
              industry: ind,
              position: pos,
              total_generated: candidates.length,
              unregistered_candidates_count: availableList.length,
              unregistered_candidates: availableList,
              full_status: rdapResults,
              verified_by: "Authoritative Verisign RDAP Registry (Rate-limited & Throttled)",
              notice: "Domains reported as NOT_FOUND_IN_REGISTRY were unregistered at time of check. Always verify real-time registrar status and premium pricing before placing registration orders."
            },
            null,
            2
          ),
        },
      ],
    };
  }

  throw new Error(`Tool ${name} not found`);
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
