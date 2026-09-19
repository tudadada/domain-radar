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
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const INDUSTRY_DICTIONARIES = {
  tech: ["ai", "data", "cloud", "core", "labs", "systems", "tech", "protocol", "intel", "node"],
  energy: ["power", "energy", "oil", "gas", "marine", "subsea", "grid", "clean", "battery"],
  finance: ["capital", "fund", "ventures", "invest", "holdings", "group", "wealth", "trust"],
  arctic: ["geo", "drilling", "permafrost", "risk", "ice", "polar", "climate", "carbon"],
  security: ["sec", "defense", "audit", "guard", "safe", "shield", "auth", "trust"],
  general: ["pro", "hub", "central", "point", "base", "network", "direct", "online"]
};

async function checkDns(domain) {
  try {
    await dns.lookup(domain);
    return "TAKEN";
  } catch (err) {
    return "POTENTIALLY_AVAILABLE";
  }
}

function checkVerisignRdap(domain) {
  return new Promise((resolve) => {
    const url = `https://rdap.verisign.com/com/v1/domain/${domain}`;
    const req = https.get(url, { headers: { "User-Agent": "DomainRadar/1.0" }, timeout: 4000 }, (res) => {
      if (res.statusCode === 200) resolve("TAKEN");
      else if (res.statusCode === 404) resolve("AVAILABLE");
      else resolve("UNKNOWN");
    });
    req.on("error", () => resolve("TIMEOUT"));
    req.on("timeout", () => { req.destroy(); resolve("TIMEOUT"); });
  });
}

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "scan_keyword_tlds",
        description: "Audits a core keyword across major TLDs (.com, .net, .org, .ai, .io, .co, .ca, .de) to report registration status and commercial density.",
        inputSchema: {
          type: "object",
          properties: {
            keyword: {
              type: "string",
              description: "The root keyword to audit (e.g. permafrost, subsea)",
            },
          },
          required: ["keyword"],
        },
      },
      {
        name: "find_available_combinations",
        description: "Generates industry-specific combinations (prefix/suffix) with a target keyword and checks Verisign RDAP to return 100% AVAILABLE domains.",
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
              description: "Position of keyword",
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
    const tlds = ["com", "net", "org", "ai", "io", "co", "ca", "de", "us"];
    const results = {};

    await Promise.all(
      tlds.map(async (t) => {
        const domain = `${kw}.${t}`;
        results[domain] = await checkDns(domain);
      })
    );

    const takenCount = Object.values(results).filter(v => v === "TAKEN").length;
    const commercialDensity = takenCount >= 7 ? "ULTRA_HIGH" : takenCount >= 4 ? "HIGH" : "MODERATE";

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
              matrix: results,
              audited_at: new Date().toISOString()
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
    await Promise.all(
      candidates.map(async (dom) => {
        rdapResults[dom] = await checkVerisignRdap(dom);
      })
    );

    const availableList = Object.keys(rdapResults).filter(d => rdapResults[d] === "AVAILABLE");

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
              available_domains_count: availableList.length,
              available_domains: availableList,
              full_status: rdapResults,
              verified_by: "Verisign RDAP authoritative registry"
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
