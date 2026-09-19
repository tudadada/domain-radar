#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import dns from "dns/promises";
import https from "https";
import http from "http";

const server = new Server(
  {
    name: "surf.insight/domain-radar",
    version: "1.2.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const USER_AGENT = "domain-radar/1.2.0 (https://insight.surf; support@insight.surf)";
const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

const INDUSTRY_DICTIONARIES = {
  general: ["pro", "hub", "point", "base", "network", "direct", "online", "group", "world", "zone", "link", "shop", "club", "center"],
  tech: ["ai", "data", "cloud", "core", "labs", "systems", "tech", "protocol", "intel", "node", "cyber", "stack"],
  energy: ["power", "energy", "oil", "gas", "marine", "subsea", "grid", "clean", "solar", "battery", "green"],
  finance: ["capital", "fund", "ventures", "invest", "holdings", "group", "wealth", "trust", "equity", "asset"],
  arctic: ["geo", "drilling", "permafrost", "risk", "ice", "polar", "climate", "carbon", "frost", "cold"],
  security: ["sec", "defense", "audit", "guard", "safe", "shield", "auth", "trust", "lock", "cyber"],
};

const INFIX_MODIFIERS = ["the", "my", "get", "top", "pro", "global", "smart", "all", "best"];

const DIGIT_PATTERNS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "24", "360", "365", "247", "101", "88", "99", "2026"];

const BUILTIN_RDAP_BASES = {
  com: "https://rdap.verisign.com/com/v1/domain/",
  net: "https://rdap.verisign.com/net/v1/domain/",
  org: "https://rdap.publicinterestregistry.org/rdap/domain/",
  info: "https://rdap.identitydigital.services/rdap/domain/",
  biz: "https://rdap.nic.biz/domain/",
  ca: "https://rdap.ca.fury.ca/rdap/domain/",
  de: "https://rdap.denic.de/domain/",
  io: "https://rdap.identitydigital.services/rdap/domain/",
  ai: "https://rdap.identitydigital.services/rdap/domain/",
  xyz: "https://rdap.centralnic.com/xyz/domain/",
  tech: "https://rdap.radix.host/rdap/domain/",
  app: "https://pubapi.registry.google/rdap/domain/",
  cloud: "https://rdap.registry.cloud/rdap/domain/",
  co: "https://rdap.nic.co/domain/",
};

let ianaBootstrapCache = null;
let ianaBootstrapPromise = null;

async function getIanaMap() {
  if (ianaBootstrapCache) return ianaBootstrapCache;
  if (!ianaBootstrapPromise) {
    ianaBootstrapPromise = new Promise((resolve) => {
      const req = https.get(
        "https://data.iana.org/rdap/dns.json",
        { headers: { "User-Agent": USER_AGENT }, timeout: 4000 },
        (res) => {
          let data = "";
          res.on("data", (chunk) => (data += chunk));
          res.on("end", () => {
            try {
              const json = JSON.parse(data);
              const map = {};
              for (const [tlds, urls] of json.services) {
                for (const t of tlds) {
                  const u = urls[0].endsWith("/") ? urls[0] : urls[0] + "/";
                  map[t] = u.endsWith("domain/") ? u : u + "domain/";
                }
              }
              ianaBootstrapCache = map;
              resolve(map);
            } catch (e) {
              resolve({});
            }
          });
        }
      );
      req.on("error", () => resolve({}));
      req.on("timeout", () => {
        req.destroy();
        resolve({});
      });
    });
  }
  return ianaBootstrapPromise;
}

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
  let base = BUILTIN_RDAP_BASES[tld];
  if (!base) {
    const ianaMap = await getIanaMap();
    if (ianaMap && ianaMap[tld]) {
      base = ianaMap[tld];
    }
  }

  if (base) {
    const targetUrl = base.endsWith("/") ? base + domain : base + "/" + domain;
    const rdapStatus = await queryRdap(targetUrl);
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

async function probeDomainActivity(domain) {
  try {
    await dns.lookup(domain);
  } catch (e) {
    return {
      status: "INACTIVE",
      detail: "No resolving DNS A/AAAA records (dormant/unconfigured)",
    };
  }

  return new Promise((resolve) => {
    let finished = false;
    const done = (val) => {
      if (!finished) {
        finished = true;
        resolve(val);
      }
    };

    const reqHttps = https.get(
      "https://" + domain,
      {
        timeout: 2500,
        headers: { "User-Agent": BROWSER_UA },
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > 2500) reqHttps.destroy();
        });
        res.on("close", () => {
          const lower = body.toLowerCase();
          const isParked = [
            "domain for sale",
            "buy this domain",
            "sedoparking",
            "dan.com",
            "hugedomains",
            "parked free",
            "this domain is parked",
            "inquire about this domain",
            "domain is for sale",
          ].some((k) => lower.includes(k));

          if (isParked) {
            done({
              status: "PARKED",
              detail: "Parked or listed for sale on aftermarket marketplace",
              httpStatus: res.statusCode,
            });
          } else {
            done({
              status: "ACTIVE",
              detail: "Active website/service operating (Commercial Use)",
              httpStatus: res.statusCode,
            });
          }
        });
      }
    );

    reqHttps.on("error", () => {
      // Fallback to HTTP
      const reqHttp = http.get(
        "http://" + domain,
        {
          timeout: 2000,
          headers: { "User-Agent": BROWSER_UA },
        },
        (resHttp) => {
          let bodyHttp = "";
          resHttp.on("data", (chunk) => {
            bodyHttp += chunk;
            if (bodyHttp.length > 2000) reqHttp.destroy();
          });
          resHttp.on("close", () => {
            const lower = bodyHttp.toLowerCase();
            const isParked = [
              "domain for sale",
              "buy this domain",
              "sedoparking",
              "dan.com",
              "hugedomains",
              "parked free",
              "is parked",
            ].some((k) => lower.includes(k));

            if (isParked) {
              done({
                status: "PARKED",
                detail: "Parked or listed for sale on aftermarket marketplace",
                httpStatus: resHttp.statusCode,
              });
            } else {
              done({
                status: "ACTIVE",
                detail: "Active website operating over HTTP",
                httpStatus: resHttp.statusCode,
              });
            }
          });
        }
      );

      reqHttp.on("error", () =>
        done({
          status: "INACTIVE",
          detail: "DNS configured but web server is unreachable/offline",
        })
      );
      reqHttp.on("timeout", () => {
        reqHttp.destroy();
        done({
          status: "INACTIVE",
          detail: "Connection timed out",
        });
      });
    });

    reqHttps.on("timeout", () => {
      reqHttps.destroy();
      done({
        status: "INACTIVE",
        detail: "HTTPS connection timed out",
      });
    });
  });
}

async function batchProcess(items, fn, batchSize = 3, delayMs = 100) {
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
        name: "search_keyword_domains",
        title: "DotDB-Style Keyword Domain Intelligence",
        description:
          "Full DotDB-style domain search engine. Supports keyword placement (beginning/prefix, end/suffix, any/contains), character inclusion toggles (alphabets, digits, hyphens), site status filtering (Active in use, Parked for sale, Inactive/dormant, and Unregistered available), and extension filtering across 1,200+ IANA TLDs.",
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
              description: "The core keyword to search/audit (e.g. weddingshoes, permafrost, agent)",
            },
            position: {
              type: "string",
              enum: ["beginning", "end", "any"],
              description: "Keyword position: 'beginning' (starts with keyword), 'end' (ends with keyword), or 'any' (keyword anywhere)",
              default: "any",
            },
            include_alphabets: {
              type: "boolean",
              description: "Include word/alphabet combinations. Set to false if searching purely numeric variants.",
              default: true,
            },
            include_digits: {
              type: "boolean",
              description: "Include numeric digits (0-9, 24, 365, etc.). When false, enforces pure letter-only domains.",
              default: true,
            },
            include_hyphens: {
              type: "boolean",
              description: "Include hyphenated domain variants. When false, enforces strictly unhyphenated domains.",
              default: true,
            },
            site_status_filter: {
              type: "array",
              items: {
                type: "string",
                enum: ["active", "parked", "inactive", "unregistered", "all"],
              },
              description: "Filter returned results by site status: 'active' (live site in use), 'parked' (for sale/parking), 'inactive' (dormant/no DNS), 'unregistered' (available in registry), or 'all'",
              default: ["all"],
            },
            extensions: {
              type: "array",
              items: { type: "string" },
              description: "List of TLD extensions to check (e.g. ['com', 'net', 'ai', 'io', 'xyz']). Defaults to ['com'].",
              default: ["com"],
            },
            industry: {
              type: "string",
              enum: ["general", "tech", "energy", "finance", "arctic", "security"],
              description: "Target industry dictionary for word pairings",
              default: "general",
            },
            min_length: {
              type: "integer",
              description: "Minimum character length (excluding extension)",
            },
            max_length: {
              type: "integer",
              description: "Maximum character length (excluding extension)",
            },
            exclude: {
              type: "string",
              description: "Substring or word to exclude from generated candidates",
            },
          },
          required: ["keyword"],
        },
      },
      {
        name: "scan_keyword_tlds",
        title: "Scan Keyword TLD Coverage Matrix",
        description:
          "Audits a core keyword across major authoritative RDAP registries (supports 1,200+ global TLDs: .com, .net, .org, .ai, .io, .xyz, .tech, .app, .cloud, etc.) to report commercial registration density and probe live web activity for taken domains.",
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
              description: "The root keyword to audit across TLD extensions (e.g. weddingshoes, permafrost, agent)",
            },
            tlds: {
              type: "array",
              items: { type: "string" },
              description: "List of TLDs to scan. Defaults to premier 11: com, net, org, ai, io, xyz, tech, app, cloud, co, de",
            },
          },
          required: ["keyword"],
        },
      },
      {
        name: "search_keyword_combinations",
        title: "Search Keyword Combinations (Alias)",
        description: "Alias for search_keyword_domains.",
        annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
        inputSchema: {
          type: "object",
          properties: {
            keyword: { type: "string" },
            position: { type: "string", enum: ["beginning", "end", "any", "prefix", "suffix", "inside", "all"] },
            include_alphabets: { type: "boolean" },
            include_digits: { type: "boolean" },
            include_hyphens: { type: "boolean" },
            extensions: { type: "array", items: { type: "string" } },
          },
          required: ["keyword"],
        },
      },
      {
        name: "find_available_combinations",
        title: "Legacy Combinations Alias",
        description: "Backward-compatible alias for search_keyword_domains.",
        annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
        inputSchema: {
          type: "object",
          properties: {
            keyword: { type: "string" },
            position: { type: "string" },
            industry: { type: "string" },
          },
          required: ["keyword"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const rawKw = (args?.keyword || "").toLowerCase().replace(/[^a-z0-9-]/g, "");

  if (!rawKw) throw new Error("A valid keyword is required");

  if (name === "scan_keyword_tlds") {
    const rawTlds = Array.isArray(args?.tlds) && args.tlds.length > 0
      ? args.tlds.map((t) => t.replace(/^\./, "").toLowerCase())
      : ["com", "net", "org", "ai", "io", "xyz", "tech", "app", "cloud", "co", "de"];

    const registryResults = {};
    await batchProcess(
      rawTlds,
      async (t) => {
        const domain = `${rawKw}.${t}`;
        registryResults[domain] = await checkDomainStatus(domain, t);
      },
      3,
      100
    );

    const takenDomains = Object.keys(registryResults).filter(
      (d) => registryResults[d] === "TAKEN"
    );
    const unregisteredDomains = Object.keys(registryResults).filter(
      (d) => registryResults[d] === "NOT_FOUND_IN_REGISTRY"
    );

    const activityReport = {};
    if (takenDomains.length > 0) {
      await batchProcess(
        takenDomains,
        async (dom) => {
          activityReport[dom] = await probeDomainActivity(dom);
        },
        3,
        100
      );
    }

    const activeInUse = takenDomains.filter(
      (d) => activityReport[d]?.status === "ACTIVE"
    );
    const parkedDomains = takenDomains.filter(
      (d) => activityReport[d]?.status === "PARKED"
    );
    const inactiveDomains = takenDomains.filter(
      (d) => activityReport[d]?.status === "INACTIVE"
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              keyword: rawKw,
              total_extensions_audited: rawTlds.length,
              summary: {
                unregistered_available: unregisteredDomains.length,
                registered_total: takenDomains.length,
                active_websites_in_use: activeInUse.length,
                parked_for_sale: parkedDomains.length,
                inactive_dormant: inactiveDomains.length,
              },
              unregistered_extensions: unregisteredDomains,
              active_domains_in_use: activeInUse,
              parked_for_sale_domains: parkedDomains,
              inactive_dormant_domains: inactiveDomains,
              detailed_activity: activityReport,
              audited_at: new Date().toISOString(),
              verified_by: "Authoritative IANA RDAP Registry & Live Network Probe (insight.surf)",
            },
            null,
            2
          ),
        },
      ],
    };
  }

  if (
    name === "search_keyword_domains" ||
    name === "search_keyword_combinations" ||
    name === "find_available_combinations"
  ) {
    // Normalization of position parameter (DotDB style)
    let pos = args?.position || "any";
    if (pos === "prefix") pos = "beginning";
    if (pos === "suffix") pos = "end";
    if (pos === "inside" || pos === "all" || pos === "both") pos = "any";

    const incAlpha = args?.include_alphabets !== false;
    const incDigits = args?.include_digits !== false;
    const incHyphens = args?.include_hyphens !== false;
    const ind = args?.industry || "general";
    const excludeStr = (args?.exclude || "").toLowerCase();
    const minLen = typeof args?.min_length === "number" ? args.min_length : 0;
    const maxLen = typeof args?.max_length === "number" ? args.max_length : 63;

    const statusFilter = Array.isArray(args?.site_status_filter) && args.site_status_filter.length > 0
      ? args.site_status_filter.map((s) => s.toLowerCase())
      : ["all"];

    const rawTlds = Array.isArray(args?.extensions) && args.extensions.length > 0
      ? args.extensions.map((t) => t.replace(/^\./, "").toLowerCase())
      : Array.isArray(args?.tlds) && args.tlds.length > 0
      ? args.tlds.map((t) => t.replace(/^\./, "").toLowerCase())
      : ["com"];

    const dict = INDUSTRY_DICTIONARIES[ind] || INDUSTRY_DICTIONARIES.general;
    const stems = new Set();

    // Helper to add stem considering hyphens
    const addStem = (left, right) => {
      stems.add(`${left}${right}`);
      if (incHyphens) {
        stems.add(`${left}-${right}`);
      }
    };

    const addTripleStem = (mod, core, word) => {
      stems.add(`${mod}${core}${word}`);
      if (incHyphens) {
        stems.add(`${mod}-${core}-${word}`);
      }
    };

    // 1. Alphabet word generation
    if (incAlpha) {
      if (pos === "beginning" || pos === "any") {
        for (const w of dict) addStem(rawKw, w);
      }
      if (pos === "end" || pos === "any") {
        for (const w of dict) addStem(w, rawKw);
      }
      if (pos === "any") {
        for (const mod of INFIX_MODIFIERS.slice(0, 4)) {
          for (const w of dict.slice(0, 3)) {
            addTripleStem(mod, rawKw, w);
          }
        }
      }
    }

    // 2. Numeric digits generation (0-9, 24, 365, etc.)
    if (incDigits) {
      if (pos === "beginning" || pos === "any") {
        for (const d of DIGIT_PATTERNS) addStem(rawKw, d);
      }
      if (pos === "end" || pos === "any") {
        for (const d of DIGIT_PATTERNS) addStem(d, rawKw);
      }
    }

    // Filter stems by length and exclude criteria
    const filteredStems = Array.from(stems).filter((s) => {
      if (minLen > 0 && s.length < minLen) return false;
      if (maxLen < 63 && s.length > maxLen) return false;
      if (excludeStr && s.includes(excludeStr)) return false;
      return true;
    });

    // Expand stems across target TLDs
    const candidateList = [];
    for (const s of filteredStems) {
      for (const t of rawTlds) {
        candidateList.push({ domain: `${s}.${t}`, tld: t, stem: s });
      }
    }

    // Deduplicate
    const uniqueMap = new Map();
    for (const c of candidateList) {
      if (!uniqueMap.has(c.domain)) uniqueMap.set(c.domain, c);
    }
    const uniqueCandidates = Array.from(uniqueMap.values());

    // Step 1: RDAP check
    const rdapStatus = {};
    await batchProcess(
      uniqueCandidates,
      async (c) => {
        rdapStatus[c.domain] = await checkDomainStatus(c.domain, c.tld);
      },
      3,
      100
    );

    const unregisteredList = uniqueCandidates
      .filter((c) => rdapStatus[c.domain] === "NOT_FOUND_IN_REGISTRY")
      .map((c) => c.domain);

    const takenCandidates = uniqueCandidates.filter(
      (c) => rdapStatus[c.domain] === "TAKEN"
    );

    // Step 2: Site Status Probing (Active in use vs Parked vs Inactive)
    const activityReport = {};
    if (takenCandidates.length > 0) {
      await batchProcess(
        takenCandidates,
        async (c) => {
          activityReport[c.domain] = await probeDomainActivity(c.domain);
        },
        3,
        100
      );
    }

    const activeList = takenCandidates
      .filter((c) => activityReport[c.domain]?.status === "ACTIVE")
      .map((c) => c.domain);

    const parkedList = takenCandidates
      .filter((c) => activityReport[c.domain]?.status === "PARKED")
      .map((c) => c.domain);

    const inactiveList = takenCandidates
      .filter((c) => activityReport[c.domain]?.status === "INACTIVE")
      .map((c) => c.domain);

    // Apply site status filtering if specified by user
    const filterAll = statusFilter.includes("all");
    const wantActive = filterAll || statusFilter.includes("active");
    const wantParked = filterAll || statusFilter.includes("parked");
    const wantInactive = filterAll || statusFilter.includes("inactive");
    const wantUnregistered = filterAll || statusFilter.includes("unregistered");

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              search_query: {
                keyword: rawKw,
                position: pos,
                includes: {
                  alphabets: incAlpha,
                  digits: incDigits,
                  hyphens: incHyphens,
                },
                extensions_scanned: rawTlds,
                site_status_filter: statusFilter,
              },
              summary_statistics: {
                total_evaluated: uniqueCandidates.length,
                unregistered_available_count: unregisteredList.length,
                registered_total_count: takenCandidates.length,
                site_status_breakdown: {
                  active_in_use_count: activeList.length,
                  parked_for_sale_count: parkedList.length,
                  inactive_dormant_count: inactiveList.length,
                },
              },
              results: {
                unregistered_domains: wantUnregistered ? unregisteredList : undefined,
                active_domains_in_use: wantActive ? activeList : undefined,
                parked_for_sale_domains: wantParked ? parkedList : undefined,
                inactive_dormant_domains: wantInactive ? inactiveList : undefined,
              },
              site_status_details: activityReport,
              verified_by: "DotDB-Standard Engine (Authoritative RDAP + Live HTTP Probe via insight.surf)",
              notice: "Unregistered domains were not found in authoritative registries at audit time. Always verify registrar pricing and trademark conflicts prior to purchase.",
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
