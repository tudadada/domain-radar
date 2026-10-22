import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { INDUSTRY_DICTIONARIES, INFIX_MODIFIERS, DIGIT_PATTERNS } from "./constants.js";
import { checkDomainStatus } from "./rdap.js";
import { probeDomainActivity } from "./probe.js";
import { asyncPool } from "./utils.js";
import { getTldList } from "./iana-tlds.js";
import dns from "dns/promises";
import fs from "fs/promises";
import path from "path";

/**
 * Verifies basic network DNS connectivity to prevent false negative reports on network drop.
 */
async function verifyNetworkConnectivity() {
  const canaryHosts = ["iana.org", "dns.google", "cloudflare.com"];
  for (const host of canaryHosts) {
    try {
      const res = await dns.resolve(host);
      if (res && res.length > 0) return true;
    } catch (e) {}
  }
  return false;
}

/**
 * Canary wildcard DNS detector per TLD.
 * Prevents ccTLD / registrar wildcards from falsely claiming all arbitrary domains are registered.
 */
const wildcardTldCache = new Map();

async function isWildcardTld(tld) {
  if (wildcardTldCache.has(tld)) {
    return wildcardTldCache.get(tld);
  }
  const canaryDomain = `canary-chk-${Math.random().toString(36).slice(2, 10)}-audit.${tld}`;
  let isWild = false;
  try {
    const [ns, ip] = await Promise.allSettled([
      dns.resolveNs(canaryDomain),
      dns.resolve(canaryDomain)
    ]);
    if (
      (ns.status === "fulfilled" && ns.value && ns.value.length > 0) ||
      (ip.status === "fulfilled" && ip.value && ip.value.length > 0)
    ) {
      isWild = true;
    }
  } catch (e) {
    isWild = false;
  }
  wildcardTldCache.set(tld, isWild);
  return isWild;
}

/**
 * Escapes CSV special characters to ensure valid RFC 4180 format.
 */
function escapeCsvField(val) {
  if (val === null || val === undefined) return "";
  const str = String(val);
  if (str.includes(",") || str.includes("\"") || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Builds RFC 4180 compliant CSV string from domain records.
 */
export function buildCsvContent(records, keyword) {
  const headers = [
    "Index",
    "Domain",
    "TLD",
    "TLD_Type",
    "Status",
    "Registration_Year",
    "Creation_Date",
    "Expiration_Date",
    "Registrar",
    "Source",
    "Audited_At"
  ];

  const now = new Date().toISOString();
  const rows = [headers.join(",")];

  records.forEach((r, idx) => {
    let tldType = "New gTLD";
    if (r.tld.length === 2) {
      tldType = "ccTLD";
    } else if (["com", "net", "org", "info", "biz", "pro", "mobi", "name"].includes(r.tld)) {
      tldType = "Legacy gTLD";
    }

    const row = [
      idx + 1,
      escapeCsvField(r.domain),
      escapeCsvField(r.tld),
      escapeCsvField(tldType),
      escapeCsvField(r.status || "TAKEN"),
      escapeCsvField(r.registration_year || "Unknown"),
      escapeCsvField(r.registration_date || "Unknown"),
      escapeCsvField(r.expiration_date || "Unknown"),
      escapeCsvField(r.registrar || "Private / Protected"),
      escapeCsvField(r.source || "Registry"),
      escapeCsvField(now)
    ];
    rows.push(row.join(","));
  });

  return rows.join("\r\n");
}

export function registerTools(server) {
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "scan_keyword_tlds",
          title: "Scan Keyword TLD Timeline, Coverage Radar & CSV Exporter",
          description: "Scans an exact keyword across all registered TLDs (over 1,400+ IANA extensions), extracts registration year and creation date, sorts all domains chronologically from oldest to newest, generates executive era metrics, and optionally exports complete results to a clean CSV spreadsheet.",
          inputSchema: {
            type: "object",
            properties: {
              keyword: { 
                type: "string", 
                description: "The exact core keyword to audit (e.g. 'openai', 'anthropic', 'apple', 'crypto')" 
              },
              scope: {
                type: "string",
                enum: ["all", "popular", "gtld", "cctld"],
                default: "all",
                description: "'all' for all 1,400+ IANA TLDs; 'popular' for top commercial extensions; 'gtld' for new gTLDs; 'cctld' for country codes."
              },
              sort_by: {
                type: "string",
                enum: ["year_asc", "year_desc", "alphabetical"],
                default: "year_asc",
                description: "Sorting order: 'year_asc' (oldest year to newest, default), 'year_desc' (newest to oldest), or 'alphabetical'."
              },
              export_csv: {
                type: "boolean",
                default: false,
                description: "Whether to export the full results to a local CSV file (default: true). Highly recommended for large datasets."
              },
              csv_path: {
                type: "string",
                description: "Optional custom file path to save the exported CSV (e.g. './apple_timeline.csv'). Defaults to current directory."
              },
              min_year: {
                type: "integer",
                description: "Optional filter to include only domains registered in or after this year (e.g. 1980)."
              },
              max_year: {
                type: "integer",
                description: "Optional filter to include only domains registered in or before this year (e.g. 2005)."
              },
              tlds: {
                type: "array",
                items: { type: "string" },
                description: "Optional custom list of specific TLDs to check instead of scope."
              },
              probe_activity: {
                type: "boolean",
                default: false,
                description: "Whether to probe live web activity for taken domains (default false for fastest timeline scan)."
              },
              concurrency: {
                type: "integer",
                default: 40,
                description: "DNS resolution concurrency pool (default 40, max 100)."
              },
              limit: {
                type: "integer",
                default: 1000,
                description: "Max registered domains to inspect in detail (default: 1000)."
              }
            },
            required: ["keyword"],
          },
        },
        {
          name: "get_domain_whois",
          title: "Get Domain WHOIS & Registration Details",
          description: "Retrieve RDAP/WHOIS details for a specific domain including creation date, expiry date, registrant status, and current live activity status.",
          inputSchema: {
            type: "object",
            properties: {
              domain: { type: "string", description: "The full domain name to query (e.g. example.com)" }
            },
            required: ["domain"],
          },
        },
        {
          name: "search_keyword_domains",
          title: "DotDB-Style Keyword Domain Intelligence",
          description: "Full DotDB-style domain search engine. Supports keyword placement, character toggles, site status filtering, and custom extensions.",
          inputSchema: {
            type: "object",
            properties: {
              keyword: { type: "string" },
              position: { type: "string", enum: ["beginning", "end", "any"], default: "any" },
              include_alphabets: { type: "boolean", default: true },
              include_digits: { type: "boolean", default: true },
              include_hyphens: { type: "boolean", default: true },
              site_status_filter: { type: "array", items: { type: "string", enum: ["active", "parked", "inactive", "unregistered", "all"] }, default: ["all"] },
              extensions: { type: "array", items: { type: "string" }, default: ["com"] },
              industry: { type: "string", enum: ["general", "tech", "energy", "finance", "arctic", "security", "custom"], default: "general" },
              custom_words: { type: "array", items: { type: "string" }, description: "Custom prefix/suffix words if industry is 'custom'" },
              min_length: { type: "integer" },
              max_length: { type: "integer" },
              exclude: { type: "string" },
            },
            required: ["keyword"],
          },
        },
        {
          name: "search_keyword_combinations",
          description: "Alias for search_keyword_domains.",
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
          description: "Legacy Combinations Alias",
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

    if (name === "get_domain_whois") {
      const domain = (args?.domain || "").toLowerCase().trim();
      if (!domain || !domain.includes(".")) throw new Error("A valid domain is required");
      
      const parts = domain.split(".");
      const tld = parts.slice(1).join(".");
      
      const rdapResult = await checkDomainStatus(domain, tld, true);
      const activityResult = await probeDomainActivity(domain);
      
      if (rdapResult?.details?.raw) delete rdapResult.details.raw;

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                domain,
                registry_status: rdapResult,
                live_activity: activityResult,
                audited_at: new Date().toISOString()
              },
              null,
              2
            ),
          },
        ],
      };
    }

    const rawKw = (args?.keyword || "").toLowerCase().replace(/[^a-z0-9-]/g, "");
    if (!rawKw) throw new Error("A valid keyword is required");

    if (name === "scan_keyword_tlds") {
      const isOnline = await verifyNetworkConnectivity();
      if (!isOnline) {
        throw new Error("DNS network connectivity check failed: Unable to resolve root nameservers. Please verify your internet connection before scanning.");
      }
      const scope = args?.scope || "all";
      const sortBy = args?.sort_by || "year_asc";
      const probeActivity = args?.probe_activity === true;
      const concurrency = typeof args?.concurrency === "number" ? Math.min(Math.max(args.concurrency, 10), 100) : 40;
      const limit = typeof args?.limit === "number" ? args.limit : 1000;
      const exportCsv = args?.export_csv === true; // Default: false

      const minYear = typeof args?.min_year === "number" ? args.min_year : null;
      const maxYear = typeof args?.max_year === "number" ? args.max_year : null;

      // 1. Get targeted TLD list
      const targetTlds = await getTldList(scope, args?.tlds);

      // 2. High-speed concurrent DNS pre-filter across all targeted TLDs
      const takenCandidates = [];
      const unregisteredTlds = [];
      const unverifiedTlds = [];

      await asyncPool(concurrency, targetTlds, async (tld) => {
        const domain = `${rawKw}.${tld}`;
        let hasNs = false;
        let hasIp = false;

        try {
          const ns = await dns.resolveNs(domain);
          if (ns && ns.length > 0) hasNs = true;
        } catch (e) {
          // If DNS failed with temporary/network error, don't assume unregistered yet
        }

        if (!hasNs) {
          try {
            const ip = await dns.resolve(domain);
            if (ip && ip.length > 0) hasIp = true;
          } catch (e) {
            if (e.code !== "ENOTFOUND" && e.code !== "ENODATA" && e.code !== "EBADNAME") {
              // Network or resolver failure
              unverifiedTlds.push({ tld, reason: e.code || e.message });
              return;
            }
          }
        }

        if (hasNs || hasIp) {
          const isWildcard = await isWildcardTld(tld);
          takenCandidates.push({ domain, tld, isWildcard });
        } else {
          unregisteredTlds.push(tld);
        }
      });

      // 3. For taken candidates, query RDAP/WHOIS to extract registration year & creation date
      let registeredRecords = [];
      const rdapPoolLimit = 10;

      await asyncPool(rdapPoolLimit, takenCandidates.slice(0, limit), async ({ domain, tld, isWildcard }) => {
        try {
          const res = await checkDomainStatus(domain, tld, true);

          // Bug 1 Fix: Explicitly exclude domains confirmed not registered
          if (res?.status === "NOT_FOUND_IN_REGISTRY" || res?.status === "AVAILABLE") {
            unregisteredTlds.push(tld);
            return;
          }

          if (res?.status === "TAKEN") {
            const details = res?.details || {};
            const creationDate = details.creationDate || null;
            
            let year = null;
            if (creationDate) {
              const yMatch = String(creationDate).match(/\b(19\d{2}|20\d{2})\b/);
              if (yMatch) year = parseInt(yMatch[1], 10);
            }

            registeredRecords.push({
              domain,
              tld,
              registration_year: year,
              registration_date: creationDate || "Unknown",
              expiration_date: details.expirationDate || "Unknown",
              registrar: details.registrar || "Private / Protected",
              status: "TAKEN",
              source: details.source || "Registry"
            });
            return;
          }

          // Bug 2 Fix: If status is not TAKEN, wildcard TLDs cannot rely on DNS delegation!
          if (isWildcard) {
            unverifiedTlds.push({ tld, reason: "Wildcard DNS without authoritative RDAP/WHOIS record" });
            return;
          }

          // For standard TLDs, DNS resolution is a solid delegation indicator even if RDAP timed out or has no server
          registeredRecords.push({
            domain,
            tld,
            registration_year: null,
            registration_date: "Unknown",
            expiration_date: "Unknown",
            registrar: "Private / Protected",
            status: "TAKEN",
            source: "DNS Delegation"
          });
        } catch (err) {
          if (isWildcard) {
            unverifiedTlds.push({ tld, reason: "Wildcard DNS inspection error" });
            return;
          }
          registeredRecords.push({
            domain,
            tld,
            registration_year: null,
            registration_date: "Unknown",
            expiration_date: "Unknown",
            registrar: "Private / Protected",
            status: "TAKEN",
            source: "DNS Delegation"
          });
        }
      });

      // Filter by min_year / max_year if specified
      if (minYear !== null || maxYear !== null) {
        registeredRecords = registeredRecords.filter(r => {
          if (!r.registration_year) return false;
          if (minYear !== null && r.registration_year < minYear) return false;
          if (maxYear !== null && r.registration_year > maxYear) return false;
          return true;
        });
      }

      // 4. Probe live activity if requested
      if (probeActivity && registeredRecords.length > 0) {
        await asyncPool(5, registeredRecords, async (record) => {
          try {
            const probe = await probeDomainActivity(record.domain);
            record.live_activity = probe;
          } catch (e) {
            record.live_activity = { status: "UNKNOWN" };
          }
        });
      }

      // 5. Sort results
      registeredRecords.sort((a, b) => {
        if (sortBy === "year_asc") {
          // Oldest to Newest
          if (a.registration_year && b.registration_year) {
            if (a.registration_year !== b.registration_year) return a.registration_year - b.registration_year;
            return (a.registration_date || "").localeCompare(b.registration_date || "");
          }
          if (a.registration_year) return -1;
          if (b.registration_year) return 1;
          return a.domain.localeCompare(b.domain);
        } else if (sortBy === "year_desc") {
          // Newest to Oldest
          if (a.registration_year && b.registration_year) {
            if (a.registration_year !== b.registration_year) return b.registration_year - a.registration_year;
            return (b.registration_date || "").localeCompare(a.registration_date || "");
          }
          if (a.registration_year) return -1;
          if (b.registration_year) return 1;
          return a.domain.localeCompare(b.domain);
        } else {
          // Alphabetical
          return a.domain.localeCompare(b.domain);
        }
      });

      // 6. Generate CSV file if requested
      let csvFilePath = null;
      let csvRaw = null;
      if (exportCsv && registeredRecords.length > 0) {
        csvRaw = buildCsvContent(registeredRecords, rawKw);
        const fileName = `${rawKw}_tld_timeline_${Date.now()}.csv`;
        const targetPath = args?.csv_path ? path.resolve(args.csv_path) : path.resolve(process.cwd(), fileName);
        try {
          await fs.writeFile(targetPath, csvRaw, "utf8");
          csvFilePath = targetPath;
        } catch (e) {
          const fallbackPath = path.resolve(process.cwd(), fileName);
          await fs.writeFile(fallbackPath, csvRaw, "utf8");
          csvFilePath = fallbackPath;
        }
      }

      // 7. Calculate Era Distribution & Dominant Registrars
      let pre2000 = 0, era2000s = 0, era2010s = 0, era2020s = 0, unknownYears = 0;
      registeredRecords.forEach(r => {
        if (!r.registration_year) {
          unknownYears++;
        } else if (r.registration_year < 2000) {
          pre2000++;
        } else if (r.registration_year < 2010) {
          era2000s++;
        } else if (r.registration_year < 2020) {
          era2010s++;
        } else {
          era2020s++;
        }
      });

      const registrarCounts = {};
      registeredRecords.forEach(r => {
        const reg = r.registrar || "Private / Protected";
        registrarCounts[reg] = (registrarCounts[reg] || 0) + 1;
      });
      const topRegistrars = Object.entries(registrarCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([regName, count]) => `${regName} (${count})`);

      const withYear = registeredRecords.filter(r => r.registration_year !== null);
      const oldest = withYear.length > 0 ? withYear[0] : null;
      const newest = withYear.length > 0 ? withYear[withYear.length - 1] : null;

      // 8. Build Stratified English Markdown Representation
      let md = `## Keyword Registration Timeline Radar: "${rawKw}"\n\n`;
      md += `### Executive Overview\n`;
      md += `- **Keyword Audited**: \`${rawKw}\`\n`;
      md += `- **Coverage Density**: **${registeredRecords.length}** / **${targetTlds.length}** TLDs registered (${((registeredRecords.length / targetTlds.length) * 100).toFixed(1)}%)\n`;
      if (oldest) {
        const oDate = oldest.registration_date.includes("T") ? oldest.registration_date.split("T")[0] : oldest.registration_date;
        md += `- **Oldest Inception**: \`${oldest.domain}\` (**${oldest.registration_year}**, ${oDate})\n`;
      }
      if (newest) {
        const nDate = newest.registration_date.includes("T") ? newest.registration_date.split("T")[0] : newest.registration_date;
        md += `- **Latest Acquisition**: \`${newest.domain}\` (**${newest.registration_year}**, ${nDate})\n`;
      }
      if (topRegistrars.length > 0) {
        md += `- **Top Sponsoring Registrars**: ${topRegistrars.join(", ")}\n`;
      }
      if (unverifiedTlds.length > 0) {
        md += `\n> [!WARNING] **${unverifiedTlds.length}** TLDs could not be definitively verified due to wildcard DNS or network/resolver timeouts.\n`;
      }
      if (csvFilePath) {
        const forwardSlashPath = csvFilePath.replace(/\\/g, "/");
        md += `- **Exported CSV Spreadsheet**: [\`${path.basename(csvFilePath)}\`](file:///${forwardSlashPath})\n`;
      }

      md += `\n### Historical Era Distribution\n`;
      md += `\`\`\`text\n`;
      md += `Pioneer Era     (Pre-2000)  : ${pre2000.toString().padStart(3)} extensions [${"#".repeat(Math.min(pre2000, 20))}]\n`;
      md += `Web 2.0 Era     (2000-2009) : ${era2000s.toString().padStart(3)} extensions [${"#".repeat(Math.min(era2000s, 20))}]\n`;
      md += `New gTLD Boom   (2010-2019) : ${era2010s.toString().padStart(3)} extensions [${"#".repeat(Math.min(era2010s, 20))}]\n`;
      md += `Modern Era      (2020-Pres) : ${era2020s.toString().padStart(3)} extensions [${"#".repeat(Math.min(era2020s, 20))}]\n`;
      md += `Undisclosed/DNS (ccTLD/WHOIS): ${unknownYears.toString().padStart(3)} extensions [${"#".repeat(Math.min(unknownYears, 20))}]\n`;
      md += `\`\`\`\n\n`;

      // Top 10 Oldest
      const oldestList = registeredRecords.filter(r => r.registration_year !== null).slice(0, 10);
      if (oldestList.length > 0) {
        md += `### Oldest Registrations (The Pioneers)\n\n`;
        md += `| # | Domain | TLD | Reg. Year | Exact Creation Date | Registrar |\n`;
        md += `|---|---|---|---|---|---|\n`;
        oldestList.forEach((r, idx) => {
          const dateStr = r.registration_date && r.registration_date.includes("T") ? r.registration_date.split("T")[0] : r.registration_date;
          md += `| ${idx + 1} | \`${r.domain}\` | .${r.tld} | **${r.registration_year}** | ${dateStr} | ${r.registrar} |\n`;
        });
      }

      // Top 5 Newest
      const newestList = registeredRecords.filter(r => r.registration_year !== null).slice(-5).reverse();
      if (newestList.length > 0 && newestList[0].domain !== oldestList[0]?.domain) {
        md += `\n### Latest Registrations (Recent Additions)\n\n`;
        md += `| # | Domain | TLD | Reg. Year | Exact Creation Date | Registrar |\n`;
        md += `|---|---|---|---|---|---|\n`;
        newestList.forEach((r, idx) => {
          const dateStr = r.registration_date && r.registration_date.includes("T") ? r.registration_date.split("T")[0] : r.registration_date;
          md += `| ${idx + 1} | \`${r.domain}\` | .${r.tld} | **${r.registration_year}** | ${dateStr} | ${r.registrar} |\n`;
        });
      }

      // Collapsible section for all remaining domains if > 15
      if (registeredRecords.length > 15) {
        md += `\n<details>\n<summary><b>View Complete Registered Portfolio (${registeredRecords.length} domains)</b></summary>\n\n`;
        md += `| # | Domain | TLD | Reg. Year | Exact Creation Date | Registrar |\n`;
        md += `|---|---|---|---|---|---|\n`;
        registeredRecords.forEach((r, idx) => {
          const yStr = r.registration_year ? `**${r.registration_year}**` : "—";
          const dStr = r.registration_date && r.registration_date !== "Unknown" ? (r.registration_date.includes("T") ? r.registration_date.split("T")[0] : r.registration_date) : "Undisclosed";
          md += `| ${idx + 1} | \`${r.domain}\` | .${r.tld} | ${yStr} | ${dStr} | ${r.registrar} |\n`;
        });
        md += `\n</details>\n`;
      }

      const responsePayload = {
        keyword: rawKw,
        scope,
        sort_by: sortBy,
        total_tlds_scanned: targetTlds.length,
        total_registered_found: registeredRecords.length,
        total_unverified: unverifiedTlds.length,
        csv_file_path: csvFilePath,
        csv_exported: exportCsv && Boolean(csvFilePath),
        oldest_registration: oldest ? { domain: oldest.domain, year: oldest.registration_year, date: oldest.registration_date } : null,
        newest_registration: newest ? { domain: newest.domain, year: newest.registration_year, date: newest.registration_date } : null,
        era_distribution: {
          pioneer_pre_2000: pre2000,
          web2_2000_2009: era2000s,
          gtld_boom_2010_2019: era2010s,
          modern_2020_present: era2020s,
          undisclosed_cctld_whois: unknownYears
        },
        registered_domains: registeredRecords,
        unregistered_sample: unregisteredTlds.slice(0, 50),
        unverified_sample: unverifiedTlds.slice(0, 20),
        markdown_summary: md,
        audited_at: new Date().toISOString()
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(responsePayload, null, 2),
          },
        ],
      };
    }

    if (
      name === "search_keyword_domains" ||
      name === "search_keyword_combinations" ||
      name === "find_available_combinations"
    ) {
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
        ? args.site_status_filter.map(s => s.toLowerCase())
        : ["all"];

      const rawTlds = Array.isArray(args?.extensions) && args.extensions.length > 0
        ? args.extensions.map(t => t.replace(/^\./, "").toLowerCase())
        : Array.isArray(args?.tlds) && args.tlds.length > 0
        ? args.tlds.map(t => t.replace(/^\./, "").toLowerCase())
        : ["com"];

      let dict = INDUSTRY_DICTIONARIES[ind] || INDUSTRY_DICTIONARIES.general;
      if (ind === "custom" && Array.isArray(args?.custom_words)) {
        dict = args.custom_words.map(w => w.toLowerCase().replace(/[^a-z0-9-]/g, "")).filter(Boolean);
      }

      const stems = new Set();
      const addStem = (left, right) => {
        stems.add(`${left}${right}`);
        if (incHyphens) stems.add(`${left}-${right}`);
      };
      const addTripleStem = (mod, core, word) => {
        stems.add(`${mod}${core}${word}`);
        if (incHyphens) stems.add(`${mod}-${core}-${word}`);
      };

      if (incAlpha) {
        if (pos === "beginning" || pos === "any") {
          for (const w of dict) addStem(rawKw, w);
        }
        if (pos === "end" || pos === "any") {
          for (const w of dict) addStem(w, rawKw);
        }
        if (pos === "any") {
          for (const mod of INFIX_MODIFIERS.slice(0, 4)) {
            for (const w of dict.slice(0, 3)) addTripleStem(mod, rawKw, w);
          }
        }
      }

      if (incDigits) {
        if (pos === "beginning" || pos === "any") {
          for (const d of DIGIT_PATTERNS) addStem(rawKw, d);
        }
        if (pos === "end" || pos === "any") {
          for (const d of DIGIT_PATTERNS) addStem(d, rawKw);
        }
      }

      const filteredStems = Array.from(stems).filter((s) => {
        if (minLen > 0 && s.length < minLen) return false;
        if (maxLen < 63 && s.length > maxLen) return false;
        if (excludeStr && s.includes(excludeStr)) return false;
        return true;
      });

      const uniqueCandidates = [];
      const uniqueMap = new Set();
      for (const s of filteredStems) {
        for (const t of rawTlds) {
          const domain = `${s}.${t}`;
          if (!uniqueMap.has(domain)) {
            uniqueMap.add(domain);
            uniqueCandidates.push({ domain, tld: t });
          }
        }
      }

      const rdapStatus = {};
      await asyncPool(5, uniqueCandidates, async (c) => {
        rdapStatus[c.domain] = await checkDomainStatus(c.domain, c.tld);
      });

      const unregisteredList = uniqueCandidates.filter(c => rdapStatus[c.domain] === "NOT_FOUND_IN_REGISTRY").map(c => c.domain);
      const takenCandidates = uniqueCandidates.filter(c => rdapStatus[c.domain] === "TAKEN");

      const activityReport = {};
      if (takenCandidates.length > 0) {
        await asyncPool(5, takenCandidates, async (c) => {
          activityReport[c.domain] = await probeDomainActivity(c.domain);
        });
      }

      const activeList = takenCandidates.filter(c => activityReport[c.domain]?.status === "ACTIVE").map(c => c.domain);
      const parkedList = takenCandidates.filter(c => activityReport[c.domain]?.status === "PARKED").map(c => c.domain);
      const inactiveList = takenCandidates.filter(c => activityReport[c.domain]?.status === "INACTIVE").map(c => c.domain);

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
                  includes: { alphabets: incAlpha, digits: incDigits, hyphens: incHyphens },
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
                verified_by: "DotDB-Standard Engine (Authoritative RDAP + Live HTTP Probe)",
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
}
