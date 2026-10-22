import { USER_AGENT, BUILTIN_RDAP_BASES, BUILTIN_WHOIS_SERVERS, CCTLD_POLICY_NOTES } from "./constants.js";
import { fetchWithTimeout } from "./utils.js";
import net from "net";
import dns from "dns/promises";

let ianaBootstrapCache = null;
let ianaBootstrapPromise = null;

// Registry host-level polite rate limiter to prevent HTTP 429 (especially Identity Digital & Verisign)
const hostQueues = new Map();

async function throttleHost(hostname, minIntervalMs = 90) {
  if (!hostQueues.has(hostname)) {
    hostQueues.set(hostname, Promise.resolve());
  }
  const current = hostQueues.get(hostname);
  const next = current.then(async () => {
    await new Promise(resolve => setTimeout(resolve, minIntervalMs));
  });
  hostQueues.set(hostname, next);
  await current;
}

export async function getIanaMap() {
  if (ianaBootstrapCache) return ianaBootstrapCache;
  if (!ianaBootstrapPromise) {
    ianaBootstrapPromise = (async () => {
      try {
        const res = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", {
          headers: { "User-Agent": USER_AGENT },
          timeout: 4500
        });
        if (!res.ok) throw new Error("Failed to fetch IANA map");
        const json = await res.json();
        const map = {};
        for (const [tlds, urls] of json.services) {
          for (const t of tlds) {
            const u = urls[0].endsWith("/") ? urls[0] : urls[0] + "/";
            map[t] = u.endsWith("domain/") ? u : u + "domain/";
          }
        }
        ianaBootstrapCache = map;
        return map;
      } catch (e) {
        return {};
      }
    })();
  }
  return ianaBootstrapPromise;
}

export function fetchWhoisRaw(server, query) {
  return new Promise((resolve) => {
    const client = new net.Socket();
    client.setTimeout(4000);
    let data = "";
    client.connect(43, server, () => {
      client.write(query + "\r\n");
    });
    client.on("data", (chunk) => { data += chunk.toString(); });
    client.on("close", () => resolve(data));
    client.on("error", () => resolve(null));
    client.on("timeout", () => {
      client.destroy();
      resolve(null);
    });
  });
}

export async function queryWhoisFallback(domain) {
  const parts = domain.split(".");
  const tld = parts[parts.length - 1].toLowerCase();
  
  let whoisServer = BUILTIN_WHOIS_SERVERS?.[tld];
  if (!whoisServer) {
    // Find the authoritative WHOIS server for the TLD from IANA
    const ianaData = await fetchWhoisRaw("whois.iana.org", tld);
    if (ianaData) {
      const match = ianaData.match(/whois:\s+([a-zA-Z0-9.-]+)/i);
      if (match && match[1]) whoisServer = match[1].trim();
    }
  }

  if (!whoisServer) return { status: "UNKNOWN" };

  const queryStr = whoisServer.includes("verisign") ? `=${domain}` : domain;
  const whoisData = await fetchWhoisRaw(whoisServer, queryStr);
  if (!whoisData) return { status: "UNKNOWN" };

  // --- LOGIC BUG 4 FIX: Check for POSITIVE registration indicators FIRST ---
  // Many registries place "not found" disclaimers in the footer/TOS.
  // We must look for creation date, status, nameservers, or registrar before checking negative keywords.

  // 1. Check creation date
  let creationDate = null;
  const createMatch = whoisData.match(/(?:creation\s+date|created|registered\s+on|registration\s+time|entry\s+created|created-date|reg-date)[\s:]+([^\r\n]+)/i);
  if (createMatch && createMatch[1]) {
    const rawDate = createMatch[1].trim();
    const d = new Date(rawDate);
    if (!isNaN(d.getTime())) {
      creationDate = d.toISOString();
    } else {
      const y = rawDate.match(/\b(19\d{2}|20\d{2})\b/);
      if (y) creationDate = rawDate;
    }
  }

  // 2. Check expiration date
  let expirationDate = null;
  const expireMatch = whoisData.match(/(?:registry\s+expiry\s+date|expiry\s+date|expiration\s+date|paid-till|expires\s+on|expires)[\s:]+([^\r\n]+)/i);
  if (expireMatch && expireMatch[1]) {
    const rawDate = expireMatch[1].trim();
    const d = new Date(rawDate);
    if (!isNaN(d.getTime())) expirationDate = d.toISOString();
  }

  // 3. Check registrar
  let registrar = null;
  const regMatch = whoisData.match(/(?:registrar|registrar\s+name|sponsoring\s+registrar)[\s:]+([^\r\n]+)/i);
  if (regMatch && regMatch[1]) {
    registrar = regMatch[1].trim();
  }

  // 4. Check nameservers or positive status
  const hasNs = /(?:nameserver|nserver|name\s+server)[\s:]+/i.test(whoisData);
  const hasDomainStatus = /(?:domain\s+status|status)[\s:]+(?:ok|active|client|server)/i.test(whoisData);

  // If any strong positive indicator exists, the domain is TAKEN
  if (creationDate || registrar || hasNs || hasDomainStatus) {
    return {
      status: "TAKEN",
      details: {
        creationDate,
        expirationDate,
        registrar: registrar || "Unknown Registrar",
        source: `WHOIS (${whoisServer})`
      }
    };
  }

  // 5. Only if NO positive indicators were found, check negative "not found" patterns
  const lower = whoisData.toLowerCase();
  if (
    lower.includes("no match") ||
    lower.includes("not found") ||
    lower.includes("no data found") ||
    lower.includes("is free") ||
    lower.includes("available for registration") ||
    lower.includes("do not have an entry") ||
    lower.includes("nothing found") ||
    lower.includes("domain not found")
  ) {
    return { status: "NOT_FOUND_IN_REGISTRY" };
  }

  return { status: "UNKNOWN" };
}

export async function queryRdap(url, domain) {
  try {
    // Apply host throttle to respect registry rate limits
    try {
      const parsedUrl = new URL(url);
      await throttleHost(parsedUrl.hostname, 80);
    } catch (e) {}

    const res = await fetchWithTimeout(url, {
      headers: { 
        "User-Agent": USER_AGENT,
        "Accept": "application/rdap+json" 
      },
      timeout: 4500
    });

    if (res.status === 200) {
      try {
        const data = await res.json();
        const statuses = data.status || [];
        const events = data.events || [];
        const entities = data.entities || [];
        
        let creationDate, expirationDate;
        events.forEach(ev => {
          const act = (ev.eventAction || "").toLowerCase();
          if (act === "registration" || act === "created" || act === "creation") {
            creationDate = ev.eventDate;
          }
          if (act === "expiration" || act === "expiry") {
            expirationDate = ev.eventDate;
          }
        });

        let registrar = "Private / Protected";
        entities.forEach(ent => {
          if (ent.roles && ent.roles.includes("registrar")) {
            if (ent.vcardArray && ent.vcardArray[1]) {
              const fn = ent.vcardArray[1].find(v => v[0] === "fn");
              if (fn && fn[3]) registrar = fn[3];
            } else if (ent.handle) {
              registrar = ent.handle;
            }
          }
        });

        return { 
          status: "TAKEN", 
          details: { 
            rdapStatus: statuses, 
            creationDate, 
            expirationDate, 
            registrar,
            source: "RDAP" 
          } 
        };
      } catch (err) {
        return { status: "TAKEN", details: { source: "RDAP" } };
      }
    } 
    
    if (res.status === 404) {
      return { status: "NOT_FOUND_IN_REGISTRY" };
    } 
    
    if (res.status === 429 || res.status === 501 || res.status === 503) {
      const fallback = await queryWhoisFallback(domain);
      return fallback;
    }

    return { status: "UNKNOWN" };
  } catch (e) {
    if (e.name === 'AbortError') {
      return { status: "TIMEOUT" };
    }
    return { status: "UNKNOWN" };
  }
}

export async function checkDomainStatus(domain, tld, returnFullDetails = false) {
  let base = BUILTIN_RDAP_BASES[tld];
  if (!base) {
    const ianaMap = await getIanaMap();
    if (ianaMap && ianaMap[tld]) {
      base = ianaMap[tld];
    }
  }

  if (base) {
    const targetUrl = base.endsWith("/") ? base + domain : base + "/" + domain;
    const result = await queryRdap(targetUrl, domain);
    
    if (returnFullDetails) {
      // If RDAP returned 404, the domain is definitively NOT registered
      if (result.status === "NOT_FOUND_IN_REGISTRY") {
        return result;
      }

      // If RDAP was TIMEOUT or had no creation date, try fallback socket WHOIS
      if (result.status !== "NOT_FOUND_IN_REGISTRY" && !result.details?.creationDate) {
        const whoisFallback = await queryWhoisFallback(domain);
        if (whoisFallback.status === "TAKEN") {
          result.status = "TAKEN";
          result.details = result.details || {};
          if (whoisFallback.details?.creationDate) {
            result.details.creationDate = whoisFallback.details.creationDate;
          }
          if (whoisFallback.details?.registrar && (!result.details.registrar || result.details.registrar === "Private / Protected")) {
            result.details.registrar = whoisFallback.details.registrar;
          }
          if (whoisFallback.details?.expirationDate && !result.details.expirationDate) {
            result.details.expirationDate = whoisFallback.details.expirationDate;
          }
          result.details.source = whoisFallback.details?.source || "WHOIS";
        } else if (whoisFallback.status === "NOT_FOUND_IN_REGISTRY") {
          return whoisFallback;
        }
      }
      if (result.details && !result.details.creationDate && CCTLD_POLICY_NOTES[tld]) {
        result.details.policyNote = CCTLD_POLICY_NOTES[tld];
      }
      return result;
    }

    if (result.status === "TAKEN" || result.status === "NOT_FOUND_IN_REGISTRY") {
      return result.status;
    }
  }

  // Fallback to WHOIS socket if no RDAP base was found
  if (returnFullDetails) {
    const whoisRes = await queryWhoisFallback(domain);
    if (whoisRes.status === "TAKEN" || whoisRes.status === "NOT_FOUND_IN_REGISTRY") {
      if (whoisRes.details && !whoisRes.details.creationDate && CCTLD_POLICY_NOTES[tld]) {
        whoisRes.details.policyNote = CCTLD_POLICY_NOTES[tld];
      }
      return whoisRes;
    }
  }

  // Authoritative DNS Name Server delegation fallback
  try {
    const ns = await dns.resolveNs(domain);
    if (ns && ns.length > 0) {
      const details = { dns: ns, source: "DNS Delegation" };
      if (CCTLD_POLICY_NOTES[tld]) {
        details.policyNote = CCTLD_POLICY_NOTES[tld];
      }
      return returnFullDetails ? { status: "TAKEN", details } : "TAKEN";
    }
  } catch (err) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      return returnFullDetails ? { status: "NOT_FOUND_IN_REGISTRY" } : "NOT_FOUND_IN_REGISTRY";
    }
  }

  return returnFullDetails ? { status: "UNKNOWN" } : "UNKNOWN";
}
