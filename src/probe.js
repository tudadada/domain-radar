import dns from "dns/promises";
import { fetchWithTimeout } from "./utils.js";
import { BROWSER_UA, PARKED_KEYWORDS } from "./constants.js";

export async function probeDomainActivity(domain) {
  let hasWebIP = false;
  let hasEmailOrTxt = false;

  try {
    const aRecords = await dns.resolve4(domain).catch(() => []);
    const aaaaRecords = await dns.resolve6(domain).catch(() => []);
    if (aRecords.length > 0 || aaaaRecords.length > 0) hasWebIP = true;

    // Additional probes for MX/TXT to detect active internal usage even without a website
    const mxRecords = await dns.resolveMx(domain).catch(() => []);
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    if (mxRecords.length > 0 || txtRecords.length > 0) hasEmailOrTxt = true;
  } catch (e) {
    // If all fail
  }

  if (!hasWebIP && !hasEmailOrTxt) {
    return {
      status: "INACTIVE",
      detail: "No resolving DNS A/AAAA/MX/TXT records (dormant/unconfigured)",
    };
  }

  if (!hasWebIP && hasEmailOrTxt) {
    return {
      status: "ACTIVE",
      detail: "No Web IP, but has active MX/TXT records (likely used for email/services)",
    };
  }

  // Probe HTTP(S) if it has Web IP
  try {
    let res = await fetchWithTimeout(`https://${domain}`, {
      headers: { "User-Agent": BROWSER_UA },
      timeout: 2500
    }).catch(() => null);

    if (!res) {
      // Fallback to HTTP
      res = await fetchWithTimeout(`http://${domain}`, {
        headers: { "User-Agent": BROWSER_UA },
        timeout: 2000
      });
    }

    const text = await res.text();
    const lower = text.toLowerCase();
    
    const isParked = PARKED_KEYWORDS.some((k) => lower.includes(k));

    if (isParked) {
      return {
        status: "PARKED",
        detail: "Parked or listed for sale on aftermarket marketplace",
        httpStatus: res.status,
      };
    } else {
      return {
        status: "ACTIVE",
        detail: `Active website operating over HTTP(S)`,
        httpStatus: res.status,
      };
    }
  } catch (err) {
    return {
      status: "INACTIVE",
      detail: "DNS configured but web server is unreachable/offline",
    };
  }
}
