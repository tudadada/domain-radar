export const USER_AGENT = "domain-radar/2.0.0 (https://insight.surf; support@insight.surf)";
export const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

export const INDUSTRY_DICTIONARIES = {
  general: ["pro", "hub", "point", "base", "network", "direct", "online", "group", "world", "zone", "link", "shop", "club", "center"],
  tech: ["ai", "data", "cloud", "core", "labs", "systems", "tech", "protocol", "intel", "node", "cyber", "stack"],
  energy: ["power", "energy", "oil", "gas", "marine", "subsea", "grid", "clean", "solar", "battery", "green"],
  finance: ["capital", "fund", "ventures", "invest", "holdings", "group", "wealth", "trust", "equity", "asset"],
  arctic: ["geo", "drilling", "permafrost", "risk", "ice", "polar", "climate", "carbon", "frost", "cold"],
  security: ["sec", "defense", "audit", "guard", "safe", "shield", "auth", "trust", "lock", "cyber"],
};

export const INFIX_MODIFIERS = ["the", "my", "get", "top", "pro", "global", "smart", "all", "best"];

export const DIGIT_PATTERNS = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "24", "360", "365", "247", "101", "88", "99", "2026"];

export const BUILTIN_RDAP_BASES = {
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
  dev: "https://pubapi.registry.google/rdap/domain/",
  cloud: "https://rdap.registry.cloud/rdap/domain/",
  co: "https://rdap.nic.co/domain/",
  me: "https://rdap.identitydigital.services/rdap/domain/",
  us: "https://rdap.nic.us/domain/",
};

export const BUILTIN_WHOIS_SERVERS = {
  com: "whois.verisign-grs.com",
  net: "whois.verisign-grs.com",
  org: "whois.pir.org",
  info: "whois.afilias.net",
  biz: "whois.nic.biz",
  co: "whois.registry.co",
  me: "whois.nic.me",
  us: "whois.nic.us",
  uk: "whois.nic.uk",
  de: "whois.denic.de",
  fr: "whois.nic.fr",
  nl: "whois.domain-registry.nl",
  in: "whois.registry.in",
  it: "whois.nic.it",
  eu: "whois.eu",
  cc: "whois.nic.cc",
  tv: "whois.nic.tv",
  io: "whois.nic.io",
  ai: "whois.nic.ai",
  vn: "whois.nic.vn",
  au: "whois.auda.org.au",
  br: "whois.registro.br",
  ch: "whois.nic.ch",
  se: "whois.iis.se",
  no: "whois.norid.no",
  ru: "whois.tcinet.ru",
  pl: "whois.dns.pl",
  es: "whois.nic.es",
  cz: "whois.nic.cz",
  at: "whois.nic.at",
  be: "whois.dnsbelgium.be",
  dk: "whois.punktum.dk",
  fi: "whois.fi",
  nz: "whois.srs.net.nz",
  sg: "whois.sgnic.sg",
  hk: "whois.hkirc.hk",
  tw: "whois.twnic.net.tw",
  cl: "whois.nic.cl",
  za: "whois.registry.net.za"
};

export const PARKED_KEYWORDS = [
  "domain for sale",
  "buy this domain",
  "sedoparking",
  "dan.com",
  "hugedomains",
  "parked free",
  "this domain is parked",
  "inquire about this domain",
  "domain is for sale",
  "is parked",
  "afternic",
  "squadhelp",
  "namecheap parking",
  "godaddy parking",
  "domain owner",
  "this page is parked"
];
