import { registerTools } from "./src/mcp-tools.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

class MockServer {
  constructor() {
    this.listHandler = null;
    this.callHandler = null;
  }
  setRequestHandler(schema, handler) {
    if (schema === ListToolsRequestSchema || schema?.method === "tools/list") {
      this.listHandler = handler;
    } else if (schema === CallToolRequestSchema || schema?.method === "tools/call") {
      this.callHandler = handler;
    }
  }
  async callTool(name, args) {
    return this.callHandler({ params: { name, arguments: args } });
  }
  async listTools() {
    return this.listHandler({});
  }
}

async function run() {
  const server = new MockServer();
  registerTools(server);

  console.log("=== 1. Listing Tools ===");
  const tools = await server.listTools();
  console.log(`Registered ${tools.tools.length} tools:`);
  tools.tools.forEach(t => console.log(` - ${t.name}`));

  console.log("\n=== 2. Testing scan_keyword_tlds (Timeline Audit) ===");
  const res = await server.callTool("scan_keyword_tlds", {
    keyword: "anthropic",
    scope: "popular",
    sort_by: "year_asc"
  });

  const data = JSON.parse(res.content[0].text);
  console.log(`Total scanned: ${data.total_tlds_scanned} TLDs | Registered: ${data.total_registered_found}`);
  console.log(`Oldest:`, data.oldest_registration);
  console.log(`Newest:`, data.newest_registration);
  console.log("\nTop 5 Oldest Domains:");
  data.registered_domains.slice(0, 5).forEach((d, i) => {
    console.log(` ${i + 1}. ${d.domain.padEnd(20)} Year: ${d.registration_year || "—"} (${d.registration_date})`);
  });
  console.log("\nAll tests passed successfully!");
}

run().catch(console.error);
