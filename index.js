#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./src/mcp-tools.js";

const server = new Server(
  {
    name: "surf.insight/domain-radar",
    version: "2.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

registerTools(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
