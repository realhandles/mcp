#!/usr/bin/env node
// RealHandles MCP server, stdio transport. Lets an agent look up a RealHandles
// identity and CRYPTOGRAPHICALLY verify its signed proof.
//
// This entry is unchanged in behavior: same two tools, same output, same bin.
// The tool definitions moved to tools.ts so the stateless HTTP function can
// serve the identical set without a second copy of the logic.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { TOOLS } from './tools.js';

const server = new McpServer({ name: 'realhandles', version: '0.1.0' });

for (const t of TOOLS) {
  server.tool(t.name, t.description, t.input, async (args: any) => ({
    content: [{ type: 'text' as const, text: await t.run(args) }],
  }));
}

const transport = new StdioServerTransport();
await server.connect(transport);
