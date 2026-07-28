// RealHandles MCP over stateless HTTP.
//
// Under the 2026-07-28 spec, sessions are gone rather than optional: every
// request is self-describing, so any request can land on any instance. That
// makes this an ordinary function, with no initialize/initialized handshake and
// no Mcp-Session-Id to track.
//
// Written as a plain JSON-RPC handler rather than through an SDK transport on
// purpose. The stateless transport is new and the SDK pinned here predates it,
// so hand-rolling the four methods keeps this working regardless of SDK version
// and keeps the wire behavior obvious.
import { TOOLS } from '../../src/tools.js';
import type { Config } from '@netlify/functions';

const PROTOCOL_VERSION = '2026-07-28';
const SERVER_INFO = { name: 'realhandles', version: '0.1.0' };

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, Mcp-Method, Mcp-Name, Mcp-Protocol-Version',
};

type RpcId = string | number | null;

function ok(id: RpcId, result: unknown, method?: string) {
  return Response.json(
    { jsonrpc: '2.0', id, result },
    {
      headers: {
        ...CORS,
        // Echoed so a gateway can route on headers without parsing the body,
        // which is the point of header-based routing in the new spec.
        ...(method ? { 'Mcp-Method': method } : {}),
        'Mcp-Name': SERVER_INFO.name,
      },
    },
  );
}

function fail(id: RpcId, code: number, message: string) {
  return Response.json({ jsonrpc: '2.0', id, error: { code, message } }, { status: 200, headers: CORS });
}

const toolList = TOOLS.map((t) => ({
  name: t.name,
  description: t.description,
  inputSchema: t.inputSchema,
}));

export default async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  // A plain GET is not part of the protocol now that there is no stream to open,
  // so use it to describe the endpoint for anyone who opens it in a browser.
  if (req.method === 'GET') {
    return Response.json(
      {
        ...SERVER_INFO,
        protocolVersion: PROTOCOL_VERSION,
        transport: 'stateless-http',
        tools: TOOLS.map((t) => t.name),
        docs: 'https://realhandles.com',
      },
      { headers: CORS },
    );
  }

  if (req.method !== 'POST') return fail(null, -32600, 'Use POST with a JSON-RPC body.');

  let body: any;
  try {
    body = await req.json();
  } catch {
    return fail(null, -32700, 'Parse error: body was not valid JSON.');
  }

  // Batch requests: each is independent, which is exactly what stateless buys.
  if (Array.isArray(body)) {
    const results = await Promise.all(body.map((m) => handle(m)));
    return Response.json(results.filter(Boolean), { headers: CORS });
  }

  const single = await handle(body);
  if (!single) return new Response(null, { status: 202, headers: CORS });
  return Response.json(single, {
    headers: { ...CORS, 'Mcp-Method': String(body?.method ?? ''), 'Mcp-Name': SERVER_INFO.name },
  });
};

async function handle(msg: any): Promise<any | null> {
  const id: RpcId = msg?.id ?? null;
  const method: string = msg?.method ?? '';

  // Notifications carry no id and expect no reply.
  if (id === null && method.startsWith('notifications/')) return null;

  switch (method) {
    // Optional in the new spec, for clients that want capabilities up front.
    case 'server/discover':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          serverInfo: SERVER_INFO,
          capabilities: { tools: { listChanged: false } },
        },
      };

    // Accepted so clients that still send the old handshake keep working
    // instead of hard-failing on their first call.
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          serverInfo: SERVER_INFO,
          capabilities: { tools: { listChanged: false } },
        },
      };

    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };

    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: toolList } };

    case 'tools/call': {
      const name = msg?.params?.name;
      const tool = TOOLS.find((t) => t.name === name);
      if (!tool) {
        return { jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${name}` } };
      }
      try {
        const text = await tool.run(msg?.params?.arguments ?? {});
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }] } };
      } catch (err) {
        // Reported as a tool result, not a protocol error: the call reached the
        // tool, the tool failed, and the model should see why.
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `Tool "${name}" failed: ${err instanceof Error ? err.message : String(err)}` }],
            isError: true,
          },
        };
      }
    }

    default:
      return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
}

export const config: Config = {
  path: '/mcp',
};
