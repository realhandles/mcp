#!/usr/bin/env node
// RealHandles MCP server. Lets an agent look up a RealHandles identity and
// CRYPTOGRAPHICALLY verify its signed proof. Verification runs locally against
// the signature (via @realhandles/verify), so a result never depends on trusting
// realhandles.com: the API is used only to locate the signed manifest.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  verifySignedManifest,
  computeTrustScore,
  isVerifiedMethod,
  jwkToDidKey,
  type Proof,
  type ClaimedAccount,
} from '@realhandles/verify';

const ORIGIN = (process.env.REALHANDLES_ORIGIN ?? 'https://realhandles.com').replace(/\/+$/, '');

async function fetchJson(url: string): Promise<any | null> {
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

const shape = (a: ClaimedAccount) => ({ platform: a.platform, handle: a.handle, url: a.profileUrl, method: a.method });

// Discover an identity's signed manifest (alias/rename-aware) via the read API,
// then VERIFY the JWS locally so the trust decision never depends on the API.
async function verifyIdentity(handle: string) {
  const api = await fetchJson(`${ORIGIN}/api/identity/${encodeURIComponent(handle)}`);
  if (!api || !api.jws) return { found: false as const };
  const result = await verifySignedManifest({ jws: api.jws });
  if (!result.valid || !result.manifest) {
    return { found: true as const, valid: false as const, reason: result.reason ?? 'signature did not verify' };
  }
  const m = result.manifest;
  const proofs: Proof[] = m.accounts.map((a) =>
    a.platform === 'domain'
      ? { kind: 'domain', domain: a.handle, method: a.method, verifiedAt: a.verifiedAt }
      : { kind: 'platform', platform: a.platform, handle: a.handle, method: a.method, verifiedAt: a.verifiedAt }
  );
  return {
    found: true as const,
    valid: true as const,
    username: m.subject.username,
    displayName: m.subject.displayName ?? null,
    keyId: result.keyId ?? null,
    didKey: jwkToDidKey(m.subject.publicKey),
    profile: `${ORIGIN}/${m.subject.username}`,
    trustScore: computeTrustScore(proofs).score,
    accounts: {
      verified: m.accounts.filter((a) => isVerifiedMethod(a.method)).map(shape),
      claimed: m.accounts.filter((a) => !isVerifiedMethod(a.method)).map(shape),
    },
  };
}

const server = new McpServer({ name: 'realhandles', version: '0.1.0' });

server.tool(
  'verify_identity',
  'Look up a RealHandles identity by handle and cryptographically verify its signed proof. The signature is checked locally, so the result does not require trusting realhandles.com. Returns the verified accounts (split into verified and claimed), the key fingerprint, the did:key, and the trust score.',
  { handle: z.string().describe('A RealHandles handle, e.g. "david" or "davidvkimball".') },
  async ({ handle }) => {
    const r = await verifyIdentity(handle);
    if (!r.found) return { content: [{ type: 'text' as const, text: `No published RealHandles identity for "${handle}".` }] };
    return { content: [{ type: 'text' as const, text: JSON.stringify(r, null, 2) }] };
  }
);

server.tool(
  'check_link',
  'Check whether a URL is a mutually confirmed account of a RealHandles identity (useful for rendering a "verified" badge). Returns the identity if the two-way link checks out, otherwise linked: false.',
  { url: z.string().url().describe('The URL to check, e.g. a link-in-bio or profile page.') },
  async ({ url }) => {
    const r = await fetchJson(`${ORIGIN}/api/link-status?url=${encodeURIComponent(url)}`);
    return { content: [{ type: 'text' as const, text: JSON.stringify(r ?? { linked: false }, null, 2) }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
