// Tool definitions, shared by both transports. The stdio entry (src/index.ts)
// and the stateless HTTP function (netlify/functions/mcp.mts) both build from
// this list, so a tool is described in exactly one place.
//
// Verification runs locally against the signature via @realhandles/verify. The
// API is used only to locate the signed manifest, so a result never depends on
// trusting realhandles.com. That property is the whole point of the server and
// it holds identically over stdio and over HTTP.
import { z } from 'zod';
import {
  verifySignedManifest,
  computeTrustScore,
  isVerifiedMethod,
  jwkToDidKey,
  type Proof,
  type ClaimedAccount,
} from '@realhandles/verify';

export const ORIGIN = (process.env.REALHANDLES_ORIGIN ?? 'https://realhandles.com').replace(/\/+$/, '');

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

export async function verifyIdentity(handle: string) {
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

export type ToolDef = {
  name: string;
  description: string;
  /** Zod shape, for the stdio server. */
  input: Record<string, z.ZodTypeAny>;
  /** Equivalent JSON Schema, for tools/list over HTTP. Kept alongside the zod
   *  shape rather than derived, so the wire contract stays readable and the
   *  package needs no schema-conversion dependency. */
  inputSchema: Record<string, unknown>;
  run: (args: any) => Promise<string>;
};

export const TOOLS: ToolDef[] = [
  {
    name: 'verify_identity',
    description:
      'Look up a RealHandles identity by handle and cryptographically verify its signed proof. The signature is checked locally, so the result does not require trusting realhandles.com. Returns the verified accounts (split into verified and claimed), the key fingerprint, the did:key, and the trust score.',
    input: { handle: z.string().describe('A RealHandles handle, e.g. "david" or "davidvkimball".') },
    inputSchema: {
      type: 'object',
      properties: { handle: { type: 'string', description: 'A RealHandles handle, e.g. "david" or "davidvkimball".' } },
      required: ['handle'],
      additionalProperties: false,
    },
    async run({ handle }) {
      const r = await verifyIdentity(String(handle));
      if (!r.found) return `No published RealHandles identity for "${handle}".`;
      return JSON.stringify(r, null, 2);
    },
  },
  {
    name: 'check_link',
    description:
      'Check whether a URL is a mutually confirmed account of a RealHandles identity (useful for rendering a "verified" badge). Returns the identity if the two-way link checks out, otherwise linked: false.',
    input: { url: z.string().url().describe('The URL to check, e.g. a link-in-bio or profile page.') },
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string', format: 'uri', description: 'The URL to check, e.g. a link-in-bio or profile page.' } },
      required: ['url'],
      additionalProperties: false,
    },
    async run({ url }) {
      const r = await fetchJson(`${ORIGIN}/api/link-status?url=${encodeURIComponent(String(url))}`);
      return JSON.stringify(r ?? { linked: false }, null, 2);
    },
  },
];
