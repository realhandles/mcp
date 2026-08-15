// Tool definitions, shared by both transports. The stdio entry (src/index.ts)
// and the stateless HTTP function (netlify/functions/mcp.mts) both build from
// this list, so a tool is described in exactly one place.
//
// TWO QUESTIONS, AND ONLY ONE OF THEM IS MATH. Read this before touching the
// account split, because the obvious simplification of either half reopens a
// live impersonation hole.
//
//   "Was this payload signed by the key that owns the identity?" is math. It is
//   answered HERE, locally, by @realhandles/verify, and that answer never
//   depends on trusting realhandles.com. This is the property the README sells
//   and it is untouched.
//
//   "Did anyone ever actually check that this GitHub account belongs to them?"
//   is NOT math and cannot be. `platform`, `handle` and `method` on an account
//   entry are whatever the signer typed, so a flawless signature over
//   {platform:'github', handle:'torvalds', method:'oauth'} is a flawless
//   signature over a lie. Only the party that performed the verification holds
//   a record of it, so that half comes from GET /api/identity, which already
//   intersects the signed manifest against its own proof rows.
//
// This server used to answer the second question by reading `method` out of the
// manifest, which meant the SIGNER decided their own badge. See verifyIdentity
// below, and src/lib/crosscheck.ts in the realhandles.com repo for the full
// argument and the rest of the surfaces it governs.
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

/**
 * Canonical lookup key for one published account: platform + handle, normalized.
 *
 * Must match `accountKey` in the site's src/lib/crosscheck.ts exactly, because
 * this is what joins the two halves of the check: one side is an account out of
 * the locally verified manifest, the other is an account the API says its own
 * proof rows back. A normalization that disagrees by so much as a leading "@"
 * does not fail loudly, it just silently drops somebody's badge.
 *
 * A domain needs no special case. In a signed manifest a domain IS an account
 * whose platform is the literal string "domain" and whose handle is the domain,
 * so the uniform rule produces "domain:example.com" on both sides.
 */
function accountKey(platform: string, handle: string): string {
  return `${String(platform ?? '').toLowerCase()}:${String(handle ?? '').replace(/^@/, '').toLowerCase()}`;
}

/**
 * The accounts realhandles.com will itself stand behind, or null when it did not
 * say.
 *
 * GET /api/identity already returns `accounts.verified` and `accounts.claimed`
 * split by its own cross-check: an entry reaches `verified` only where a
 * verified proof row on that login backs it AND, where both sides recorded the
 * platform's immutable account id, the ids agree. That is the record this
 * server cannot reproduce and must not guess at.
 *
 * NULL IS NOT AN EMPTY SET, and the distinction is the whole reason this returns
 * a nullable rather than a set. An older deploy of the site returns no such
 * split, and the honest reading of a missing answer is "this deployment did not
 * tell us", never "it checked and found nothing". Both fail closed to the same
 * badge, but only one of them is a fact we can put in the output, so the caller
 * gets to say which it is instead of asserting the stronger claim.
 */
function serverVerifiedKeys(api: any): ReadonlySet<string> | null {
  const listed = api?.accounts?.verified;
  if (!Array.isArray(listed)) return null;
  const keys = new Set<string>();
  for (const a of listed) {
    const platform = typeof a?.platform === 'string' ? a.platform : '';
    const handle = typeof a?.handle === 'string' ? a.handle : '';
    if (!platform || !handle) continue;
    keys.add(accountKey(platform, handle));
  }
  return keys;
}

export async function verifyIdentity(handle: string) {
  const api = await fetchJson(`${ORIGIN}/api/identity/${encodeURIComponent(handle)}`);
  if (!api || !api.jws) return { found: false as const };
  const result = await verifySignedManifest({ jws: api.jws });
  if (!result.valid || !result.manifest) {
    return { found: true as const, valid: false as const, reason: result.reason ?? 'signature did not verify' };
  }
  const m = result.manifest;

  // BOTH HALVES, and neither one alone. The accounts iterated below come from
  // the VERIFIED payload, so nothing here rests on the API's own JSON being
  // truthful about what the owner published; dropping the signature check and
  // simply echoing the API's two lists would swap one wrong root of trust for
  // another. The API supplies only the narrowing: which of those signed entries
  // it actually verified. `isVerifiedMethod` stays in front of it for the same
  // reason `accountVerdict` asks it first, that a self-attested entry has
  // nothing for a proof row to confirm, and because a filter that can only ever
  // remove an account is the safe way for these two records to disagree.
  const backed = serverVerifiedKeys(api);
  const isBacked = (a: ClaimedAccount) =>
    !!backed && isVerifiedMethod(a.method) && backed.has(accountKey(a.platform, a.handle));

  const verified = m.accounts.filter(isBacked);
  // Only cross-checked accounts are scored, mirroring `scorableAccounts` on the
  // site. Feeding the whole manifest in was how this server came to report a
  // HIGHER trust score than realhandles.com does for the same person, which is
  // the worst direction for the error to run: a number nobody else can
  // reproduce, biased toward believing whoever wrote the manifest.
  const proofs: Proof[] = verified.map((a) =>
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
    // Says which of the two questions above got a real answer. The signature is
    // checked either way, so `valid` above is unaffected; this qualifies the
    // account split and the trust score only.
    crossChecked: backed !== null,
    ...(backed === null
      ? {
          crossCheckNote:
            'The directory did not return its cross-checked account split, so every account is reported as claimed and the trust score is 0. That is a missing answer, not a finding: it does not mean these accounts failed verification.',
        }
      : {}),
    trustScore: computeTrustScore(proofs).score,
    accounts: {
      verified: verified.map(shape),
      claimed: m.accounts.filter((a) => !isBacked(a)).map(shape),
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
      'Look up a RealHandles identity by handle and cryptographically verify its signed proof. The signature is checked locally, so whether the manifest is authentic does not require trusting realhandles.com. Accounts are split into verified and claimed by the RealHandles directory\'s own verification records, not by what the manifest calls them, because a signer can write any label beside any account. An account lands in "claimed" whenever nothing independently backs it. Also returns the key fingerprint, the did:key, and the trust score, which counts verified accounts only.',
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
