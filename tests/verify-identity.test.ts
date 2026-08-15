// The one thing this server must not get wrong: who decides "Verified".
//
// A signature proves WHO wrote a manifest. It proves nothing about whether the
// accounts inside it are true, because `platform`, `handle` and `method` are
// whatever the signer typed. So the impersonation case below is not a
// hypothetical shape invented for a test: it is a validly signed manifest,
// signed by a key its owner really controls, listing github.com/torvalds with
// method 'oauth'. Every assertion here exists to keep that manifest out of the
// verified bucket and out of the trust score.
//
// Run with `pnpm test`. Node's own test runner and Node's own type stripping,
// no test dependency: this package ships two source files and a fetch stub is
// the entire fixture surface.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { keyIdFromJwk, computeTrustScore } from '@realhandles/verify';
import { verifyIdentity, ORIGIN } from '../src/tools.ts';

const b64u = (bytes: Uint8Array | ArrayBuffer) =>
  Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

interface Account {
  platform: string;
  handle: string;
  profileUrl: string;
  method: string;
  verifiedAt: string;
}

/** A real Ed25519 signature over a real manifest, so nothing here passes by luck. */
async function signManifest(accounts: Account[]) {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const publicKey = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Record<string, unknown>;
  delete publicKey.key_ops;
  delete publicKey.ext;
  const keyId = await keyIdFromJwk(publicKey as any);
  const manifest = {
    version: '1',
    subject: { username: 'testuser', displayName: 'Test User', publicKey, keyId },
    accounts,
    issued: '2026-08-15T00:00:00.000Z',
    statement: 'I control the key that signed this manifest.',
  };
  const signingInput = `${b64u(Buffer.from(JSON.stringify({ alg: 'EdDSA' })))}.${b64u(
    Buffer.from(JSON.stringify(manifest))
  )}`;
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, Buffer.from(signingInput));
  return { jws: `${signingInput}.${b64u(sig)}`, keyId, manifest };
}

/** github:torvalds is the forgery; x:realowner is the account genuinely verified. */
const FORGED: Account = {
  platform: 'github',
  handle: 'torvalds',
  profileUrl: 'https://github.com/torvalds',
  method: 'oauth',
  verifiedAt: '2026-08-15T00:00:00.000Z',
};
const REAL: Account = {
  platform: 'x',
  handle: 'realowner',
  profileUrl: 'https://x.com/realowner',
  method: 'tweet-proof',
  verifiedAt: '2026-08-15T00:00:00.000Z',
};

/** Stub `fetch` for one call and hand back the URL it was asked for. */
function stubFetch(body: unknown, ok = true) {
  const calls: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: any) => {
    calls.push(String(url));
    return { ok, json: async () => body } as any;
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = original; } };
}

test('an account the directory does not back is claimed, however the manifest labels it', async () => {
  const signed = await signManifest([FORGED, REAL]);
  // The cross-checked split the site already computes: it backs x:realowner and
  // has no proof row behind github:torvalds.
  const stub = stubFetch({
    jws: signed.jws,
    accounts: {
      verified: [{ platform: 'x', handle: 'realowner' }],
      claimed: [{ platform: 'github', handle: 'torvalds' }],
    },
  });
  try {
    const r = await verifyIdentity('testuser');
    assert.equal(stub.calls[0], `${ORIGIN}/api/identity/testuser`);
    assert.equal(r.found, true);
    assert.equal((r as any).valid, true, 'the signature is genuine and must still verify');
    assert.equal((r as any).crossChecked, true);
    assert.deepEqual(
      (r as any).accounts.verified.map((a: any) => `${a.platform}:${a.handle}`),
      ['x:realowner']
    );
    assert.deepEqual(
      (r as any).accounts.claimed.map((a: any) => `${a.platform}:${a.handle}`),
      ['github:torvalds']
    );
  } finally {
    stub.restore();
  }
});

test('the trust score counts only cross-checked accounts, so it matches the site', async () => {
  const signed = await signManifest([FORGED, REAL]);
  const stub = stubFetch({
    jws: signed.jws,
    accounts: { verified: [{ platform: 'x', handle: 'realowner' }], claimed: [] },
  });
  try {
    const r = await verifyIdentity('testuser');
    const expected = computeTrustScore([
      { kind: 'platform', platform: 'x', handle: 'realowner', method: 'tweet-proof', verifiedAt: REAL.verifiedAt },
    ]).score;
    assert.equal((r as any).trustScore, expected);
    // The point of the assertion above is that the forged account bought
    // nothing. Pinned explicitly so a future scoring change cannot make the two
    // numbers coincide and quietly retire the check.
    const inflated = computeTrustScore([
      { kind: 'platform', platform: 'x', handle: 'realowner', method: 'tweet-proof', verifiedAt: REAL.verifiedAt },
      { kind: 'platform', platform: 'github', handle: 'torvalds', method: 'oauth', verifiedAt: FORGED.verifiedAt },
    ]).score;
    assert.ok(inflated > expected, 'fixture is only meaningful while the forgery would have added points');
    assert.notEqual((r as any).trustScore, inflated);
  } finally {
    stub.restore();
  }
});

test('handles are matched normalized, so an "@" or a capital does not cost a badge', async () => {
  const signed = await signManifest([{ ...REAL, handle: 'RealOwner' }]);
  const stub = stubFetch({
    jws: signed.jws,
    accounts: { verified: [{ platform: 'X', handle: '@realowner' }], claimed: [] },
  });
  try {
    const r = await verifyIdentity('testuser');
    assert.equal((r as any).accounts.verified.length, 1);
    assert.equal((r as any).accounts.claimed.length, 0);
  } finally {
    stub.restore();
  }
});

test('a domain is cross-checked by the same uniform rule', async () => {
  const domain: Account = {
    platform: 'domain',
    handle: 'example.com',
    profileUrl: 'https://example.com',
    method: 'domain-anchor',
    verifiedAt: '2026-08-15T00:00:00.000Z',
  };
  const signed = await signManifest([domain, { ...domain, handle: 'notmine.com' }]);
  const stub = stubFetch({
    jws: signed.jws,
    accounts: { verified: [{ platform: 'domain', handle: 'example.com' }], claimed: [] },
  });
  try {
    const r = await verifyIdentity('testuser');
    assert.deepEqual((r as any).accounts.verified.map((a: any) => a.handle), ['example.com']);
    assert.deepEqual((r as any).accounts.claimed.map((a: any) => a.handle), ['notmine.com']);
  } finally {
    stub.restore();
  }
});

test('an API response with no cross-checked split fails closed and says so', async () => {
  // What an older deploy of the site returns. Understating is safe; the caller
  // is told the split is missing so it does not read the silence as a finding.
  const signed = await signManifest([REAL]);
  const stub = stubFetch({ jws: signed.jws });
  try {
    const r = await verifyIdentity('testuser');
    assert.equal((r as any).valid, true);
    assert.equal((r as any).crossChecked, false);
    assert.match((r as any).crossCheckNote, /claimed/);
    assert.equal((r as any).accounts.verified.length, 0);
    assert.equal((r as any).accounts.claimed.length, 1);
    assert.equal((r as any).trustScore, 0);
  } finally {
    stub.restore();
  }
});

test('a tampered payload still fails on the signature, whatever the API says', async () => {
  const signed = await signManifest([REAL]);
  const [header, , sig] = signed.jws.split('.');
  const forgedPayload = b64u(
    Buffer.from(JSON.stringify({ ...signed.manifest, subject: { ...signed.manifest.subject, username: 'someoneelse' } }))
  );
  const stub = stubFetch({
    jws: `${header}.${forgedPayload}.${sig}`,
    accounts: { verified: [{ platform: 'x', handle: 'realowner' }], claimed: [] },
  });
  try {
    const r = await verifyIdentity('testuser');
    assert.equal(r.found, true);
    assert.equal((r as any).valid, false);
  } finally {
    stub.restore();
  }
});

test('no published identity is reported as not found', async () => {
  const stub = stubFetch(null, false);
  try {
    assert.deepEqual(await verifyIdentity('nobody'), { found: false });
  } finally {
    stub.restore();
  }
});
