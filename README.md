# @realhandles/mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent look up a
[RealHandles](https://realhandles.com) identity and **cryptographically verify**
its signed proof.

The verification runs locally against the signature (via
[`@realhandles/verify`](https://github.com/realhandles/verify)), so a result
never depends on trusting realhandles.com. The API is used only to locate the
signed manifest; the "is this real" decision is the math, done on your side.

## Tools

- **`verify_identity(handle)`** - resolve a handle (aliases and renames
  included), verify its signed manifest, and return the verified accounts (split
  into verified and claimed), the key fingerprint, the `did:key`, and the trust
  score.
- **`check_link(url)`** - check whether a URL is a mutually confirmed account of
  a RealHandles identity (for rendering a "verified" badge).

## Use it

### Hosted (no install)

The server runs as a stateless HTTP endpoint, so most clients just need the URL:

```
https://mcp.realhandles.com/mcp
```

Nothing to install, no account, no key. Under the 2026-07-28 spec there is no
session to establish, so a client can call it directly:

```bash
curl -X POST https://mcp.realhandles.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Local (stdio)

Still supported and unchanged. For Claude Desktop, in
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "realhandles": {
      "command": "npx",
      "args": ["-y", "@realhandles/mcp"]
    }
  }
}
```

Either way, ask things like "verify the RealHandles identity for david" or "is
https://example.com a confirmed account of a RealHandles user?"

Both transports serve the same two tools from the same definitions in
`src/tools.ts`, and verification is local to whoever runs it in both cases. The
hosted endpoint locates the signed manifest exactly like the local one does; it
does not become an authority you have to trust.

To point it at a different deployment, set `REALHANDLES_ORIGIN` (defaults to
`https://realhandles.com`).

## Develop

```bash
npm install
npm run build
```

## License

MIT

## Why the `@realhandles/verify` range is not a caret

`package.json` asks for `">=0.10.0 <1.0.0"` rather than `^0.10.0`, and that is
deliberate.

A caret on a `0.x` version does NOT cross a minor: `^0.6.0` will never install
`0.7.0`. This package has been silently stranded by that twice, and the second
time it went three minors behind before anybody noticed, because nothing breaks
loudly. A manifest carrying a field the pinned verifier does not know still
verifies, since `verifySignedManifest` checks the signature over the payload
bytes and re-parses without rejecting unknown properties. So a stale pin does not
fail; it just quietly stops being able to SURFACE things the product publishes.

While `@realhandles/verify` is pre-1.0 and is maintained in lockstep with the
site (it is `src/lib/manifest.ts`, `didkey.ts` and `handles.ts` copied verbatim,
guarded by `pnpm check:verify-sync` over there), tracking the newest 0.x is what
we actually want. Revisit when it reaches 1.0.
