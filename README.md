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

Add it to any MCP client. For Claude Desktop, in `claude_desktop_config.json`:

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

Then ask things like "verify the RealHandles identity for david" or "is
https://example.com a confirmed account of a RealHandles user?"

To point it at a different deployment, set `REALHANDLES_ORIGIN` (defaults to
`https://realhandles.com`).

## Develop

```bash
npm install
npm run build
```

## License

MIT
