# Privacy Policy — Transporter (fetchproxy)

**Last updated: 2026-05-26**

Transporter is a Chrome extension that bridges local MCP (Model Context Protocol) servers to your signed-in browser tabs. All communication is confined to your local machine. This policy describes exactly what data Transporter processes, stores, and shares.

---

## 1. What Transporter Does

Transporter acts as a relay between Node.js MCP servers running on your computer and web pages you have open in Chrome. When an MCP server makes a request, Transporter executes that request inside the browser tab you have open — carrying your existing session cookies and authentication — and returns the result to the MCP server over a local WebSocket connection.

No data leaves your machine through Transporter. Every connection is `127.0.0.1` only.

---

## 2. Data Processed

### 2.1 HTTP Requests and Responses

When an MCP server calls `fetch()` through Transporter, the extension makes the HTTP request from inside your browser tab. The request and response are passed over a local, encrypted WebSocket to the MCP server. Transporter does not log, cache, or retain request or response content after it is forwarded.

### 2.2 Session Data (Cookies, Storage, IndexedDB)

Depending on the capabilities an MCP server declares and you approve at pair time, Transporter may read — and, for one capability, modify:

| Capability | What it reads or changes |
|---|---|
| `read_cookies` | Cookies for declared domains |
| `read_local_storage` | `localStorage` contents for declared domains |
| `read_session_storage` | `sessionStorage` contents for declared domains |
| `read_indexed_db` | IndexedDB contents for declared domains |
| `capture_request_header` | Specific HTTP request headers on declared domains |
| `write_cookies` | **Changes** the value of cookies on declared domains. The only capability that modifies browser state rather than reading it. It can only overwrite a cookie that already exists and whose name the MCP already declared readable — it cannot create cookies, and it reaches nothing the MCP could not already read. |

**All session data reads — and the one write — are:**
- Scoped to the domains the MCP server explicitly declared in its hello frame.
- Gated on your explicit approval at pair time — you see the requested capabilities and domains before any access is granted.
- Passed directly to the requesting MCP server over the local encrypted WebSocket. Transporter does not store, forward, or log the content of cookies or storage values.

---

## 3. Data Stored

All persistent data is stored in `chrome.storage.local` on your device. It is **never synced** to `chrome.storage.sync`, never uploaded to any server, and never leaves your machine through the extension.

### 3.1 Extension Identity

Transporter generates a long-term Ed25519 signing keypair and an X25519 key-exchange keypair the first time it starts. These keys are used to authenticate the extension to MCP servers. They are stored in `chrome.storage.local`.

### 3.2 Trust Records

When you approve an MCP server at pair time, Transporter stores a trust record containing:
- The MCP server's public keys.
- The server name.
- The approved capability set and domain list.
- A timestamp.

Trust records are stored in `chrome.storage.local`. You can revoke any trust record from the extension popup at any time.

### 3.3 Pending-Pair State

While a pair confirmation is in progress (the 6-digit code dialog is showing), a transient pending-pair entry is held in `chrome.storage.local`. It is removed as soon as the pair is approved, rejected, or times out.

---

## 4. Data Shared Externally

**None.**

Transporter contains no telemetry, no analytics, no crash reporting, no remote configuration, no feature flags, and no A/B testing. It makes no outbound network connections of its own. The only network connections the extension is involved in are:

- The local WebSocket server it accepts on `127.0.0.1:37149` (MCP server connections).
- HTTP requests made inside your browser tabs at the explicit direction of an approved MCP server.

---

## 5. Permissions

Transporter requests several Chrome permissions. Each is required for core functionality — none is used for data collection. See [permission justifications](store-assets/permission-justifications.md) for the full per-permission justification.

---

## 6. Revoking Access

You can revoke an MCP server's trust at any time:

1. Click the Transporter icon in the Chrome toolbar to open the popup.
2. Find the MCP server entry.
3. Click **Revoke**.

After revocation, the MCP server must complete a new pair flow (including user approval) before it can make any requests through the extension.

---

## 7. Uninstalling

Uninstalling the Transporter extension removes all data stored in `chrome.storage.local`, including the extension's identity keypair and all trust records. Chrome handles this automatically on uninstall.

**Note:** MCP-side identity files (stored at `~/.fetchproxy/identity/<server-name>.json` on your computer) are not part of the extension and are not removed when you uninstall. You can delete them manually if desired.

---

## 8. Children's Privacy

Transporter is a developer tool. It is not directed at children and does not knowingly collect any information from anyone.

---

## 9. Changes to This Policy

If this policy changes materially, the updated policy will be published at this URL with a revised **Last updated** date. Because Transporter stores no account information, no individual notifications are sent.

---

## 10. Contact

Questions, concerns, or requests related to this privacy policy:

- **Email:** chris.c.hall@gmail.com
- **Issue tracker:** [github.com/chrischall/fetchproxy/issues](https://github.com/chrischall/fetchproxy/issues)
