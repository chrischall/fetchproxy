> CWS review form: paste each justification into the corresponding permission field.

---

## Permission Justifications

### `storage`

Used to persist trust records (paired MCP server identities and their approved
capability sets), the extension's own long-term Ed25519/X25519 identity keypair,
and transient pending-pair state while a pairing is in progress. No data is ever
sent off the machine; all stored values remain in `chrome.storage.local` on the
user's device.

---

### `tabs`

Required to locate the user's signed-in tab on the MCP server's declared domain
when routing a fetch request. Transporter iterates open tabs and selects one whose
hostname is the declared domain or a subdomain of it (host-or-subdomain matching).
Tab URLs are checked only at request time and are not stored or transmitted. No
tab is opened, closed, or navigated without an explicit user action in the popup.

---

### `scripting`

Required to inject the content script that executes a `fetch()` call (or a
targeted storage read) inside the page's own context. Running inside the page
context is what gives the request the page's session cookies, TLS session, and
browser identity — the core capability Transporter provides. The injected script
performs only the single operation requested (fetch, localStorage read, etc.) and
returns the result; it does not manipulate the DOM or execute arbitrary code.

---

### `cookies`

Used only when the MCP server has declared the `read_cookies` capability and the
user approved it at pair time. The `chrome.cookies` API is the only way to read
HttpOnly cookies, which cannot be accessed from page-context JavaScript. Cookies
are read for the specific declared origin and returned over the encrypted localhost
WebSocket to the MCP server. No cookies are stored by the extension beyond what
`chrome.storage` already holds for trust records.

---

### `webRequest`

Used only when the MCP server has declared the `capture_request_header` capability
and the user approved it at pair time. A one-shot `onBeforeSendHeaders` listener
captures the value of a specific named request header (e.g. a bearer token the
tab sends automatically) and returns it to the MCP server. The listener is
registered for one request and then removed. Transporter **never modifies**
requests; it is a read-only observer.

---

### `alarms`

Used exclusively for MV3 service-worker keepalive. Chrome may terminate idle
service workers after approximately 30 seconds. A `chrome.alarms` alarm fires
every 24 seconds and triggers an idempotent `connect()` call that re-establishes
the WebSocket listener if it was torn down. Without this alarm, the bridge would
silently die between bursts of MCP traffic. No alarms are used for any other
purpose.

---

### `host_permissions: <all_urls>`

The domains that Transporter needs to reach are declared dynamically by each MCP
server at pair time and approved by the user during the pairing flow. Because the
set of possible domains is open-ended (any service a developer might build an MCP
for), the manifest must declare broad host permissions. However, runtime
enforcement is strict: every fetch URL, cookie origin, storage read, and tab
selection is checked against the specific `domains[]` allowlist the user approved
for that MCP server. Requests to any host outside that allowlist are blocked by
the extension before reaching a tab. The broad manifest declaration enables the
mechanism; the per-MCP allowlist is what actually governs access.

---

## Single-Purpose Statement

Relay HTTP fetches and read user-declared session data (cookies, localStorage,
request headers) between a local MCP server and the user's signed-in browser tab
on a domain the user has explicitly approved at pair time.
