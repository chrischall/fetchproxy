import { TrustStore, type TrustedMcp, type McpIdentity } from '../trust-store.js';

interface ConfiguredPort {
  port: number;
  label?: string;
}

interface PendingTrust extends McpIdentity {
  requested_at: number;
}

const trust = new TrustStore(chrome.storage.local);
const root = document.getElementById('root')!;

const HIGH_RISK_DOMAINS = new Set(['bank', 'gov', 'mil']); // TLD-based; expanded in v2

function isHighRisk(domain: string): boolean {
  const tld = domain.split('.').pop();
  return tld ? HIGH_RISK_DOMAINS.has(tld) : false;
}

async function render(): Promise<void> {
  // 1) Pending trust prompts take priority.
  const session = await chrome.storage.session.get();
  const pending: PendingTrust[] = [];
  for (const [k, v] of Object.entries(session)) {
    if (k.startsWith('pendingTrust:')) pending.push(v as PendingTrust);
  }
  if (pending.length > 0) {
    renderPrompt(pending[0]!);
    return;
  }

  // 2) Status view.
  const local = await chrome.storage.local.get('configuredPorts');
  const configured: ConfiguredPort[] = (local.configuredPorts as ConfiguredPort[] | undefined) ?? [];
  const trusted = await trust.list();
  renderStatus(configured, trusted);
}

function renderPrompt(p: PendingTrust): void {
  const risky = isHighRisk(p.domain);
  root.innerHTML = `
    <div class="prompt">
      <div>A new MCP server wants to relay HTTP requests through your browser:</div>
      <div class="domain">${escape(p.domain)}</div>
      <div style="font-size: 12px; color: #6b7280;">
        Server: ${escape(p.server)} v${escape(p.version)}<br>
        Port: ${p.port}
      </div>
      ${risky ? `<div style="margin-top: 8px; color: #b91c1c;">⚠️ High-risk domain (${escape(p.domain.split('.').pop() ?? '')}).</div>` : ''}
      <div class="buttons">
        <button class="block" id="block">Block</button>
        <button id="once">Allow once</button>
        <button class="always" id="always">Always allow</button>
      </div>
    </div>
  `;
  document.getElementById('block')!.addEventListener('click', async () => {
    await chrome.storage.session.remove(`pendingTrust:${p.port}`);
    render();
  });
  document.getElementById('once')!.addEventListener('click', async () => {
    await trust.approve({ port: p.port, server: p.server, domain: p.domain, version: p.version }, 'once');
    await chrome.storage.session.remove(`pendingTrust:${p.port}`);
    render();
  });
  document.getElementById('always')!.addEventListener('click', async () => {
    await trust.approve({ port: p.port, server: p.server, domain: p.domain, version: p.version }, 'always');
    await chrome.storage.session.remove(`pendingTrust:${p.port}`);
    render();
  });
}

function renderStatus(configured: ConfiguredPort[], trusted: TrustedMcp[]): void {
  const rows = configured.map((c) => {
    const t = trusted.find((m) => m.port === c.port);
    const dot = t ? '<span class="dot green"></span>' : '<span class="dot yellow"></span>';
    const label = t ? `${escape(t.server)} (${escape(t.domain)})` : `Port ${c.port} — waiting for trust`;
    return `<div class="mcp-row">${dot}${label}<button data-port="${c.port}" class="remove">Remove</button></div>`;
  });
  root.innerHTML = `
    ${rows.length === 0 ? '<div class="empty">No MCP servers configured. Add one below.</div>' : rows.join('')}
    <div class="add-row">
      <input id="port-input" type="number" placeholder="Port (e.g. 37149)">
      <button id="add">Add</button>
    </div>
  `;
  document.querySelectorAll<HTMLButtonElement>('button.remove').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const port = Number(btn.dataset.port);
      const local = await chrome.storage.local.get('configuredPorts');
      const list = ((local.configuredPorts as ConfiguredPort[] | undefined) ?? []).filter((c) => c.port !== port);
      await chrome.storage.local.set({ configuredPorts: list });
      const found = trusted.find((m) => m.port === port);
      if (found) await trust.revoke({ port: found.port, server: found.server, domain: found.domain });
      render();
    });
  });
  document.getElementById('add')!.addEventListener('click', async () => {
    const input = document.getElementById('port-input') as HTMLInputElement;
    const port = Number(input.value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return;
    const local = await chrome.storage.local.get('configuredPorts');
    const list = ((local.configuredPorts as ConfiguredPort[] | undefined) ?? []).filter((c) => c.port !== port);
    list.push({ port });
    await chrome.storage.local.set({ configuredPorts: list });
    render();
  });
}

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

render();
chrome.storage.onChanged.addListener(() => render());
