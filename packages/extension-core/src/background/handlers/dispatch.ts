/**
 * The verb table: `handleRequest`, moved verbatim out of `background.ts`.
 *
 * Sits above every handler module and below the socket, so the socket reaches
 * the handlers only through here and no handler can reach back to the
 * transport (they send via `sendInner`, which is its own leaf module).
 *
 * The `req.op === 'graphql_query' ? 'graphql' : req.op` remap below is the
 * single exception to op-name-equals-capability-name. Renaming either side
 * would silently deny every graphql request, since no MCP declares a
 * `graphql_query` capability.
 */

import type { InnerRequest } from '@fetchproxy/protocol';

import { sendInner } from '../send-inner.js';
import { mcpDomains, mcpCapabilities } from '../session-scope.js';

import { handleFetchRequest } from './fetch.js';
import {
  handleReadCookiesRequest,
  handleWriteCookiesRequest,
} from './cookies.js';
import { handleReadStorageRequest } from './read-storage.js';
import {
  handleCaptureRequestHeaderRequest,
  handleCaptureRedirectRequest,
} from './capture.js';
import { handleDownloadRequest } from './download.js';
import { handleReadIndexedDbRequest } from './read-indexed-db.js';
import { handleReadDomRequest } from './read-dom.js';
import { handleGraphqlQueryRequest } from './graphql-query.js';

export async function handleRequest(mcpId: string, req: InnerRequest): Promise<void> {
  const domains = mcpDomains.get(mcpId);
  if (!domains || domains.length === 0) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      error: 'no domains for mcpId',
    });
    return;
  }
  const capabilities = mcpCapabilities.get(mcpId) ?? ['fetch'];
  // The `graphql_query` verb is the one op whose wire string differs from its
  // capability string — it is governed by the `graphql` capability. Every
  // other op's capability equals its op name.
  const requiredCapability = req.op === 'graphql_query' ? 'graphql' : req.op;
  if (!capabilities.includes(requiredCapability)) {
    // Capability gate. The MCP didn't ask for this verb at pair time —
    // refuse with an op-echoing error so the server-side awaiter can
    // surface a clear message rather than blame the transport.
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: req.op,
      error: `capability ${JSON.stringify(requiredCapability)} not granted (declared: [${capabilities.join(', ')}])`,
    });
    return;
  }
  if (req.op === 'fetch') {
    await handleFetchRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_cookies') {
    await handleReadCookiesRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'write_cookies') {
    await handleWriteCookiesRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_local_storage') {
    await handleReadStorageRequest(mcpId, req, domains, 'local');
    return;
  }
  if (req.op === 'read_session_storage') {
    await handleReadStorageRequest(mcpId, req, domains, 'session');
    return;
  }
  if (req.op === 'capture_request_header') {
    await handleCaptureRequestHeaderRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'capture_redirect') {
    await handleCaptureRedirectRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_indexed_db') {
    await handleReadIndexedDbRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_dom') {
    await handleReadDomRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'graphql_query') {
    await handleGraphqlQueryRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'download') {
    await handleDownloadRequest(mcpId, req, domains);
    return;
  }
}
