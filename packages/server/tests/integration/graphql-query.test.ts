import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  generateX25519,
  generateEd25519,
  ed25519Sign,
  readySignaturePayload,
  concatBytes,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  HKDF_SESSION_INFO,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { FetchproxyServer } from '../../src/index.js';
import { getEphemeralPort } from '../helpers/ephemeral-port.js';

/**
 * End-to-end exercise of the `graphql` capability through the real
 * WebSocket concentrator. A mock extension dials the host, auto-approves
 * the pair, and replies to a `graphql_query` inner request with a canned
 * `data` object. `FetchproxyServer.graphqlQuery` should round-trip the
 * `data` object back and pin `graphqlOps` on the wire.
 *
 * Mirrors `all-bootstrap-verbs.test.ts` for shape and lifecycle.
 */
describe('integration: graphql capability', () => {
  let server: FetchproxyServer | null = null;
  let extWs: WebSocket | null = null;

  afterEach(async () => {
    if (extWs && extWs.readyState === extWs.OPEN) extWs.close();
    if (server) await server.close();
    server = null;
    extWs = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  it('routes graphqlQuery through the bridge, pins graphqlOps, returns data', async () => {
    const port = await getEphemeralPort();
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-graphql-'));

    server = new FetchproxyServer({
      port,
      serverName: 'opentable-mcp',
      version: '1.0.0',
      domains: ['opentable.com'],
      capabilities: ['fetch', 'graphql'],
      graphqlOps: [
        { name: 'availability', operationName: 'RestaurantsAvailability' },
      ],
      identityDir: idDir,
    });
    await server.listen();
    await server.connect();

    extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      extWs!.once('open', () => resolve());
      extWs!.once('error', reject);
    });

    let sessionKey: Uint8Array | null = null;
    let mcpId: string | null = null;
    let outboundSeq = 0;
    let helloFrame: HelloFrameFromServer | null = null;
    let capturedInit: unknown = null;

    const extIdX = await generateX25519();
    const extIdEd = await generateEd25519();
    const extSessionNonce = new Uint8Array(32);
    (globalThis.crypto as Crypto).getRandomValues(extSessionNonce);

    const ready = new Promise<void>((resolveReady) => {
      extWs!.on('message', async (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);

          if (frame.type === 'hello' && frame.role === 'server') {
            helloFrame = frame;
            const identityX25519Pub = new Uint8Array(
              Buffer.from(frame.identityX25519Pub, 'base64'),
            );
            const mcpSessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
            const ephemeral = await generateX25519();
            const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
            sessionKey = await hkdfSha256(
              shared,
              mcpSessionNonce,
              new TextEncoder().encode(HKDF_SESSION_INFO),
              32,
            );
            mcpId = frame.mcpId;
            const sig = await ed25519Sign(
              extIdEd.privateKey,
              readySignaturePayload(mcpSessionNonce, extSessionNonce, ephemeral.publicKey),
            );
            const readyFrame: ReadyFrame = {
              type: 'ready',
              mcpId,
              extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
              sessionSig: Buffer.from(sig).toString('base64'),
            };
            extWs!.send(JSON.stringify(readyFrame));
            resolveReady();
            return;
          }
          if (frame.type === 'frame') {
            if (!sessionKey || !mcpId || frame.mcpId !== mcpId) return;
            const inner = await openEncryptedFrame(sessionKey, frame);
            if (inner.type !== 'request') return;
            outboundSeq += 1;
            if (inner.op === 'graphql_query') {
              capturedInit = inner.init;
              const sealed = await sealInnerFrame(sessionKey, mcpId, outboundSeq, {
                type: 'response',
                id: inner.id,
                ok: true,
                op: 'graphql_query',
                data: { availability: [{ time: '17:00', tableType: 'Standard' }] },
              });
              extWs!.send(JSON.stringify(sealed));
            }
          }
        } catch (e) {
          console.error('mock extension error:', e);
        }
      });

      const extHello: HelloFrameFromExtension = {
        type: 'hello',
        protocolVersion: 3,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '1.0.0',
        identityX25519Pub: Buffer.from(extIdX.publicKey).toString('base64'),
        identityEd25519Pub: Buffer.from(extIdEd.publicKey).toString('base64'),
        sessionNonce: Buffer.from(extSessionNonce).toString('base64'),
      };
      extWs!.send(JSON.stringify(extHello));
    });

    await ready;

    // The wire-level hello must have surfaced the declared graphqlOps.
    expect(helloFrame).not.toBeNull();
    expect(helloFrame!.graphqlOps).toEqual([
      { name: 'availability', operationName: 'RestaurantsAvailability' },
    ]);

    const result = await server.graphqlQuery({
      name: 'availability',
      variables: { restaurantIds: ['1175428'], partySize: 2 },
      tabUrl: 'https://www.opentable.com/r/la-belle-helene-charlotte-2',
    });

    expect(result).toEqual({
      availability: [{ time: '17:00', tableType: 'Standard' }],
    });
    // The MCP's name + variables + tabUrl reached the bridge intact.
    expect(capturedInit).toEqual({
      name: 'availability',
      variables: { restaurantIds: ['1175428'], partySize: 2 },
      tabUrl: 'https://www.opentable.com/r/la-belle-helene-charlotte-2',
    });
  }, 30_000);

  it('rejects graphqlQuery on an ok:false response WITHOUT closing the extension WebSocket', async () => {
    // Regression with real end-to-end value: this is the exact path the
    // auto-review found broken — an ok:false, op:'graphql_query' response
    // (e.g. the "operation not yet observed on this tab" error every
    // first-run graphql call hits) used to fail validateInnerResponse
    // (KNOWN_CAPABILITIES didn't contain 'graphql_query') and, via
    // host.ts's message-handler catch-all, close the whole extension
    // WebSocket — killing the bridge for every MCP on the concentrator,
    // not just this one call. The prior test only ever exercised ok:true,
    // so it could not have caught this. This test drives the SAME real
    // WS + encryption + validation + dispatch stack and asserts both that
    // the call rejects AND that the connection survives afterward.
    const port = await getEphemeralPort();
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-graphql-fail-'));

    server = new FetchproxyServer({
      port,
      serverName: 'opentable-mcp',
      version: '1.0.0',
      domains: ['opentable.com'],
      capabilities: ['fetch', 'graphql'],
      graphqlOps: [
        { name: 'availability', operationName: 'RestaurantsAvailability' },
      ],
      identityDir: idDir,
    });
    await server.listen();
    await server.connect();

    extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      extWs!.once('open', () => resolve());
      extWs!.once('error', reject);
    });

    let sessionKey: Uint8Array | null = null;
    let mcpId: string | null = null;
    let outboundSeq = 0;

    const extIdX = await generateX25519();
    const extIdEd = await generateEd25519();
    const extSessionNonce = new Uint8Array(32);
    (globalThis.crypto as Crypto).getRandomValues(extSessionNonce);

    const ready = new Promise<void>((resolveReady) => {
      extWs!.on('message', async (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);

          if (frame.type === 'hello' && frame.role === 'server') {
            const identityX25519Pub = new Uint8Array(
              Buffer.from(frame.identityX25519Pub, 'base64'),
            );
            const mcpSessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
            const ephemeral = await generateX25519();
            const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
            sessionKey = await hkdfSha256(
              shared,
              mcpSessionNonce,
              new TextEncoder().encode(HKDF_SESSION_INFO),
              32,
            );
            mcpId = frame.mcpId;
            const sig = await ed25519Sign(
              extIdEd.privateKey,
              readySignaturePayload(mcpSessionNonce, extSessionNonce, ephemeral.publicKey),
            );
            const readyFrame: ReadyFrame = {
              type: 'ready',
              mcpId,
              extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
              sessionSig: Buffer.from(sig).toString('base64'),
            };
            extWs!.send(JSON.stringify(readyFrame));
            resolveReady();
            return;
          }
          if (frame.type === 'frame') {
            if (!sessionKey || !mcpId || frame.mcpId !== mcpId) return;
            const inner = await openEncryptedFrame(sessionKey, frame);
            if (inner.type !== 'request') return;
            outboundSeq += 1;
            if (inner.op === 'graphql_query') {
              // The documented, expected-on-first-run failure — an
              // ok:false, op:'graphql_query' response.
              const sealed = await sealInnerFrame(sessionKey, mcpId, outboundSeq, {
                type: 'response',
                id: inner.id,
                ok: false,
                op: 'graphql_query',
                error:
                  'operation RestaurantsAvailability not yet observed on this tab — open a page on the site that triggers this GraphQL operation, then retry',
              });
              extWs!.send(JSON.stringify(sealed));
            }
          }
        } catch (e) {
          console.error('mock extension error:', e);
        }
      });

      const extHello: HelloFrameFromExtension = {
        type: 'hello',
        protocolVersion: 3,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '1.0.0',
        identityX25519Pub: Buffer.from(extIdX.publicKey).toString('base64'),
        identityEd25519Pub: Buffer.from(extIdEd.publicKey).toString('base64'),
        sessionNonce: Buffer.from(extSessionNonce).toString('base64'),
      };
      extWs!.send(JSON.stringify(extHello));
    });

    await ready;

    await expect(
      server.graphqlQuery({
        name: 'availability',
        variables: { restaurantIds: ['1175428'], partySize: 2 },
        tabUrl: 'https://www.opentable.com/r/la-belle-helene-charlotte-2',
      }),
    ).rejects.toThrow(/not yet observed on this tab/);

    // The whole point of the fix: the extension WebSocket must still be
    // open — this ok:false response must NOT have torn down the bridge.
    expect(extWs!.readyState).toBe(extWs!.OPEN);

    // And the bridge must still be genuinely usable, not just "not yet
    // closed" — issue a second, successful graphqlQuery over the SAME
    // connection to prove it. `outboundSeq` must keep counting up from
    // where the first round left it (inbound seq is strictly increasing
    // per session — resetting it here would make the server treat this
    // as a replay and silently drop it, hanging this call forever).
    extWs!.removeAllListeners('message');
    extWs!.on('message', async (data) => {
      try {
        const parsed = JSON.parse(data.toString());
        const frame = validateFrame(parsed);
        if (frame.type !== 'frame' || !sessionKey || !mcpId || frame.mcpId !== mcpId) return;
        const inner = await openEncryptedFrame(sessionKey, frame);
        if (inner.type !== 'request' || inner.op !== 'graphql_query') return;
        outboundSeq += 1;
        const sealed = await sealInnerFrame(sessionKey, mcpId, outboundSeq, {
          type: 'response',
          id: inner.id,
          ok: true,
          op: 'graphql_query',
          data: { availability: [{ time: '17:00', tableType: 'Standard' }] },
        });
        extWs!.send(JSON.stringify(sealed));
      } catch (e) {
        console.error('mock extension error (second call):', e);
      }
    });

    const secondResult = await server.graphqlQuery({
      name: 'availability',
      variables: { restaurantIds: ['1175428'], partySize: 2 },
      tabUrl: 'https://www.opentable.com/r/la-belle-helene-charlotte-2',
    });
    expect(secondResult).toEqual({
      availability: [{ time: '17:00', tableType: 'Standard' }],
    });
  }, 30_000);
});
