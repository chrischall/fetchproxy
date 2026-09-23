/**
 * Wait for the background's asynchronous work to drain.
 *
 * The socket-harness tests used to sleep a fixed 20–30ms and then assert on
 * the frames sent. Trust records now live in IndexedDB (fleet-audit #252),
 * whose operations complete on later macrotasks rather than as microtasks, so
 * under a loaded parallel run a fixed sleep can end before the reply is sent.
 * This waits at least `minMs` (what the fixed sleep was), then keeps waiting
 * until `probe()` has not changed for `quietMs`, bounded by `maxMs` — never
 * shorter than before, so a test asserting that NOTHING was sent waits at
 * least as long as it always did.
 */
export async function settle(
  probe: () => string,
  minMs = 20,
  quietMs = 40,
  maxMs = 2000,
): Promise<void> {
  const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
  const start = Date.now();
  await sleep(minMs);
  let last = probe();
  let quietSince = Date.now();
  while (Date.now() - start < maxMs) {
    await sleep(5);
    const now = probe();
    if (now !== last) {
      last = now;
      quietSince = Date.now();
    } else if (Date.now() - quietSince >= quietMs) {
      return;
    }
  }
}
