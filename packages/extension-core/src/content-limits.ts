/**
 * The content script's body caps, in their own leaf module.
 *
 * They live here rather than in `content.ts` because `MAX_RESPONSE_BODY_BYTES`
 * is one of the inputs `MAX_FRAME_BYTES` is derived from (see
 * `@fetchproxy/protocol`'s `seal.ts`), and the test that re-does that
 * arithmetic has to be able to read the number without importing a module
 * that registers a `chrome.runtime.onMessage` listener at load.
 *
 * Both are counted in UTF-16 code units — `body.length` — and NOT in bytes.
 * That is a loose proxy for what a body costs on the wire (one unit can
 * become six bytes once JSON has escaped it), which is exactly why the wire
 * budget is enforced separately, at the point the frame is sealed.
 */

export const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024; // 1 MB
export const MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024; // 5 MB
