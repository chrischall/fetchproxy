/**
 * Shared ambient shape for the `chrome.*` extension APIs this package uses.
 *
 * Every module that touches `chrome` declares its own
 * `declare const chrome: ChromeApi;` against this interface (the same
 * convention as trust-store.ts, ensure-domain-tab.ts and
 * extension-identity.ts). Declaring the shape locally — rather than relying
 * on the @types/chrome global — is deliberate: the optional namespaces below
 * (`cookies?`, `webRequest?`, `downloads?`, `action?`) are real
 * manifest-permission guards that the code branches on, and @types/chrome
 * types them as always-present.
 *
 * A `declare` emits nothing, so this file is types-only.
 */

/** The subset of `chrome.cookies.Cookie` the writer reads back off an
 *  existing cookie in order to overwrite it in place rather than shadow it. */
export interface ChromeCookie {
  name: string;
  value: string;
  domain: string;
  hostOnly: boolean;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  expirationDate?: number;
  storeId?: string;
}

export interface ChromeApi {
  runtime: {
    getManifest: () => { version: string };
    /**
     * Optional: absent under vitest and on older Chrome. Used to re-inject
     * content scripts after an update, which otherwise leaves every open tab
     * without one until the person reloads it by hand.
     */
    onInstalled?: {
      addListener: (cb: (details: { reason: string }) => void) => void;
    };
    /**
     * Part 3: broadcast a message to all extension pages (e.g. open
     * popups). Used to notify the popup that the connected-session set
     * changed so it can re-render the status dots.
     */
    sendMessage?: (msg: unknown) => void;
    onMessage?: {
      addListener: (
        cb: (
          msg: unknown,
          _sender: unknown,
          sendResponse: (r: unknown) => void,
        ) => boolean | void,
      ) => void;
    };
  };
  storage: {
    local: {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
      set: (kv: Record<string, unknown>) => Promise<void>;
      remove: (k: string) => Promise<void>;
      onChanged: {
        addListener: (
          cb: (changes: Record<string, { newValue?: unknown; oldValue?: unknown }>) => void,
        ) => void;
      };
    };
  };
  tabs: {
    query: (q: { url?: string | string[] }) => Promise<{ id?: number; url?: string }[]>;
    create: (props: { url: string }) => Promise<{ id?: number; url?: string }>;
    sendMessage: (tabId: number, message: unknown) => Promise<unknown>;
    /**
     * Optional like the namespaces above, and for the same kind of reason: it
     * is a core API on any real Chrome, but the fakes in tests do not all
     * provide it and the cold-open registry must degrade rather than throw
     * where it is absent (`lib/cold-open.ts`).
     */
    get?: (tabId: number) => Promise<{ status?: string } | undefined>;
  };
  cookies?: {
    get: (details: { url: string; name: string }) => Promise<ChromeCookie | null>;
    /**
     * 1.12.0+: needed by `write_cookies`. Attribute fields are optional
     * because a correct overwrite copies them off the existing cookie —
     * `domain` in particular must be OMITTED for a host-only cookie, which is
     * why the writer spreads it conditionally rather than passing undefined.
     */
    set: (details: {
      url: string;
      name: string;
      value: string;
      domain?: string;
      path?: string;
      secure?: boolean;
      httpOnly?: boolean;
      sameSite?: string;
      expirationDate?: number;
      storeId?: string;
    }) => Promise<ChromeCookie | null>;
  };
  webRequest?: {
    onBeforeSendHeaders: {
      addListener: (
        cb: (details: {
          requestId: string;
          url: string;
          method: string;
          requestHeaders?: { name: string; value?: string }[];
        }) => void,
        filter: { urls: string[] },
        extraInfoSpec?: string[],
      ) => void;
      removeListener: (cb: unknown) => void;
    };
    onBeforeRedirect: {
      addListener: (
        cb: (details: {
          requestId: string;
          url: string;
          method: string;
          redirectUrl: string;
        }) => void,
        filter: { urls: string[] },
      ) => void;
      removeListener: (cb: unknown) => void;
    };
  };
  downloads?: {
    download: (options: {
      url: string;
      filename?: string;
      conflictAction?: 'uniquify' | 'overwrite' | 'prompt';
      saveAs?: boolean;
    }) => Promise<number>;
    search: (query: { id: number }) => Promise<
      {
        id: number;
        filename: string;
        fileSize: number;
        state: 'in_progress' | 'interrupted' | 'complete';
        mime?: string;
        finalUrl?: string;
        error?: string;
      }[]
    >;
    erase: (query: { id: number }) => Promise<number[]>;
    onChanged: {
      addListener: (
        cb: (delta: { id: number; state?: { current: string }; error?: { current: string } }) => void,
      ) => void;
      removeListener: (cb: unknown) => void;
    };
  };
  alarms: typeof globalThis.chrome.alarms;
  action?: {
    setBadgeText: (details: { text: string }) => Promise<void> | void;
    setBadgeBackgroundColor: (details: { color: string }) => Promise<void> | void;
    openPopup?: () => Promise<void>;
  };
}
