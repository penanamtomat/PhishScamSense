export default defineBackground(async () => {
  console.log("PhishScamSense background service worker started");

  // Persist the resolved apiBase so static pages (blocked.html) can read it
  const stored = await browser.storage.local.get("apiBase");
  if (!stored.apiBase) {
    const resolved = import.meta.env.WXT_API_BASE || "http://localhost:8000";
    await browser.storage.local.set({ apiBase: resolved });
  }

  // Track in-flight checks (tabId:url) to prevent double-firing during a
  // single navigation. Cleared immediately after the check completes so the
  // same URL CAN be re-checked if the user navigates away and comes back.
  const inFlight = new Set<string>();

  // Track tabs blocked by Phase 1 so Phase 2 does not double-block
  const blockedTabs = new Set<number>();

  // URL prediction cache (1 hour TTL, max 500 entries)
  const CACHE_TTL_MS = 60 * 60 * 1000;
  const MAX_CACHE_SIZE = 500;
  interface CacheEntry {
    result: { phishing: boolean; confidence: number; threat_type?: string };
    expiresAt: number;
  }
  const predictionCache = new Map<string, CacheEntry>();
  function getCached(url: string): CacheEntry["result"] | null {
    const entry = predictionCache.get(url);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { predictionCache.delete(url); return null; }
    return entry.result;
  }
  function setCached(url: string, result: CacheEntry["result"]): void {
    if (predictionCache.size >= MAX_CACHE_SIZE) {
      const oldest = predictionCache.keys().next().value;
      if (oldest) predictionCache.delete(oldest);
    }
    predictionCache.set(url, { result, expiresAt: Date.now() + CACHE_TTL_MS });
  }

  // Rate-limit backoff state
  let rateLimitedUntil = 0;
  const RATE_LIMIT_BACKOFF_MS = 60 * 1000;

  // ---------------------------------------------------------------------------
  // Phase 1: URL-only check at navigation time (fast, lexical-based)
  // ---------------------------------------------------------------------------
  browser.tabs.onUpdated.addListener(async (tabId, changeInfo, _tab) => {
    // Only act when the tab starts loading a new URL
    if (changeInfo.status !== "loading" || !changeInfo.url) return;

    const url = changeInfo.url;

    // Skip non-http URLs (chrome://, about:, extension pages, etc.)
    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    // Guard: never check the blocked page itself (prevents redirect loop).
    const blockedPage = browser.runtime.getURL("/blocked.html");
    if (url.startsWith(blockedPage)) return;

    // Prevent double-firing for the same tab+url while a check is in-flight.
    const key = `${tabId}:${url}`;
    if (inFlight.has(key)) return;
    inFlight.add(key);

    try {
      let result = getCached(url);
      if (!result) {
        if (Date.now() < rateLimitedUntil) {
          console.warn(`[PhishScamSense] Rate limited — skipping check for ${url}. Protection temporarily reduced.`);
          await browser.action.setBadgeText({ text: "!" });
          await browser.action.setBadgeBackgroundColor({ color: "#f59e0b" });
          return;
        }
        result = await verifyWithBackend(url);
        setCached(url, result);
        await browser.action.setBadgeText({ text: "" });
      }

      if (result.phishing) {
        console.log(
          `[PhishScamSense] Phase 1 blocked — ${result.threat_type} | confidence: ${(result.confidence * 100).toFixed(1)}% | url: ${url}`
        );
        blockedTabs.add(tabId);
        const blockedPageUrl = browser.runtime.getURL("/blocked.html");
        const params = new URLSearchParams({
          url,
          threat: result.threat_type || "phishing",
          confidence: String(result.confidence),
          phase: "1",
        });
        await browser.tabs.update(tabId, {
          url: `${blockedPageUrl}?${params.toString()}`,
        });
      }
    } catch (err: unknown) {
      if (err instanceof RateLimitError) {
        rateLimitedUntil = Date.now() + RATE_LIMIT_BACKOFF_MS;
        console.warn(`[PhishScamSense] Rate limited — protection reduced for 1 minute.`);
        await browser.action.setBadgeText({ text: "!" });
        await browser.action.setBadgeBackgroundColor({ color: "#f59e0b" });
      } else {
        console.error(`Failed to check URL ${url}:`, err);
      }
    } finally {
      inFlight.delete(key);
    }
  });

  // Clean up in-flight entries and blocked state for closed tabs
  browser.tabs.onRemoved.addListener((tabId) => {
    for (const key of inFlight) {
      if (key.startsWith(`${tabId}:`)) inFlight.delete(key);
    }
    blockedTabs.delete(tabId);
  });

  // ---------------------------------------------------------------------------
  // Phase 2: Content-based check after page renders
  // ---------------------------------------------------------------------------
  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Popup status query
    if (message.type === "GET_STATUS") {
      sendResponse({ active: true });
      return false;
    }

    // Phase 2: content script has page HTML ready for analysis
    if (message.type === "PHASE2_CONTENT_READY") {
      const tabId = sender.tab?.id;
      if (tabId == null) return false;

      // Skip if Phase 1 already blocked this tab
      if (blockedTabs.has(tabId)) {
        sendResponse({ skipped: true, reason: "already_blocked" });
        return false;
      }

      // Respond immediately; analysis is fire-and-forget
      sendResponse({ received: true });

      handlePhase2(tabId, message.url, message.html).catch((err) => {
        console.error(`[PhishScamSense] Phase 2 failed for tab ${tabId}:`, err);
      });

      return false;
    }

    return false;
  });

  async function handlePhase2(
    tabId: number,
    url: string,
    html: string
  ): Promise<void> {
    // Re-check: tab may have navigated away since content script fired
    try {
      const tab = await browser.tabs.get(tabId);
      if (!tab.url?.startsWith(url.substring(0, 50))) {
        return;
      }
    } catch {
      // Tab was closed
      return;
    }

    // Skip if Phase 1 blocked while we were waiting
    if (blockedTabs.has(tabId)) return;

    try {
      const cacheKey = `phase2:${url}`;
      let result = getCached(cacheKey);
      if (!result) {
        if (Date.now() < rateLimitedUntil) {
          console.warn(`[PhishScamSense] Rate limited — skipping Phase 2 for ${url}.`);
          return;
        }
        result = await verifyWithBackend(url, html);
        setCached(cacheKey, result);
        await browser.action.setBadgeText({ text: "" });
      }

      if (result.phishing && !blockedTabs.has(tabId)) {
        console.log(
          `[PhishScamSense] Phase 2 blocked — ${result.threat_type} | confidence: ${(result.confidence * 100).toFixed(1)}% | url: ${url}`
        );
        blockedTabs.add(tabId);
        const blockedPageUrl = browser.runtime.getURL("/blocked.html");
        const params = new URLSearchParams({
          url,
          threat: result.threat_type || "phishing",
          confidence: String(result.confidence),
          phase: "2",
        });
        await browser.tabs.update(tabId, {
          url: `${blockedPageUrl}?${params.toString()}`,
        });
      }
    } catch (err: unknown) {
      if (err instanceof RateLimitError) {
        rateLimitedUntil = Date.now() + RATE_LIMIT_BACKOFF_MS;
        console.warn(`[PhishScamSense] Rate limited — Phase 2 protection reduced for 1 minute.`);
        await browser.action.setBadgeText({ text: "!" });
        await browser.action.setBadgeBackgroundColor({ color: "#f59e0b" });
      } else {
        console.warn(`[PhishScamSense] Phase 2 error for ${url}:`, err);
      }
    }
  }
});

// ---------------------------------------------------------------------------
// Backend communication
// ---------------------------------------------------------------------------
class RateLimitError extends Error {
  constructor() { super("Rate limit exceeded (429)"); this.name = "RateLimitError"; }
}

async function verifyWithBackend(
  url: string,
  html?: string
): Promise<{ phishing: boolean; confidence: number; threat_type?: string }> {
  const stored = await browser.storage.local.get("apiBase");
  const apiBase = (stored.apiBase as string | undefined)
    || import.meta.env.WXT_API_BASE
    || "http://localhost:8000";

  // Phase 1 (URL-only): 5s timeout
  // Phase 2 (content):  15s timeout (backend parses HTML)
  const timeout = html ? 15_000 : 5_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const body: { url: string; html?: string } = { url };
    if (html) body.html = html;

    // API key authentication
    // Beta mode: use the public beta key by default
    // Production mode: user can set custom key in settings
    const BETA_API_KEY = "phishscamsense-beta-2024-public";
    const keyStored = await browser.storage.local.get("apiKey");
    const apiKey = (keyStored.apiKey as string | undefined) || import.meta.env.WXT_API_KEY || BETA_API_KEY;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;

    const response = await fetch(`${apiBase}/api/v1/predict`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (response.status === 401 || response.status === 403) {
      throw new Error(`Authentication failed: ${response.status}`);
    }
    if (response.status === 429) { throw new RateLimitError(); }
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}
