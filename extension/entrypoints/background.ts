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

  // Listen to every tab navigation
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
    // Using a per-navigation key (not persistent) so re-visiting the same URL
    // after navigating away always triggers a fresh check.
    const key = `${tabId}:${url}`;
    if (inFlight.has(key)) return;
    inFlight.add(key);

    try {
      const result = await verifyWithBackend(url);

      if (result.phishing) {
        console.log(
          `[PhishScamSense] Blocked — ${result.threat_type} | confidence: ${(result.confidence * 100).toFixed(1)}% | url: ${url}`
        );
        // Redirect to blocked page
        const blockedPage = browser.runtime.getURL("/blocked.html");
        const params = new URLSearchParams({
          url,
          threat: result.threat_type || "phishing",
          confidence: String(result.confidence),
        });
        await browser.tabs.update(tabId, {
          url: `${blockedPage}?${params.toString()}`,
        });
      }
    } catch (err) {
      console.error(`Failed to check URL ${url}:`, err);
    } finally {
      // Release the in-flight lock so the same URL can be re-checked later
      inFlight.delete(key);
    }
  });

  // Clean up in-flight entries for closed tabs
  browser.tabs.onRemoved.addListener((tabId) => {
    for (const key of inFlight) {
      if (key.startsWith(`${tabId}:`)) inFlight.delete(key);
    }
  });

  // Also respond to popup status queries
  browser.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "GET_STATUS") {
      sendResponse({ active: true });
      return false;
    }
  });
});

async function verifyWithBackend(
  url: string
): Promise<{ phishing: boolean; confidence: number; threat_type?: string }> {
  const stored = await browser.storage.local.get("apiBase");
  const apiBase = (stored.apiBase as string | undefined)
    || import.meta.env.WXT_API_BASE
    || "http://localhost:8000";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(`${apiBase}/api/v1/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}
