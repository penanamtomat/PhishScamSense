export default defineBackground(() => {
  console.log("PhishScamSense background service worker started");

  // Track tabs we've already checked to avoid duplicate checks
  const checkedUrls = new Map<number, string>();

  // Listen to every tab navigation
  browser.tabs.onUpdated.addListener(async (tabId, changeInfo, _tab) => {
    // Only act when the tab starts loading a new URL
    if (changeInfo.status !== "loading" || !changeInfo.url) return;

    const url = changeInfo.url;

    // Skip non-http URLs (chrome://, about:, extension pages, etc.)
    if (!url.startsWith("http://") && !url.startsWith("https://")) return;

    // Skip if we already checked this exact URL for this tab
    if (checkedUrls.get(tabId) === url) return;
    checkedUrls.set(tabId, url);

    console.log(`Checking URL: ${url}`);

    try {
      const result = await verifyWithBackend(url);
      console.log(`Result for ${url}:`, result);

      if (result.phishing) {
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
    }
  });

  // Clean up when tabs are closed
  browser.tabs.onRemoved.addListener((tabId) => {
    checkedUrls.delete(tabId);
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
  const apiBase = (stored.apiBase as string | undefined) || "http://localhost:8000";

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
