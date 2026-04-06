export default defineBackground(() => {
  console.log("PhishScamSense background service worker started");

  browser.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "CHECK_URL") {
      verifyWithBackend(message.url).then((result) => {
        sendResponse(result);
      });
      return true; // keep message channel open for async response
    }
  });
});

async function verifyWithBackend(
  url: string
): Promise<{ phishing: boolean; confidence: number; threat_type?: string }> {
  try {
    const stored = await browser.storage.local.get("apiBase");
    const apiBase = (stored.apiBase as string | undefined) || "http://localhost:8000";

    const response = await fetch(`${apiBase}/api/v1/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) throw new Error(`Backend returned ${response.status}`);
    return await response.json();
  } catch (err) {
    console.error("verifyWithBackend failed:", err);
    return { phishing: false, confidence: 0 };
  }
}
