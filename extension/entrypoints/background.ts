import { BloomFilter } from "@/lib/bloom-filter";

let bloomFilter: BloomFilter;

export default defineBackground(() => {
  console.log("PhishScamSense background service worker started");

  // Initialize Bloom Filter with stored data
  initBloomFilter();

  // Set up periodic sync alarm for threat list updates
  browser.alarms.create("sync-threat-list", { periodInMinutes: 60 });

  browser.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === "sync-threat-list") {
      await syncThreatList();
    }
  });

  // Listen for URL check requests from content scripts or popup
  browser.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "CHECK_URL") {
      const isSuspicious = bloomFilter.contains(message.url);
      if (isSuspicious) {
        verifyWithBackend(message.url).then((result) => {
          sendResponse(result);
        });
        return true; // async response
      }
      sendResponse({ phishing: false });
    }
  });
});

async function initBloomFilter() {
  bloomFilter = new BloomFilter(1_000_000, 7);

  const stored = await browser.storage.local.get("bloomFilterData");
  if (stored.bloomFilterData) {
    bloomFilter.loadFromData(stored.bloomFilterData);
    console.log("Bloom filter loaded from storage");
  } else {
    await syncThreatList();
  }
}

async function syncThreatList() {
  try {
    const API_BASE = await getApiBase();
    const response = await fetch(`${API_BASE}/api/v1/threats/bloom-filter`);
    if (!response.ok) throw new Error("Failed to fetch threat list");

    const data = await response.json();
    bloomFilter.loadFromData(data.filter);

    await browser.storage.local.set({ bloomFilterData: data.filter });
    console.log("Threat list synced successfully");
  } catch (error) {
    console.error("Failed to sync threat list:", error);
  }
}

async function verifyWithBackend(
  url: string
): Promise<{ phishing: boolean; confidence: number }> {
  try {
    const API_BASE = await getApiBase();
    const response = await fetch(`${API_BASE}/api/v1/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) throw new Error("Backend verification failed");
    return await response.json();
  } catch {
    return { phishing: false, confidence: 0 };
  }
}

async function getApiBase(): Promise<string> {
  const stored = await browser.storage.local.get("apiBase");
  return stored.apiBase || "http://localhost:8000";
}
