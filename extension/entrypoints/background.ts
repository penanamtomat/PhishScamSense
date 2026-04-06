import { BloomFilter } from "@/lib/bloom-filter";

let bloomFilter: BloomFilter | null = null;

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
      // Fast-path: if we have a loaded bloom filter and it definitively says
      // this URL is NOT a known threat, skip the backend call.
      if (bloomFilter !== null && !bloomFilter.contains(message.url)) {
        sendResponse({ phishing: false, confidence: 0 });
        return;
      }

      // Otherwise always verify with the backend ML model.
      verifyWithBackend(message.url).then((result) => {
        sendResponse(result);
      });
      return true; // async response
    }
  });
});

async function initBloomFilter() {
  const stored = await browser.storage.local.get("bloomFilterData");
  const data = stored.bloomFilterData as number[] | undefined;
  if (data && data.length > 0) {
    bloomFilter = new BloomFilter(data.length, 7);
    bloomFilter.loadFromData(data);
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

    // Only use the filter if it has actual data
    if (Array.isArray(data.filter) && data.filter.length > 0) {
      bloomFilter = new BloomFilter(data.filter.length, data.num_hashes ?? 7);
      bloomFilter.loadFromData(data.filter);
      await browser.storage.local.set({ bloomFilterData: data.filter });
      console.log(`Threat list synced: ${data.num_items ?? "?"} threat URLs`);
    } else {
      // No valid filter data — keep bloomFilter null so all URLs go to backend
      bloomFilter = null;
      console.log("No bloom filter data available — all URLs will be verified by ML model");
    }
  } catch (error) {
    console.error("Failed to sync threat list:", error);
    // Keep bloomFilter null on error so the backend is always consulted
    bloomFilter = null;
  }
}

async function verifyWithBackend(
  url: string
): Promise<{ phishing: boolean; confidence: number; threat_type?: string }> {
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
  return (stored.apiBase as string | undefined) || "http://localhost:8000";
}
