const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get("url") || "unknown";
const threat = params.get("threat") || "phishing";
const confidence = params.get("confidence");

// Badge
const badge = document.getElementById("badge");
badge.textContent = threat.toUpperCase();
badge.className = "badge badge-" + (["phishing","malware","spam"].includes(threat) ? threat : "default");

// Title
const titles = {
  phishing: "Phishing Site Blocked",
  malware: "Malware Site Blocked",
  spam: "Spam Site Blocked",
};
document.getElementById("title").textContent = titles[threat] || "Dangerous Site Blocked";

// Description
const descriptions = {
  phishing: "This website is a potential phishing threat designed to steal your personal information.",
  malware: "This website may distribute malware that could harm your device.",
  spam: "This website has been identified as a spam site.",
};
document.getElementById("description").textContent =
  descriptions[threat] || "This website has been identified as potentially dangerous.";

// Details
document.getElementById("detail-url").textContent = blockedUrl;
document.getElementById("detail-threat").textContent = threat.charAt(0).toUpperCase() + threat.slice(1);

const phase = params.get("phase") || "1";
document.getElementById("detail-phase").textContent =
  phase === "2" ? "Content Analysis" : "URL Analysis";

const pct = confidence ? parseFloat(confidence) * 100 : 0;
document.getElementById("detail-confidence").textContent = pct.toFixed(1) + "%";

const bar = document.getElementById("confidence-bar");
bar.style.width = pct + "%";
if (pct >= 80) bar.className = "confidence-bar confidence-high";
else if (pct >= 50) bar.className = "confidence-bar confidence-mid";
else bar.className = "confidence-bar confidence-low";

// Cross-browser API shim (browser.* for Firefox, chrome.* fallback for Chrome)
const ext = typeof browser !== "undefined" ? browser : chrome;

// "Go Back to Safety" — use browser-appropriate new-tab URL
document.getElementById("back-btn").addEventListener("click", () => {
  ext.tabs.getCurrent((tab) => {
    const newTabUrl = ext.runtime.getURL("/blocked.html").startsWith("moz-extension:")
      ? "about:home"
      : "chrome://newtab";
    ext.tabs.update(tab.id, { url: newTabUrl });
  });
});

// Report false positive
document.getElementById("report-btn").addEventListener("click", async () => {
  if (!blockedUrl || blockedUrl === "unknown") return;
  const btn = document.getElementById("report-btn");
  btn.disabled = true;
  btn.textContent = "Submitting\u2026";
  try {
    const stored = await ext.storage.local.get("apiBase");
    const apiBase = stored.apiBase || "http://localhost:8000";
    const keyStored = await ext.storage.local.get("apiKey");
    const apiKey = keyStored.apiKey || "phishscamsense-beta-2024-public";
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;
    const response = await fetch(`${apiBase}/api/v1/reports/false-positive`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ url: blockedUrl }),
    });
    if (!response.ok) throw new Error("Server returned " + response.status);
    btn.textContent = "Report Submitted \u2014 Thank you!";
    btn.style.color = "#22c55e";
  } catch {
    btn.disabled = false;
    btn.textContent = "Could not submit report. Is the backend running?";
    btn.style.color = "#ef4444";
    setTimeout(() => {
      btn.textContent = "Report as False Positive";
      btn.style.color = "";
    }, 3000);
  }
});
