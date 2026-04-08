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

const pct = confidence ? parseFloat(confidence) * 100 : 0;
document.getElementById("detail-confidence").textContent = pct.toFixed(1) + "%";

const bar = document.getElementById("confidence-bar");
bar.style.width = pct + "%";
if (pct >= 80) bar.className = "confidence-bar confidence-high";
else if (pct >= 50) bar.className = "confidence-bar confidence-mid";
else bar.className = "confidence-bar confidence-low";

// "Go Back to Safety"
document.getElementById("back-btn").addEventListener("click", () => {
  window.location.href = "chrome://newtab";
});

// Report false positive
document.getElementById("report-btn").addEventListener("click", async () => {
  if (!blockedUrl || blockedUrl === "unknown") return;
  try {
    const stored = await chrome.storage.local.get("apiBase");
    const apiBase = stored.apiBase || "http://localhost:8000";
    await fetch(`${apiBase}/api/v1/reports/false-positive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: blockedUrl }),
    });
    document.getElementById("report-btn").textContent = "Report Submitted — Thank you!";
    document.getElementById("report-btn").disabled = true;
    document.getElementById("report-btn").style.color = "#22c55e";
  } catch {
    alert("Could not submit report. Is the backend running?");
  }
});
