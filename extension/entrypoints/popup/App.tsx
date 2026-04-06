import { useState, useEffect } from "react";

type Status = "safe" | "danger" | "checking" | "idle" | "error";

export default function App() {
  const [currentUrl, setCurrentUrl] = useState<string>("");
  const [status, setStatus] = useState<Status>("idle");
  const [confidence, setConfidence] = useState<number>(0);
  const [threatType, setThreatType] = useState<string>("");

  useEffect(() => {
    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      const url = tabs[0]?.url;
      if (url && url.startsWith("http")) {
        setCurrentUrl(url);
        checkUrl(url);
      } else {
        setStatus("idle");
      }
    });
  }, []);

  async function checkUrl(url: string) {
    setStatus("checking");
    try {
      const response = await browser.runtime.sendMessage({
        type: "CHECK_URL",
        url,
      });

      if (!response) {
        // Background didn't respond (service worker may have been inactive)
        setStatus("error");
        return;
      }

      if (response.phishing) {
        setStatus("danger");
        setConfidence(response.confidence ?? 0);
        setThreatType(response.threat_type ?? "threat");
      } else {
        setStatus("safe");
      }
    } catch (err) {
      console.error("checkUrl error:", err);
      setStatus("error");
    }
  }

  async function reportFalsePositive() {
    const stored = await browser.storage.local.get("apiBase");
    const apiBase = (stored.apiBase as string | undefined) || "http://localhost:8000";
    try {
      await fetch(`${apiBase}/api/v1/reports/false-positive`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentUrl }),
      });
      alert("Report submitted. Thank you!");
    } catch {
      alert("Could not submit report. Is the backend running?");
    }
  }

  return (
    <div className="w-80 p-4 bg-gray-900 text-white">
      <h1 className="text-xl font-bold mb-3">PhishScamSense</h1>

      <div className="text-xs text-gray-400 mb-3 truncate" title={currentUrl}>
        {currentUrl || "No active tab"}
      </div>

      {status === "checking" && (
        <div className="p-3 bg-gray-800 rounded-lg text-center">
          Analyzing URL...
        </div>
      )}

      {status === "safe" && (
        <div className="p-3 bg-green-900/50 border border-green-700 rounded-lg text-green-300">
          This URL appears safe.
        </div>
      )}

      {status === "danger" && (
        <div className="p-3 bg-red-900/50 border border-red-700 rounded-lg">
          <p className="text-red-300 font-semibold">
            {threatType ? `${threatType.charAt(0).toUpperCase() + threatType.slice(1)} Detected!` : "Threat Detected!"}
          </p>
          <p className="text-red-400 text-sm mt-1">
            Confidence: {(confidence * 100).toFixed(1)}%
          </p>
          <button
            onClick={reportFalsePositive}
            className="mt-2 text-xs text-gray-400 hover:text-white underline"
          >
            Report as false positive
          </button>
        </div>
      )}

      {status === "error" && (
        <div className="p-3 bg-yellow-900/50 border border-yellow-700 rounded-lg text-yellow-300">
          Could not reach backend. Is the server running?
        </div>
      )}

      {status === "idle" && (
        <div className="p-3 bg-gray-800 rounded-lg text-gray-400 text-center">
          Open a webpage to start scanning.
        </div>
      )}
    </div>
  );
}
