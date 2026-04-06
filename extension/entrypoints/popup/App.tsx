import { useState, useEffect } from "react";

type Status = "safe" | "danger" | "checking" | "idle";

export default function App() {
  const [currentUrl, setCurrentUrl] = useState<string>("");
  const [status, setStatus] = useState<Status>("idle");
  const [confidence, setConfidence] = useState<number>(0);

  useEffect(() => {
    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      if (tabs[0]?.url) {
        setCurrentUrl(tabs[0].url);
        checkUrl(tabs[0].url);
      }
    });
  }, []);

  async function checkUrl(url: string) {
    setStatus("checking");
    const response = await browser.runtime.sendMessage({
      type: "CHECK_URL",
      url,
    });
    if (response.phishing) {
      setStatus("danger");
      setConfidence(response.confidence);
    } else {
      setStatus("safe");
    }
  }

  async function reportFalsePositive() {
    const stored = await browser.storage.local.get("apiBase");
    const apiBase = stored.apiBase || "http://localhost:8000";
    await fetch(`${apiBase}/api/v1/reports/false-positive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl }),
    });
    alert("Report submitted. Thank you!");
  }

  return (
    <div className="w-80 p-4 bg-gray-900 text-white">
      <h1 className="text-xl font-bold mb-3 flex items-center gap-2">
        PhishScamSense
      </h1>

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
          <p className="text-red-300 font-semibold">Phishing Detected!</p>
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

      {status === "idle" && (
        <div className="p-3 bg-gray-800 rounded-lg text-gray-400 text-center">
          Open a webpage to start scanning.
        </div>
      )}
    </div>
  );
}
