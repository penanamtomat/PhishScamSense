import { useState, useEffect } from "react";

export default function App() {
  const [currentUrl, setCurrentUrl] = useState<string>("");
  const [active, setActive] = useState(true);
  const [apiKey, setApiKey] = useState<string>("");

  useEffect(() => {
    browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      const url = tabs[0]?.url;
      if (url && url.startsWith("http")) {
        setCurrentUrl(url);
      }
    });

    // Check if background service worker is active
    browser.runtime.sendMessage({ type: "GET_STATUS" }).then((res) => {
      setActive(res?.active ?? false);
    }).catch(() => setActive(false));

    // Load API key to show if configured
    browser.storage.local.get("apiKey").then((result) => {
      setApiKey(result.apiKey || "");
    });
  }, []);

  const openSettings = () => {
    browser.runtime.openOptionsPage();
  };

  return (
    <div className="w-80 p-4 bg-gray-900 text-white">
      <div className="flex items-center justify-between mb-3">
        <h1 className="text-xl font-bold">PhishScamSense</h1>
        <button
          onClick={openSettings}
          className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
          title="Open Settings"
        >
          ⚙️
        </button>
      </div>

      <div className="text-xs text-gray-400 mb-3 truncate" title={currentUrl}>
        {currentUrl || "No active tab"}
      </div>

      <div className={`p-3 rounded-lg text-sm ${active ? "bg-green-900/50 border border-green-700 text-green-300" : "bg-yellow-900/50 border border-yellow-700 text-yellow-300"}`}>
        {active
          ? "Protection is active. URLs are automatically checked when you navigate."
          : "Protection is inactive. Is the backend server running?"}
      </div>

      {/* API Key Status */}
      <div className="mt-3 p-2 bg-gray-800 rounded-lg">
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400">API Key:</span>
          <span className={`text-xs font-medium ${apiKey ? "text-green-400" : "text-yellow-400"}`}>
            {apiKey ? "✓ Configured" : "Using Beta Key"}
          </span>
        </div>
      </div>

      <p className="text-xs text-gray-500 mt-3">
        Dangerous URLs will be automatically blocked before the page loads.
      </p>

      <button
        onClick={openSettings}
        className="w-full mt-3 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
      >
        Open Settings
      </button>
    </div>
  );
}
