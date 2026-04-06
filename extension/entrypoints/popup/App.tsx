import { useState, useEffect } from "react";

export default function App() {
  const [currentUrl, setCurrentUrl] = useState<string>("");
  const [active, setActive] = useState(true);

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
  }, []);

  return (
    <div className="w-80 p-4 bg-gray-900 text-white">
      <h1 className="text-xl font-bold mb-3">PhishScamSense</h1>

      <div className="text-xs text-gray-400 mb-3 truncate" title={currentUrl}>
        {currentUrl || "No active tab"}
      </div>

      <div className={`p-3 rounded-lg text-sm ${active ? "bg-green-900/50 border border-green-700 text-green-300" : "bg-yellow-900/50 border border-yellow-700 text-yellow-300"}`}>
        {active
          ? "Protection is active. URLs are automatically checked when you navigate."
          : "Protection is inactive. Is the backend server running?"}
      </div>

      <p className="text-xs text-gray-500 mt-3">
        Dangerous URLs will be automatically blocked before the page loads.
      </p>
    </div>
  );
}
