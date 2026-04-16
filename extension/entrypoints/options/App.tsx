import { useState, useEffect } from "react";

interface BetaInfo {
  beta_mode: boolean;
  version: string;
  public_beta_key: string | null;
  telemetry_enabled: boolean;
  telemetry_sample_rate: number;
  rate_limiting: string;
  rate_limits: {
    predict: string;
    reports: string;
    threats: string;
  };
  docs_url: string | null;
  extension_download: string | null;
}

export default function Options() {
  const [apiKey, setApiKey] = useState("");
  const [betaInfo, setBetaInfo] = useState<BetaInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);
  const [showApiKey, setShowApiKey] = useState(false);

  useEffect(() => {
    loadSettings();
    fetchBetaInfo();
  }, []);

  const loadSettings = async () => {
    try {
      const stored = await browser.storage.local.get<{ apiKey: string }>(["apiKey"]);
      setApiKey(stored.apiKey || "phishscamsense-beta-2024-public");
    } catch (error) {
      console.error("Failed to load settings:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchBetaInfo = async () => {
    try {
      const stored = await browser.storage.local.get("apiBase");
      const baseUrl = (stored.apiBase as string | undefined) || "https://api.phishscam.my.id";
      const response = await fetch(`${baseUrl}/api/v1/beta_info`);
      if (response.ok) {
        const info = await response.json();
        setBetaInfo(info);
      }
    } catch (error) {
      console.error("Failed to fetch beta info:", error);
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    try {
      await browser.storage.local.set({ apiKey });
      setTestResult({ success: true, message: "Settings saved successfully!" });
      setTimeout(() => setTestResult(null), 3000);
    } catch (error) {
      setTestResult({ success: false, message: "Failed to save settings." });
      console.error("Failed to save settings:", error);
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async () => {
    setTesting(true);
    setTestResult(null);

    try {
      const stored = await browser.storage.local.get("apiBase");
      const apiBase = (stored.apiBase as string | undefined) || "https://api.phishscam.my.id";

      const response = await fetch(`${apiBase}/api/v1/predict`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": apiKey,
        },
        body: JSON.stringify({ url: "https://example.com" }),
      });

      if (response.ok) {
        setTestResult({ success: true, message: "Connection successful! API key is valid." });
      } else if (response.status === 401) {
        setTestResult({ success: false, message: "Authentication failed: Missing API key" });
      } else if (response.status === 403) {
        setTestResult({ success: false, message: "Authentication failed: Invalid API key" });
      } else {
        setTestResult({ success: false, message: `Connection failed: HTTP ${response.status}` });
      }
    } catch (error) {
      setTestResult({ success: false, message: "Connection failed: Backend unreachable" });
    } finally {
      setTesting(false);
    }
  };

  const resetToDefault = () => {
    setApiKey("phishscamsense-beta-2024-public");
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-gray-400">Loading settings...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-3xl font-bold mb-2">PhishScamSense Settings</h1>
        <p className="text-gray-400 mb-8">Configure your API connection and preferences</p>

        {/* Beta Info Card */}
        {betaInfo && betaInfo.beta_mode && (
          <div className="mb-8 p-4 bg-blue-900/30 border border-blue-700 rounded-lg">
            <h2 className="text-lg font-semibold text-blue-300 mb-2">🎯 Beta Mode Active</h2>
            <div className="text-sm text-gray-300 space-y-1">
              <p>Version: <span className="font-mono">{betaInfo.version}</span></p>
              <p>Public Beta Key: <span className="font-mono text-xs">{betaInfo.public_beta_key}</span></p>
              <p>Telemetry: <span className={betaInfo.telemetry_enabled ? "text-green-400" : "text-red-400"}>
                {betaInfo.telemetry_enabled ? "Enabled" : "Disabled"}
              </span> ({Math.round(betaInfo.telemetry_sample_rate * 100)}% sample rate)</p>
              <p>Rate Limiting: <span className="font-mono text-xs">{betaInfo.rate_limiting}</span></p>
            </div>
          </div>
        )}

        {/* API Configuration */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4">API Configuration</h2>

          {/* API Key */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              API Key
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  type={showApiKey ? "text" : "password"}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 pr-10"
                  placeholder="phishscamsense-beta-2024-public"
                />
                <button
                  type="button"
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showApiKey ? "👁️" : "🔒"}
                </button>
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Your API key for authentication. For beta users, use the public beta key.
            </p>
          </div>

          {/* Test Connection Button */}
          <button
            onClick={testConnection}
            disabled={testing}
            className="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed mb-3"
          >
            {testing ? "Testing..." : "Test Connection"}
          </button>

          {/* Test Result */}
          {testResult && (
            <div className={`p-3 rounded-lg text-sm ${testResult.success ? "bg-green-900/50 text-green-300" : "bg-red-900/50 text-red-300"}`}>
              {testResult.message}
            </div>
          )}
        </div>

        {/* Rate Limits Info */}
        {betaInfo && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4">Rate Limits</h2>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Predict Endpoint:</span>
                <span className="font-mono">{betaInfo.rate_limits.predict}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Reports Endpoint:</span>
                <span className="font-mono">{betaInfo.rate_limits.reports}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Threats Endpoint:</span>
                <span className="font-mono">{betaInfo.rate_limits.threats}</span>
              </div>
            </div>
            <p className="text-xs text-gray-500 mt-3">
              Rate limits are applied per IP address in beta mode
            </p>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-3">
          <button
            onClick={saveSettings}
            disabled={saving}
            className="flex-1 px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>
          <button
            onClick={resetToDefault}
            className="px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
          >
            Reset to Default
          </button>
        </div>

        {/* Help Section */}
        <div className="mt-8 p-4 bg-gray-800 rounded-lg">
          <h3 className="font-semibold mb-2">Need Help?</h3>
          <ul className="text-sm text-gray-400 space-y-1">
            <li>• Get your beta key at <a href="https://phishscam.my.id" target="_blank" className="text-blue-400 hover:underline">phishscam.my.id</a></li>
            <li>• Report issues on GitHub</li>
            <li>• Check documentation at /docs endpoint</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
