import { defineConfig } from "wxt";

export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "PhishScamSense",
    description:
      "Real-Time Multimodal Phishing Defense using Browser Extension",
    version: "0.1.0",
    permissions: ["declarativeNetRequest", "storage", "alarms", "tabs"],
    host_permissions: ["<all_urls>"],
  },
});
