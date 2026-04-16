import { defineConfig } from "wxt";

export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "PhishScamSense",
    description:
      "Real-Time Multimodal Phishing Defense using Browser Extension",
    version: "0.2.0",  // WXT requires semver without pre-release suffix
    permissions: ["storage", "tabs", "activeTab"],
    host_permissions: ["<all_urls>"],
    options_page: "entrypoints/options.html",
    options_ui: {
      page: "entrypoints/options.html",
      open_in_tab: true,
    },
  },
});
