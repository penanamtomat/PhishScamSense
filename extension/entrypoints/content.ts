export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  runAt: "document_idle",

  main() {
    const MAX_HTML_SIZE = 512 * 1024; // 512 KB hard cap

    const TAGS_TO_STRIP = [
      "script",
      "style",
      "noscript",
      "svg",
      "path",
      "source",
      "track",
    ];

    function sanitizeHtml(doc: Document): string {
      const clone = doc.cloneNode(true) as Document;

      for (const tag of TAGS_TO_STRIP) {
        clone.querySelectorAll(tag).forEach((el) => el.remove());
      }

      let html = clone.documentElement.outerHTML;
      if (html.length > MAX_HTML_SIZE) {
        html = html.substring(0, MAX_HTML_SIZE);
      }
      return html;
    }

    // Skip extension's own pages and the blocked page
    const protocol = window.location.protocol;
    if (
      protocol === "chrome-extension:" ||
      protocol === "moz-extension:" ||
      window.location.href.includes("/blocked.html")
    ) {
      return;
    }

    const html = sanitizeHtml(document);

    browser.runtime
      .sendMessage({
        type: "PHASE2_CONTENT_READY",
        url: window.location.href,
        html,
      })
      .catch((err: Error) => {
        if (err.message?.includes("Extension context invalidated")) return;
        console.warn("[PhishScamSense] Phase 2 message failed:", err.message);
      });
  },
});
