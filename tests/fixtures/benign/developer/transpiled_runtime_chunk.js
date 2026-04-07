(function () {
  const manifest = { chunk: "runtime", flags: ["prod", "metrics"] };
  const encodedConfig = "eyJ0aGVtZSI6ImRhcmsiLCJsb2NhbGUiOiJlbi1VUyJ9";
  const decoded = atob(encodedConfig);
  const runtime = {
    manifest,
    decoded,
    start() {
      console.log("runtime ready", manifest.chunk);
    }
  };
  window.__APP_RUNTIME__ = runtime;
})();
