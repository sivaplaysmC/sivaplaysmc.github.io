function extractFromDetails(blk) {
  const content = blk.querySelector("td:nth-child(2)>pre>code").textContent;
  return content;
}

function extractFromSimpleCode(container) {
  const code = container.querySelector("pre > code").textContent;
  return code;
}

document.querySelectorAll(".copy-button").forEach(btn => {
  btn.addEventListener("click", async () => {
    if (!navigator.clipboard) return;

    const root = document.getElementById(btn.dataset.copyTarget);
    if (!root) return;

    let content;

    if (root.tagName === "DETAILS") {
      content = extractFromDetails(root);
    } else {
      content = extractFromSimpleCode(root);
    }

    if (!content) return;

    try {
      await navigator.clipboard.writeText(content);

      const old = btn.textContent;
      btn.textContent = "Copied";
      btn.disabled = true;

      setTimeout(() => {
        btn.textContent = old;
        btn.disabled = false;
      }, 1000);
    } catch (e) {
      console.error("Copy failed", e);
    }
  });
});
