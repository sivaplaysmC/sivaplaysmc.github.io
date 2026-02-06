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

function setupThings() {
  const asideButtons = document.querySelectorAll(".aside-button");
  const codeSide = document.querySelector(".code-side");

  // Early return if code-side doesn't exist
  if (!codeSide) {
    console.warn("code-side element not found");
    return;
  }

  // Create tabs and panels containers if they don't exist
  let tabs = codeSide.querySelector(".code-tabs");
  let panels = codeSide.querySelector(".code-panels");

  if (!tabs) {
    tabs = document.createElement("div");
    tabs.className = "code-tabs";
    codeSide.appendChild(tabs);
  }

  if (!panels) {
    panels = document.createElement("div");
    panels.className = "code-panels";
    codeSide.appendChild(panels);
  }

  let counter = 0;

  function activateTab(id) {
    // Remove active class from all tabs and panels
    document.querySelectorAll(".code-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".code-panel").forEach(p => p.classList.remove("active"));

    // Add active class to selected tab and panel
    const selectedTab = document.querySelector(`[data-tab="${id}"]`);
    const selectedPanel = document.getElementById(id);

    if (selectedTab) selectedTab.classList.add("active");
    if (selectedPanel) selectedPanel.classList.add("active");
  }

  asideButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const sourceId = btn.dataset.asideTarget;
      const src = document.getElementById(sourceId);

      if (!src) {
        console.warn(`Source element not found: ${sourceId}`);
        return;
      }

      // Find the .chroma element inside the source
      const chromaElement = src.querySelector(".chroma");
      if (!chromaElement) {
        console.warn(`No .chroma element found in ${sourceId}`);
        return;
      }

      // Show code side
      codeSide.classList.add("visible");

      const newId = "aside-" + ++counter;

      // Clone only the .chroma element
      const clone = chromaElement.cloneNode(true);

      // Create a wrapper panel for the cloned content
      const panel = document.createElement("div");
      panel.id = newId;
      panel.className = "code-panel";
      panel.appendChild(clone);
      panels.appendChild(panel);

      // Create tab
      const tab = document.createElement("div");
      tab.className = "code-tab";
      tab.dataset.tab = newId;

      const titleElement = src.querySelector(".collapsable-code__title");
      tab.textContent = titleElement ? titleElement.textContent : "CODE";

      tab.addEventListener("click", () => activateTab(newId));
      tabs.appendChild(tab);

      // Activate the new tab
      activateTab(newId);
    });
  });
}

document.addEventListener("DOMContentLoaded", setupThings);
