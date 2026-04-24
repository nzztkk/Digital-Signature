"use strict";

function runInteractiveDemo(demo) {
  const nodes = [...demo.querySelectorAll(".anim-node")];
  const caption = demo.querySelector(".anim-caption");
  if (!nodes.length || !caption) return;

  const stepsRaw = demo.getAttribute("data-steps") || "";
  const steps = stepsRaw.split("|").map((s) => s.trim()).filter(Boolean);
  if (!steps.length) return;

  nodes.forEach((node) => node.classList.remove("active"));
  let idx = 0;
  caption.textContent = steps[0];
  nodes[0].classList.add("active");

  const timer = setInterval(() => {
    idx += 1;
    if (idx >= nodes.length || idx >= steps.length) {
      clearInterval(timer);
      return;
    }
    nodes.forEach((node) => node.classList.remove("active"));
    nodes[idx].classList.add("active");
    caption.textContent = steps[idx];
  }, 900);
}

document.querySelectorAll(".interactive-demo").forEach((demo) => {
  const btn = demo.querySelector(".interactive-btn");
  if (!btn) return;
  btn.addEventListener("click", () => runInteractiveDemo(demo));
});
