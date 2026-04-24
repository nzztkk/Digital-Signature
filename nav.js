"use strict";

(function markActiveNavigation() {
  const currentPath = window.location.pathname.split("/").pop() || "index.html";
  const links = document.querySelectorAll(".top-nav a");

  links.forEach((link) => {
    const href = link.getAttribute("href") || "";
    const normalizedHref = href.replace("./", "");
    if (normalizedHref === currentPath) {
      link.classList.add("active");
      link.setAttribute("aria-current", "page");
    }
  });
})();
