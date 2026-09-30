/**
 * Character-Cell Design (CCD) layout driver.
 * Packs main column widths and gutters in whole ch cells (digital).
 * Horizontal: --cc-w (px). Vertical: 1rem.
 */
let chPx = 0;
let remPx = 16;
let initialized = false;

const ruler = document.createElement("div");
ruler.setAttribute("aria-hidden", "true");
ruler.style.cssText =
  "position:absolute;left:-9999px;top:0;visibility:hidden;font-size:1rem;white-space:pre;pointer-events:none;";
ruler.textContent = "0";

function readContentMax(): number {
  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue("--cc-content-max")
    .trim();
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 80;
}

export function snapCcd(): void {
  if (!ruler.isConnected) document.body.appendChild(ruler);

  chPx = ruler.getBoundingClientRect().width || 16;
  remPx = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
  document.documentElement.style.setProperty("--cc-w", `${chPx}px`);

  const totalW = document.documentElement.clientWidth;
  const maxCells = readContentMax();
  const totalCells = Math.floor(totalW / chPx);
  const contentCells = Math.min(maxCells, totalCells);

  // The content column itself still snaps to whole ch cells (so text lines
  // up on the grid), but the two side margins split whatever's left over
  // evenly in px, not in ch -- splitting leftover *cells* instead means an
  // odd number of them can't divide evenly, and the extra cell always
  // landed on the right (Math.floor rounds the left side down), showing up
  // as a visibly lopsided gutter instead of a centered column.
  const contentW = contentCells * chPx;
  const remainingW = Math.max(0, totalW - contentW);
  const leftW = remainingW / 2;
  const rightW = remainingW - leftW;

  document.documentElement.style.setProperty("--cc-side", `${leftW}px`);

  const main = document.getElementById("app");
  if (main) {
    main.style.width = `${contentW}px`;
    main.style.maxWidth = "none";
    main.style.marginLeft = `${leftW}px`;
    main.style.marginRight = `${rightW}px`;
    main.style.marginTop = "0";
    main.style.marginBottom = "0";
  }

  const footer = document.getElementById("site-footer");
  if (footer) {
    footer.style.width = "100%";
    footer.style.maxWidth = "none";
    footer.style.marginLeft = "0";
    footer.style.marginRight = "0";
    footer.style.paddingBlockEnd = "";
    footer.style.padding = "";
  }

  const nav = document.getElementById("nav-menu");
  if (nav) {
    nav.style.right = `${Math.max(16, rightW + 2 * chPx)}px`;
  }

  if (document.body.classList.contains("show-grid")) {
    document.body.style.backgroundSize = `${chPx}px ${remPx}px`;
    document.body.style.backgroundPosition = `${leftW}px 0`;
  }

  snapVerticalCells();
  autoSizeCcdFields();
}

// Used to snap each field-block's height to a whole rem via a computed
// px padding-block-end -- dropped on request (dito's CSS never uses px),
// clearing any such padding a previous build may have left inline instead.
function snapVerticalCells(): void {
  const roots = document.querySelectorAll<HTMLElement>(
    "#create-form-area .field-block, #create-form-area, .panel",
  );
  roots.forEach((el) => {
    el.style.paddingBlockEnd = "";
  });
}

export function autoSizeCcdFields(): void {
  if (!remPx) remPx = 16;
  document.querySelectorAll<HTMLElement>(".ccd-grow").forEach((el) => {
    if (el instanceof HTMLTextAreaElement) {
      if (el.closest("#load-glass-card")) {
        el.style.height = "";
        return;
      }
      el.style.height = "auto";
      const style = getComputedStyle(el);
      const padY =
        parseFloat(style.paddingTop) + parseFloat(style.paddingBottom);
      const borderY =
        parseFloat(style.borderTopWidth) + parseFloat(style.borderBottomWidth);
      const contentH = el.scrollHeight - padY - borderY;
      const lines = Math.max(1, Math.round(contentH / remPx));
      el.style.height = `${lines * remPx + padY + borderY}px`;
    }
  });
  snapVerticalCells();
}

export function initCcd(): void {
  if (initialized) return;
  initialized = true;
  snapCcd();

  const bindGrow = (el: Element) => {
    if (el instanceof HTMLTextAreaElement) {
      el.addEventListener("input", autoSizeCcdFields);
    }
  };

  document.querySelectorAll(".ccd-grow").forEach(bindGrow);

  const mo = new MutationObserver(() => {
    document.querySelectorAll(".ccd-grow").forEach(bindGrow);
    autoSizeCcdFields();
  });
  mo.observe(document.body, { childList: true, subtree: true });

  let timer = 0;
  window.addEventListener("resize", () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(snapCcd, 100);
  });

  if (document.fonts?.ready) {
    document.fonts.ready.then(() => snapCcd()).catch(() => {});
  }

  document.addEventListener("keydown", (event) => {
    if (event.key !== "g" && event.key !== "G") return;
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    const t = event.target as HTMLElement | null;
    const tag = t?.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || t?.isContentEditable) {
      return;
    }
    event.preventDefault();
    document.body.classList.toggle("show-grid");
    snapCcd();
  });
}
