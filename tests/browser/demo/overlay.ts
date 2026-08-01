/**
 * Overlay injected into every document of the demo recording.
 *
 * Playwright's video capture records the DOM, so the "camera work" (a fake
 * cursor, caption bar and full-screen title cards) has to live inside the page
 * itself. This script is registered with `addInitScript`, so it re-runs on every
 * navigation; `ensure()` is idempotent and the driver re-applies caption/cursor
 * state after each page load.
 *
 * Everything here is styled through CSSOM (element.style / insertRule) rather
 * than markup so it survives the app's CSP, and every node is pointer-events:none
 * so real mouse input still reaches the app underneath.
 */
export const OVERLAY_INIT = () => {
  const BRAND = "#ff7b00";
  const ID = "__autentico_demo_overlay";

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  function build() {
    if (document.getElementById(ID)) return;
    if (!document.body) return;

    const root = document.createElement("div");
    root.id = ID;
    const rs = root.style;
    rs.position = "fixed";
    rs.inset = "0";
    rs.zIndex = "2147483647";
    rs.pointerEvents = "none";
    rs.fontFamily =
      'system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';

    // Keyframes have to go through CSSOM to survive CSP.
    const style = document.createElement("style");
    root.appendChild(style);
    document.body.appendChild(root);
    const sheet = style.sheet as CSSStyleSheet;
    sheet.insertRule(
      "@keyframes __ad_ripple { from { transform: translate(-50%,-50%) scale(.3); opacity:.55 } to { transform: translate(-50%,-50%) scale(1); opacity:0 } }",
      0
    );
    sheet.insertRule(
      "@keyframes __ad_blink { 0%,49% { opacity:1 } 50%,100% { opacity:0 } }",
      0
    );

    // ---- cursor -----------------------------------------------------------
    const cursor = document.createElement("div");
    cursor.setAttribute("data-ad", "cursor");
    const cs = cursor.style;
    cs.position = "absolute";
    cs.left = "0";
    cs.top = "0";
    cs.width = "24px";
    cs.height = "24px";
    cs.marginLeft = "-3px";
    cs.marginTop = "-2px";
    cs.transform = "translate(640px, 400px)";
    cs.transition = "transform 700ms cubic-bezier(.22,.61,.36,1)";
    cs.willChange = "transform";
    cs.filter = "drop-shadow(0 2px 4px rgba(0,0,0,.45))";
    cursor.innerHTML =
      '<svg width="24" height="24" viewBox="0 0 24 24" fill="none">' +
      '<path d="M5 2.5 L5 19 L9.2 15.1 L11.9 21.2 L14.9 19.9 L12.2 13.9 L18 13.6 Z" ' +
      'fill="#ffffff" stroke="#16161a" stroke-width="1.4" stroke-linejoin="round"/></svg>';
    root.appendChild(cursor);

    // ---- caption ----------------------------------------------------------
    const caption = document.createElement("div");
    caption.setAttribute("data-ad", "caption");
    const cap = caption.style;
    cap.position = "absolute";
    cap.left = "50%";
    cap.bottom = "34px";
    cap.transform = "translateX(-50%) translateY(10px)";
    cap.display = "flex";
    cap.alignItems = "center";
    cap.gap = "11px";
    cap.maxWidth = "min(84%, 900px)";
    cap.padding = "13px 24px";
    cap.borderRadius = "999px";
    cap.background = "rgba(14,14,17,.93)";
    cap.color = "#f5f5f7";
    cap.fontSize = "17px";
    cap.lineHeight = "1.35";
    cap.fontWeight = "560";
    cap.letterSpacing = ".1px";
    cap.textAlign = "center";
    cap.boxShadow = "0 10px 34px rgba(0,0,0,.34), 0 0 0 1px rgba(255,255,255,.07) inset";
    cap.opacity = "0";
    cap.transition = "opacity 260ms ease, transform 260ms ease";

    const dot = document.createElement("span");
    const ds = dot.style;
    ds.width = "8px";
    ds.height = "8px";
    ds.borderRadius = "50%";
    ds.background = BRAND;
    ds.flex = "0 0 auto";
    ds.boxShadow = `0 0 10px ${BRAND}`;
    const capText = document.createElement("span");
    capText.setAttribute("data-ad", "caption-text");
    caption.appendChild(dot);
    caption.appendChild(capText);
    root.appendChild(caption);

    // ---- full-screen card -------------------------------------------------
    const card = document.createElement("div");
    card.setAttribute("data-ad", "card");
    const kd = card.style;
    kd.position = "absolute";
    kd.inset = "0";
    kd.display = "flex";
    kd.flexDirection = "column";
    kd.alignItems = "center";
    kd.justifyContent = "center";
    kd.background =
      "radial-gradient(1100px 620px at 50% 42%, #1d1b21 0%, #0c0c0f 62%, #08080a 100%)";
    kd.opacity = "0";
    kd.transition = "opacity 420ms ease";
    kd.color = "#fff";
    root.appendChild(card);

    (window as any).__demo = {
      root,
      cursor,
      caption,
      capText,
      card,
      sleep,
      BRAND,
    };
  }

  function api() {
    build();
    return (window as any).__demo;
  }

  (window as any).__autenticoDemo = {
    ensure() {
      build();
    },

    cursor(x: number, y: number, instant?: boolean) {
      const d = api();
      if (!d) return;
      if (instant) d.cursor.style.transition = "none";
      d.cursor.style.transform = `translate(${x}px, ${y}px)`;
      if (instant) {
        void d.cursor.offsetHeight;
        d.cursor.style.transition = "transform 700ms cubic-bezier(.22,.61,.36,1)";
      }
    },

    cursorSpeed(ms: number) {
      const d = api();
      if (d) d.cursor.style.transition = `transform ${ms}ms cubic-bezier(.22,.61,.36,1)`;
    },

    ripple(x: number, y: number) {
      const d = api();
      if (!d) return;
      const r = document.createElement("div");
      const s = r.style;
      s.position = "absolute";
      s.left = x + "px";
      s.top = y + "px";
      s.width = "52px";
      s.height = "52px";
      s.marginLeft = "-26px";
      s.marginTop = "-26px";
      s.borderRadius = "50%";
      s.border = `2.5px solid ${d.BRAND}`;
      s.background = "rgba(255,123,0,.16)";
      s.transformOrigin = "center";
      s.animation = "__ad_ripple 520ms ease-out forwards";
      // The ripple is drawn from the element's own center, so re-add the
      // translate the keyframes expect.
      s.transform = "translate(-50%,-50%)";
      s.left = x + "px";
      s.top = y + "px";
      s.marginLeft = "0";
      s.marginTop = "0";
      d.root.appendChild(r);
      setTimeout(() => r.remove(), 560);
    },

    caption(text: string) {
      const d = api();
      if (!d) return;
      if (!text) {
        d.caption.style.opacity = "0";
        d.caption.style.transform = "translateX(-50%) translateY(10px)";
        return;
      }
      d.capText.textContent = text;
      d.caption.style.opacity = "1";
      d.caption.style.transform = "translateX(-50%) translateY(0)";
    },

    async card(opts: {
      kicker?: string;
      title?: string;
      subtitle?: string;
      bullets?: string[];
      link?: string;
      logo?: boolean;
    }) {
      const d = api();
      if (!d) return;
      const c = d.card;
      c.innerHTML = "";

      const wrap = document.createElement("div");
      wrap.style.textAlign = "center";
      wrap.style.padding = "0 60px";
      wrap.style.maxWidth = "980px";

      if (opts.logo) {
        const img = document.createElement("img");
        img.src = "/account/favicon.svg";
        img.style.width = "78px";
        img.style.height = "78px";
        img.style.marginBottom = "26px";
        img.style.filter = "drop-shadow(0 6px 26px rgba(255,123,0,.5))";
        wrap.appendChild(img);
      }
      if (opts.kicker) {
        const k = document.createElement("div");
        k.textContent = opts.kicker;
        k.style.fontSize = "13px";
        k.style.letterSpacing = "2.6px";
        k.style.textTransform = "uppercase";
        k.style.fontWeight = "700";
        k.style.color = d.BRAND;
        k.style.marginBottom = "16px";
        wrap.appendChild(k);
      }
      if (opts.title) {
        const t = document.createElement("div");
        t.textContent = opts.title;
        t.style.fontSize = "62px";
        t.style.fontWeight = "760";
        t.style.letterSpacing = "-1.6px";
        t.style.lineHeight = "1.06";
        t.style.marginBottom = "20px";
        wrap.appendChild(t);
      }
      if (opts.subtitle) {
        const s = document.createElement("div");
        s.textContent = opts.subtitle;
        s.style.fontSize = "23px";
        s.style.fontWeight = "440";
        s.style.lineHeight = "1.5";
        s.style.color = "rgba(255,255,255,.72)";
        wrap.appendChild(s);
      }
      if (opts.bullets?.length) {
        const ul = document.createElement("div");
        ul.style.display = "flex";
        ul.style.flexWrap = "wrap";
        ul.style.justifyContent = "center";
        ul.style.gap = "10px";
        ul.style.marginTop = "30px";
        for (const b of opts.bullets) {
          const chip = document.createElement("span");
          chip.textContent = b;
          chip.style.fontSize = "15px";
          chip.style.fontWeight = "560";
          chip.style.padding = "9px 16px";
          chip.style.borderRadius = "999px";
          chip.style.color = "rgba(255,255,255,.88)";
          chip.style.background = "rgba(255,255,255,.07)";
          chip.style.border = "1px solid rgba(255,255,255,.12)";
          ul.appendChild(chip);
        }
        wrap.appendChild(ul);
      }
      if (opts.link) {
        const l = document.createElement("div");
        l.textContent = opts.link;
        l.style.marginTop = "34px";
        l.style.fontSize = "21px";
        l.style.fontWeight = "640";
        l.style.color = d.BRAND;
        l.style.fontFamily = 'ui-monospace, SFMono-Regular, Menlo, monospace';
        wrap.appendChild(l);
      }

      c.appendChild(wrap);
      c.style.opacity = "1";
    },

    async terminal(title: string) {
      const d = api();
      if (!d) return;
      const c = d.card;
      c.innerHTML = "";

      const shell = document.createElement("div");
      shell.style.width = "820px";
      shell.style.maxWidth = "86%";
      shell.style.borderRadius = "13px";
      shell.style.overflow = "hidden";
      shell.style.background = "#111114";
      shell.style.boxShadow =
        "0 30px 90px rgba(0,0,0,.6), 0 0 0 1px rgba(255,255,255,.09)";

      const bar = document.createElement("div");
      bar.style.display = "flex";
      bar.style.alignItems = "center";
      bar.style.gap = "8px";
      bar.style.padding = "12px 16px";
      bar.style.background = "#1a1a1f";
      for (const col of ["#ff5f57", "#febc2e", "#28c840"]) {
        const dot = document.createElement("span");
        dot.style.width = "11px";
        dot.style.height = "11px";
        dot.style.borderRadius = "50%";
        dot.style.background = col;
        bar.appendChild(dot);
      }
      const t = document.createElement("span");
      t.textContent = title;
      t.style.marginLeft = "10px";
      t.style.fontSize = "12.5px";
      t.style.color = "rgba(255,255,255,.5)";
      bar.appendChild(t);
      shell.appendChild(bar);

      const body = document.createElement("pre");
      body.setAttribute("data-ad", "term");
      body.style.margin = "0";
      body.style.padding = "20px 22px 26px";
      body.style.fontFamily = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
      body.style.fontSize = "14px";
      body.style.lineHeight = "1.62";
      body.style.color = "#dfe1e6";
      body.style.whiteSpace = "pre-wrap";
      body.style.minHeight = "330px";
      shell.appendChild(body);

      c.appendChild(shell);
      c.style.opacity = "1";
      d.term = body;
    },

    /** Types text into the terminal card one character at a time. */
    async type(text: string, speed = 26) {
      const d = api();
      if (!d?.term) return;
      for (const ch of text) {
        d.term.append(ch);
        await sleep(speed);
      }
    },

    /** Appends already-rendered output (program output, not typed input). */
    write(text: string, color?: string) {
      const d = api();
      if (!d?.term) return;
      const span = document.createElement("span");
      span.textContent = text;
      if (color) span.style.color = color;
      d.term.appendChild(span);
    },

    prompt() {
      const d = api();
      if (!d?.term) return;
      const span = document.createElement("span");
      span.textContent = "$ ";
      span.style.color = "#ff7b00";
      span.style.fontWeight = "700";
      d.term.appendChild(span);
    },

    hideCard() {
      const d = api();
      if (d) d.card.style.opacity = "0";
    },
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", build);
  } else {
    build();
  }
};
