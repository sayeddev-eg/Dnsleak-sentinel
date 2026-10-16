import { useEffect, useRef } from "react";

/**
 * Calm animated "network" background:
 *  - slowly drifting nodes (hosts) linked by faint edges
 *  - small packets travelling along edges (DNS traffic metaphor)
 *  - a few very faint drifting DNS/hex tokens
 * Low opacity on purpose — it should feel alive, never distracting.
 */
const TOKENS = [
  "udp/53", "TXT", "AAAA", "NXDOMAIN", "0x7f3a", "base32", "entropy 4.71",
  "qname.len=63", "c2.beacon", "dns.query", "SOA", "CNAME", "0xdeadbeef",
  "a9f3e1.tunnel.io", "ttl=30", "exfil?", "id=0x1c2f", "RR=12",
];

// Per-theme canvas colors (RGB triplets — canvas can't read CSS variables)
const DARK = {
  token: "125, 207, 255", tokenK: 1,
  edge: "115, 218, 202", edgeK: 0.12,
  node: "192, 202, 245", nodeA: 0.28,
  hub: "187, 154, 247",
  good: "125, 207, 255", bad: "247, 118, 142",
};
const LIGHT = {
  token: "59, 111, 224", tokenK: 0.9,
  edge: "18, 154, 135", edgeK: 0.16,
  node: "51, 65, 99", nodeA: 0.22,
  hub: "132, 85, 232",
  good: "11, 140, 192", bad: "214, 66, 107",
};

export default function CyberBackground({ density = 1 }) {
  const ref = useRef(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    let w = 0, h = 0, dpr = 1, raf = 0, last = 0;
    let nodes = [], packets = [], tokens = [];

    const rand = (a, b) => a + Math.random() * (b - a);

    const init = () => {
      dpr = 1; // faint decorative layer — full-res rendering isn't worth the GPU cost
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const count = Math.round(Math.min(48, (w * h) / 32000) * density);
      nodes = Array.from({ length: count }, () => ({
        x: rand(0, w),
        y: rand(0, h),
        vx: rand(-0.12, 0.12),
        vy: rand(-0.12, 0.12),
        r: rand(1, 2.2),
        hub: Math.random() < 0.08,
      }));
      packets = [];
      tokens = Array.from({ length: Math.round(10 * density) }, () => newToken(true));
    };

    const newToken = (anywhere = false) => ({
      text: TOKENS[(Math.random() * TOKENS.length) | 0],
      x: rand(0, w),
      y: anywhere ? rand(0, h) : h + 20,
      v: rand(0.08, 0.22),
      a: rand(0.035, 0.07),
    });

    const LINK = 150;

    const step = (t) => {
      raf = requestAnimationFrame(step);
      if (t - last < 45) return; // ~22fps is plenty for slow drift
      last = t;

      ctx.clearRect(0, 0, w, h);
      const C = document.documentElement.dataset.theme === "light" ? LIGHT : DARK;

      // drift tokens
      ctx.font = "11px 'JetBrains Mono', monospace";
      for (const tk of tokens) {
        tk.y -= tk.v;
        if (tk.y < -20) Object.assign(tk, newToken());
        ctx.fillStyle = `rgba(${C.token}, ${tk.a * C.tokenK})`;
        ctx.fillText(tk.text, tk.x, tk.y);
      }

      // move nodes
      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < -20) n.x = w + 20; else if (n.x > w + 20) n.x = -20;
        if (n.y < -20) n.y = h + 20; else if (n.y > h + 20) n.y = -20;
      }

      // edges
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < LINK * LINK) {
            const o = (1 - Math.sqrt(d2) / LINK) * C.edgeK;
            ctx.strokeStyle = `rgba(${C.edge}, ${o})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
            if (packets.length < 14 && Math.random() < 0.0009) {
              const bad = Math.random() < 0.18;
              packets.push({ a, b, p: 0, s: rand(0.006, 0.014), bad });
            }
          }
        }
      }

      // packets
      packets = packets.filter((pk) => pk.p <= 1);
      for (const pk of packets) {
        pk.p += pk.s;
        const x = pk.a.x + (pk.b.x - pk.a.x) * pk.p;
        const y = pk.a.y + (pk.b.y - pk.a.y) * pk.p;
        const col = pk.bad ? C.bad : C.good;
        const g = ctx.createRadialGradient(x, y, 0, x, y, 7);
        g.addColorStop(0, `rgba(${col}, 0.55)`);
        g.addColorStop(1, `rgba(${col}, 0)`);
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(x, y, 7, 0, Math.PI * 2);
        ctx.fill();
      }

      // nodes
      for (const n of nodes) {
        ctx.fillStyle = n.hub ? `rgba(${C.hub}, 0.45)` : `rgba(${C.node}, ${C.nodeA})`;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.hub ? n.r + 1.2 : n.r, 0, Math.PI * 2);
        ctx.fill();
        if (n.hub) {
          ctx.strokeStyle = `rgba(${C.hub}, 0.14)`;
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r + 6, 0, Math.PI * 2);
          ctx.stroke();
        }
      }
    };

    init();
    if (reduce) {
      step(1000); // draw a single static frame
      cancelAnimationFrame(raf);
    } else {
      raf = requestAnimationFrame(step);
    }

    const onResize = () => init();
    const onVis = () => {
      if (document.hidden) cancelAnimationFrame(raf);
      else if (!reduce) raf = requestAnimationFrame(step);
    };
    window.addEventListener("resize", onResize);
    document.addEventListener("visibilitychange", onVis);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [density]);

  return (
    <div className="cyber-bg" aria-hidden="true">
      <canvas ref={ref} />
    </div>
  );
}
