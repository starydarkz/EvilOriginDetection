/**
 * cosmos.js — Animated starfield for Evil Origin Detection dark mode.
 * Renders on a fixed canvas behind all content.
 * Stars twinkle individually with randomized speed and color.
 * Red accent stars match the Evil Red brand color.
 */
(function () {
  const canvas = document.getElementById('cosmos-bg');
  if (!canvas) return;
  const ctx    = canvas.getContext('2d');
  let stars    = [];
  let raf;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function generateStars() {
    stars = [];
    const density = Math.floor((canvas.width * canvas.height) / 2600);
    for (let i = 0; i < density; i++) {
      const roll = Math.random();
      // Color distribution: 80% white/blue, 12% blue accent, 8% evil red
      const color = roll < 0.80
        ? 'rgba(210,215,255,'
        : roll < 0.92
        ? 'rgba(123,140,222,'
        : 'rgba(224,92,92,';
      stars.push({
        x:     Math.random() * canvas.width,
        y:     Math.random() * canvas.height,
        r:     roll < 0.65 ? 0.35 : roll < 0.88 ? 0.65 : 1.05,
        base:  0.2 + Math.random() * 0.8,
        speed: 0.15 + Math.random() * 0.9,
        phase: Math.random() * Math.PI * 2,
        color,
      });
    }
  }

  function draw(t) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    // Only render when dark mode is active
    if (!document.body.classList.contains('dark')) {
      raf = requestAnimationFrame(draw);
      return;
    }
    for (const s of stars) {
      const opacity = s.base * (0.5 + 0.5 * Math.sin(t * s.speed * 0.001 + s.phase));
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fillStyle = s.color + opacity.toFixed(2) + ')';
      ctx.fill();
    }
    raf = requestAnimationFrame(draw);
  }

  function init() {
    resize();
    generateStars();
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(draw);
  }

  window.addEventListener('resize', () => { resize(); generateStars(); });
  init();
})();
