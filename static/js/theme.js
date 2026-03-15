/**
 * theme.js — Theme management for Evil Origin Detection.
 * Persists preference in localStorage.
 * Applies 'dark' or 'light' class to <body>.
 */
(function () {
  const STORAGE_KEY = 'eod-theme';

  function setTheme(t) {
    document.body.className = t;
    const btnDark  = document.getElementById('btn-dark');
    const btnLight = document.getElementById('btn-light');
    if (btnDark)  btnDark.classList.toggle('active',  t === 'dark');
    if (btnLight) btnLight.classList.toggle('active', t === 'light');
    localStorage.setItem(STORAGE_KEY, t);

    // Cosmos canvas visibility is handled by CSS: body.dark #cosmos-bg { opacity:1 }
    // Forensic grid visibility: body.light #forensic-grid { opacity:1 }
  }

  // Expose globally so onclick="setTheme(...)" works in templates
  window.setTheme = setTheme;

  // Apply saved or system preference on load (before paint)
  const saved = localStorage.getItem(STORAGE_KEY);
  const preferred = saved || (
    window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  );
  setTheme(preferred);
})();
