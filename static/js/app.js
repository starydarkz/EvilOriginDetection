/**
 * app.js — Evil Origin Detection frontend logic.
 * Handles: IOC counter, prefix insertion, help toggle, example fill.
 */

// ── IOC Counter ──────────────────────────────────────────────────────
const IOC_PATTERNS = {
  ip:      /^ip=\S+/i,
  red:     /^red=\S+/i,
  domain:  /^domain=\S+/i,
  hash:    /^hash=\S+/i,
  url:     /^url=\S+/i,
  mail:    /^mail=\S+/i,
};

function updateCounter(ta) {
  const lines  = (ta || document.getElementById('ioc-input'))
    .value.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
  const counts = {};
  let total    = 0;

  for (const line of lines) {
    for (const [type, rx] of Object.entries(IOC_PATTERNS)) {
      if (rx.test(line.trim())) {
        counts[type] = (counts[type] || 0) + 1;
        total++;
        break;
      }
    }
  }

  const parts = Object.entries(counts).map(([k, v]) => `${v} ${k}`);
  const el    = document.getElementById('ioc-counter');
  if (el) {
    el.textContent = total === 0
      ? '0 indicators detected'
      : `${total} indicator${total > 1 ? 's' : ''} — ${parts.join(', ')}`;
  }
}

// ── Prefix insertion ─────────────────────────────────────────────────
function insertPrefix(prefix) {
  const ta    = document.getElementById('ioc-input');
  if (!ta) return;
  const lines = ta.value.split('\n').filter(l => l.trim());
  lines.push(prefix);
  ta.value = lines.join('\n') + '\n';
  ta.focus();
  updateCounter(ta);
}

// ── Fill example ─────────────────────────────────────────────────────
function fillExample(val) {
  const ta    = document.getElementById('ioc-input');
  if (!ta) return;
  const lines = ta.value.split('\n').filter(l => l.trim());
  if (!lines.includes(val)) lines.push(val);
  ta.value = lines.join('\n');
  ta.focus();
  updateCounter(ta);
}

// ── Help toggle ──────────────────────────────────────────────────────
function toggleHelp() {
  const body = document.getElementById('help-body');
  const chev = document.getElementById('help-chev');
  if (body) body.classList.toggle('open');
  if (chev) chev.classList.toggle('open');
}

// ── Generic collapse ─────────────────────────────────────────────────
function toggleCollapse(bodyId, chevId) {
  const body = document.getElementById(bodyId);
  const chev = document.getElementById(chevId);
  if (body) body.classList.toggle('open');
  if (chev) chev.classList.toggle('open');
}

// ── Keyboard shortcuts ────────────────────────────────────────────
document.addEventListener('keydown', function(e) {
  const ta = document.getElementById('ioc-input');
  if (!ta) return;

  // / or Ctrl+L → focus input (when not already focused)
  if ((e.key === '/' || (e.ctrlKey && e.key === 'l')) &&
      document.activeElement !== ta) {
    e.preventDefault();
    ta.focus();
    ta.setSelectionRange(ta.value.length, ta.value.length);
    return;
  }

  // Ctrl+Enter or Cmd+Enter → submit form
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    const form = document.getElementById('analyze-form');
    if (form) form.submit();
    return;
  }

  // Escape → clear input (only when focused)
  if (e.key === 'Escape' && document.activeElement === ta) {
    ta.value = '';
    updateCounter(ta);
    ta.blur();
    return;
  }
});
