/**
 * graph.js — Cytoscape.js graph for Evil Origin Detection results page.
 *
 * Nodes: only real IOC types (ip, domain, hash, url, email, network, username)
 * On click: context panel with source, reason, and action buttons
 * Loading state: hidden once Cytoscape renders successfully
 */
(function () {
  const container = document.getElementById('graph-container');
  if (!container) return;

  const iocId     = container.dataset.iocId;
  if (!iocId) return;

  const loadingEl = container.querySelector('.graph-empty');
  const ANALYZABLE = new Set(['ip', 'domain', 'hash', 'url', 'email', 'network']);

  // ── Bootstrap ────────────────────────────────────────────────────
  const script    = document.createElement('script');
  script.src      = 'https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.29.2/cytoscape.min.js';
  script.onerror  = () => showEmpty('Graph library unavailable');
  script.onload   = () => {
    fetch(`/results/${iocId}/graph`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(data => {
        if (!data.nodes || data.nodes.length === 0) {
          showEmpty('No correlated artifacts found');
          return;
        }
        renderGraph(data);
        if (loadingEl) loadingEl.style.display = 'none';
      })
      .catch(err => showEmpty(`Graph unavailable: ${err.message}`));
  };
  document.head.appendChild(script);

  function showEmpty(msg) {
    if (loadingEl) {
      loadingEl.innerHTML =
        '<span style="font-size:24px;opacity:0.2">◎</span>' +
        `<span style="font-size:11px;color:var(--text3)">${msg}</span>`;
    }
  }

  // ── Render ────────────────────────────────────────────────────────
  let cy = null;

  function renderGraph(data) {
    const isDark = document.body.classList.contains('dark');

    cy = cytoscape({
      container,
      elements: [...data.nodes, ...data.edges],
      style:    buildStyle(isDark),
      layout: {
        name:            'cose',
        padding:         60,
        nodeRepulsion:   () => 12000,
        edgeElasticity:  () => 40,
        gravity:         0.8,
        animate:         false,
        randomize:       true,
      },
      userZoomingEnabled:  true,
      userPanningEnabled:  true,
      boxSelectionEnabled: false,
      minZoom: 0.1,
      maxZoom: 5,
    });

    cy.on('tap', 'node', evt => {
      showPanel(evt.target.data(), evt.renderedPosition);
    });
    cy.on('tap', evt => {
      if (evt.target === cy) hidePanel();
    });

    container._cy = cy;
  }

  // ── Styles ────────────────────────────────────────────────────────
  function buildStyle(isDark) {
    const text    = isDark ? '#c8cae8' : '#0d0f1e';
    const muted   = isDark ? '#6b6d9a' : '#6b7290';
    const edgeDef = isDark ? 'rgba(99,102,180,0.25)' : 'rgba(13,15,30,0.15)';

    return [
      {
        selector: 'node',
        style: {
          'width':              ele => ele.data('central') ? 58 : nodeSize(ele.data('type')),
          'height':             ele => ele.data('central') ? 58 : nodeSize(ele.data('type')),
          'background-color':   ele => nodeColor(ele.data()),
          'background-opacity': ele => ele.data('central') ? 0.28 : 0.14,
          'border-width':       ele => ele.data('central') ? 2.5 : 1,
          'border-color':       ele => nodeColor(ele.data()),
          'border-opacity':     0.9,
          'label':              'data(label)',
          'font-family':        'JetBrains Mono, monospace',
          'font-size':          ele => ele.data('central') ? '10px' : '9px',
          'color':              text,
          'text-valign':        'bottom',
          'text-margin-y':      5,
          'text-max-width':     '130px',
          'text-wrap':          'ellipsis',
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-width':       3,
          'background-opacity': 0.32,
          'border-opacity':     1,
        }
      },
      // Edges
      {
        selector: 'edge',
        style: {
          'width':              1,
          'line-color':         edgeDef,
          'target-arrow-color': edgeDef,
          'target-arrow-shape':'triangle',
          'arrow-scale':        0.7,
          'curve-style':        'bezier',
          'opacity':            0.75,
        }
      },
      {
        selector: 'edge[type="threat"]',
        style: {
          'line-color':         isDark ? 'rgba(224,92,92,0.55)' : 'rgba(192,57,43,0.45)',
          'target-arrow-color': isDark ? 'rgba(224,92,92,0.55)' : 'rgba(192,57,43,0.45)',
          'width':              1.5,
          'line-style':         'dashed',
          'line-dash-pattern':  [5, 3],
        }
      },
      {
        selector: 'edge[type="resolution"]',
        style: {
          'line-color':         isDark ? 'rgba(123,140,222,0.45)' : 'rgba(45,74,207,0.35)',
          'target-arrow-color': isDark ? 'rgba(123,140,222,0.45)' : 'rgba(45,74,207,0.35)',
        }
      },
    ];
  }

  function nodeColor(d) {
    if (d.verdict === 'malicious')  return '#e05c5c';
    if (d.verdict === 'suspicious') return '#f5a623';
    if (d.verdict === 'clean')      return '#56cfb2';
    const map = {
      ip:       '#7b8cde',
      domain:   '#a78bfa',
      hash:     '#56cfb2',
      url:      '#f5a623',
      email:    '#e05c5c',
      network:  '#38bdf8',
      username: '#f472b6',
    };
    return map[d.type] || '#6b6d9a';
  }

  function nodeSize(type) {
    return { hash: 30, url: 32, username: 28 }[type] || 36;
  }

  // ── Context panel ─────────────────────────────────────────────────
  let panelEl = null;

  function showPanel(d, pos) {
    hidePanel();

    const label   = d.label   || d.id   || '';
    const type    = d.type    || '';
    const verdict = d.verdict || 'unknown';
    const score   = d.score   != null ? `${d.score}/100` : null;
    const source  = d.source  || null;
    const reason  = d.reason  || null;
    const canAnalyze = ANALYZABLE.has(type) && !d.central;

    const vColors = {
      malicious:  'var(--v-malicious)',
      suspicious: 'var(--v-suspicious)',
      clean:      'var(--v-clean)',
      unknown:    'var(--text3)',
    };
    const vColor = vColors[verdict] || 'var(--text3)';

    panelEl = document.createElement('div');
    panelEl.id = 'graph-node-panel';
    panelEl.style.cssText = [
      'position:absolute',
      'z-index:200',
      'min-width:200px',
      'max-width:260px',
      'border-radius:9px',
      'padding:14px 16px',
      'pointer-events:all',
      'font-family:\'JetBrains Mono\',monospace',
      'box-shadow:0 6px 24px rgba(0,0,0,0.45)',
      // Use CSS vars — works in both themes
      'background:var(--surface-solid,#0e0e20)',
      'border:0.5px solid var(--border2)',
    ].join(';');

    panelEl.innerHTML = `
      <!-- Value -->
      <div style="font-size:11px;font-weight:500;
                  color:var(--text,#e8eaf6);margin-bottom:6px;
                  word-break:break-all;line-height:1.5">
        ${escHtml(label)}
      </div>

      <!-- Type + verdict row -->
      <div style="display:flex;gap:6px;align-items:center;
                  margin-bottom:${(source || reason) ? '10px' : '6px'}">
        <span style="font-size:9px;padding:2px 7px;border-radius:3px;
                     background:rgba(99,102,180,0.15);
                     color:var(--blue,#7b8cde);
                     letter-spacing:0.08em;text-transform:uppercase">
          ${escHtml(type)}
        </span>
        <span style="font-size:9px;color:${vColor};font-weight:500">
          ${verdict}${score ? ' · ' + score : ''}
        </span>
      </div>

      <!-- Source / reason (more info) -->
      ${source || reason ? `
      <div style="font-size:10px;color:var(--text2,#9a9cc0);
                  background:var(--bg3,rgba(14,14,32,0.5));
                  border-radius:5px;padding:7px 9px;margin-bottom:10px;
                  border:0.5px solid var(--border,rgba(99,102,180,0.18))">
        ${source ? `<div style="color:var(--text3,#6b6d9a);font-size:9px;
                                letter-spacing:0.1em;text-transform:uppercase;
                                margin-bottom:3px">Source</div>
                    <div style="margin-bottom:${reason ? '6px' : '0'}">${escHtml(source)}</div>` : ''}
        ${reason ? `<div style="color:var(--text3,#6b6d9a);font-size:9px;
                                letter-spacing:0.1em;text-transform:uppercase;
                                margin-bottom:3px">Correlation</div>
                    <div style="line-height:1.5">${escHtml(reason)}</div>` : ''}
      </div>` : ''}

      <!-- Action buttons -->
      <div style="display:flex;flex-direction:column;gap:5px">
        ${canAnalyze ? `
        <button onclick="graphAnalyze('${escAttr(label)}','${escAttr(type)}')"
                style="width:100%;padding:7px 10px;border-radius:6px;border:none;
                       background:var(--accent,#e05c5c);color:#fff;cursor:pointer;
                       font-size:10px;font-weight:500;letter-spacing:0.04em;
                       display:flex;align-items:center;justify-content:center;gap:5px;
                       font-family:'JetBrains Mono',monospace">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          Analyze ${type}
        </button>` : ''}
        <button onclick="graphCopy('${escAttr(label)}')"
                id="graph-copy-btn"
                style="width:100%;padding:6px 10px;border-radius:6px;cursor:pointer;
                       border:0.5px solid var(--border2);background:transparent;
                       color:var(--text3,#6b6d9a);font-size:10px;
                       font-family:'JetBrains Mono',monospace">
          ⎘ Copy value
        </button>
        ${!d.central ? `
        <button onclick="graphClose()"
                style="width:100%;padding:5px 10px;border-radius:6px;cursor:pointer;
                       border:0.5px solid var(--border);background:transparent;
                       color:var(--text3,#6b6d9a);font-size:10px;
                       font-family:'JetBrains Mono',monospace">
          ✕ Close
        </button>` : ''}
      </div>
    `;

    container.style.position = 'relative';
    container.appendChild(panelEl);

    // Position near click, clamped to container
    requestAnimationFrame(() => {
      if (!panelEl) return;
      const cW = container.offsetWidth;
      const cH = container.offsetHeight;
      const pW = panelEl.offsetWidth  || 220;
      const pH = panelEl.offsetHeight || 200;
      const margin = 12;
      let left = pos.x + margin;
      let top  = pos.y - 20;
      if (left + pW > cW - margin) left = pos.x - pW - margin;
      if (top  + pH > cH - margin) top  = cH - pH - margin;
      if (top  < margin) top  = margin;
      if (left < margin) left = margin;
      panelEl.style.left = left + 'px';
      panelEl.style.top  = top  + 'px';
    });
  }

  function hidePanel() {
    const existing = document.getElementById('graph-node-panel');
    if (existing) existing.remove();
    panelEl = null;
  }

  // ── Global handlers ───────────────────────────────────────────────
  window.graphAnalyze = function(label, type) {
    const prefixes = {
      ip:'ip=', domain:'domain=', hash:'hash=',
      url:'url=', email:'mail=', network:'red=', username:'mail='
    };
    const prefix = prefixes[type] || '';
    const f = document.createElement('form');
    f.method = 'POST'; f.action = '/analyze';
    const i = document.createElement('input');
    i.type = 'hidden'; i.name = 'ioc_input'; i.value = prefix + label;
    f.appendChild(i); document.body.appendChild(f); f.submit();
  };

  window.graphCopy = function(label) {
    navigator.clipboard?.writeText(label).then(() => {
      const btn = document.getElementById('graph-copy-btn');
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = '✓ Copied';
        setTimeout(() => { if (btn) btn.textContent = orig; }, 1500);
      }
    });
  };

  window.graphClose = hidePanel;

  // ── Helpers ───────────────────────────────────────────────────────
  function escHtml(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function escAttr(s) {
    return String(s).replace(/'/g,"\\'").replace(/"/g,'\\"');
  }

})();
