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
      showPanel(evt.target.data());
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

  function showPanel(d) {
    const label      = d.label   || d.id   || '';
    const type       = d.type    || '';
    const verdict    = d.verdict || 'unknown';
    const score      = d.score   != null ? d.score : null;
    const source     = d.source  || null;
    const reason     = d.reason  || null;
    const canAnalyze = ANALYZABLE.has(type) && !d.central;

    const vColors = {malicious:'var(--v-malicious)',suspicious:'var(--v-suspicious)',clean:'var(--v-clean)',unknown:'var(--text3)'};
    const vColor  = vColors[verdict] || 'var(--text3)';
    const vBg     = {malicious:'rgba(255,85,85,0.12)',suspicious:'rgba(255,170,68,0.12)',clean:'rgba(68,221,187,0.1)',unknown:'rgba(90,90,128,0.1)'}[verdict]||'transparent';
    const vBorder = {malicious:'rgba(255,85,85,0.25)',suspicious:'rgba(255,170,68,0.25)',clean:'rgba(68,221,187,0.2)',unknown:'rgba(90,90,128,0.2)'}[verdict]||'transparent';

    // Use the dedicated side panel when on the results page
    const emptyState = document.getElementById('graph-empty-state');
    const nodeDetail = document.getElementById('graph-node-detail');

    if (emptyState && nodeDetail) {
      emptyState.style.display = 'none';
      nodeDetail.style.display = 'block';
      nodeDetail.innerHTML = `
        <div style="font-family:'Outfit',sans-serif;font-size:16px;font-weight:600;
                    color:var(--text);margin-bottom:10px;word-break:break-all;line-height:1.3">
          ${escHtml(label)}
        </div>
        <div style="display:flex;gap:6px;align-items:center;margin-bottom:14px;flex-wrap:wrap">
          <span style="font-size:10px;padding:2px 9px;border-radius:5px;
                       background:${vBg};border:1px solid ${vBorder};color:${vColor};
                       font-family:'Space Mono',monospace;letter-spacing:0.06em;text-transform:uppercase">
            ${verdict}
          </span>
          <span style="font-family:'Space Mono',monospace;font-size:10px;
                       color:var(--text3);letter-spacing:0.08em;text-transform:uppercase">
            ${escHtml(type)}
          </span>
        </div>
        ${score != null ? `
        <div style="margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid var(--border)">
          <div style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3);
                      letter-spacing:0.12em;text-transform:uppercase;margin-bottom:4px">Risk Score</div>
          <div style="font-family:'Outfit',sans-serif;font-size:36px;font-weight:800;
                      letter-spacing:-0.03em;color:${vColor}">
            ${score}<span style="font-size:16px;color:var(--text3);font-weight:400">/100</span>
          </div>
        </div>` : ''}
        ${(source || reason) ? `
        <div style="margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid var(--border)">
          ${source ? `<div style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3);
                                  letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px">Source</div>
                      <div style="font-size:13px;color:var(--text2);margin-bottom:${reason?'12px':'0'}">${escHtml(source)}</div>` : ''}
          ${reason ? `<div style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3);
                                  letter-spacing:0.1em;text-transform:uppercase;margin-bottom:4px">Correlation</div>
                      <div style="font-size:13px;color:var(--text2);line-height:1.6">${escHtml(reason)}</div>` : ''}
        </div>` : ''}
        <div style="display:flex;flex-direction:column;gap:8px">
          ${canAnalyze ? `
          <button onclick="graphAnalyze('${escAttr(label)}','${escAttr(type)}')"
                  style="width:100%;padding:10px;border-radius:9px;border:none;
                         background:var(--accent);color:#fff;cursor:pointer;
                         font-size:14px;font-weight:600;font-family:'Outfit',sans-serif;
                         display:flex;align-items:center;justify-content:center;gap:7px"
                  onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
              <circle cx="11" cy="11" r="8"/>
              <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            Analyze ${type}
          </button>` : ''}
          <button onclick="graphCopy('${escAttr(label)}')" id="graph-copy-btn"
                  style="width:100%;padding:9px;border-radius:9px;cursor:pointer;
                         border:1px solid var(--border);background:var(--bg2);
                         color:var(--text2);font-size:13px;font-family:'Outfit',sans-serif;font-weight:500"
                  onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background='var(--bg2)'">
            ⎘ Copy value
          </button>
        </div>
      `;
      return;
    }

    // Fallback: floating panel (for standalone /graph page)
    hidePanel();
    panelEl = document.createElement('div');
    panelEl.id = 'graph-node-panel';
    panelEl.style.cssText = 'position:absolute;z-index:200;min-width:200px;max-width:260px;border-radius:12px;padding:16px;pointer-events:all;background:var(--surface-solid,#0e0e20);border:1px solid var(--border2);box-shadow:0 8px 32px rgba(0,0,0,0.4)';
    panelEl.innerHTML = `
      <div style="font-size:14px;font-weight:600;font-family:'Outfit',sans-serif;
                  color:var(--text);margin-bottom:8px;word-break:break-all">${escHtml(label)}</div>
      <div style="display:flex;gap:6px;margin-bottom:12px">
        <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:${vBg};
                     border:1px solid ${vBorder};color:${vColor};font-family:'Space Mono',monospace">${verdict}</span>
        <span style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3)">${escHtml(type)}</span>
      </div>
      ${reason ? `<div style="font-size:12px;color:var(--text3);margin-bottom:12px;padding:8px;background:var(--bg3);border-radius:6px">${escHtml(reason)}</div>` : ''}
      <div style="display:flex;flex-direction:column;gap:6px">
        ${canAnalyze ? `<button onclick="graphAnalyze('${escAttr(label)}','${escAttr(type)}')"
                style="padding:8px;border-radius:7px;border:none;background:var(--accent);
                       color:#fff;cursor:pointer;font-size:13px;font-family:'Outfit',sans-serif">
                Analyze ${type}</button>` : ''}
        <button onclick="graphCopy('${escAttr(label)}')" id="graph-copy-btn"
                style="padding:7px;border-radius:7px;cursor:pointer;border:1px solid var(--border);
                       background:transparent;color:var(--text3);font-size:12px;font-family:'Outfit',sans-serif">
          ⎘ Copy value</button>
        <button onclick="graphClose()"
                style="padding:6px;border-radius:7px;cursor:pointer;border:1px solid var(--border);
                       background:transparent;color:var(--text3);font-size:11px;font-family:'Outfit',sans-serif">
          ✕ Close</button>
      </div>`;
    container.appendChild(panelEl);
  }

  function hidePanel() {
    const existing = document.getElementById('graph-node-panel');
    if (existing) existing.remove();
    panelEl = null;
    const emptyState = document.getElementById('graph-empty-state');
    const nodeDetail = document.getElementById('graph-node-detail');
    if (emptyState) emptyState.style.display = 'flex';
    if (nodeDetail) nodeDetail.style.display = 'none';
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
