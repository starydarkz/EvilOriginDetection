/**
 * graph.js — Cytoscape.js correlation graph for Evil Origin Detection.
 */
(function () {
  const container = document.getElementById('graph-container');
  if (!container) return;

  const iocId     = container.dataset.iocId;
  if (!iocId) return;

  const loadingEl = container.querySelector('#graph-loading') ||
                    container.querySelector('.graph-empty');
  const ANALYZABLE = new Set(['ip', 'domain', 'hash', 'url', 'email', 'network']);

  // ── Bootstrap ────────────────────────────────────────────────────
  const script   = document.createElement('script');
  script.src     = 'https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.29.2/cytoscape.min.js';
  script.onerror = () => showEmpty('Graph library unavailable');
  script.onload  = () => {
    fetch(`/results/${iocId}/graph`)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(data => {
        if (!data.nodes || data.nodes.length === 0) {
          showEmpty('No data to graph');
          return;
        }
        // Always render — even if only central node exists
        renderGraph(data);
        if (loadingEl) loadingEl.style.display = 'none';

        // If only the central node, show a friendly message in the panel
        if (data.nodes.length === 1) {
          const emptyState = document.getElementById('graph-empty-state');
          if (emptyState) {
            emptyState.innerHTML = `
              <span style="font-size:22px;opacity:0.15">◎</span>
              <span style="font-family:'Space Mono',monospace;font-size:10px;
                           letter-spacing:0.14em;text-transform:uppercase;color:var(--text3)">
                No correlations found
              </span>
              <span style="font-size:12px;color:var(--text3);text-align:center;
                           line-height:1.6;max-width:200px">
                No related artifacts were detected across sources for this indicator.
              </span>`;
          }
        }
      })
      .catch(err => showEmpty(`Graph unavailable: ${err.message}`));
  };
  document.head.appendChild(script);

  function showEmpty(msg) {
    if (loadingEl) {
      loadingEl.style.display = 'flex';
      loadingEl.innerHTML =
        '<span style="font-size:24px;opacity:0.2">◎</span>' +
        `<span style="font-size:12px;color:var(--text3)">${msg}</span>`;
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
      layout: data.nodes.length === 1
        ? { name: 'grid' }
        : {
            name:           'cose',
            padding:        50,
            nodeRepulsion:  () => 14000,
            edgeElasticity: () => 45,
            gravity:        0.9,
            animate:        false,
            randomize:      true,
          },
      userZoomingEnabled:  true,
      userPanningEnabled:  true,
      boxSelectionEnabled: false,
      minZoom: 0.1,
      maxZoom: 5,
    });

    cy.on('tap', 'node', evt => showPanel(evt.target.data()));
    cy.on('tap', evt => { if (evt.target === cy) hidePanel(); });

    // Auto-select central node on load so panel shows immediately
    const centralNode = cy.nodes('[?central]').first();
    if (centralNode.length) {
      showPanel(centralNode.data());
    }

    container._cy = cy;
  }

  // ── Styles ────────────────────────────────────────────────────────
  function buildStyle(isDark) {
    const text    = isDark ? '#e0e0f8' : '#0d0f1e';
    const muted   = isDark ? '#6b6d9a' : '#6b7290';
    const edgeDef = isDark ? 'rgba(120,120,200,0.28)' : 'rgba(13,15,30,0.14)';

    return [
      {
        selector: 'node',
        style: {
          'width':              ele => ele.data('central') ? 62 : nodeSize(ele.data('type')),
          'height':             ele => ele.data('central') ? 62 : nodeSize(ele.data('type')),
          'background-color':   ele => nodeColor(ele.data()),
          'background-opacity': ele => ele.data('central') ? 0.32 : 0.16,
          'border-width':       ele => ele.data('central') ? 2.5 : 1.5,
          'border-color':       ele => nodeColor(ele.data()),
          'border-opacity':     0.9,
          'label':              ele => {
            const d   = ele.data();
            const lbl = d.label || '';
            // For hash nodes: prefer file_name as display label
            if (d.type === 'hash' && d.file_name && !d.central) {
              return d.file_name.length > 20 ? d.file_name.slice(0, 18) + '…' : d.file_name;
            }
            // Truncate long hashes/values for canvas display
            if (lbl.length > 22 && !d.central) {
              return lbl.slice(0, 10) + '…' + lbl.slice(-6);
            }
            return lbl;
          },
          'font-family':        'Space Mono, monospace',
          'font-size':          ele => ele.data('central') ? '11px' : '9px',
          'color':              text,
          'text-valign':        'bottom',
          'text-margin-y':      6,
          'text-max-width':     '120px',
          'text-wrap':          'ellipsis',
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-width':       3,
          'background-opacity': 0.35,
          'border-opacity':     1,
        }
      },
      {
        selector: 'node[?central]',
        style: {
          'border-width':       2.5,
          'background-opacity': 0.32,
        }
      },
      {
        selector: 'edge',
        style: {
          'width':              1.2,
          'line-color':         edgeDef,
          'target-arrow-color': edgeDef,
          'target-arrow-shape':'triangle',
          'arrow-scale':        0.75,
          'curve-style':        'bezier',
          'opacity':            0.8,
        }
      },
      {
        selector: 'edge[type="threat"]',
        style: {
          'line-color':         'rgba(255,85,85,0.45)',
          'target-arrow-color': 'rgba(255,85,85,0.45)',
          'line-style':         'dashed',
          'line-dash-pattern':  [6, 3],
        }
      },
      {
        selector: 'edge[type="resolution"]',
        style: {
          'line-color':         isDark ? 'rgba(102,153,255,0.35)' : 'rgba(44,85,200,0.25)',
          'target-arrow-color': isDark ? 'rgba(102,153,255,0.35)' : 'rgba(44,85,200,0.25)',
        }
      },
    ];

    function isDark() { return document.body.classList.contains('dark'); }
  }

  function nodeSize(type) {
    return { ip:36, domain:34, hash:30, url:30, email:32, network:28, username:28 }[type] || 30;
  }

  function nodeColor(data) {
    const byVerdict = {
      malicious:  '#ff5555', suspicious: '#ffaa44',
      clean:      '#44ddbb', unknown:    '#6699ff',
    };
    const byType = {
      ip:'#6699ff', domain:'#aa77ff', hash:'#44ddbb',
      url:'#ffaa44', email:'#ff5555', network:'#44aaff', username:'#ff88aa',
    };
    return byVerdict[data.verdict] || byType[data.type] || '#6699ff';
  }

  // ── Side panel ────────────────────────────────────────────────────
  let panelEl = null;

  function showPanel(d) {
    const label      = d.label   || d.id   || '';
    const type       = d.type    || '';
    const verdict    = d.verdict || 'unknown';
    const score      = d.score   != null ? d.score : null;
    const source     = d.source  || null;
    const reason     = d.reason  || null;
    const canAnalyze = ANALYZABLE.has(type) && !d.central;

    // Extra metadata for hashes
    const fileNameVal   = d.file_name     || null;
    const malwareFamily = d.malware_family || null;

    const vColors = {
      malicious:'var(--v-malicious)', suspicious:'var(--v-suspicious)',
      clean:'var(--v-clean)', unknown:'var(--text3)',
    };
    const vColor  = vColors[verdict] || 'var(--text3)';
    const vBg     = { malicious:'rgba(255,85,85,0.12)', suspicious:'rgba(255,170,68,0.12)',
                      clean:'rgba(68,221,187,0.1)',      unknown:'rgba(90,90,128,0.1)' }[verdict] || 'transparent';
    const vBorder = { malicious:'rgba(255,85,85,0.25)', suspicious:'rgba(255,170,68,0.25)',
                      clean:'rgba(68,221,187,0.2)',      unknown:'rgba(90,90,128,0.2)' }[verdict] || 'transparent';

    // Store full value globally for copy
    window._graphNodeValue = label;

    // Use the dedicated side panel (results page)
    const emptyState = document.getElementById('graph-empty-state');
    const nodeDetail = document.getElementById('graph-node-detail');

    if (emptyState && nodeDetail) {
      emptyState.style.display = 'none';
      nodeDetail.style.display = 'block';
      nodeDetail.innerHTML = `
        ${/* Value box — full value, selectable */ ''}
        <div style="margin-bottom:12px">
          <div style="font-family:'Space Mono',monospace;font-size:10px;
                      color:var(--text3);letter-spacing:0.12em;text-transform:uppercase;
                      margin-bottom:5px">Value</div>
          <div style="font-family:'Space Mono',monospace;font-size:11px;
                      color:var(--text);word-break:break-all;line-height:1.6;
                      user-select:all;cursor:text;
                      background:var(--bg3);border:1px solid var(--border);
                      border-radius:7px;padding:8px 10px"
               title="Click to select · use button below to copy">
            ${escHtml(label)}
          </div>
        </div>

        ${/* Verdict + type badges */ ''}
        <div style="display:flex;gap:6px;align-items:center;margin-bottom:14px;flex-wrap:wrap">
          <span style="font-size:10px;padding:3px 9px;border-radius:5px;
                       background:${vBg};border:1px solid ${vBorder};color:${vColor};
                       font-family:'Space Mono',monospace;letter-spacing:0.06em;text-transform:uppercase;
                       font-weight:700">
            ${verdict}
          </span>
          <span style="font-family:'Space Mono',monospace;font-size:10px;
                       color:var(--text3);letter-spacing:0.08em;text-transform:uppercase;
                       padding:3px 8px;background:var(--bg3);border-radius:4px;
                       border:1px solid var(--border)">
            ${escHtml(type)}
          </span>
        </div>

        ${/* Score */ score != null ? `
        <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--border)">
          <div style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3);
                      letter-spacing:0.12em;text-transform:uppercase;margin-bottom:4px">Risk Score</div>
          <div style="font-family:'Outfit',sans-serif;font-size:34px;font-weight:800;
                      letter-spacing:-0.03em;color:${vColor}">
            ${score}<span style="font-size:15px;color:var(--text3);font-weight:400">/100</span>
          </div>
        </div>` : ''}

        ${/* Hash metadata — filename, malware family */ (type === 'hash' && (fileNameVal || malwareFamily)) ? `
        <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--border)">
          <div style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3);
                      letter-spacing:0.1em;text-transform:uppercase;margin-bottom:6px">File Info</div>
          ${fileNameVal ? `<div style="font-size:13px;color:var(--text2);margin-bottom:4px">
            <span style="color:var(--text3);font-size:11px">Name: </span>${escHtml(fileNameVal)}</div>` : ''}
          ${malwareFamily ? `<div style="font-size:13px;color:var(--v-malicious);font-weight:600">
            ⚠ ${escHtml(malwareFamily)}</div>` : ''}
        </div>` : ''}

        ${/* Source + correlation reason */ (source || reason) ? `
        <div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--border)">
          ${source ? `
          <div style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3);
                      letter-spacing:0.1em;text-transform:uppercase;margin-bottom:3px">Source</div>
          <div style="font-size:13px;color:var(--text2);margin-bottom:${reason?'10px':'0'}">${escHtml(source)}</div>` : ''}
          ${reason ? `
          <div style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3);
                      letter-spacing:0.1em;text-transform:uppercase;margin-bottom:3px">Correlation</div>
          <div style="font-size:12px;color:var(--text2);line-height:1.6">${escHtml(reason)}</div>` : ''}
        </div>` : ''}

        ${/* Action buttons */ ''}
        <div style="display:flex;flex-direction:column;gap:8px">
          ${canAnalyze ? `
          <button onclick="graphAnalyze('${escAttr(label)}','${escAttr(type)}')"
                  style="width:100%;padding:10px;border-radius:9px;border:none;
                         background:var(--accent);color:#fff;cursor:pointer;
                         font-size:14px;font-weight:600;font-family:'Outfit',sans-serif;
                         display:flex;align-items:center;justify-content:center;gap:7px;
                         transition:opacity 0.15s"
                  onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
              <circle cx="11" cy="11" r="8"/>
              <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            Analyze ${escHtml(type)}
          </button>` : ''}
          <button id="graph-copy-btn"
                  onclick="graphCopy(window._graphNodeValue)"
                  style="width:100%;padding:9px;border-radius:9px;cursor:pointer;
                         border:1px solid var(--border);background:var(--bg2);
                         color:var(--text2);font-size:13px;font-family:'Outfit',sans-serif;
                         font-weight:500;transition:background 0.15s"
                  onmouseover="this.style.background='var(--bg3)'"
                  onmouseout="this.style.background='var(--bg2)'">
            ⎘ Copy full value
          </button>
        </div>
      `;
      return;
    }

    // Fallback: floating panel (standalone /graph page)
    hidePanel();
    panelEl = document.createElement('div');
    panelEl.id = 'graph-node-panel';
    panelEl.style.cssText = [
      'position:absolute','z-index:200','min-width:210px','max-width:270px',
      'border-radius:12px','padding:16px','pointer-events:all',
      'background:var(--surface-solid,#10101c)',
      'border:1px solid var(--border2)',
      'box-shadow:0 8px 32px rgba(0,0,0,0.45)',
    ].join(';');
    panelEl.innerHTML = `
      <div style="font-family:'Space Mono',monospace;font-size:11px;
                  color:var(--text);word-break:break-all;line-height:1.5;
                  margin-bottom:8px;user-select:all">${escHtml(label)}</div>
      <div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">
        <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:${vBg};
                     border:1px solid ${vBorder};color:${vColor};font-family:'Space Mono',monospace">
          ${verdict}</span>
        <span style="font-family:'Space Mono',monospace;font-size:10px;color:var(--text3)">
          ${escHtml(type)}</span>
      </div>
      ${reason ? `<div style="font-size:12px;color:var(--text3);margin-bottom:12px;
                               padding:8px;background:var(--bg3);border-radius:6px;
                               line-height:1.5">${escHtml(reason)}</div>` : ''}
      <div style="display:flex;flex-direction:column;gap:6px">
        ${canAnalyze ? `<button onclick="graphAnalyze('${escAttr(label)}','${escAttr(type)}')"
                style="padding:8px;border-radius:7px;border:none;background:var(--accent);
                       color:#fff;cursor:pointer;font-size:13px;font-family:'Outfit',sans-serif">
                Analyze ${escHtml(type)}</button>` : ''}
        <button onclick="graphCopy('${escAttr(label)}')" id="graph-copy-btn"
                style="padding:7px;border-radius:7px;cursor:pointer;border:1px solid var(--border);
                       background:transparent;color:var(--text3);font-size:12px;
                       font-family:'Outfit',sans-serif">
          ⎘ Copy value</button>
        <button onclick="graphClose()"
                style="padding:6px;border-radius:7px;cursor:pointer;border:1px solid var(--border);
                       background:transparent;color:var(--text3);font-size:11px;
                       font-family:'Outfit',sans-serif">
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
    const f = document.createElement('form');
    f.method = 'POST'; f.action = '/analyze';
    const i = document.createElement('input');
    i.type = 'hidden'; i.name = 'ioc_input';
    i.value = (prefixes[type] || '') + label;
    f.appendChild(i); document.body.appendChild(f); f.submit();
  };

  window.graphCopy = function(label) {
    const val = label || window._graphNodeValue || '';
    if (!val) return;
    navigator.clipboard.writeText(val).then(() => {
      const btn = document.getElementById('graph-copy-btn');
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = '✓ Copied!';
        btn.style.color = 'var(--teal)';
        setTimeout(() => {
          if (btn) { btn.textContent = orig; btn.style.color = ''; }
        }, 1800);
      }
    }).catch(() => {
      // Fallback for older browsers
      const ta = document.createElement('textarea');
      ta.value = val; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
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
    return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  }

})();
