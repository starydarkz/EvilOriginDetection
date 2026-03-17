/**
 * graph.js — Cytoscape.js integration for Evil Origin Detection.
 * Loaded on results page when #graph-container exists.
 *
 * Fixes:
 * - "Loading graph..." stays visible after load → hidden once Cytoscape renders
 * - Click on node → tooltip mini-menu with Analyze button per supported type
 * - Edge types styled differently (threat vs resolution vs info)
 */
(function () {
  const container = document.getElementById('graph-container');
  if (!container) return;

  const iocId = container.dataset.iocId;
  if (!iocId) return;

  const loadingEl = container.querySelector('.graph-empty');

  // ── Load Cytoscape then fetch data ─────────────────────────────
  const script = document.createElement('script');
  script.src = 'https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.29.2/cytoscape.min.js';
  script.onerror = () => {
    if (loadingEl) loadingEl.innerHTML =
      '<span style="font-size:11px;color:var(--text3)">Graph library failed to load</span>';
  };
  script.onload = () => {
    fetch(`/results/${iocId}/graph`)
      .then(r => r.json())
      .then(data => {
        if (!data.nodes || data.nodes.length === 0) {
          if (loadingEl) loadingEl.innerHTML =
            '<span style="font-size:28px;opacity:0.2">◎</span>' +
            '<span style="font-size:11px;color:var(--text3)">No graph artifacts found</span>';
          return;
        }
        renderGraph(data);
        // Hide loading state once rendered
        if (loadingEl) loadingEl.style.display = 'none';
      })
      .catch(err => {
        if (loadingEl) loadingEl.innerHTML =
          `<span style="font-size:11px;color:var(--text3)">Graph unavailable: ${err.message}</span>`;
      });
  };
  document.head.appendChild(script);

  // ── Supported IOC types for analysis ───────────────────────────
  const ANALYZABLE = new Set(['ip', 'domain', 'hash', 'url', 'email', 'network']);

  // ── Render ──────────────────────────────────────────────────────
  function renderGraph(data) {
    const isDark = document.body.classList.contains('dark');
    const textColor   = isDark ? '#c8cae8' : '#0d0f1e';
    const mutedColor  = isDark ? '#6b6d9a' : '#6b7290';
    const edgeDefault = isDark ? 'rgba(99,102,180,0.22)' : 'rgba(13,15,30,0.12)';

    const cy = cytoscape({
      container,
      elements: [...data.nodes, ...data.edges],
      style: buildStyle(isDark, textColor, mutedColor, edgeDefault),
      layout: {
        name:         'cose',
        padding:      50,
        nodeRepulsion: () => 10000,
        edgeElasticity: () => 32,
        animate:      false,
        randomize:    true,
      },
      userZoomingEnabled:  true,
      userPanningEnabled:  true,
      boxSelectionEnabled: false,
      minZoom: 0.15,
      maxZoom: 4,
    });

    // ── Node click → show tooltip ────────────────────────────────
    cy.on('tap', 'node', evt => {
      const d = evt.target.data();
      showTooltip(d, evt.renderedPosition || { x: 200, y: 200 });
    });

    // ── Background click → hide tooltip ─────────────────────────
    cy.on('tap', evt => {
      if (evt.target === cy) hideTooltip();
    });

    // ── Store cy globally for external access ────────────────────
    container._cy = cy;
  }

  // ── Style builder ────────────────────────────────────────────────
  function buildStyle(isDark, textColor, mutedColor, edgeDefault) {
    return [
      {
        selector: 'node',
        style: {
          'width':              ele => ele.data('central') ? 56 : sizeByType(ele.data('type')),
          'height':             ele => ele.data('central') ? 56 : sizeByType(ele.data('type')),
          'background-color':   ele => nodeColor(ele.data()),
          'background-opacity': ele => ele.data('central') ? 0.25 : 0.15,
          'border-width':       ele => ele.data('central') ? 2.5 : 1,
          'border-color':       ele => nodeColor(ele.data()),
          'border-opacity':     0.9,
          'label':              'data(label)',
          'font-family':        'JetBrains Mono, monospace',
          'font-size':          ele => ele.data('central') ? '10px' : '9px',
          'color':              textColor,
          'text-valign':        'bottom',
          'text-margin-y':      4,
          'text-max-width':     '120px',
          'text-wrap':          'ellipsis',
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-width':       3.5,
          'background-opacity': 0.35,
        }
      },
      {
        selector: 'node[type="tag"]',
        style: {
          'shape':        'round-rectangle',
          'width':        'label',
          'height':       20,
          'padding':      '6px',
          'text-valign':  'center',
          'text-halign':  'center',
          'font-size':    '8px',
        }
      },
      {
        selector: 'node[type="technology"]',
        style: {
          'shape':           'round-rectangle',
          'background-color': isDark ? '#1e2a3a' : '#e8f0fe',
          'border-color':    isDark ? '#3b4a6b' : '#3b5bdb',
          'color':           isDark ? '#7b8cde' : '#3b5bdb',
          'width':           'label',
          'height':          18,
          'padding':         '5px',
          'text-valign':     'center',
          'font-size':       '8px',
        }
      },
      {
        selector: 'node[type="asn"]',
        style: {
          'shape':        'diamond',
          'width':        32,
          'height':       32,
        }
      },
      // Edges by type
      {
        selector: 'edge',
        style: {
          'width':              1,
          'line-color':         edgeDefault,
          'target-arrow-color': edgeDefault,
          'target-arrow-shape':'triangle',
          'arrow-scale':        0.7,
          'curve-style':        'bezier',
          'opacity':            0.8,
          'font-family':        'JetBrains Mono, monospace',
          'font-size':          '8px',
          'color':              mutedColor,
        }
      },
      {
        selector: 'edge[type="threat"]',
        style: {
          'line-color':         isDark ? 'rgba(224,92,92,0.5)' : 'rgba(192,57,43,0.4)',
          'target-arrow-color': isDark ? 'rgba(224,92,92,0.5)' : 'rgba(192,57,43,0.4)',
          'width':              1.5,
          'line-style':         'dashed',
          'line-dash-pattern':  [5, 3],
        }
      },
      {
        selector: 'edge[type="resolution"]',
        style: {
          'line-color':         isDark ? 'rgba(123,140,222,0.4)' : 'rgba(45,74,207,0.3)',
          'target-arrow-color': isDark ? 'rgba(123,140,222,0.4)' : 'rgba(45,74,207,0.3)',
          'width':              1,
        }
      },
      {
        selector: 'edge[type="intel"]',
        style: {
          'line-color':         isDark ? 'rgba(86,207,178,0.35)' : 'rgba(13,138,106,0.3)',
          'target-arrow-color': isDark ? 'rgba(86,207,178,0.35)' : 'rgba(13,138,106,0.3)',
          'line-style':         'dotted',
        }
      },
    ];
  }

  // ── Node color by verdict + type ─────────────────────────────────
  function nodeColor(d) {
    if (d.verdict === 'malicious')  return '#e05c5c';
    if (d.verdict === 'suspicious') return '#f5a623';
    if (d.verdict === 'clean')      return '#56cfb2';
    const typeColors = {
      ip:         '#7b8cde',
      domain:     '#a78bfa',
      hash:       '#56cfb2',
      url:        '#f5a623',
      email:      '#e05c5c',
      asn:        '#6b6d9a',
      malware:    '#e05c5c',
      tag:        '#f5a623',
      technology: '#7b8cde',
      threat:     '#e05c5c',
      network:    '#38bdf8',
    };
    return typeColors[d.type] || '#6b6d9a';
  }

  function sizeByType(type) {
    const sizes = { asn: 28, tag: 22, technology: 20, threat: 30 };
    return sizes[type] || 34;
  }

  // ── Tooltip mini-menu ─────────────────────────────────────────────
  let tooltipEl = null;

  function showTooltip(d, pos) {
    hideTooltip();

    const label   = d.label || d.id || '';
    const type    = d.type  || '';
    const verdict = d.verdict || 'unknown';
    const score   = d.score != null ? `${d.score}/100` : null;
    const canAnalyze = ANALYZABLE.has(type);

    // Verdict color
    const vColors = {
      malicious:  'var(--v-malicious)',
      suspicious: 'var(--v-suspicious)',
      clean:      'var(--v-clean)',
      unknown:    'var(--v-unknown)',
    };
    const vColor = vColors[verdict] || 'var(--text3)';

    // Build prefix for analyze
    const prefixMap = {
      ip: 'ip=', domain: 'domain=', hash: 'hash=',
      url: 'url=', email: 'mail=', network: 'red=',
    };

    tooltipEl = document.createElement('div');
    tooltipEl.style.cssText = `
      position: absolute;
      z-index: 100;
      background: var(--surface-solid, #0e0e20);
      border: 0.5px solid var(--border2);
      border-radius: 8px;
      padding: 12px 14px;
      min-width: 180px;
      max-width: 240px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
      pointer-events: all;
      font-family: 'JetBrains Mono', monospace;
    `;

    tooltipEl.innerHTML = `
      <div style="font-size:11px;font-weight:500;color:var(--text, #e8eaf6);
                  margin-bottom:6px;word-break:break-all;line-height:1.4">
        ${escHtml(label)}
      </div>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
        <span style="font-size:9px;padding:2px 7px;border-radius:3px;
                     background:rgba(99,102,180,0.15);color:var(--blue, #7b8cde);
                     letter-spacing:0.08em;text-transform:uppercase">
          ${escHtml(type)}
        </span>
        <span style="font-size:9px;color:${vColor};font-weight:500">
          ${verdict}${score ? ' · ' + score : ''}
        </span>
      </div>
      ${canAnalyze && !d.central ? `
      <div style="display:flex;flex-direction:column;gap:5px">
        <button onclick="graphAnalyzeNode('${escAttr(label)}','${escAttr(type)}')"
                style="width:100%;padding:6px 10px;border-radius:5px;border:none;
                       background:var(--accent, #e05c5c);color:#fff;cursor:pointer;
                       font-family:'JetBrains Mono',monospace;font-size:10px;
                       font-weight:500;letter-spacing:0.04em;
                       display:flex;align-items:center;justify-content:center;gap:5px">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          Analyze this ${type}
        </button>
        <button onclick="graphCopyNode('${escAttr(label)}')"
                style="width:100%;padding:5px 10px;border-radius:5px;
                       border:0.5px solid var(--border2);background:transparent;
                       color:var(--text3, #6b6d9a);cursor:pointer;
                       font-family:'JetBrains Mono',monospace;font-size:10px">
          ⎘ Copy value
        </button>
      </div>` : `
      <div style="font-size:10px;color:var(--text3, #6b6d9a)">
        ${d.central ? 'Central IOC — use Rescan to refresh' : 'No analysis available for this type'}
      </div>
      `}
    `;

    container.style.position = 'relative';
    container.appendChild(tooltipEl);

    // Position tooltip near click, keep inside container
    const cRect = container.getBoundingClientRect();
    const margin = 10;
    let left = pos.x + margin;
    let top  = pos.y - 20;

    // Clamp to container bounds after brief render
    requestAnimationFrame(() => {
      if (!tooltipEl) return;
      const tRect = tooltipEl.getBoundingClientRect();
      if (left + tRect.width > cRect.width - margin) {
        left = pos.x - tRect.width - margin;
      }
      if (top + tRect.height > cRect.height - margin) {
        top = cRect.height - tRect.height - margin;
      }
      if (top < margin) top = margin;
      if (left < margin) left = margin;
      tooltipEl.style.left = left + 'px';
      tooltipEl.style.top  = top  + 'px';
    });
  }

  function hideTooltip() {
    if (tooltipEl && tooltipEl.parentNode) {
      tooltipEl.parentNode.removeChild(tooltipEl);
    }
    tooltipEl = null;
  }

  // ── Global handlers called from tooltip buttons ───────────────────
  window.graphAnalyzeNode = function(label, type) {
    const prefixMap = {
      ip: 'ip=', domain: 'domain=', hash: 'hash=',
      url: 'url=', email: 'mail=', network: 'red=',
    };
    const prefix = prefixMap[type] || '';
    const form   = document.createElement('form');
    form.method  = 'POST';
    form.action  = '/analyze';
    const inp    = document.createElement('input');
    inp.type     = 'hidden';
    inp.name     = 'ioc_input';
    inp.value    = prefix + label;
    form.appendChild(inp);
    document.body.appendChild(form);
    form.submit();
  };

  window.graphCopyNode = function(label) {
    navigator.clipboard?.writeText(label).then(() => {
      if (tooltipEl) {
        const btn = tooltipEl.querySelector('button:last-child');
        if (btn) {
          const orig = btn.textContent;
          btn.textContent = '✓ Copied';
          setTimeout(() => { if (btn) btn.textContent = orig; }, 1500);
        }
      }
    });
  };

  // ── Escape helpers ────────────────────────────────────────────────
  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function escAttr(s) {
    return String(s).replace(/'/g, "\\'").replace(/"/g, '\\"');
  }

})();
