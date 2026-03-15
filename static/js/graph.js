/**
 * graph.js — Cytoscape.js graph renderer for Evil Origin Detection.
 * Loaded only on the results page when #graph-container exists.
 * Fetches graph data from /results/{id}/graph then renders.
 */
(function () {
  const container = document.getElementById('graph-container');
  if (!container) return;

  const iocId = container.dataset.iocId;
  if (!iocId) return;

  // Color map by node type / verdict
  function nodeColor(data) {
    if (data.central) {
      const v = data.verdict || 'unknown';
      return { malicious:'#e05c5c', suspicious:'#f5a623', clean:'#56cfb2', unknown:'#6b6d9a' }[v] || '#6b6d9a';
    }
    return { ip:'#7b8cde', domain:'#a78bfa', hash:'#56cfb2', asn:'#6b6d9a', malware:'#e05c5c', url:'#f5a623' }[data.type] || '#6b6d9a';
  }

  fetch(`/results/${iocId}/graph`)
    .then(r => r.json())
    .then(data => {
      if (!data.nodes || data.nodes.length === 0) {
        container.innerHTML = '<div class="graph-empty"><span style="font-size:28px;opacity:0.25">◎</span><span>No graph data available</span></div>';
        return;
      }

      // Inject Cytoscape from CDN then render
      const script = document.createElement('script');
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.29.2/cytoscape.min.js';
      script.onload = () => renderGraph(data);
      document.head.appendChild(script);
    })
    .catch(() => {
      container.innerHTML = '<div class="graph-empty"><span>Graph data unavailable</span></div>';
    });

  function renderGraph(data) {
    const isDark = document.body.classList.contains('dark');
    const bg     = isDark ? 'transparent' : 'transparent';

    const cy = cytoscape({
      container,
      elements: [...data.nodes, ...data.edges],
      style: [
        {
          selector: 'node',
          style: {
            'width':              (el) => el.data('central') ? 52 : 36,
            'height':             (el) => el.data('central') ? 52 : 36,
            'background-color':   (el) => nodeColor(el.data()),
            'background-opacity': 0.18,
            'border-width':       (el) => el.data('central') ? 2 : 1,
            'border-color':       (el) => nodeColor(el.data()),
            'border-opacity':     0.8,
            'label':              'data(label)',
            'font-family':        'JetBrains Mono, monospace',
            'font-size':          '9px',
            'color':              isDark ? '#e8eaf6' : '#0d0f1e',
            'text-valign':        'bottom',
            'text-margin-y':      4,
            'text-max-width':     '100px',
            'text-wrap':          'truncate',
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-width':   3,
            'border-opacity': 1,
          }
        },
        {
          selector: 'edge',
          style: {
            'width':              1,
            'line-color':         isDark ? 'rgba(99,102,180,0.3)' : 'rgba(13,15,30,0.15)',
            'target-arrow-color': isDark ? 'rgba(99,102,180,0.4)' : 'rgba(13,15,30,0.2)',
            'target-arrow-shape':'triangle',
            'arrow-scale':        0.8,
            'curve-style':        'bezier',
            'label':              'data(label)',
            'font-family':        'JetBrains Mono, monospace',
            'font-size':          '8px',
            'color':              isDark ? '#6b6d9a' : '#6b7290',
            'text-background-opacity': 0,
          }
        }
      ],
      layout: { name: 'cose', padding: 40, nodeRepulsion: 8000, animate: false },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    // Tooltip panel
    const tooltip = document.getElementById('graph-tooltip');

    cy.on('tap', 'node', (evt) => {
      const d = evt.target.data();
      if (tooltip) {
        document.getElementById('tt-label').textContent   = d.label || '';
        document.getElementById('tt-type').textContent    = d.type  || '';
        document.getElementById('tt-verdict').textContent = d.verdict || 'unknown';
        document.getElementById('tt-score').textContent   = d.score != null ? `${d.score}/100` : '—';
        const analyzeBtn = document.getElementById('tt-analyze');
        if (analyzeBtn && !d.central) {
          analyzeBtn.style.display = 'inline-flex';
          analyzeBtn.onclick = () => {
            const form = document.createElement('form');
            form.method = 'POST'; form.action = '/analyze';
            const input = document.createElement('input');
            input.type = 'hidden'; input.name = 'ioc_input';
            input.value = d.type === 'ip' ? `ip=${d.label}` : `domain=${d.label}`;
            form.appendChild(input); document.body.appendChild(form); form.submit();
          };
        } else if (analyzeBtn) {
          analyzeBtn.style.display = 'none';
        }
        tooltip.style.display = 'block';
      }
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy && tooltip) tooltip.style.display = 'none';
    });
  }
})();
