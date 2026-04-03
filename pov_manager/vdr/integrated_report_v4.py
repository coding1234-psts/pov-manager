"""v4 threat profile report: base CSS asset + bridge styles + tab/theme scripts."""

from __future__ import annotations

from pathlib import Path

_ASSETS = Path(__file__).resolve().parent / "assets"
_V4_CSS_FILE = _ASSETS / "integrated_report_v4.css"


def integrated_report_v4_stylesheet() -> str:
    """Full v4 CSS: design tokens from static file plus report/AI bridge rules."""
    base = _V4_CSS_FILE.read_text(encoding="utf-8")
    return f"{base}\n{_INTEGRATED_V4_BRIDGE_CSS}"


INTEGRATED_REPORT_V4_TAB_SCRIPT = r"""
(function(){
  var tabs = document.querySelectorAll('.tab');
  var panels = document.querySelectorAll('.panel');
  function go(k) {
    tabs.forEach(function(t) {
      var on = t.getAttribute('data-t') === k;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    panels.forEach(function(p) {
      var on = p.getAttribute('data-p') === k;
      p.classList.toggle('active', on);
    });
  }
  tabs.forEach(function(t) {
    t.addEventListener('click', function() { go(t.getAttribute('data-t')); });
  });
  var root = document.documentElement;
  var toggle = document.getElementById('themeToggle');
  if (toggle) {
    var stored = localStorage.getItem('tp-theme');
    if (stored) root.setAttribute('data-theme', stored);
    toggle.addEventListener('click', function() {
      var current = root.getAttribute('data-theme') || 'dark';
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      localStorage.setItem('tp-theme', next);
    });
  }
})();
"""

# v4 design tokens for AI embed (reporter markup unchanged; scoped under .ai-embed)
_INTEGRATED_V4_BRIDGE_CSS = """
  /* Integrated report — misc */
  .empty-msg { font-size: 13px; color: var(--text-3); font-style: italic; margin: 12px 0; }
  .ai-embed { overflow-x: auto; margin-top: 4px; }
  .ai-embed pre { white-space: pre-wrap; word-break: break-word; }
  .meta { font-size: 12px; color: var(--text-4); margin-top: 12px; }

  /* AI exposure embed — v4 tokens */
  .ai-embed .ai-exposure-report {
    --ai-risk-color: var(--warn);
    font-family: inherit;
    font-size: 14px;
    line-height: 1.55;
    background: transparent;
    color: var(--text-1);
  }
  .ai-embed .ai-exposure-report *,
  .ai-embed .ai-exposure-report *::before,
  .ai-embed .ai-exposure-report *::after { box-sizing: border-box; }
  .ai-embed .ai-exposure-report .container {
    max-width: none; margin: 0; padding: 0;
  }
  .ai-embed .ai-exposure-report .score-card {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    box-shadow: var(--shadow-card);
    padding: 24px 28px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 28px;
    flex-wrap: wrap;
  }
  /* SVG score gauge (reporter); do not use legacy border ring here */
  .ai-embed .ai-exposure-report .score-ring--gauge {
    position: relative;
    width: 110px;
    height: 110px;
    flex-shrink: 0;
    border: none;
    border-radius: 0;
    display: block;
  }
  .ai-embed .ai-exposure-report .score-ring--gauge .score-gauge-svg {
    display: block;
    width: 110px;
    height: 110px;
    filter: drop-shadow(0 0 8px var(--accent-glow));
  }
  .ai-embed .ai-exposure-report .score-ring--gauge .score-ring-overlay {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    pointer-events: none;
  }
  .ai-embed .ai-exposure-report .score-ring--gauge .score-ring-overlay .num {
    font-size: 30px;
    font-weight: 800;
    color: var(--ai-risk-color);
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
  }
  .ai-embed .ai-exposure-report .score-ring--gauge .score-ring-overlay .lbl {
    font-size: 10px;
    color: var(--text-4);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
    text-align: center;
    max-width: 100%;
    padding: 0 6px;
    box-sizing: border-box;
  }
  .ai-embed .ai-exposure-report .score-meta h2 {
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 6px;
    color: var(--ai-risk-color);
  }
  .ai-embed .ai-exposure-report .score-meta p {
    color: var(--text-2);
    max-width: 640px;
  }
  .ai-embed .ai-exposure-report > .container > section {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    box-shadow: var(--shadow-card);
    padding: 20px 22px;
    margin-bottom: 16px;
  }
  .ai-embed .ai-exposure-report > .container > section[style*="transparent"] {
    background: transparent;
    border: none;
    box-shadow: none;
    padding: 0;
    margin-bottom: 0;
  }
  .ai-embed .ai-exposure-report > .container > section h2 {
    font-size: 15px;
    font-weight: 700;
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
    color: var(--text-1);
  }
  .ai-embed .ai-exposure-report > .container > section[style*="transparent"] > h2 {
    border-bottom: none;
    padding: 0 0 10px;
    margin-bottom: 14px;
  }
  .ai-embed .ai-exposure-report table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  .ai-embed .ai-exposure-report th {
    text-align: left;
    padding: 10px 12px;
    background: var(--surface-2);
    color: var(--text-1);
    font-weight: 600;
    border: 1px solid var(--border);
  }
  .ai-embed .ai-exposure-report td {
    padding: 10px 12px;
    border: 1px solid var(--border);
    vertical-align: top;
    color: var(--text-2);
  }
  .ai-embed .ai-exposure-report .scorecard-table td.score-cell {
    font-weight: 700;
    font-size: 14px;
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
  }
  .ai-embed .ai-exposure-report .scorecard-table td.findings-cell {
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
  }
  .ai-embed .ai-exposure-report .breakdown-total td {
    font-weight: 700;
    border-top: 1px solid var(--border) !important;
  }
  .ai-embed .ai-exposure-report .url {
    font-size: 11px;
    color: var(--text-4);
    word-break: break-all;
  }
  .ai-embed .ai-exposure-report .evidence {
    font-size: 12px;
    color: var(--text-3);
    max-width: 280px;
  }
  .ai-embed .ai-exposure-report details {
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    margin-bottom: 10px;
    box-shadow: var(--shadow-card);
    overflow: hidden;
  }
  .ai-embed .ai-exposure-report summary {
    padding: 14px 18px;
    cursor: pointer;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-1);
    user-select: none;
    transition: background var(--dur) var(--ease);
  }
  .ai-embed .ai-exposure-report summary::-webkit-details-marker { display: none; }
  .ai-embed .ai-exposure-report summary::before {
    content: '\\25B6';
    font-size: 10px;
    color: var(--text-4);
    flex-shrink: 0;
  }
  .ai-embed .ai-exposure-report details[open] > summary::before { content: '\\25BC'; }
  .ai-embed .ai-exposure-report summary:hover { background: var(--surface-2); }
  .ai-embed .ai-exposure-report .details-body { padding: 0 18px 18px; }
  .ai-embed .ai-exposure-report .details-body h3 {
    font-size: 11px;
    font-weight: 700;
    color: var(--text-3);
    margin: 16px 0 8px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .ai-embed .ai-exposure-report .remediation-card {
    border-left: 3px solid var(--accent);
    padding: 14px 18px;
    margin-bottom: 14px;
    background: var(--surface-0);
    border-radius: 0 var(--r-sm) var(--r-sm) 0;
  }
  .ai-embed .ai-exposure-report .rem-priority {
    display: inline-block;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: var(--r-full);
    margin-bottom: 8px;
    color: #fff;
  }
  .ai-embed .ai-exposure-report .rem-priority.critical { background: var(--critical); }
  .ai-embed .ai-exposure-report .rem-priority.high { background: var(--warn); }
  .ai-embed .ai-exposure-report .rem-priority.medium { background: var(--blue); }
  .ai-embed .ai-exposure-report .remediation-card li {
    margin-bottom: 6px;
    font-size: 13px;
    color: var(--text-2);
    line-height: 1.45;
  }
  .ai-embed .ai-exposure-report code {
    background: var(--surface-2);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    color: var(--accent);
    font-family: 'JetBrains Mono', monospace;
  }
  .ai-embed .ai-exposure-report pre {
    background: var(--surface-0);
    padding: 12px;
    border-radius: var(--r-sm);
    font-size: 12px;
    overflow-x: auto;
    border: 1px solid var(--border);
    color: var(--text-2);
  }
  .ai-embed .ai-exposure-report .none {
    color: var(--text-4);
    font-style: italic;
    font-size: 13px;
  }
  .ai-embed .ai-exposure-report .error-row {
    background: var(--critical-dim);
    color: var(--critical);
    font-size: 13px;
  }
"""
