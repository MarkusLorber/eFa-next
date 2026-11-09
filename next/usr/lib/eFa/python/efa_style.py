# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The look of eFa-next, one source for the web interface (efa-web) and the setup wizard (efa-init): the logo, the colour
tokens in light and dark, and the base of cards, form fields and buttons. Only text, no code of either program."""

# Same drawing as assets/logo.svg.
LOGO = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 440 120" role="img" aria-label="eFa-next">
  <title>eFa-next</title>
  <style>
    .text { fill: #646563; }
    .line { stroke: #646563; }
    @media (prefers-color-scheme: dark) {
      .text { fill: #f2f2f2; }
      .line { stroke: #f2f2f2; }
    }
  </style>
  <!-- Rings and outlined envelope, a flat take on the eFa logo -->
  <g transform="rotate(-14 80 54)">
    <rect x="42" y="22" width="76" height="54" rx="6" fill="#ffffff" fill-opacity="0" class="line" stroke-width="5"/>
    <path d="M45 26 80 54l35-28" fill="none" class="line" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
  </g>
  <text x="166" y="76" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="68" font-weight="800" letter-spacing="-2" class="text">e<tspan fill="#c0cf48">F</tspan>a<tspan font-weight="300" letter-spacing="0" dx="8">next</tspan></text>
  <text x="169" y="102" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="17" letter-spacing="1.5" class="text">email <tspan font-weight="700">FILTER</tspan> appliance</text>
</svg>"""

# The colours, light and dark (the system setting of the browser).
TOKENS = """:root{--lime:#C0CF48;--gray:#646563;--ink:#3f444a;--bg:#f4f5f2;--card:#fff;--line:#e2e4dc;--ok:#3d8b4a;--warn:#b07800;--bad:#b83a3a;--side:#3f444a;--field:#fff;--soft:#eef0e8;--hover:#f4f5f2;--muted:#5b6157;--border:#858880;--area:#f8f9f4;--chart:#c5c8bd;--pill:#eef1d2;--pill-g:#dcefdf;--pill-g-ink:#2c6b38;--note:#fbefcf;--note-ink:#8a6200;--pend:#fff4d6;--pend-ink:#3f444a;--danger-line:#e4b9b9;color-scheme:light dark}
@media (prefers-color-scheme: dark){:root{--gray:#a9aba6;--ink:#e6e7e3;--bg:#1b1d1a;--card:#252723;--line:#3a3d37;--ok:#5fb36c;--warn:#e0a526;--bad:#e06a6a;--side:#2a2d29;--field:#2e302d;--soft:#2e302d;--hover:#30332e;--muted:#b4baa3;--border:#767970;--area:#20221f;--chart:#6b6e66;--pill:#3b4120;--pill-g:#1f3a25;--pill-g-ink:#9fd6a8;--note:#3d3218;--note-ink:#f0c869;--pend:#3d3218;--pend-ink:#f0e6cf;--danger-line:#7a3a3a}}
"""

# The base the wizard is built from, as the login page of the web interface: logo above, one card, fields and buttons.
BASE = """*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);min-height:100vh}
main.solo{width:100%;max-width:44rem;margin:0 auto;padding:24px 16px}
.brand{display:block;padding:18px 22px;background:var(--side);border-radius:12px 12px 0 0}
.brand svg{display:block;width:100%;max-width:22rem;height:auto}.brand .text{fill:#f2f2f2}.brand .line{stroke:#f2f2f2}
.card{background:var(--card);border:1px solid var(--line);border-radius:0 0 12px 12px;padding:20px 22px}
h1{margin:0 0 4px;font-size:26px}h2{margin:0 0 10px;font-size:19px}
a{color:var(--ink)}a:hover{color:var(--gray)}
.err{color:var(--bad);font-weight:500;overflow-wrap:anywhere}
label{display:block;margin:12px 0;font-weight:500}
input[type=text],input:not([type]),input[type=password],input[type=email],select{display:block;width:100%;max-width:28rem;margin-top:4px;
padding:8px 10px;border:1px solid var(--border);border-radius:8px;font:inherit;background:var(--field);color:var(--ink)}
input[type=radio],input[type=checkbox]{width:auto;margin-right:6px;accent-color:var(--lime)}
input:focus,select:focus{outline:2px solid var(--ink);border-color:var(--ink)}
button,a.btn{font:inherit;padding:8px 18px;border-radius:8px;border:1px solid var(--lime);background:var(--lime);color:#2a2e22;font-weight:600;
cursor:pointer;text-decoration:none;display:inline-block;margin:12px 10px 0 0}
a.btn.s,button.s{background:var(--field);border-color:var(--line);color:var(--ink);font-weight:400}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:14px;overflow:hidden;margin:0 0 14px}
.seg a{padding:3px 12px;text-decoration:none;color:var(--ink);background:var(--card)}.seg a.cur{background:var(--lime);color:#2a2e22;font-weight:600}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 10px 6px 0;border-bottom:1px solid var(--line);vertical-align:top}
pre{background:var(--area);padding:10px;border-radius:8px;overflow:auto}code{background:var(--soft);padding:1px 5px;border-radius:4px}
:focus-visible{outline:3px solid var(--lime);outline-offset:2px}
.bar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.bar svg{max-width:15rem}.bar .seg{margin:0}
.bar .seg a{background:transparent;color:#f2f2f2}.bar .seg a.cur{background:var(--lime);color:#2a2e22}
.prog{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:2px 0 8px}.prog i{display:block;height:100%;background:var(--lime)}
ol.groups{display:flex;flex-wrap:wrap;gap:2px 14px;list-style:none;padding:0;margin:0 0 16px;font-size:13px;color:var(--gray)}
ol.groups .done::before{content:"\\2713  ";color:var(--ok)}ol.groups .cur{color:var(--ink);font-weight:600}
.step{color:var(--gray);font-size:13px;margin:0}.help{color:var(--gray);margin:0 0 6px}.hint{display:block;color:var(--gray);font-weight:400;font-size:13px}
.actions{display:flex;align-items:center;gap:10px;margin-top:18px;border-top:1px solid var(--line);padding-top:4px}.actions .next{margin-left:auto;margin-right:0}
.legal{max-height:20rem;overflow:auto;border:1px solid var(--line);border-radius:8px;padding:2px 14px;background:var(--area)}
.codes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:10px 0}
.codes code{font:600 16px/1.4 ui-monospace,Consolas,monospace;padding:8px;text-align:center;border:1px solid var(--line);letter-spacing:.04em}
h3{font-size:15px;margin:18px 0 4px;display:flex;justify-content:space-between}h3 a{font-weight:400;font-size:13px}.card th{width:45%}.addr .btn{font-size:22px;padding:12px 22px}
@media (max-width:560px){.codes{grid-template-columns:1fr}.card{padding:16px}.bar svg{max-width:11rem}}
"""
