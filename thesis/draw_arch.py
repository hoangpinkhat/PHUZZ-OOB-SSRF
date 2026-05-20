"""
Vẽ sơ đồ kiến trúc hệ thống Phuzz+SSRF
Output: thesis/Thesis/figures/arch_system.png
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe

# ── output path ──────────────────────────────────────────────────────────────
OUT_DIR = os.path.join(os.path.dirname(__file__), "Thesis", "figures")
os.makedirs(OUT_DIR, exist_ok=True)
OUT = os.path.join(OUT_DIR, "arch_system.png")

# ── palette ───────────────────────────────────────────────────────────────────
C_FUZZER   = "#2C6FAC"   # blue
C_WEB      = "#27875A"   # green
C_OOB      = "#B85C00"   # orange
C_DB       = "#6B3D9A"   # purple
C_TMPFS    = "#555E6B"   # dark grey
C_NET      = "#E8EEF4"   # light blue bg
C_BORDER   = "#30363D"
C_RED      = "#C0392B"
C_ARROW    = "#30363D"
C_SSRF_ARR = "#C0392B"
C_READ_ARR = "#2C6FAC"
C_WRITE_G  = "#27875A"
C_WRITE_O  = "#B85C00"
WHITE      = "#FFFFFF"

fig, ax = plt.subplots(figsize=(16, 10))
ax.set_xlim(0, 16)
ax.set_ylim(0, 10)
ax.axis('off')
fig.patch.set_facecolor(WHITE)

# ── helpers ───────────────────────────────────────────────────────────────────
def box(x, y, w, h, fc, title, lines=(), radius=0.25, title_size=12):
    rect = FancyBboxPatch((x, y), w, h,
        boxstyle=f"round,pad={radius}",
        linewidth=1.8, edgecolor=C_BORDER,
        facecolor=fc, zorder=3)
    ax.add_patch(rect)
    n = len(lines)
    title_y = y + h - 0.42 if n else y + h/2
    ax.text(x + w/2, title_y, title,
            ha='center', va='center', fontsize=title_size,
            fontweight='bold', color=WHITE, zorder=4,
            fontfamily='monospace')
    for i, ln in enumerate(lines):
        ax.text(x + w/2, y + h - 0.85 - i*0.38, ln,
                ha='center', va='center', fontsize=8.5,
                color=WHITE, alpha=0.90, zorder=4,
                fontfamily='monospace')

def arrow(x1, y1, x2, y2, color=C_ARROW, lw=1.8,
          style='->', ls='solid', label='', lx=None, ly=None,
          label_color=None, ha='center'):
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle=style, color=color,
                        lw=lw, linestyle=ls,
                        connectionstyle='arc3,rad=0.0'),
        zorder=5)
    if label:
        mx = lx if lx is not None else (x1+x2)/2
        my = ly if ly is not None else (y1+y2)/2
        ax.text(mx, my, label, ha=ha, va='center',
                fontsize=8, color=label_color or color,
                fontweight='bold', zorder=6,
                bbox=dict(facecolor='white', edgecolor='none',
                          alpha=0.85, pad=1))

# ── Docker network background ─────────────────────────────────────────────────
net = FancyBboxPatch((0.3, 0.3), 15.4, 9.2,
    boxstyle="round,pad=0.2",
    linewidth=2, edgecolor='#8FA8C8',
    facecolor=C_NET, linestyle=(0,(6,3)), zorder=1, alpha=0.6)
ax.add_patch(net)
ax.text(0.65, 9.25, "Docker network  phuzz-net  172.20.0.0/24",
        fontsize=10, color='#4A6A8A', style='italic', zorder=6)

# ── shared-tmpfs (bottom strip) ───────────────────────────────────────────────
box(0.7, 0.55, 14.6, 1.65, C_TMPFS,
    "shared-tmpfs  (512 MB)",
    ("ssrf-hooks/<covID>.json     "
     "oob-logs/<token>.json     "
     "coverage-reports/     "
     "ssrf-error-reports/",),
    radius=0.2, title_size=11)

# ── containers ────────────────────────────────────────────────────────────────
# phuzz-fuzzer
box(0.7, 5.8, 3.8, 2.8, C_FUZZER,
    "phuzz-fuzzer",
    ("fuzzer.py",
     "SSRFMutator (21 variants)",
     "CmdInjSSRFMutator (10 var.)",
     "SSRFVulnCheck (2-stage)"))

# phuzz-web
box(5.7, 5.8, 4.6, 2.8, C_WEB,
    "phuzz-web",
    ("PHP 7.4 / 8.2 + Apache",
     "08_ssrf.php  (23 hooks)",
     "09_ssrf_stream.php",
     "WordPress mu-plugin"))

# phuzz-db
box(12.0, 5.8, 3.3, 2.8, C_DB,
    "phuzz-db",
    ("MySQL 8",
     "Ứng dụng WordPress",
     "hoặc standalone PHP"))

# phuzz-oob
box(5.7, 3.0, 4.6, 2.3, C_OOB,
    "phuzz-oob  (172.20.0.10)",
    ("Flask HTTP :8000  HTTPS :8443",
     "dnsmasq: *.oob → 172.20.0.10",
     "Atomic write  oob-logs/"))

# ── data-flow arrows ──────────────────────────────────────────────────────────

# 1. Fuzzer → Web: HTTP request (X-Covid header)
arrow(4.5, 7.35, 5.7, 7.35,
      color=C_ARROW, lw=2.2,
      label="① HTTP + X-Fuzzer-Covid: <ID>\n   payload OOB trong param",
      lx=5.1, ly=7.85, label_color=C_ARROW)

# 2. Web → DB
arrow(10.3, 7.2, 12.0, 7.2,
      color=C_DB, lw=1.8,
      label="SQL", lx=11.15, ly=7.45, label_color=C_DB)

# 3. PHP hook: Web writes ssrf-hooks/
arrow(7.0, 5.8, 6.2, 2.2,
      color=C_WRITE_G, lw=2.0,
      label="② hook ghi\nssrf-hooks/<ID>.json",
      lx=5.5, ly=4.0, label_color=C_WRITE_G, ha='center')

# 4. App makes SSRF call → OOB server  (dashed red = vulnerability path)
arrow(8.0, 5.8, 8.0, 5.3,
      color=C_SSRF_ARR, lw=2.2, ls=(0,(4,2)),
      label="③ PHP gọi curl/fgc/…\nvới URL = OOB payload",
      lx=9.6, ly=5.55, label_color=C_SSRF_ARR, ha='center')

# 5. OOB server writes oob-logs/
arrow(8.0, 3.0, 8.8, 2.2,
      color=C_WRITE_O, lw=2.0,
      label="④ ghi oob-logs/<token>.json",
      lx=9.8, ly=2.65, label_color=C_WRITE_O, ha='center')

# 6. Fuzzer reads ssrf-hooks/ AND oob-logs/ from tmpfs
arrow(2.6, 2.2, 2.6, 5.8,
      color=C_READ_ARR, lw=2.2, style='<-',
      label="⑤ đọc ssrf-hooks/\n   đọc oob-logs/\n   (AND logic)",
      lx=1.05, ly=4.0, label_color=C_READ_ARR, ha='center')

# 7. Fuzzer reads coverage-reports/
arrow(3.1, 2.2, 5.7, 6.8,
      color='#808080', lw=1.4, style='<-', ls=(0,(3,2)),
      label="coverage", lx=4.8, ly=4.7, label_color='#808080')

# ── legend ────────────────────────────────────────────────────────────────────
legend_items = [
    (C_FUZZER,   "phuzz-fuzzer  —  fuzzer + mutator + vulnchecker"),
    (C_WEB,      "phuzz-web      —  ứng dụng PHP được instrument"),
    (C_OOB,      "phuzz-oob      —  OOB listener (Flask + dnsmasq)"),
    (C_DB,       "phuzz-db        —  MySQL 8"),
    (C_TMPFS,    "shared-tmpfs  —  giao tiếp inter-container"),
    (C_SSRF_ARR, "━━ (đỏ nét đứt)  —  luồng SSRF payload / OOB callback"),
    (C_READ_ARR, "━━ (xanh)         —  Fuzzer đọc tín hiệu phản hồi"),
]
for i, (c, lbl) in enumerate(legend_items):
    ax.add_patch(mpatches.Patch(facecolor=c, edgecolor='none'))
    ax.text(0.75 + (i % 4) * 4.0, 0.25 - (i // 4) * 0.25, f"■ {lbl}",
            fontsize=7.5, color=c, zorder=6,
            fontweight='bold' if c == C_SSRF_ARR else 'normal')

# Actually let's put legend outside on the right
# (skip legend inside figure to keep it clean)

ax.set_title("Kiến trúc hệ thống Phuzz+SSRF — Luồng phát hiện Blind SSRF qua OOB",
             fontsize=13, fontweight='bold', pad=12, color=C_BORDER)

plt.tight_layout(pad=0.5)
plt.savefig(OUT, dpi=180, bbox_inches='tight', facecolor=WHITE)
plt.close()
print(f"Saved → {OUT}")
