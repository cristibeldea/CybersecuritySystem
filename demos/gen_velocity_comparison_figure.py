"""Genereaza figura comparativa intre profilul de viteza al unui bot si al unui om."""
import sys, os, math, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))

import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from test_threshold_calibration import (
    trajectory_bezier_jitter,
    trajectory_human_like,
)

HUMAN_DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "human_telemetry.json")

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "axes.titleweight": "bold",
    "axes.spines.top": False,
    "axes.spines.right": False,
})

BOT_COLOR   = "#d9534f"
HUMAN_COLOR = "#5cb85c"

def compute_velocities(points):
    velocities, segment_times = [], []
    for i in range(1, len(points)):
        dx = points[i]["x"] - points[i-1]["x"]
        dy = points[i]["y"] - points[i-1]["y"]
        dt = max(1.0, points[i]["t"] - points[i-1]["t"])
        velocities.append(math.hypot(dx, dy) / dt)
        segment_times.append((points[i]["t"] + points[i-1]["t"]) / 2)
    return np.array(velocities), np.array(segment_times)

def skewness(arr):
    if len(arr) < 3: return 0.0
    m = arr.mean(); s = arr.std()
    if s < 1e-9: return 0.0
    return float(np.mean(((arr - m) / s) ** 3))

def bell_ratio(velocities):
    n = len(velocities)
    if n < 3: return 0.0
    third = n // 3
    v_first  = velocities[:third].mean()
    v_middle = velocities[third:2*third].mean()
    v_last   = velocities[2*third:].mean()
    edge = (v_first + v_last) / 2
    return float(v_middle / edge) if edge > 1e-9 else 0.0

def load_human_payloads():
    if not os.path.exists(HUMAN_DATA_FILE):
        return None
    try:
        with open(HUMAN_DATA_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list) and len(data) >= 3:
            return data
    except Exception as e:
        print(f"[!] Eroare la citirea {HUMAN_DATA_FILE}: {e}")
    return None

human_payloads = load_human_payloads()

if human_payloads:
    print(f"[+] Folosesc {len(human_payloads)} mostre UMANE REALE din {HUMAN_DATA_FILE}")
    HUMAN_SOURCE = f"date umane reale ({len(human_payloads)} mostre)"
    payloads_sorted = sorted(human_payloads, key=lambda p: len(p.get("points", [])))
    representative = payloads_sorted[len(payloads_sorted) // 2]
    human_pts = representative["points"]

    all_human_v = []
    for p in human_payloads:
        v, _ = compute_velocities(p.get("points", []))
        all_human_v.extend(v.tolist())
    human_v_all = np.array(all_human_v)
else:
    print(f"[!] Nu am gasit {HUMAN_DATA_FILE}.")
    print(f"    Foloseste collect_human_telemetry.py mai intai pentru date reale.")
    print(f"    Cad inapoi pe traiectorie sintetica.")
    HUMAN_SOURCE = "traiectorie sintetica (cvasi-uman)"
    human_pts = trajectory_human_like(0)
    human_v_all_list = []
    for seed in range(15):
        v, _ = compute_velocities(trajectory_human_like(seed))
        human_v_all_list.extend(v.tolist())
    human_v_all = np.array(human_v_all_list)

bot_pts = trajectory_bezier_jitter(0)
bot_v_all_list = []
for seed in range(15):
    v, _ = compute_velocities(trajectory_bezier_jitter(seed))
    bot_v_all_list.extend(v.tolist())
bot_v_all = np.array(bot_v_all_list)

bot_v,   bot_t   = compute_velocities(bot_pts)
human_v, human_t = compute_velocities(human_pts)

bot_skew    = skewness(bot_v)
human_skew  = skewness(human_v)
bot_bell    = bell_ratio(bot_v)
human_bell  = bell_ratio(human_v)

fig, axes = plt.subplots(2, 2, figsize=(11, 7.5),
                          gridspec_kw={"hspace": 0.45, "wspace": 0.30})

ax = axes[0, 0]
ax.plot((bot_t - bot_t[0]) / 1000, bot_v, color=BOT_COLOR, lw=1.2, alpha=0.85)
ax.fill_between((bot_t - bot_t[0]) / 1000, bot_v, alpha=0.18, color=BOT_COLOR)
ax.set_title("BOT (Bezier + jitter) — profil de viteza", color=BOT_COLOR)
ax.set_xlabel("timp [s]")
ax.set_ylabel("viteza [px/ms]")
ax.text(0.98, 0.95, f"bell-curve ratio = {bot_bell:.2f}",
        transform=ax.transAxes, ha="right", va="top", fontsize=9,
        bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="#bbb", lw=0.8))

ax = axes[0, 1]
ax.plot((human_t - human_t[0]) / 1000, human_v, color=HUMAN_COLOR, lw=1.2, alpha=0.85)
ax.fill_between((human_t - human_t[0]) / 1000, human_v, alpha=0.18, color=HUMAN_COLOR)
ax.set_title("OM — profil de viteza  (esantion reprezentativ)", color=HUMAN_COLOR)
ax.set_xlabel("timp [s]")
ax.set_ylabel("viteza [px/ms]")
ax.text(0.98, 0.95, f"bell-curve ratio = {human_bell:.2f}",
        transform=ax.transAxes, ha="right", va="top", fontsize=9,
        bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="#bbb", lw=0.8))

def skew_label(s: float) -> str:
    """Eticheta textuala pentru valoarea de skewness."""
    if abs(s) < 0.25:
        return "quasi-simetrica"
    if abs(s) < 0.75:
        return "asimetrie usoara"
    if abs(s) < 1.5:
        return "asimetrie moderata"
    return "asimetrie puternica"

bot_sk_val   = skewness(bot_v_all)
human_sk_val = skewness(human_v_all)

ax = axes[1, 0]
ax.hist(bot_v_all, bins=40, color=BOT_COLOR, alpha=0.75,
        edgecolor="white", lw=0.5)
ax.set_title("BOT — distributia vitezelor (15 traiectorii sintetice)", color=BOT_COLOR)
ax.set_xlabel("viteza [px/ms]")
ax.set_ylabel("frecventa")
ax.axvline(bot_v_all.mean(), color="black", linestyle="--", lw=1.2, alpha=0.75,
           label=f"media = {bot_v_all.mean():.2f}")
ax.text(0.98, 0.95,
        f"skewness = {bot_sk_val:.3f}\n({skew_label(bot_sk_val)})",
        transform=ax.transAxes, ha="right", va="top", fontsize=9,
        bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="#bbb", lw=0.8))
ax.legend(loc="center right", fontsize=8, frameon=False)

ax = axes[1, 1]
ax.hist(human_v_all, bins=40, color=HUMAN_COLOR, alpha=0.75,
        edgecolor="white", lw=0.5)
ax.set_title(f"OM — distributia vitezelor ({HUMAN_SOURCE})", color=HUMAN_COLOR)
ax.set_xlabel("viteza [px/ms]")
ax.set_ylabel("frecventa")
ax.axvline(human_v_all.mean(), color="black", linestyle="--", lw=1.2, alpha=0.75,
           label=f"media = {human_v_all.mean():.2f}")
ax.text(0.50, 0.95,
        f"skewness = {human_sk_val:.3f}\n({skew_label(human_sk_val)})",
        transform=ax.transAxes, ha="left", va="top", fontsize=9,
        bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="#bbb", lw=0.8))
ax.legend(loc="center right", fontsize=8, frameon=False)

fig.suptitle(
    "Comparatie cinematica bot vs. om — profil temporal si distributie statistica a vitezelor",
    fontsize=12, fontweight="bold", y=0.99
)

out_path = r"C:\Users\Cristi\Desktop\Licenta\bot_vs_human_velocity_comparison.png"
plt.savefig(out_path, dpi=300, bbox_inches="tight", facecolor="white")
print(f"Salvat: {out_path}")

try:
    plt.show()
except Exception:
    pass
