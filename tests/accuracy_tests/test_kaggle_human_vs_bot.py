"""Test de acuratete pe Kaggle Mouse Dynamics: scoruri umane reale versus bot sintetic."""
import os
import sys
import io
import json
import math
import random
from typing import List, Dict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
WEB_DIR = os.path.join(PROJECT_ROOT, "web")
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

from captcha.behavior_features import extract_features  # noqa: E402
from captcha.behavior_scoring import compute_behavior_risk  # noqa: E402

import pandas as pd  # noqa: E402

CSV_PATH = os.path.join(
    PROJECT_ROOT, "tests", "resources",
    "mouse_dynamics_kaggle_dataset", "Train_Mouse.csv",
)
OUT_JSON = os.path.join(os.path.dirname(__file__), "data", "accuracy_results.json")
OUT_CSV = os.path.join(os.path.dirname(__file__), "data", "scores.csv")

N_BOTS_PER_TYPE = 30

def convert_kaggle_session(group: pd.DataFrame) -> Dict:
    """Converteste o sesiune Kaggle in payload pentru extract_features."""
    g = group.sort_values("timestamp").reset_index(drop=True)
    if g.empty:
        return None

    t0 = int(g["timestamp"].iloc[0])
    duration_ms = float(int(g["timestamp"].iloc[-1]) - t0)

    points = []
    clicks = []
    for _, row in g.iterrows():
        et = int(row["event_type"])
        rel_t = float(int(row["timestamp"]) - t0)
        x = float(row["screen_x"]) if pd.notna(row["screen_x"]) else 0.0
        y = float(row["screen_y"]) if pd.notna(row["screen_y"]) else 0.0
        if et in (2, 4):
            points.append({"t": rel_t, "x": x, "y": y})
        elif et == 5:
            clicks.append({"t": rel_t, "x": x, "y": y})

    return {
        "duration_ms": duration_ms,
        "points": points,
        "clicks": clicks,
        "focus": [],
        "tile_hovers": {},
        "had_pointer": True,
        "hp": False,
    }

def load_human_sessions(csv_path: str) -> List[Dict]:
    df = pd.read_csv(csv_path)
    sessions = []
    for session_id, group in df.groupby("session_id"):
        payload = convert_kaggle_session(group)
        if payload is None:
            continue
        sessions.append({
            "label": "human",
            "source": "kaggle",
            "session_id": str(session_id),
            "user_id": str(group["user_id"].iloc[0]),
            "payload": payload,
        })
    return sessions

def bot_straight_line(seed: int) -> Dict:
    """Linie dreapta, viteza constanta, zero jitter, zero click-uri."""
    rng = random.Random(seed)
    x0 = rng.uniform(100, 300)
    y0 = rng.uniform(100, 300)
    x1 = rng.uniform(800, 1200)
    y1 = rng.uniform(400, 700)
    n_points = 100
    duration = 1500.0
    points = []
    for i in range(n_points):
        f = i / (n_points - 1)
        points.append({"t": f * duration, "x": x0 + f * (x1 - x0), "y": y0 + f * (y1 - y0)})
    return {
        "duration_ms": duration,
        "points": points,
        "clicks": [{"t": duration, "x": x1, "y": y1}],
        "focus": [], "tile_hovers": {},
        "had_pointer": False,
        "hp": False,
    }

def bot_teleport(seed: int) -> Dict:
    """Teleportare: doar 2 puncte (start si final), cu click la final."""
    rng = random.Random(seed)
    x0 = rng.uniform(0, 100)
    y0 = rng.uniform(0, 100)
    x1 = rng.uniform(700, 1100)
    y1 = rng.uniform(400, 700)
    duration = 200.0
    return {
        "duration_ms": duration,
        "points": [
            {"t": 0, "x": x0, "y": y0},
            {"t": duration, "x": x1, "y": y1},
        ],
        "clicks": [{"t": duration, "x": x1, "y": y1}],
        "focus": [], "tile_hovers": {},
        "had_pointer": False,
        "hp": False,
    }

def bot_sleep_loop(seed: int) -> Dict:
    """Bot semi-sofisticat: drum cu mai multe puncte si intervale fixe."""
    rng = random.Random(seed)
    x0 = rng.uniform(100, 200)
    y0 = rng.uniform(100, 200)
    x1 = rng.uniform(900, 1100)
    y1 = rng.uniform(500, 700)
    n_points = 80
    duration = 1600.0
    points = []
    step = duration / n_points
    for i in range(n_points):
        t = i * step
        f = i / (n_points - 1)
        points.append({"t": t, "x": x0 + f * (x1 - x0), "y": y0 + f * (y1 - y0)})
    clicks = []
    for k in range(4):
        clicks.append({"t": (k + 1) * (duration / 4), "x": x1, "y": y1})
    return {
        "duration_ms": duration,
        "points": points,
        "clicks": clicks,
        "focus": [], "tile_hovers": {},
        "had_pointer": True,
        "hp": False,
    }

def bot_jittered_line(seed: int) -> Dict:
    """Bot mai sofisticat: linie dreapta cu jitter mic gaussian."""
    rng = random.Random(seed)
    x0 = rng.uniform(100, 200)
    y0 = rng.uniform(100, 200)
    x1 = rng.uniform(900, 1100)
    y1 = rng.uniform(500, 700)
    n_points = 100
    duration = 1500.0
    points = []
    for i in range(n_points):
        f = i / (n_points - 1)
        x = x0 + f * (x1 - x0) + rng.gauss(0, 1.5)
        y = y0 + f * (y1 - y0) + rng.gauss(0, 1.5)
        points.append({"t": f * duration, "x": x, "y": y})
    return {
        "duration_ms": duration,
        "points": points,
        "clicks": [{"t": duration, "x": x1, "y": y1}],
        "focus": [], "tile_hovers": {},
        "had_pointer": True,
        "hp": False,
    }

def bot_curved_jittered(seed: int) -> Dict:
    """Bot sofisticat mediu: traiectorie curba (arc de cerc) cu jitter."""
    rng = random.Random(seed)
    x0 = rng.uniform(100, 200)
    y0 = rng.uniform(500, 600)
    x1 = rng.uniform(900, 1100)
    y1 = rng.uniform(200, 300)
    ctrl_x = (x0 + x1) / 2 + rng.uniform(-50, 50)
    ctrl_y = min(y0, y1) - rng.uniform(100, 200)
    n_points = 120
    duration = 1800.0
    points = []
    for i in range(n_points):
        f = i / (n_points - 1)
        bx = (1-f)**2 * x0 + 2*(1-f)*f * ctrl_x + f**2 * x1
        by = (1-f)**2 * y0 + 2*(1-f)*f * ctrl_y + f**2 * y1
        bx += rng.gauss(0, 2.0)
        by += rng.gauss(0, 2.0)
        points.append({"t": f * duration, "x": bx, "y": by})
    return {
        "duration_ms": duration,
        "points": points,
        "clicks": [{"t": duration, "x": x1, "y": y1}],
        "focus": [], "tile_hovers": {},
        "had_pointer": True,
        "hp": False,
    }

def bot_sigma_lognormal(seed: int) -> Dict:
    """Bot foarte sofisticat care incearca sa reproduca profilul de viteza uman."""
    rng = random.Random(seed)
    x0 = rng.uniform(100, 200)
    y0 = rng.uniform(500, 600)
    x1 = rng.uniform(900, 1100)
    y1 = rng.uniform(200, 300)
    n_points = 110
    duration = 1700.0
    points = []
    for i in range(n_points - 4):
        t_norm = i / (n_points - 5)
        if t_norm < 0.5:
            ease = 4 * t_norm**3
        else:
            ease = 1 - pow(-2 * t_norm + 2, 3) / 2
        x = x0 + ease * (x1 - x0) + rng.gauss(0, 1.8)
        y = y0 + ease * (y1 - y0) + rng.gauss(0, 1.8)
        points.append({"t": t_norm * duration * 0.94, "x": x, "y": y})
    overshoot_x = x1 + rng.uniform(5, 12)
    overshoot_y = y1 - rng.uniform(3, 8)
    points.append({"t": duration * 0.96, "x": overshoot_x, "y": overshoot_y})
    points.append({"t": duration * 0.97, "x": overshoot_x - 2, "y": overshoot_y + 1})
    points.append({"t": duration * 0.99, "x": x1 + 1, "y": y1 - 1})
    points.append({"t": duration, "x": x1, "y": y1})
    return {
        "duration_ms": duration,
        "points": points,
        "clicks": [{"t": duration, "x": x1, "y": y1}],
        "focus": [], "tile_hovers": {},
        "had_pointer": True,
        "hp": False,
    }

BOT_GENERATORS = {
    "straight_line": bot_straight_line,
    "teleport": bot_teleport,
    "sleep_loop": bot_sleep_loop,
    "jittered_line": bot_jittered_line,
    "curved_jittered": bot_curved_jittered,
    "sigma_lognormal": bot_sigma_lognormal,
}

def generate_bot_sessions(n_per_type: int) -> List[Dict]:
    sessions = []
    for bot_type, gen in BOT_GENERATORS.items():
        for seed in range(n_per_type):
            payload = gen(seed)
            sessions.append({
                "label": "bot",
                "source": f"synthetic:{bot_type}",
                "session_id": f"{bot_type}-{seed}",
                "user_id": None,
                "payload": payload,
            })
    return sessions

def score_session(sess: Dict) -> int:
    features = extract_features(sess["payload"])
    risk, _ = compute_behavior_risk(features)
    return risk

def compute_metrics(scores: List[Dict], threshold: int) -> Dict:
    """Calculeaza metrici (detectie, FP, precision, F1) pentru un prag dat."""
    tp = fp = tn = fn = 0
    for s in scores:
        is_bot = s["label"] == "bot"
        flagged = s["score"] >= threshold
        if is_bot and flagged: tp += 1
        elif is_bot and not flagged: fn += 1
        elif (not is_bot) and flagged: fp += 1
        else: tn += 1

    total_bots = tp + fn
    total_humans = fp + tn
    fpr = (fp / total_humans) if total_humans > 0 else 0.0
    fnr = (fn / total_bots) if total_bots > 0 else 0.0
    tpr = (tp / total_bots) if total_bots > 0 else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * tpr / (precision + tpr)) if (precision + tpr) > 0 else 0.0
    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "false_positive_rate_pct": round(fpr * 100, 2),
        "false_negative_rate_pct": round(fnr * 100, 2),
        "detection_rate_pct": round(tpr * 100, 2),
        "precision_pct": round(precision * 100, 2),
        "f1_score": round(f1, 4),
    }

def main():
    print("=" * 78)
    print("  TEST ACURATETE: TRAFIC UMAN REAL (KAGGLE) vs BOTI SINTETICI")
    print("=" * 78)

    if not os.path.exists(CSV_PATH):
        print(f"[x] Nu gasesc Train_Mouse.csv la {CSV_PATH}")
        sys.exit(1)

    print(f"[*] Incarcare sesiuni umane din {os.path.basename(CSV_PATH)}...")
    human_sessions = load_human_sessions(CSV_PATH)
    print(f"    {len(human_sessions)} sesiuni umane incarcate")

    print(f"[*] Generare {N_BOTS_PER_TYPE} boti per tip ({len(BOT_GENERATORS)} tipuri)...")
    bot_sessions = generate_bot_sessions(N_BOTS_PER_TYPE)
    print(f"    {len(bot_sessions)} sesiuni de bot generate")

    print("[*] Calculare scoruri de risc...")
    all_scores = []
    for sess in human_sessions + bot_sessions:
        score = score_session(sess)
        all_scores.append({
            "label": sess["label"],
            "source": sess["source"],
            "session_id": sess["session_id"],
            "score": score,
        })

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    df_scores = pd.DataFrame(all_scores)
    df_scores.to_csv(OUT_CSV, index=False)

    human_scores = [s["score"] for s in all_scores if s["label"] == "human"]
    bot_scores_by_type = {}
    for s in all_scores:
        if s["label"] == "bot":
            bot_type = s["source"].split(":")[-1]
            bot_scores_by_type.setdefault(bot_type, []).append(s["score"])

    print()
    print("DISTRIBUTII DE SCORURI:")
    print(f"  Umani (N={len(human_scores)}):")
    print(f"    min={min(human_scores)}, max={max(human_scores)}, "
          f"mean={sum(human_scores)/len(human_scores):.1f}, "
          f"median={sorted(human_scores)[len(human_scores)//2]}")
    for bot_type, scores in bot_scores_by_type.items():
        print(f"  Bot '{bot_type}' (N={len(scores)}):")
        print(f"    min={min(scores)}, max={max(scores)}, "
              f"mean={sum(scores)/len(scores):.1f}, "
              f"median={sorted(scores)[len(scores)//2]}")

    print()
    print("=" * 78)
    print(f"  {'PRAG':>5} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'DETECT%':>9} {'FP%':>7} {'PREC%':>8} {'F1':>7}")
    print("-" * 78)
    metrics_by_threshold = []
    for threshold in range(30, 86, 5):
        m = compute_metrics(all_scores, threshold)
        metrics_by_threshold.append(m)
        print(f"  {m['threshold']:>5} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} {m['fn']:>4} "
              f"{m['detection_rate_pct']:>8.1f}% {m['false_positive_rate_pct']:>6.2f}% "
              f"{m['precision_pct']:>7.1f}% {m['f1_score']:>7.4f}")
    print("=" * 78)

    best = max(metrics_by_threshold, key=lambda m: m["f1_score"])
    print()
    print(f"[+] PRAG OPTIM (F1 maxim): {best['threshold']}")
    print(f"    Rata detectie:      {best['detection_rate_pct']:.1f}% din boti prinsi")
    print(f"    Rata fals-pozitive: {best['false_positive_rate_pct']:.2f}% din umani banati gresit")
    print(f"    Precision:          {best['precision_pct']:.1f}%")
    print(f"    F1 score:           {best['f1_score']:.4f}")

    current_50 = next((m for m in metrics_by_threshold if m["threshold"] == 50), None)
    if current_50:
        print()
        print(f"[*] PRAG CURENT DIN SISTEM (50, pentru etapa checkbox):")
        print(f"    Rata detectie:      {current_50['detection_rate_pct']:.1f}%")
        print(f"    Rata fals-pozitive: {current_50['false_positive_rate_pct']:.2f}%")
        print(f"    F1 score:           {current_50['f1_score']:.4f}")

    out = {
        "dataset": {
            "csv_path": CSV_PATH,
            "n_human_sessions": len(human_sessions),
            "n_bot_sessions": len(bot_sessions),
            "n_bots_per_type": N_BOTS_PER_TYPE,
            "bot_types": list(BOT_GENERATORS.keys()),
        },
        "distributions": {
            "human": {
                "n": len(human_scores),
                "min": min(human_scores), "max": max(human_scores),
                "mean": round(sum(human_scores)/len(human_scores), 2),
                "median": sorted(human_scores)[len(human_scores)//2],
            },
            "bots_by_type": {
                bot_type: {
                    "n": len(scores),
                    "min": min(scores), "max": max(scores),
                    "mean": round(sum(scores)/len(scores), 2),
                    "median": sorted(scores)[len(scores)//2],
                }
                for bot_type, scores in bot_scores_by_type.items()
            },
        },
        "metrics_by_threshold": metrics_by_threshold,
        "best_threshold": best,
        "current_threshold_50": current_50,
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Rezultate complete: {OUT_JSON}")
    print(f"[+] Scoruri individuale: {OUT_CSV}")

    generate_plots(all_scores, metrics_by_threshold)

def generate_plots(all_scores, metrics_by_threshold):
    """Genereaza curba ROC si histograma distributiilor."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib nu este instalat; sar peste generarea graficelor.")
        return

    plots_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(plots_dir, exist_ok=True)

    roc_points = []
    for thr in range(0, 101):
        m = compute_metrics(all_scores, thr)
        roc_points.append({
            "threshold": thr,
            "fpr": m["false_positive_rate_pct"] / 100.0,
            "tpr": m["detection_rate_pct"] / 100.0,
        })

    fprs = [p["fpr"] for p in roc_points]
    tprs = [p["tpr"] for p in roc_points]

    sorted_pts = sorted(roc_points, key=lambda p: p["fpr"])
    sorted_fpr = [p["fpr"] for p in sorted_pts]
    sorted_tpr = [p["tpr"] for p in sorted_pts]
    auc = 0.0
    for i in range(1, len(sorted_fpr)):
        auc += (sorted_fpr[i] - sorted_fpr[i-1]) * (sorted_tpr[i] + sorted_tpr[i-1]) / 2

    fig, ax = plt.subplots(figsize=(8, 7))
    ax.plot(fprs, tprs, "b-", linewidth=2, label=f"Sistem WebToxin (AUC={auc:.4f})")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.4, label="Clasificator aleator")
    p50 = next((p for p in roc_points if p["threshold"] == 50), None)
    if p50:
        ax.plot(p50["fpr"], p50["tpr"], "ro", markersize=12,
                label=f"Prag curent 50 (FPR={p50['fpr']*100:.1f}%, TPR={p50['tpr']*100:.1f}%)")
        ax.annotate("prag 50", xy=(p50["fpr"], p50["tpr"]),
                    xytext=(p50["fpr"] + 0.1, p50["tpr"] - 0.05),
                    fontsize=10,
                    arrowprops=dict(arrowstyle="->", color="red", lw=1))
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.set_xlabel("Rata fals-pozitivelor (FPR)", fontsize=12)
    ax.set_ylabel("Rata detectiei (TPR)", fontsize=12)
    ax.set_title("Curba ROC — Sistem comportamental WebToxin\n"
                 "umani reali (Kaggle Mouse Dynamics) vs boti sintetici",
                 fontsize=13)
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(True, alpha=0.3)
    roc_path = os.path.join(plots_dir, "roc_curve.png")
    plt.tight_layout()
    plt.savefig(roc_path, dpi=150)
    plt.close()
    print(f"[+] Curba ROC: {roc_path}")

    human_scores = [s["score"] for s in all_scores if s["label"] == "human"]
    bot_scores = [s["score"] for s in all_scores if s["label"] == "bot"]

    fig, ax = plt.subplots(figsize=(10, 6))
    bins = list(range(0, 105, 5))
    ax.hist(human_scores, bins=bins, alpha=0.6, label=f"Umani reali (N={len(human_scores)})",
            color="green", edgecolor="darkgreen")
    ax.hist(bot_scores, bins=bins, alpha=0.6, label=f"Boti sintetici (N={len(bot_scores)})",
            color="red", edgecolor="darkred")
    ax.axvline(x=50, color="black", linestyle="--", linewidth=2,
               label="Prag de decizie (50)")
    ax.set_xlabel("Scor de risc comportamental", fontsize=12)
    ax.set_ylabel("Numar de sesiuni", fontsize=12)
    ax.set_title("Distributia scorurilor de risc — umani vs boti", fontsize=13)
    ax.legend(loc="upper center", fontsize=10)
    ax.grid(True, alpha=0.3)
    hist_path = os.path.join(plots_dir, "score_distribution.png")
    plt.tight_layout()
    plt.savefig(hist_path, dpi=150)
    plt.close()
    print(f"[+] Histograma distributiilor: {hist_path}")

    fig, ax = plt.subplots(figsize=(12, 6))
    bot_types = {}
    for s in all_scores:
        if s["label"] == "bot":
            t = s["source"].split(":")[-1]
            bot_types.setdefault(t, []).append(s["score"])

    positions = list(range(len(bot_types) + 1))
    labels = ["umani"] + list(bot_types.keys())
    data = [human_scores] + list(bot_types.values())
    bp = ax.boxplot(data, positions=positions, widths=0.6, patch_artist=True,
                    labels=labels)
    colors = ["lightgreen"] + ["lightcoral"] * len(bot_types)
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
    ax.axhline(y=50, color="black", linestyle="--", linewidth=1.5,
               label="Prag de decizie (50)")
    ax.set_ylabel("Scor de risc", fontsize=12)
    ax.set_title("Distributia scorurilor pe categorii", fontsize=13)
    ax.legend(loc="center right", fontsize=10)
    ax.grid(True, alpha=0.3, axis="y")
    plt.xticks(rotation=20, ha="right")
    box_path = os.path.join(plots_dir, "score_boxplot.png")
    plt.tight_layout()
    plt.savefig(box_path, dpi=150)
    plt.close()
    print(f"[+] Boxplot per categorie: {box_path}")

    return {"auc": auc, "roc_points": roc_points}

if __name__ == "__main__":
    main()
