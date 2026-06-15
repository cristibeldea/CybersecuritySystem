"""Test de acuratete pe setul de date academic Web Bot Detection cu etichetare ground truth."""
import os
import sys
import io
import json
import re
import math
from typing import Dict, List, Optional, Tuple

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
WEB_DIR = os.path.join(PROJECT_ROOT, "web")
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

from captcha.behavior_features import extract_features  # noqa: E402
from captcha.behavior_scoring import compute_behavior_risk  # noqa: E402

DATASET_ROOT = os.path.join(
    PROJECT_ROOT, "tests", "resources", "web_bot_detection_dataset"
)
OUT_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(OUT_DIR, exist_ok=True)
OUT_JSON = os.path.join(OUT_DIR, "web_bot_detection_results.json")
OUT_CSV = os.path.join(OUT_DIR, "web_bot_detection_scores.csv")

ANNOTATION_FILES = [
    ("phase1", "moderate_train",
     "phase1/annotations/humans_and_moderate_bots/train",
     "phase1/data/mouse_movements/humans_and_moderate_bots"),
    ("phase1", "moderate_test",
     "phase1/annotations/humans_and_moderate_bots/test",
     "phase1/data/mouse_movements/humans_and_moderate_bots"),
    ("phase1", "advanced_train",
     "phase1/annotations/humans_and_advanced_bots/train",
     "phase1/data/mouse_movements/humans_and_advanced_bots"),
    ("phase1", "advanced_test",
     "phase1/annotations/humans_and_advanced_bots/test",
     "phase1/data/mouse_movements/humans_and_advanced_bots"),
    ("phase2", "advanced",
     "phase2/annotations/humans_and_advanced_bots/humans_and_advanced_bots",
     "phase2/data/mouse_movements/humans_and_advanced_bots"),
    ("phase2", "moderate_and_advanced",
     "phase2/annotations/humans_and_moderate_and_advanced_bots/humans_and_moderate_and_advanced_bots",
     "phase2/data/mouse_movements/humans_and_moderate_and_advanced_bots"),
]

def load_annotations() -> List[Dict]:
    """Returneaza lista de sesiuni cu campurile session_id, label si phase."""
    sessions: Dict[str, Dict] = {}
    for phase, subset, ann_rel, mouse_rel in ANNOTATION_FILES:
        ann_path = os.path.join(DATASET_ROOT, ann_rel)
        mouse_dir = os.path.join(DATASET_ROOT, mouse_rel)
        if not os.path.exists(ann_path):
            continue
        with open(ann_path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                sid = parts[0]
                label = " ".join(parts[1:])
                folder = os.path.join(mouse_dir, sid)
                if not os.path.isdir(folder):
                    continue
                key = (phase, sid)
                if key not in sessions:
                    sessions[key] = {
                        "session_id": sid,
                        "label": label,
                        "phase": phase,
                        "subset": subset,
                        "folder": folder,
                    }
    return list(sessions.values())

COORD_RE = re.compile(r"\[(-?\d+),(-?\d+)\]")
ACTION_RE = re.compile(r"\[m\((-?\d+),(-?\d+)\)\]|\[c\(([lrm])\)\]")

def parse_session(folder: str) -> Optional[Dict]:
    """Returneaza payload-ul pentru extract_features sau None la eroare."""
    json_path = os.path.join(folder, "mouse_movements.json")
    if not os.path.exists(json_path):
        return None
    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception:
        return None

    times_str = data.get("mousemove_times", "") or ""
    coords_str = data.get("mousemove_total_behaviour", "") or ""
    total_str = data.get("total_behaviour", "") or ""

    try:
        timestamps = [int(t) for t in times_str.split(",") if t.strip()]
    except ValueError:
        return None

    coords = []
    for m in COORD_RE.finditer(coords_str):
        coords.append((int(m.group(1)), int(m.group(2))))

    if not timestamps or not coords:
        return None

    n = min(len(timestamps), len(coords))
    if n < 5:
        return None

    timestamps = timestamps[:n]
    coords = coords[:n]
    t0 = timestamps[0]
    points = [
        {"t": float(timestamps[i] - t0),
         "x": float(coords[i][0]),
         "y": float(coords[i][1])}
        for i in range(n)
    ]

    clicks = []
    last_xy = (0, 0)
    cursor_t = 0
    moves_seen = 0
    for m in ACTION_RE.finditer(total_str):
        if m.group(1) is not None:
            last_xy = (int(m.group(1)), int(m.group(2)))
            moves_seen += 1
        else:
            if moves_seen > 0 and moves_seen <= len(timestamps):
                t = float(timestamps[moves_seen - 1] - t0)
            else:
                t = float(points[-1]["t"]) if points else 0.0
            clicks.append({"t": t, "x": float(last_xy[0]), "y": float(last_xy[1])})

    duration_ms = float(points[-1]["t"] - points[0]["t"]) if len(points) >= 2 else 0.0

    return {
        "duration_ms": duration_ms,
        "points": points,
        "clicks": clicks,
        "focus": [],
        "tile_hovers": {},
        "had_pointer": True,
        "hp": False,
    }

def score_session(payload: Dict) -> int:
    features = extract_features(payload)
    risk, _ = compute_behavior_risk(features)
    return risk

def compute_metrics(scores: List[Dict], threshold: int,
                    bot_labels=("moderate_bot", "advanced_bot")) -> Dict:
    tp = fp = tn = fn = 0
    for s in scores:
        is_bot = s["label"] in bot_labels
        flagged = s["score"] >= threshold
        if is_bot and flagged: tp += 1
        elif is_bot and not flagged: fn += 1
        elif (not is_bot) and flagged: fp += 1
        else: tn += 1
    total_bots = tp + fn
    total_humans = fp + tn
    fpr = (fp / total_humans) if total_humans > 0 else 0.0
    tpr = (tp / total_bots) if total_bots > 0 else 0.0
    fnr = (fn / total_bots) if total_bots > 0 else 0.0
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

def generate_plots(all_scores, metrics_by_threshold):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] matplotlib nu este instalat; sar peste grafice.")
        return None

    roc_points = []
    for thr in range(0, 101):
        m = compute_metrics(all_scores, thr)
        roc_points.append({"threshold": thr,
                           "fpr": m["false_positive_rate_pct"] / 100.0,
                           "tpr": m["detection_rate_pct"] / 100.0})
    sorted_pts = sorted(roc_points, key=lambda p: p["fpr"])
    auc = 0.0
    for i in range(1, len(sorted_pts)):
        auc += ((sorted_pts[i]["fpr"] - sorted_pts[i-1]["fpr"])
                * (sorted_pts[i]["tpr"] + sorted_pts[i-1]["tpr"]) / 2)
    fig, ax = plt.subplots(figsize=(8, 7))
    ax.plot([p["fpr"] for p in roc_points], [p["tpr"] for p in roc_points],
            "b-", linewidth=2, label=f"WebToxin (AUC={auc:.4f})")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.4, label="Aleator")
    p50 = next((p for p in roc_points if p["threshold"] == 50), None)
    if p50:
        ax.plot(p50["fpr"], p50["tpr"], "ro", markersize=12,
                label=f"Prag 50 (FPR={p50['fpr']*100:.1f}%, TPR={p50['tpr']*100:.1f}%)")
    ax.set_xlim(-0.02, 1.02); ax.set_ylim(-0.02, 1.02)
    ax.set_xlabel("Rata fals-pozitivelor (FPR)")
    ax.set_ylabel("Rata detectiei (TPR)")
    ax.set_title("Curba ROC — Web Bot Detection Dataset\n"
                 "(umani vs boti moderate + advanced)")
    ax.legend(loc="lower right"); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    p = os.path.join(OUT_DIR, "web_bot_roc.png")
    plt.savefig(p, dpi=150); plt.close()
    print(f"    Curba ROC: {p}")

    by_label = {}
    for s in all_scores:
        by_label.setdefault(s["label"], []).append(s["score"])
    fig, ax = plt.subplots(figsize=(10, 6))
    labels = ["human", "moderate_bot", "advanced_bot"]
    data = [by_label.get(lab, []) for lab in labels]
    bp = ax.boxplot(data, widths=0.6, patch_artist=True,
                    tick_labels=[f"{lab} (N={len(by_label.get(lab, []))})" for lab in labels])
    colors = ["lightgreen", "lightsalmon", "lightcoral"]
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
    ax.axhline(y=50, color="black", linestyle="--", linewidth=1.5,
               label="Prag de decizie (50)")
    ax.set_ylabel("Scor de risc")
    ax.set_title("Distributia scorurilor pe categorii (Web Bot Detection Dataset)")
    ax.legend(loc="center right"); ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    p = os.path.join(OUT_DIR, "web_bot_boxplot.png")
    plt.savefig(p, dpi=150); plt.close()
    print(f"    Boxplot: {p}")

    fig, ax = plt.subplots(figsize=(10, 6))
    bins = list(range(0, 105, 5))
    for lab, color in zip(labels, ["green", "orange", "red"]):
        if by_label.get(lab):
            ax.hist(by_label[lab], bins=bins, alpha=0.55,
                    label=f"{lab} (N={len(by_label[lab])})",
                    color=color, edgecolor="black", linewidth=0.5)
    ax.axvline(x=50, color="black", linestyle="--", linewidth=2, label="Prag 50")
    ax.set_xlabel("Scor de risc"); ax.set_ylabel("Numar sesiuni")
    ax.set_title("Distributia scorurilor — Web Bot Detection Dataset")
    ax.legend(loc="upper center"); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    p = os.path.join(OUT_DIR, "web_bot_distribution.png")
    plt.savefig(p, dpi=150); plt.close()
    print(f"    Histograma: {p}")

    return {"auc": auc, "roc_points": roc_points}

def main():
    print("=" * 78)
    print("  TEST ACURATETE — WEB BOT DETECTION DATASET (etichetare ground truth)")
    print("=" * 78)
    print(f"  Sursa: {DATASET_ROOT}")
    print("=" * 78)

    print("\n[*] Incarcare adnotari...")
    sessions = load_annotations()
    print(f"    {len(sessions)} sesiuni unice cu folder corespondent")

    label_counts = {}
    by_phase = {}
    for s in sessions:
        label_counts[s["label"]] = label_counts.get(s["label"], 0) + 1
        by_phase.setdefault(s["phase"], {})
        by_phase[s["phase"]][s["label"]] = by_phase[s["phase"]].get(s["label"], 0) + 1
    print("    Distributie totala:")
    for lab, n in sorted(label_counts.items()):
        print(f"      {lab}: {n}")
    print("    Pe faze:")
    for phase, d in by_phase.items():
        print(f"      {phase}: {d}")

    print(f"\n[*] Parsare mouse_movements.json si calculare scor...")
    all_scores = []
    skipped = 0
    for s in sessions:
        payload = parse_session(s["folder"])
        if payload is None:
            skipped += 1
            continue
        score = score_session(payload)
        all_scores.append({
            "session_id": s["session_id"],
            "label": s["label"],
            "phase": s["phase"],
            "subset": s["subset"],
            "score": score,
        })
    print(f"    {len(all_scores)} sesiuni scoruite, {skipped} ignorate")

    import csv
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["session_id", "label", "phase",
                                                "subset", "score"])
        writer.writeheader()
        for row in all_scores:
            writer.writerow(row)
    print(f"    Scoruri individuale: {OUT_CSV}")

    by_lab = {}
    for s in all_scores:
        by_lab.setdefault(s["label"], []).append(s["score"])
    print("\nDISTRIBUTII DE SCORURI:")
    for lab, scores in sorted(by_lab.items()):
        scores_s = sorted(scores)
        n = len(scores_s)
        print(f"  {lab} (N={n}):")
        print(f"    min={scores_s[0]}, max={scores_s[-1]}, "
              f"mean={sum(scores_s)/n:.1f}, median={scores_s[n//2]}")

    print(f"\n[*] Cautare prag optim (granularitate 1 punct)...")
    metrics_fine = []
    for thr in range(30, 101):
        metrics_fine.append(compute_metrics(all_scores, thr))

    best_f1 = max(metrics_fine, key=lambda m: m["f1_score"])
    zero_fp = [m for m in metrics_fine if m["false_positive_rate_pct"] == 0]
    best_zero_fp = max(zero_fp, key=lambda m: m["detection_rate_pct"]) if zero_fp else None
    best_balanced = max(metrics_fine,
                        key=lambda m: m["detection_rate_pct"] - 2*m["false_positive_rate_pct"])

    p_current = next(m for m in metrics_fine if m["threshold"] == 50)

    interest = sorted(set([50, best_f1["threshold"], best_balanced["threshold"],
                            best_zero_fp["threshold"] if best_zero_fp else 60,
                            55, 60, 65, 70]))
    metrics_by_threshold = []
    print()
    print("=" * 110)
    print(f"  {'PRAG':>5} {'TAG':<22} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'DETECT%':>9} {'FP%':>8} {'PREC%':>8} {'F1':>8}")
    print("-" * 110)
    for thr in interest:
        m = compute_metrics(all_scores, thr)
        metrics_by_threshold.append(m)
        tags = []
        if thr == 50: tags.append("curent")
        if thr == best_f1["threshold"]: tags.append("F1-max")
        if thr == best_balanced["threshold"]: tags.append("echilibrat")
        if best_zero_fp and thr == best_zero_fp["threshold"]: tags.append("FP=0%")
        tag_str = "[" + ",".join(tags) + "]" if tags else ""
        print(f"  {m['threshold']:>5} {tag_str:<22} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} {m['fn']:>4} "
              f"{m['detection_rate_pct']:>8.2f}% {m['false_positive_rate_pct']:>7.2f}% "
              f"{m['precision_pct']:>7.2f}% {m['f1_score']:>8.4f}")
    print("=" * 110)

    print(f"\n[*] Defalcat pe tipuri de bot la pragurile-cheie:")
    print(f"  {'PRAG':>5} {'CATEGORIE':<14} {'DETECT%':>9} {'FP%':>8} {'F1':>8}")
    print("-" * 50)
    key_thresholds = sorted(set([50, best_balanced["threshold"],
                                  best_zero_fp["threshold"] if best_zero_fp else 60]))
    for thr in key_thresholds:
        for bot_label in ["moderate_bot", "advanced_bot"]:
            m = compute_metrics(all_scores, thr, bot_labels=(bot_label,))
            print(f"  {thr:>5} {bot_label:<14} {m['detection_rate_pct']:>8.2f}% "
                  f"{m['false_positive_rate_pct']:>7.2f}% {m['f1_score']:>8.4f}")

    print()
    print("[+] SUMAR — TREI INTERPRETARI ALE PRAGULUI OPTIM:")
    print(f"    1) PRAG CURENT (50, calibrat CAPTCHA):")
    print(f"       detectie={p_current['detection_rate_pct']:.1f}%, "
          f"FP={p_current['false_positive_rate_pct']:.2f}%, "
          f"F1={p_current['f1_score']:.4f}")
    print(f"    2) PRAG F1-MAX ({best_f1['threshold']}, optim matematic dar agresiv):")
    print(f"       detectie={best_f1['detection_rate_pct']:.1f}%, "
          f"FP={best_f1['false_positive_rate_pct']:.2f}%, "
          f"F1={best_f1['f1_score']:.4f}")
    print(f"    3) PRAG ECHILIBRAT ({best_balanced['threshold']}, detectie - 2xFP):")
    print(f"       detectie={best_balanced['detection_rate_pct']:.1f}%, "
          f"FP={best_balanced['false_positive_rate_pct']:.2f}%, "
          f"F1={best_balanced['f1_score']:.4f}")
    if best_zero_fp:
        print(f"    4) PRAG CONSERVATOR ({best_zero_fp['threshold']}, FP=0% garantat):")
        print(f"       detectie={best_zero_fp['detection_rate_pct']:.1f}%, "
              f"FP={best_zero_fp['false_positive_rate_pct']:.2f}%, "
              f"F1={best_zero_fp['f1_score']:.4f}")
    best = best_balanced

    print(f"\n[*] Generare grafice...")
    plot_info = generate_plots(all_scores, metrics_by_threshold)

    distributions = {}
    for lab, scores in by_lab.items():
        scores_s = sorted(scores)
        n = len(scores_s)
        distributions[lab] = {
            "n": n, "min": scores_s[0], "max": scores_s[-1],
            "mean": round(sum(scores_s)/n, 2),
            "median": scores_s[n//2],
        }
    out = {
        "dataset": DATASET_ROOT,
        "label_counts": label_counts,
        "n_sessions_scored": len(all_scores),
        "n_skipped": skipped,
        "distributions": distributions,
        "metrics_by_threshold": metrics_by_threshold,
        "best_threshold": best,
        "current_threshold_50": p_current,
        "best_f1": best_f1,
        "best_balanced": best_balanced,
        "best_zero_fp": best_zero_fp,
        "auc": plot_info["auc"] if plot_info else None,
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Rezultate complete: {OUT_JSON}")

if __name__ == "__main__":
    main()
