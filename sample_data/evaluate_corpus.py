"""Evaluation harness for the FYP Results chapter.

Unlike a flag-tabulator, this measures ForenSight against GROUND TRUTH: it takes
a labelled corpus, runs the detector, and reports a confusion matrix, per-task
precision / recall / F1, and a per-signal ablation (which signal carries the
result). This is the evidence that answers "does it actually work, and how well".

--------------------------------------------------------------------------------
HOW TO PROVIDE GROUND TRUTH
--------------------------------------------------------------------------------
Put labelled images in a corpus folder, one subfolder per class:

    eval_corpus/
        real/          authentic camera originals (unedited)
        ai/            AI-generated images
        edited/        manually edited (non-AI: crop, paint, splice, filter)
        transferred/   real photos re-saved by WhatsApp/Telegram (benign)

(You may omit classes you do not have; metrics adapt.)

Run:  python sample_data/evaluate_corpus.py [corpus_dir]     (default: eval_corpus)

Definitions used for scoring (stated so they are defensible):
  * AI task:            positive = truly AI-generated.
  * Manipulation task:  positive = truly ai OR edited. 'transferred' and 'real'
                        are NEGATIVE (a benign re-save is not manipulation) -
                        so any flag on 'transferred' is counted as a FALSE
                        POSITIVE. This deliberately surfaces the known
                        transfer-vs-edit limitation instead of hiding it.
"""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensight import (config, exif_engine, jpeg_analyzer, recompression_analyzer,
                        thumbnail_engine, file_type_analyzer, provenance_analyzer,
                        integrity_analyzer)
from forensight.integrity_analyzer import AnalysisBundle

LABELS = ("real", "ai", "edited", "transferred")
_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif"}


# --------------------------------------------------------------------------
# Per-image detection (mirrors analysis_service - rule-based only)
# --------------------------------------------------------------------------
def analyse(path: Path) -> dict:
    exif = exif_engine.extract_exif(path)
    ftype = file_type_analyzer.analyze_file_type(path)
    prov = provenance_analyzer.analyze_provenance(path)
    jr = jpeg_analyzer.analyze_jpeg(path)
    bundle = AnalysisBundle(exif=exif, file_type=ftype, provenance=prov)
    if jr.is_jpeg:
        bundle.jpeg = jr
        rc = recompression_analyzer.analyze(jr)
        bundle.recompressed = rc.recompressed
        bundle.recompression_quality = rc.quality
    tc = thumbnail_engine.compare_thumbnail(path)
    if tc.available:
        bundle.thumbnail_mismatch = tc.mismatch
        bundle.thumbnail_difference = tc.difference
    a = integrity_analyzer.assess(bundle)

    software_flag = any("software" in i.lower() for i in exif.indicators)
    return {
        "score": a.score if a.score is not None else 0,
        "outcome": a.outcome,
        "flagged": (a.score or 0) >= config.SCORE_BAND_POTENTIAL,   # tool: not-clean
        "pred_ai": bool(prov.ai_generated),                         # AI decision (C2PA)
        # individual signals (for the ablation / baseline)
        "sig_provenance": bool(prov.detected),
        "sig_recompressed": bool(bundle.recompressed),
        "sig_thumb": bool(bundle.thumbnail_mismatch),
        "sig_filetype": ftype["result"] == file_type_analyzer.MISMATCH,
        "sig_software": software_flag,
        "generator": prov.generator or prov.editor,
    }


# --------------------------------------------------------------------------
# Metrics (no sklearn dependency)
# --------------------------------------------------------------------------
def _prf(pairs) -> dict:
    """pairs: iterable of (truth_bool, pred_bool) -> precision/recall/F1/acc."""
    tp = sum(1 for t, p in pairs if t and p)
    fp = sum(1 for t, p in pairs if not t and p)
    fn = sum(1 for t, p in pairs if t and not p)
    tn = sum(1 for t, p in pairs if not t and not p)
    n = tp + fp + fn + tn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / n if n else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1, "accuracy": acc}


def _print_metric(name: str, m: dict):
    print(f"  {name:<22} P={m['precision']:.3f}  R={m['recall']:.3f}  "
          f"F1={m['f1']:.3f}  Acc={m['accuracy']:.3f}  "
          f"(TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']})")


# --------------------------------------------------------------------------
# Corpus loading
# --------------------------------------------------------------------------
def load_corpus(root: Path):
    """Yield (path, label) for every labelled image under root/<label>/."""
    items = []
    for label in LABELS:
        d = root / label
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if p.suffix.lower() in _EXTS:
                items.append((p, label))
    return items


def main(folder: str = "eval_corpus"):
    root = Path(__file__).resolve().parent.parent / folder
    if not root.is_dir():
        print(f"Corpus folder not found: {root}\n")
        print("Create it with one subfolder per class and drop labelled images in:")
        print("  eval_corpus/real/   eval_corpus/ai/   eval_corpus/edited/   "
              "eval_corpus/transferred/")
        return
    items = load_corpus(root)
    if not items:
        print(f"No labelled images found under {root}/<label>/.")
        print(f"Expected subfolders: {', '.join(LABELS)}")
        return

    print(f"ForenSight evaluation - corpus: {root.name}  "
          f"({len(items)} images)   (rule-based, explainable)\n")

    results = []
    for path, label in items:
        r = analyse(path)
        r["file"] = path.name
        r["label"] = label
        results.append(r)

    # -- per-image table --------------------------------------------------
    hdr = f"{'File':<30}{'Truth':<12}{'Score':>6}  {'Flagged':<8}{'PredAI':<7}Gen"
    print(hdr); print("-" * len(hdr))
    for r in results:
        gen = f" {r['generator']}" if r["generator"] else ""
        print(f"{r['file'][:29]:<30}{r['label']:<12}{r['score']:>6}  "
              f"{'YES' if r['flagged'] else '-':<8}"
              f"{'YES' if r['pred_ai'] else '-':<7}{gen}")
    print()

    # -- confusion matrix: true label x tool decision ---------------------
    bands = {integrity_analyzer.NO_SIGNIFICANT_ANOMALIES: "Clean",
             integrity_analyzer.POTENTIAL_MANIPULATION: "Processing",
             integrity_analyzer.STRONG_INDICATORS: "Strong",
             integrity_analyzer.INSUFFICIENT_DATA: "NoData"}
    cols = ["Clean", "Processing", "Strong", "NoData"]
    present = [l for l in LABELS if any(r["label"] == l for r in results)]
    print("Confusion matrix  (rows = ground truth, cols = tool assessment)")
    print(f"  {'':<12}" + "".join(f"{c:>12}" for c in cols))
    for label in present:
        counts = {c: 0 for c in cols}
        for r in results:
            if r["label"] == label:
                counts[bands.get(r["outcome"], "NoData")] += 1
        print(f"  {label:<12}" + "".join(f"{counts[c]:>12}" for c in cols))
    print()

    # -- Task 1: AI detection (the headline) ------------------------------
    has_ai = any(r["label"] == "ai" for r in results)
    if has_ai:
        print("TASK 1 - AI-generated detection (positive = truly AI):")
        _print_metric("ForenSight (C2PA provenance)",
                      _prf((r["label"] == "ai", r["pred_ai"]) for r in results))
        print()

    # -- Task 2: manipulation detection + signal ablation -----------------
    def truth_manip(r):
        return r["label"] in ("ai", "edited")
    print("TASK 2 - Manipulation detection (positive = ai OR edited; "
          "real/transferred = negative):")
    _print_metric("ForenSight (score>=1)",
                  _prf((truth_manip(r), r["flagged"]) for r in results))
    for name, key in [("- provenance signal", "sig_provenance"),
                      ("- recompression sig", "sig_recompressed"),
                      ("- thumbnail signal", "sig_thumb"),
                      ("- filetype signal", "sig_filetype"),
                      ("- EXIF software sig", "sig_software")]:
        _print_metric(name, _prf((truth_manip(r), r[key]) for r in results))
    print()

    # -- transferred false-positive rate (the known limitation) -----------
    transferred = [r for r in results if r["label"] == "transferred"]
    if transferred:
        fp = sum(1 for r in transferred if r["flagged"])
        print(f"Transferred-image false-positive rate (flagged as processed): "
              f"{fp}/{len(transferred)} = {fp / len(transferred):.0%}")
        print("  (Expected non-zero: messaging re-compression is a software "
              "re-save. This is the documented transfer-vs-edit limitation.)\n")

    # -- CSV out ----------------------------------------------------------
    out = root.parent / "eval_results.csv"
    cols_csv = ["file", "label", "score", "outcome", "flagged", "pred_ai",
                "sig_provenance", "sig_recompressed", "sig_thumb",
                "sig_filetype", "sig_software", "generator"]
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(",".join(cols_csv) + "\n")
        for r in results:
            fh.write(",".join(str(r.get(c, "")) for c in cols_csv) + "\n")
    print(f"Per-image results written to: {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "eval_corpus")
