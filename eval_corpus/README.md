# Evaluation corpus (for `sample_data/evaluate_corpus.py`)

Drop **labelled** images into the four subfolders below, then run the harness to
get precision / recall / F1, a confusion matrix, and a per-signal ablation.

```
eval_corpus/
    real/          authentic camera/phone originals, UNEDITED
    ai/            AI-generated images (Grok, Gemini, GPT-Image, Midjourney, SD, ...)
    edited/        manually edited (Photoshop, GIMP, Adobe Express, CapCut, filters, splices)
    transferred/   real photos re-saved by WhatsApp / Telegram / download (benign)
```

The **folder name is the ground-truth label** — put each image in the folder that
matches what it actually is. You may omit a class you do not have; the metrics
adapt.

## Run

```bash
python sample_data/evaluate_corpus.py
```

Outputs: per-image table, confusion matrix (truth x tool band), Task 1 (AI
detection), Task 2 (manipulation detection) with a per-signal ablation, the
transferred-image false-positive rate, and a `eval_results.csv`.

## How to build the corpus (aim for ~15-30 per class for defensible numbers)

| Class | Where to get them |
|-------|-------------------|
| **real** | Your own unedited camera/phone photos (straight off the device, not sent anywhere) |
| **ai** | Generate with Grok / Gemini / ChatGPT image / Midjourney; or download an AI-image set |
| **edited** | Edit some real photos in Photoshop/GIMP/Adobe Express/CapCut and export |
| **transferred** | Send some real photos to yourself via WhatsApp/Telegram, then save them |

Keep the classes **balanced** (similar counts each) so the metrics are not skewed.
Do not reuse the same source image across classes if you can avoid it.

## What the numbers mean (for your report)

- **Task 1 - AI detection:** how well provenance (and, separately, the ML model)
  identify truly AI images. Expect strong precision when C2PA metadata is present,
  and the honest generalisation gap on metadata-stripped images.
- **Task 2 - Manipulation detection:** how well the tool flags ai/edited images
  while leaving real/transferred alone. The **ablation** shows which signal
  carries the result.
- **Transferred FP rate:** documents the transfer-vs-edit limitation directly.

This folder is git-ignored by convention (evidence data should not be committed);
keep the images locally.
