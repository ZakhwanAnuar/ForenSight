# ForenSight

**A Lightweight Case-Oriented Digital-Forensics Tool for Recovered-Image
Recovery and Image-Manipulation Analysis**

ForenSight is a desktop application for **image integrity & provenance
forensics**, focused on **detecting AI-generated and edited images**. Given an
acquired data source (a `dd`/`img`/`raw` disk image or VM disk file), it recovers
embedded pictures — including **deleted** ones — by **signature-based carving**,
validates and hashes each one, then runs a suite of **rule-based analyses** —
**C2PA content-provenance / AI detection**, EXIF metadata, JPEG re-compression,
embedded-thumbnail consistency and file-type verification — combined into an
explainable **0–100 Integrity & Provenance Score**, with an **optional,
experimental pixel-based ML classifier** as a secondary supporting signal.
Everything happens inside a single traceable, reproducible, hash-verified case,
ending in a signed PDF report. **No Error Level Analysis.** The primary signals
are transparent and rule-based; the optional ML classifier is clearly labelled
experimental and degrades gracefully when TensorFlow or the model file is absent.

> ForenSight is a **research prototype / final-year-project tool**, not a
> certified replacement for Autopsy, FTK, EnCase or X-Ways. Its analysis outputs
> are **indicators** that require examiner interpretation — they are not
> independent proof that an image was manipulated. The **primary** detection is
> transparent and rule-based; an **optional, experimental** pixel-based ML
> classifier provides a secondary signal and is documented as such, not relied
> upon as proof.

---

## Quick start

```bash
python -m pip install -r requirements.txt
python main.py
```

Python 3.10+ is required (developed and tested on 3.12). On launch the app opens
maximized and shows a **Welcome** dialog (New Case / Open Recent / Open Case),
Autopsy-style.

### Bundled sample image

```bash
python sample_data/make_sample.py      # -> sample_data/suspect_test.dd
```

`suspect_test.dd` contains a mix of image blobs — valid, edited (EXIF software
tag / recompressed), and truncated JPEG/PNG/BMP/GIF — laid out in raw image
space for the carving-and-analysis workflow.

---

## End-to-end workflow

```
Create/Open Case → Add Data Source → Verify SHA-256 →
Recover Images (carving) → Validate + Hash → Analysis (Provenance/AI · EXIF ·
JPEG · Re-compression · Thumbnail · File-Type) → Integrity & Provenance Score →
Bookmark/Notes → Timeline + Chain of Custody → Report → Close & Generate Final
Report → Hash Report → Case Locked 🔒
```

The application is organised into six tabs across the top navigation bar:

| Tab | Purpose |
|-----|---------|
| **Home** | Case dashboard: summary stats and quick actions |
| **Evidence** | Three-pane workspace (directory tree · results table · detail viewer). Add a data source, **Recover Images**, **Analyse** (provenance/EXIF/JPEG/re-compression/thumbnail/file-type), verify integrity, bookmark, and filter by clicking tree nodes. Analysis results appear in the detail viewer and colour the results table by outcome (green/amber/red) |
| **Timeline** | Chronological view of case and evidence events |
| **Chain of Custody** | Hash-linked audit log of every action, with tamper verification |
| **Bookmarks** | Flagged items of interest with priority and examiner notes |
| **Report** | Live report preview, then **Close & Generate Final Report** (PDF) |

---

## Features

| Area | Capabilities |
|------|--------------|
| **Case management** | Create / open / close cases, recent-cases list, input validation, dashboard, single-instance guard, automatic PDF on close, read-only locked cases |
| **Evidence** | Add a data source (disk image / VM file), threaded **SHA-256** hashing, integrity verification (MATCH / MISMATCH / UNAVAILABLE), immutable originals |
| **Image recovery** | Signature-based carving of **JPEG / PNG / BMP / GIF** with structural validation, over-carve discard, deduplication and **idempotent re-scans**; each recovered image is classified **Allocated (live) / Deleted / Unallocated** by cross-referencing the source filesystem |
| **AI / provenance (headline)** | Rule-based detection of **C2PA "Content Credentials"** and AI-generation markers (`trainedAlgorithmicMedia`, known generators such as Grok, Google/Gemini, OpenAI GPT Image, Firefly), the C2PA **created/edited** action, **credential trust classification** (CA-issued & attributable vs **self-signed / ephemeral & forgeable**), plus **editing-app fingerprints** (Meitu, CapCut, Hypic, PicsArt, Snapseed, Photoshop…) |
| **Structural analysis** | **EXIF** extraction with indicators, **JPEG** quantization/quality, **re-compression** detection (quantization-table fingerprinting — an ELA-free re-save signal), **thumbnail-vs-full-image** consistency, **file-type** (extension-vs-content) verification |
| **Integrity scoring** | Combined, explainable **0–100 Integrity & Provenance Score** with documented weights, severity bands, and a **Fact / Indicator** confidence tag on every finding |
| **Investigation** | Directory-style navigation tree that filters the evidence table, bookmarks with priority, examiner notes, timeline, chain-of-custody audit |
| **Reporting** | ReportLab PDF: centred cover, evidence table, per-image analysis cards with scores, chain of custody, formal examiner declaration, complete SHA-256 hashes + a sidecar `<report>_SHA256.txt` |

### Evidence navigation tree

The Evidence tab presents a classic directory tree. Clicking any node filters
the results table instantly:

- **Data Sources** — each imported image, with its recovered-file count
- **Views** — File Types (JPEG/PNG/BMP/GIF); **All Recovered Images** (an
  expandable folder holding **Live Files (Allocated)**, **Deleted Files
  (Recovered)** and **Suspicious / Quarantined**)
- **Results** — Bookmarks, Strong Indicators, Processing Detected, No Anomalies

### Live vs deleted recovery (allocation status)

Signature carving alone cannot tell a *live* file from a *deleted* one — it just
reads raw bytes. To distinguish them, ForenSight parses the source filesystem
(via The Sleuth Kit), reads the **on-disk cluster ranges (data runs)** of every
file, and classifies each recovered image by the **byte offset** at which it was
carved:

- **Allocated** — the offset lies in a live file's clusters
- **Deleted** — the offset lies in a deleted file's clusters (metadata intact)
- **Unallocated** — the offset lies in neither (carved from free space)
- **Unknown** — the image has no parseable filesystem (raw blob)

This **offset-based** method (the same approach Autopsy/TSK use) works on FAT and
NTFS alike, and — unlike a size/hash heuristic — is unaffected by carved-vs-
recorded size differences or by different files sharing identical headers.
Requires `pytsk3` (optional — without it, everything is honestly reported as
*Unknown* rather than over-claiming a deletion status).

**Honest limit:** on NTFS a deleted file's MFT record is often reused, wiping its
data runs. Such a file's data is still recovered by carving, but with no metadata
linking it to the deletion it is reported **Unallocated** rather than **Deleted**
— the data is recovered, but the deletion cannot be *attributed*. Deleted files
whose metadata survives (the common case for recent deletions) are correctly
classified **Deleted**. No tool can attribute data to a deletion whose metadata
has been destroyed.

### Integrity & Provenance Score

The score measures how much an image has been **processed** and what
**provenance** it carries — *not* a probability of malicious intent. Each
analysed image is scored 0–100 by summing documented weights (defined in
[`forensight/config.py`](forensight/config.py), capped at 100). Every finding is
tagged **Fact** (declared by the file's metadata) or **Indicator** (derived,
suggestive only):

| Finding | Class | Weight |
|---------|-------|-------:|
| **AI-generation provenance declared** (C2PA `trainedAlgorithmicMedia` / known generator) | Fact | 60 |
| File type / content mismatch (e.g. PDF bytes named `.jpg`) | Indicator | 40 |
| Embedded thumbnail differs from the full image (later editing) | Indicator | 30 |
| Editing-software / image-processing name in metadata | Fact | 20 |
| Unusual JPEG compression characteristics | Indicator | 15 |
| EXIF timestamp inconsistency | Indicator | 10 |
| JPEG re-compression / re-save (quantization-table fingerprint) | Fact (informational) | **0** |

The score maps to a non-accusatory band:

| Band | Score |
|------|-------|
| **N/A** — Insufficient data (file not decodable) | — |
| **No Anomalies** | 0 |
| **Processing Detected** | 1–39 |
| **Strong Indicators** | ≥ 40 |

**Why re-compression is reported but not scored (base-rate reasoning).** JPEG
re-compression (standard quantization tables, not a camera original) is **true of
almost every image in circulation** — downloads, screenshots, exports, and every
messaging-app transfer re-encode with standard tables. Its base rate is ~100%, so
scoring it would flag nearly every image *"Processing Detected"* and **destroy the
discriminative meaning of the triage bands**. ForenSight therefore reports
re-compression as **informational context (weight 0)** and drives the bands only
with **discriminative** signals — provenance, file-type/thumbnail mismatch, EXIF
anomalies — which are absent from the vast majority of benign images. This is a
deliberate specificity choice: *Processing Detected* now means *"a discriminative
indicator is present, look here"*, not *"this JPEG was re-saved (like almost all
JPEGs)"*. What re-compression **cannot** do is distinguish an edit from a benign
re-save (both produce identical standard tables); separating those, or detecting
an edit after metadata is stripped, needs pixel-level ML (out of scope). The
authoritative *editing/AI* signal remains the C2PA provenance **Fact**.

### Detecting AI-generated / edited images (the headline)

ForenSight does **not** analyse pixels to *guess* whether an image is
AI-generated — that would require a trained ML model, deliberately out of scope.
Instead it reads the **provenance metadata** that modern generative and editing
tools embed: **C2PA "Content Credentials"** manifests, the C2PA/IPTC
`digitalSourceType` value `trainedAlgorithmicMedia`, the C2PA **created/edited**
action, and known generator identifiers (Grok, Google/Gemini, OpenAI GPT Image,
Firefly, DALL·E, Midjourney, Stable Diffusion, SynthID, …). When present, this is
an authoritative, standards-based indicator that the image was AI-generated or
AI-edited, scored heavily (+60 → **Strong Indicators**).

Two honest caveats: a bare C2PA manifest with **no** generative declaration is
informational only (Content Credentials also assert *authenticity*), and
provenance metadata can be **stripped** — so absence of a marker never proves an
image is authentic.

**Credential trust.** ForenSight also inspects the manifest's **signing
certificate** and classifies its trust: **CA-issued** (chains to a root CA, so
the claim is *attributable* to an organisation — e.g. `Google LLC`, `OpenAI`) vs
**self-signed / ephemeral** (e.g. Grok's `Self-signed ephemeral CA … LOCAL USE`),
which means the claim is **not independently verifiable and could be produced by
anyone**. This distinguishes trustworthy provenance from a forgeable one — a real
forensic concern. (It *inspects* the certificate; it does not yet cryptographically
verify the signature against the C2PA trust list — that is future work.)

### Why ELA was removed

Error Level Analysis was evaluated and **dropped**. Modern editors (CapCut,
Hypic, Meitu, etc.) re-encode the whole image uniformly on export, which erases
the region-vs-region error-level contrast ELA relies on — so ELA reads ~0% and
detects none of these edits. ForenSight instead uses **provenance** (the
effective modern signal) plus rule-based structural checks (re-compression,
thumbnail consistency, file-type). Editing that both re-saves uniformly **and**
strips metadata can only be caught by pixel-level ML forensics, which is out of
scope for this rule-based tool — a limitation stated plainly rather than
papered over with an unreliable heuristic.

## Forensic positioning

- Recovered files are described as *"recovered from raw/unallocated image space
  by signature-based carving"* — no filesystem deletion metadata is claimed.
- Provenance findings are declared **Facts**; EXIF / JPEG / re-compression /
  thumbnail / file-type results are **Indicators**, each carrying an explicit
  caution and requiring examiner interpretation.
- The original evidence image is **never modified**; all analysis is read-only.
- Carving is conservative: JPEG marker validation, PNG `IHDR` validation, BMP
  header/size checks and over-carve discard suppress the false positives that
  naive signature carvers produce.

## Project structure

```
ForenSight/
├── main.py                     # entry point (maximized window + Welcome dialog)
├── requirements.txt
├── forensight/
│   ├── config.py  utils.py  hash_utils.py  logging_config.py
│   ├── database.py  audit_manager.py
│   ├── case_manager.py  recent_cases.py  evidence_manager.py
│   ├── carver.py  file_validator.py  carving_service.py
│   ├── exif_engine.py  jpeg_analyzer.py  recompression_analyzer.py
│   ├── thumbnail_engine.py  file_type_analyzer.py  provenance_analyzer.py
│   ├── integrity_analyzer.py  analysis_service.py  stats.py  reporter.py
│   ├── main_gui.py
│   └── ui/   (style, tree_assets, common widgets, dialogs, wizards,
│              views, workers)
├── sample_data/make_evidence_disk2.py  # realistic disk-image generator
├── sample_data/evaluate_corpus.py      # evaluation harness (Results chapter)
└── tests/                      # pytest suite (59 tests)
```

## Case workspace layout

```
<Case Name>/
├── CaseData/     (case_config.json, crime_lens_case.db)
├── Evidence/     (Original, Carved_JPEGs/PNGs/BMPs/GIFs, Suspicious)
├── Analysis/     (EXIF_Dumps, JPEG_Analysis, Thumbnails)
├── Reports/      (Drafts, Final)
└── Logs/         (application.log)
```

## Testing

```bash
python -m pytest -q
```

The suite (59 tests) covers case management, hashing/integrity, carving
(including split-signature boundaries, false-positive regressions and
cancellation), file validation, EXIF/JPEG/re-compression/thumbnail/file-type
analysis, C2PA provenance detection and attribution, integrity scoring,
audit-chain tamper detection and report generation.

## Known limitations

Signature-based carving can fail on fragmented files, and overwritten data is
generally unrecoverable. **Provenance detection only works when the metadata is
present** — an image whose C2PA/EXIF has been stripped cannot be attributed. The
optional ML classifier attempts pixel-level detection but is experimental and
does not generalise reliably to generators absent from its training data (e.g.
2025 tools such as Grok, Gemini and GPT-Image), so the rule-based provenance
signal remains primary. EXIF can be forged; editing-software metadata is not
independent proof of tampering; a processing indicator shows the image was
processed, not that it was faked. Physical-drive acquisition and live-filesystem
parsing are out of scope.

**EnCase/EWF (`.E01`) images.** ForenSight reads **raw** images (`dd`/`img`/`raw`).
An E01 is a *container*, not a raw disk, so ForenSight does not parse it as a
filesystem. When an E01 is added, the tool **detects it and warns** the examiner:
carving will still run against the container bytes, but (a) live-vs-deleted
allocation degrades to *"Unallocated"* for every file, and (b) carving may find
nothing if the E01 is compressed. The examiner can proceed anyway or cancel. For
full results — including deleted-file classification — convert the E01 to raw
first with libewf's `ewfexport` (`ewfexport -u -f raw -t output image.E01`) and
add the resulting raw image. Native E01 decoding (via libewf) is future work.

**Downstream re-encoding destroys upstream fingerprints ("the last processor
wins").** ForenSight detects editing when the editor's fingerprint survives in
the file (a C2PA editor manifest or an EXIF *Software* tag). When an image is
edited and then passed through a downstream re-encoder — most importantly a
messaging platform such as **Telegram or WhatsApp**, which strips all metadata
and re-compresses the whole image on send — that final step **overwrites every
fingerprint of the steps before it**: the editor's metadata is stripped and its
compression signature is replaced. The resulting file is byte-for-byte
indistinguishable from a photo that was merely forwarded without editing, so the
prior edit **cannot be detected from the file alone**. This is an inherent
property of image processing chains, not a limitation specific to ForenSight — no
metadata-based tool can recover evidence that a later re-encoder has erased.
Detecting such cases requires evidence *outside* the transferred file (the
original device, an earlier copy, or cloud backups) or pixel-level ML forensics,
which is itself unreliable after aggressive re-compression and is out of scope.

**Chain-of-custody threat model (scope and future work).** The audit log is a
SHA-256 hash chain: each event hashes the previous one, so the "Verify Chain"
check detects *accidental corruption* and *naive edits* to the log. It does
**not**, on its own, defeat a knowledgeable attacker who has write access to the
case database: because the chain uses a plain (keyless) hash, such an attacker
could edit an event and recompute every subsequent hash to produce a
self-consistent chain. Binding the chain to a per-case **digital signature**
(private key) or an external **RFC-3161 trusted timestamp**, and authenticating
the examiner identity rather than accepting a typed name, would close this gap;
these are identified as future work. ForenSight is a research prototype, not a
certified forensic suite — all findings require examiner interpretation.
