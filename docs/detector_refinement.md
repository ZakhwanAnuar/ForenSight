# Detector Refinement Through Real-Data Validation

## Overview

The image-integrity detector was first developed and tested against
self-generated sample disk images built from a controlled set of photographs.
While this confirmed the intended behaviour, self-generated data shares the
assumptions of the code that produced it and therefore cannot expose defects
that arise from the messy variety of real-world files. To validate the detector
properly, it was run against independent, third-party reference data: the
**NIST Computer Forensic Reference Data Sets (CFReDS) file-carving images**, the
**Digital Forensics Tool Testing (DFTT) images**, and a set of genuinely edited
photographs carrying real editing-application metadata.

This external validation exposed eight defects that the self-generated corpus had
not. Each was diagnosed to its root cause, corrected, and locked with an
automated regression test (or, for Refinement 8, cross-validated against Autopsy)
so it cannot recur. The refinements below demonstrate an evidence-driven tuning
of the detector's **precision** (avoiding false alarms) and **recall** (avoiding
missed detections), plus a correctness fix to deleted-file attribution. The full
test suite grew from 56 to 70 tests across this process, and all pass.

## Validation datasets

| Dataset | Source | Purpose |
|---|---|---|
| `L0_Graphic.dd` | NIST CFReDS (File Carving) | Carving accuracy against a known ground-truth file set |
| `8-jpeg-search.dd` | DFTT (Test 8, JPEG Search) | Carving + deleted-file recovery on an NTFS filesystem |
| Edited photographs | Real images carrying EXIF `Software` tags | Editing-detection precision and recall |

Ground truth for each disk image was established independently: for
`L0_Graphic.dd`, by decoding every image candidate in the raw image (a definitive
inventory of five graphics: PNG, JPEG, BMP, GIF and TIFF); for
`8-jpeg-search.dd`, by decoding every JPEG candidate (six genuine JPEGs, one of
them deleted) and by enumerating the NTFS filesystem to record which files were
allocated and which were deleted.

## Refinement 1: metadata-region confinement (precision)

**Observation.** When analysing the BMP recovered from `L0_Graphic.dd`, the
detector reported *"Edited with GIMP"* and classified the image as *Potential
Manipulation*. Manual inspection showed the image had not been edited with GIMP.

**Diagnosis.** The editing-application detector searched for signature strings
across the entire file, including pixel data. The recovered file was an
uncompressed BMP with a 40-byte header (BITMAPINFOHEADER), which carries no
metadata section, so every byte after the header is raw pixel data. The four-byte
string "GIMP" occurred by chance within the pixel data (at offset 0xEACC2),
inside a run of pixel values that happened to fall in the ASCII-letter range.
Short signatures are statistically likely to appear in the pixels of a
multi-megabyte image, producing a false positive.

**Refinement.** Signature matching was confined to the file's *metadata region*
rather than the whole file. The metadata region is defined per format: for JPEG,
the bytes preceding the Start-of-Scan marker; for PNG, the bytes preceding the
first `IDAT` chunk; for BMP, the header only (a version-3 BMP has no metadata, so
no editor can legitimately be detected in it). Editing-application and generator
names legitimately appear only in metadata (EXIF, XMP, ICC, text chunks), never
in pixel data, so this eliminates the collision class without weakening genuine
detection.

**Outcome.** The BMP is now correctly classified as *No Anomalies*. This defect
was significant because the same whole-file scan also set the AI-generation flag
for generator names, meaning a coincidental three-byte string in pixel data could
have falsely classified an image as AI-generated with the maximum score.

**Regression test.** `test_editor_signature_ignored_in_pixel_data` constructs a
BMP with the string "GIMP" placed in the pixel data and asserts no editor is
detected; `test_editor_signature_detected_in_metadata` confirms the same name in
a JPEG header is still detected.

## Refinement 2: editor coverage expansion (recall)

**Observation.** An image whose EXIF `Software` tag read *"Adobe Express Photos
6.7.1.0 (Windows)"*, which is unambiguous evidence of editing, was classified as
*No Anomalies*.

**Diagnosis.** The detector maintained two separate, hand-written lists of
editing applications, one for the EXIF `Software` check and one for the
metadata-byte scan. The two lists had diverged over time, and neither contained
Adobe Express, so the editor named directly in the metadata was missed by both
detection paths.

**Refinement.** The editor lists were expanded to a broad, current set covering
Adobe (including Express, Photoshop Express and Elements), desktop editors, and
common mobile and web editors.

**Outcome.** The image is now correctly classified as *Processing Detected*, and
the change also captures many mobile editors that the original lists omitted.

**Regression test.** `test_exif_software_editor_is_flagged` asserts that an
Adobe Express `Software` tag is flagged, and `test_exif_camera_software_not_flagged`
confirms that ordinary camera or phone firmware is not.

## Refinement 3: presence-based fallback (recall generalisation)

**Observation.** A name-list approach can only detect editors it already knows.
Any editing application absent from the list, however obvious, would still be
classified as *No Anomalies*.

**Diagnosis.** Detection depended entirely on matching a known editor name. This
is inherently incomplete: new and niche applications will never all be
enumerated.

**Refinement.** A presence-based fallback was added. If an image carries an EXIF
`Software` tag that is *not* recognisable as camera firmware, a device operating
system, or a known camera manufacturer, it is flagged as *"non-camera
application software"*, even when the specific application is unknown. Device
firmware is distinguished from applications using a version-string pattern, an
operating-system marker list, a camera-manufacturer list, and a check for whether
the `Software` value echoes the camera make or model. When a recognised camera
manufacturer is present, an unrecognised `Software` value is treated as firmware
rather than an editor, to avoid false positives on device firmware codes.

**Outcome.** Detection generalises beyond the known-editor list: an unknown
editor that leaves any application name in the metadata is now flagged, while
genuine camera and phone images remain unflagged. This shifts the detector from
"only editors we know by name" to "any application that is not a known camera",
which is a materially stronger recall position for rule-based detection.

**Regression tests.** `test_unknown_editor_flagged_by_presence_fallback` asserts
an editor absent from the known list is still flagged; and
`test_camera_firmware_code_not_flagged_by_fallback` confirms a device firmware
code with a recognised camera make is not.

## Refinement 4: signature consolidation (maintainability)

**Observation.** Refinement 2 traced the Adobe Express miss to two divergent
copies of the editor list. Divergence between duplicated lists was itself the
underlying fault.

**Refinement.** All editor signatures, together with the camera-manufacturer and
operating-system marker lists, were consolidated into a single shared module.
Both detection paths now derive their data from this one source: the EXIF check
takes lower-case substrings from it, and the metadata scan takes case-sensitive
byte signatures from it. Adding an application in one place now updates both
paths simultaneously.

**Outcome.** The two paths are provably identical to the shared source and can no
longer drift apart, removing the structural cause of Refinement 2's defect.

## Refinement 5: JPEG quality treated as informational (precision)

**Observation.** When analysing the JPEGs recovered from the DFTT
`8-jpeg-search.dd` image, all five valid JPEGs were classified as *Processing
Detected*. These are ordinary reference photographs with no manipulation.

**Diagnosis.** Every image had an estimated JPEG quality of 98.5, and a rule
flagged very high quality (and, symmetrically, very low quality) as a structural
"indicator" that added to the score. Quality alone is not discriminative:
professional exports, scans and camera maximum-quality settings all produce very
high quality, while web and messaging images produce very low quality, so the
rule fired on ordinary images. The defect was compounded by the scoring stage
matching the word "indicator" inside the hedge phrase "(indicator only)", which
was intended to signal weakness rather than to trigger a score.

**Refinement.** JPEG quality was reclassified as **informational only** and
excluded from the score, by the same base-rate reasoning already applied to JPEG
re-compression. The quality and quantization summary are still reported for the
examiner, but no longer raise the score or the classification band.

**Outcome.** The five reference JPEGs are now correctly classified as *No
Anomalies*, while the quality remains visible as context.

**Regression test.** `test_jpeg_quality_extreme_is_informational_not_scored`
asserts that a very-high-quality JPEG contributes zero to the score.

## Refinement 6: over-carve masking a valid file (recall)

**Observation.** On the same DFTT image, the carver recovered five of the six
genuine JPEGs. The missed file, at offset 0x4E9000, was the **deleted** JPEG that
the test is specifically designed to exercise recovery of.

**Diagnosis.** The missed file fell entirely within the byte span of a separate,
corrupt candidate: an over-carved 1.8 MB blob beginning at 0x344000 whose end
marker lay far past its true extent. To suppress overlapping duplicate
detections, the carver records how far the current file extends and skips any
later signature that begins within that span. Critically, this "covered" marker
was advanced for every extracted candidate, including ones that later failed
validation. The corrupt blob therefore masked the valid, deleted JPEG that lay
behind it, and that file was never emitted for recovery.

**Refinement.** The carver now advances the "covered" marker **only for
candidates that actually decode as an image**. A genuine file still masks its own
interior markers (for example an embedded thumbnail), but a corrupt or
over-carved blob no longer masks a valid file within its bogus span. The corrupt
candidate is still emitted and quarantined downstream; it simply no longer
suppresses its neighbours.

**Outcome.** All six JPEGs are now recovered, including the deleted file that the
test targets, and the existing overlapping-duplicate suppression for valid files
is preserved. This raised recall on this image from five of six to six of six.

**Regression tests.** `test_invalid_overcarve_does_not_mask_valid_file` places a
valid JPEG within the span of a corrupt candidate and asserts it is still
recovered; `test_decodes_as_image_helper` confirms the decode check accepts a
real image and rejects a corrupt blob.

## Refinement 7: evidence deduplication in score aggregation (calibration)

**Observation.** A photograph edited with Adobe Express, carrying that editor's
name in its EXIF `Software` tag, was scored 40 and classified as *Strong
Indicators*. Editing with a consumer application is a moderate signal and should
fall in the lower *Processing Detected* band, not the highest one.

**Diagnosis.** The single fact "edited with Adobe Express" was detected by two
independent code paths, each of which added the editing-software weight of 20:
the EXIF `Software` tag check, and the provenance metadata scan. Because both
paths read the same underlying bytes (the EXIF segment lies within the metadata
region the provenance scan examines), the same evidence was counted twice,
summing to 40 and crossing the *Strong Indicators* threshold. Genuine
corroboration requires independent evidence; here the two detections were not
independent, so the doubled score reflected confidence the evidence did not
support.

**Refinement.** Score aggregation now records whether the editing-software fact
has already contributed, and counts it **once** regardless of how many detectors
report it. The second detector still lists its finding for transparency, but with
a weight of zero, annotated as already counted.

**Outcome.** The image is now scored 20 and correctly classified as *Processing
Detected*. Independent, higher-weight signals such as an explicit C2PA
AI-generation declaration are unaffected and still reach *Strong Indicators*.

**Regression test.** `test_editing_software_not_double_counted` asserts that the
same editor detected by both the EXIF tag and the provenance scan contributes 20,
not 40, and yields *Processing Detected*.

## Refinement 8: offset-based allocation with deleted-metadata resolution (recovery attribution)

**Observation.** On the DFTT `8-jpeg-search.dd` NTFS image, ForenSight reported
**zero deleted files**, while Autopsy 4.22.1 correctly flagged two deleted files
(`file6.jpg`, 175630 bytes, and `file7.hmm`, 326859 bytes) with full size and
timestamps. Deleted-file classification is a headline capability, so parity with
Autopsy here is essential.

**Diagnosis.** Two faults compounded:

1. *Wrong matching technique.* Allocation was decided by a FAT-oriented heuristic
   - matching a carved file's *(size + first-512-byte hash)* against filesystem
   entries. On NTFS this is unreliable: carved sizes differ from recorded sizes,
   and many JPEGs from one source share identical first-512 bytes, so live files
   were mis-classified and matches collided.
2. *Discarded deleted metadata.* For a deleted NTFS entry, `entry.info.meta` is
   `None`, but the directory record still points to the (now unallocated) MFT
   record through `meta_addr`. ForenSight read only `entry.info.meta`, saw
   `None`, recorded size 0 / no inode, and skipped the file entirely - so its
   data runs were never read and it could never be classified Deleted. Autopsy
   resolves that pointer; ForenSight did not.

**Refinement.** Both faults were corrected:

1. Allocation was rewritten to be **offset-based**, the method Autopsy/TSK use:
   the on-disk cluster ranges (data runs) of every file are read as absolute byte
   offsets, and a carved file is classified by whether its offset falls in a live
   file's clusters (Allocated), a deleted file's clusters (Deleted), or neither
   (Unallocated). This is size-independent and immune to header collisions; on
   overlap, the live owner wins.
2. When a directory entry's metadata is absent, ForenSight now resolves it via
   `name.meta_addr` and `open_meta`, recovering a deleted file's size, inode,
   timestamps and data runs - exactly as Autopsy does.
3. Allocation is reported only for validated files; an invalid/over-carved
   candidate is labelled Unknown rather than being attributed to allocated space.

**Outcome.** On the same NTFS image, ForenSight now classifies the **same two
deleted files as Autopsy** (`file6.jpg` and `file7.hmm`) as *Deleted*, with the
remaining valid files correctly *Allocated* by cluster ownership. The result was
**cross-validated against Autopsy 4.22.1** on identical evidence.

**Honest limit.** A deleted file whose metadata is *fully* wiped (no resolvable
`meta_addr`) still cannot be attributed; its data is recovered but reported
Unallocated. No tool can do otherwise once the linking metadata is destroyed.

**Verification.** Offset-based classification is unit-tested
(`test_allocation_classify_logic`, `test_allocation_live_wins_on_overlap`); the
deleted-metadata resolution was verified end-to-end against Autopsy on the DFTT
reference image.

## Refinement 9: cryptographic C2PA verification (provenance integrity)

**Observation.** Earlier versions *detected* that a C2PA "Content Credentials"
manifest was present and inspected the signing certificate's text (issuer
strings, self-signed markers), but they never **cryptographically verified** the
credential. A manifest can be copied onto a different image, edited, or forged
wholesale; string inspection cannot tell a genuine, unbroken credential from a
tampered one. For a forensic tool this is the difference between reporting "the
file claims X" and proving "the claim is authentic and the pixels are unchanged."

**Diagnosis.** Full C2PA validation requires parsing the JUMBF manifest,
extracting the COSE_Sign1 claim signature and the signer's X.509 certificate
chain, and checking three cryptographic bindings that together form the C2PA
chain of trust: asset bytes -> `c2pa.hash.data` assertion -> claim -> signature
-> certificate. None of this was performed.

**Refinement.** A dedicated verifier (`forensight/c2pa_verifier.py`) was added
that performs real public-key verification:

1. **Signature validity** - the COSE_Sign1 structure over the claim is verified
   against the embedded leaf certificate's public key (ECDSA ES256/384/512,
   RSA PS/PKCS#1, or Ed25519; COSE raw `r||s` signatures are converted to DER).
2. **Signer identity** - the leaf certificate's subject and issuer are extracted,
   and whether it is self-signed (i.e. not attributable to an independent CA).
3. **Assertion binding** - each assertion the claim references is re-hashed and
   compared to the value the claim committed to, so an assertion cannot be swapped
   after signing.
4. **Asset integrity (tamper check)** - the `c2pa.hash.data` assertion's hash is
   recomputed over the actual asset bytes (minus the manifest's own byte range)
   and compared to the signed value, proving whether the *image was edited after
   the credential was created*.

The verdict feeds the forensic score as a FACT (proven by cryptography, not a
heuristic): a valid signature over bytes that no longer match is scored as
**post-signing tampering** (weight 60, Strong Indicators), and a signature that
fails outright is scored as a **forged/corrupted manifest** (weight 40). Both are
written to the chain-of-custody audit log. The dependencies (`cryptography`,
`cbor2`) are optional: if they are absent the tool degrades gracefully to the
previous string-based certificate inspection.

**Outcome.** ForenSight can now make a decisive, cryptographically-backed
statement about a C2PA image: *valid and intact*, *validly signed but edited
after signing*, or *forged*. This turns provenance from a self-declaration the
tool merely reads into a claim the tool independently verifies.

**Verification.** A test harness (`tests/test_c2pa_verifier.py`) builds genuine
signed manifests (self-signed EC certificate, COSE_Sign1 over the claim, a
`c2pa.hash.data` assertion over the asset) embedded in a JPEG via APP11, and
confirms the verifier validates a correct signature, detects a pixel edited after
signing (hash mismatch), detects a forged signature, and detects a swapped
assertion - end-to-end, with no external fixtures.

**Cross-validation against real, production credentials (two vendors).** The
verifier was validated against genuine C2PA files from two independent issuers,
which between them exercise different signature algorithms, certificate-chain
depths, header encodings and container formats:

* *OpenAI GPT Image* (PNG, C2PA specification version 2.2). Correctly reported a
  cryptographically valid **ES256** signature, the real signer *"OpenAI Media
  Service, OpenAI OpCo, LLC"*, a **CA-issued** two-certificate chain through
  *"Trufo C2PA Claim Signing CA (2025)"*, verified assertion binding and an intact
  asset. A single flipped byte was then correctly reported as **post-signing
  tampering**, naming the original signer.
* *Adobe / C2PA reference test files* (JPEG, C2PA 1.x). Run against the C2PA
  project's own published, known-answer files, ForenSight matched the expected
  result on all three: the valid file (`...-CA`) verified with a **PS256 (RSA-PSS)**
  signature over a **three-certificate chain**; the bad-signature file
  (`...-E-sig-CA`) was correctly reported **signature INVALID**; and the
  altered-data file (`...-E-dat-CA`) was correctly reported as **valid signature
  but asset edited after signing**. This is a signer-agnostic, known-answer
  cross-validation against the specification authors' own conformance suite.

Testing against the real credentials also surfaced four conformance defects the
self-consistent synthetic harness had not exposed - a direct illustration of the
value of real-data validation:

1. *C2PA v2 claim schema.* Version 2.x renames the claim's assertion list from
   `assertions` to `created_assertions` / `gathered_assertions`. The verifier
   originally read only the v1 field, so assertion binding was silently skipped on
   v2 manifests. It now reads all three, restoring the binding check.
2. *Assertion hashing scope.* The C2PA hashed-URI digest is computed over the
   assertion's JUMBF box **payload** (its description and content boxes), not the
   whole box including its outer length/type header. The synthetic harness hashed
   the full box on both sides and so passed regardless; the real credentials, which
   follow the specification, exposed the discrepancy.
3. *Multi-segment APP11 reassembly.* A manifest larger than one JPEG APP11 marker
   (~64 KB) is fragmented across several segments, each of which **repeats the
   8-byte JUMBF box header**. The verifier originally concatenated every segment
   verbatim, so the duplicated headers shifted all subsequent box boundaries and
   parsing derailed before reaching the claim. Reassembly now drops the repeated
   header on continuation packets.
4. *Legacy certificate header label.* C2PA 1.x stores the signer chain under the
   text COSE header `"x5chain"`, whereas 2.x uses the registered integer label
   33. The verifier now accepts both, so it validates old and new credentials
   alike.

**Honest limit.** Verification proves *internal consistency and authorship by the
embedded certificate*; it does not by itself establish that the signer is
trustworthy. A self-signed manifest can be perfectly valid yet produced by
anyone, which is why self-signed credentials are reported as "not independently
verifiable." Full trust would additionally require checking the certificate
against the C2PA trust list, which is documented as future work.

## Summary of results

On the NIST `L0_Graphic.dd` reference image, the carving stage achieved **100%
precision** (four of four recovered files were valid, byte-complete images at
their correct dimensions, with no false positives) and **80% recall** (four of
five files; the single miss was a TIFF, a format outside the supported carving
signatures, and is documented as scoped future work). On the DFTT
`8-jpeg-search.dd` image, the over-carve fix (Refinement 6) raised carving recall
from five of six to **six of six**, restoring recovery of the deleted JPEG the
test targets.

For the analysis stage, the refinements corrected two false positives
(Refinements 1 and 5), one false negative (Refinement 2), generalised detection
to unknown editors (Refinement 3), removed the maintainability fault that had
caused the false negative (Refinement 4), recovered a masked valid file
(Refinement 6), and corrected a score-calibration fault that over-escalated a
single finding (Refinement 7). For the recovery stage, Refinement 8 rebuilt
deleted-file attribution to an offset-based method and achieved parity with
Autopsy on a real NTFS image. For the provenance stage, Refinement 9 added
cryptographic C2PA verification, cross-validated against genuine credentials from
two independent issuers - an OpenAI image (ES256, C2PA 2.2) and the C2PA
project's own Adobe reference files (PS256, C2PA 1.x, known-answer valid /
bad-signature / altered-data cases) - matching the expected result on every one,
and in the process exposing and fixing four conformance defects invisible to the
synthetic tests.

| Refinement | Dataset | Defect class | Metric improved |
|---|---|---|---|
| 1. Metadata-region confinement | NIST L0_Graphic | False positive | Precision |
| 2. Editor coverage expansion | Edited photograph | False negative | Recall |
| 3. Presence-based fallback | Edited photograph | Missed unknown editors | Recall (generalisation) |
| 4. Signature consolidation | Edited photograph | Maintainability / list drift | Robustness |
| 5. JPEG quality informational | DFTT 8-jpeg-search | False positive | Precision |
| 6. Over-carve masking fix | DFTT 8-jpeg-search | Missed valid (deleted) file | Recall |
| 7. Evidence deduplication | Edited photograph | Double-counted evidence | Calibration |
| 8. Offset-based allocation + deleted-metadata resolution | DFTT 8-jpeg-search (vs Autopsy) | Missed deleted files | Recovery attribution |
| 9. Cryptographic C2PA verification | Synthetic manifests + real OpenAI (C2PA 2.x) and Adobe (C2PA 1.x) credentials | Unverified provenance claims; C2PA v1/v2 conformance | New capability (tamper/forgery proof) |

## Honest limitation

The metadata-based refinements (1 to 5) operate on **metadata**. They detect
editing when the
editor leaves an identifying trace in the file. They cannot detect editing when
the metadata is absent, either because the editor stripped it or because a
downstream re-encoder, such as a messaging platform, removed it and re-compressed
the image. This is an inherent property of metadata-based analysis and is not
specific to this tool; recovering evidence that a later processing step has
erased requires the original artefact or pixel-level machine-learning forensics,
neither of which is reliable after aggressive re-compression and both of which
are outside the scope of this rule-based detector. Documenting this boundary is
itself a contribution, since it defines precisely where metadata-based detection
ends and other techniques must begin.
