# ForenSight: A Digital Forensic Tool for Image Recovery and Content-Provenance Verification

**Final Year Project Report**

Author: Muhammad Zakhwan Bin Shamsul Anuar
Student ID: CS01085237
Institution: Universiti Tenaga Nasional (UNITEN)

---

## Abstract

Digital images are central to modern criminal, civil and corporate investigations, yet they are also increasingly easy to delete, alter, or generate synthetically. Investigators therefore need tools that can (a) recover images from seized storage, including deleted ones, (b) assess whether an image is authentic, edited, or AI-generated, and (c) preserve the evidential integrity of every step so the findings are admissible.

This project presents **ForenSight**, a desktop digital-forensic application that unifies three capabilities that are usually spread across separate tools: signature-based image carving with live-versus-deleted attribution, rule-based image-provenance analysis with **cryptographic C2PA (Content Credentials) verification**, and a hash-linked chain-of-custody audit trail. ForenSight is deliberately transparent and explainable: its manipulation assessment is rule-based rather than a black-box classifier, and every finding is tagged as a verifiable *fact* or an interpretive *indicator*.

The tool was validated against independent third-party reference data. Carving achieved 100% precision and 80% recall on a NIST reference disk image; deleted-file attribution was cross-validated against Autopsy on Digital Forensics Tool Testing (DFTT) NTFS images; and the C2PA verifier was confirmed against genuine production credentials from two independent issuers (OpenAI and the C2PA project's Adobe reference suite), correctly reporting valid signatures, self-signed versus CA-issued signers, and post-signing tampering. The system is covered by 183 automated tests, including 103 malformed-input robustness tests. The report also states honestly where the approach ends: metadata-based provenance detection cannot recover evidence that a later re-compression step (for example a messaging platform) has erased.

---

## Table of Contents

1. Introduction
2. Background and Literature Review
3. Methodology
4. System Design and Implementation
5. Results and Evaluation
6. Limitations and Future Work
7. Conclusion
8. References

---

## Chapter 1: Introduction

### 1.1 Background

Photographs and other digital images are among the most common and most persuasive forms of digital evidence. They appear in cases ranging from fraud and harassment to the most serious crimes, and their evidential value depends on two questions: *can the image be recovered*, and *can it be trusted*.

Both questions have become harder. Storage devices routinely delete, overwrite and fragment files, so recovering an image often means reconstructing it from raw disk space rather than reading it from an intact file system. At the same time, consumer editing applications and, more recently, generative artificial-intelligence (AI) systems have made it trivial to alter an image or to synthesise one from nothing. An investigator confronted with an image can no longer assume it is a faithful record of a real scene.

In response, an industry coalition (Adobe, Microsoft, Google, the BBC, camera manufacturers and others) has produced the **C2PA (Coalition for Content Provenance and Authenticity)** standard, also marketed as *Content Credentials*. C2PA embeds a cryptographically signed record of how an image was created and edited directly into the file. Generative services such as OpenAI's image models and Adobe Firefly now attach C2PA credentials to their output, and the European Union's AI Act (Article 50) moves in the same direction by requiring that AI-generated content be marked. Provenance metadata is therefore becoming a realistic foundation for image-authenticity assessment.

### 1.2 Problem Statement

Consider a routine but realistic scenario. An investigator recovers a JPEG from the unallocated space of a suspect's drive and must answer three questions before it can stand as evidence: *Where did these bytes physically come from, and can that be reproduced? Is the image an authentic capture, an edit, or an AI-generated fabrication, and on what defensible basis? And can every step of its handling be shown, in court, to be untampered?* Today, answering these three questions requires three different tools, two of which give answers an examiner cannot fully defend under cross-examination. That is the problem this project addresses.

More precisely, existing practice leaves three gaps that must be closed *together*, because closing any one without the others still leaves the evidence contestable:

1. **Fragmented tooling.** Image recovery, image-authenticity analysis and chain-of-custody management are typically handled by separate tools. Investigators must move evidence between them, which is slow and, more importantly, breaks the continuity of custody at exactly the moments an opposing counsel will probe.
2. **Opaque manipulation detection.** Many manipulation-detection tools rely on machine-learning classifiers that output a probability with no explanation. Such outputs are difficult to defend in court, where an examiner must be able to explain *why* an image was flagged; "the model was 87% confident" is not a defensible basis for a legal finding.
3. **Detection without verification.** Tools that read provenance metadata usually only *detect its presence*. They do not *cryptographically verify* the signature, so they cannot distinguish a genuine, unbroken credential from one that has been copied onto another image, altered, or forged — the precise cases in which the metadata matters most.

The consequence of these gaps is concrete and serious: image evidence that could have been recovered, authenticated and defended is instead weakened or excluded, not because the underlying technology does not exist, but because it has never been integrated into a single workflow in which every verdict is explainable and every action is tamper-evident. The problem, then, is not the invention of new detection algorithms; it is the integration of proven, standards-based techniques into one transparent, evidentially sound pipeline. This is a software-engineering and forensic-soundness problem, and it is the one ForenSight sets out to solve.

### 1.3 Aim

To design and implement an integrated, transparent digital-forensic desktop tool that recovers images (including deleted ones) from storage media, assesses their authenticity and provenance in an explainable manner, cryptographically verifies C2PA credentials, and preserves a tamper-evident chain of custody throughout.

### 1.4 Objectives

1. To implement signature-based image carving that recovers JPEG, PNG, BMP and GIF images from raw disk images and classifies each recovered image as allocated (live), deleted or unallocated, validated against third-party reference data.
2. To implement a transparent, rule-based image-provenance and integrity assessment that detects AI-generation and editing markers and **cryptographically verifies** C2PA Content Credentials, including detection of post-signing tampering.
3. To implement a hash-linked chain-of-custody audit trail and automated forensic reporting that make every recovery and analysis step traceable and tamper-evident.

### 1.5 Scope

ForenSight is a single-user desktop application for Windows. It processes raw disk images (`.dd`/`.raw`) and loose image files. Image carving supports JPEG, PNG, BMP and GIF. Provenance analysis operates on metadata standards (C2PA, EXIF, XMP, generator signatures). The tool deliberately uses **no machine learning of any kind**: black-box classifiers cannot be explained to a court and do not generalise reliably across new generative models, so every decision in ForenSight is rule-based and fully explainable by design. Error Level Analysis is offered as an optional visual aid for manual inspection and is deliberately excluded from the score. Full certificate-trust-list validation of C2PA signers is out of scope and identified as future work.

### 1.6 Significance

ForenSight targets a genuinely critical problem — the recovery and authentication of image evidence — rather than a cosmetic one. Its two distinguishing contributions at implementation level are (i) the integration of cryptographic C2PA verification into a recovery-and-custody workflow, allowing an examiner to *prove* whether an image was edited after it was signed, and (ii) a fully explainable, fact-versus-indicator scoring model suited to evidential contexts.

### 1.7 Report Structure

Chapter 2 reviews the relevant background and related tools. Chapter 3 describes the methodology and system requirements. Chapter 4 presents the design and implementation. Chapter 5 reports results and evaluation against third-party data. Chapter 6 states limitations and future work, and Chapter 7 concludes.

---

## Chapter 2: Background and Literature Review

### 2.1 Digital Forensics and the Chain of Custody

Digital forensics is the identification, preservation, analysis and presentation of digital evidence in a manner that is admissible in legal proceedings. A foundational requirement is the **chain of custody**: a documented, tamper-evident record of everyone who handled the evidence and every action performed on it. Any break in that chain can render evidence inadmissible. A forensic tool must therefore not only produce results but also record *how* those results were obtained, in a form that cannot be silently altered.

### 2.2 File Carving and Deleted-File Recovery

When a file system record is intact, recovering a file is straightforward. When it is deleted or damaged, investigators fall back on **file carving**: scanning raw storage for file signatures (magic numbers) and reconstructing files directly from their bytes, independent of the file system. Signature-based carving is well established (as in tools such as PhotoRec and Scalpel) but has known weaknesses, notably with fragmented files.

Recovering *deleted* files with correct attribution is harder still. It requires parsing the file system to determine which byte ranges belong to live files and which to deleted ones. **The Sleuth Kit (TSK)** is the de-facto open-source library for this, and **Autopsy** is the widely used graphical front-end built on it. A rigorous forensic tool should agree with these reference implementations on the same evidence.

### 2.3 Image-Manipulation Detection

A long-standing pixel-level technique is **Error Level Analysis (ELA)**, which re-saves an image at a known quality and looks for regions whose compression error differs from their surroundings, on the assumption that edited regions have a different compression history. ELA is attractive because it needs no metadata, but it has a decisive weakness: it depends on *regional differences* in compression history. When an image is re-compressed *uniformly and globally* — as every modern editor does on export, and as every messaging platform (WhatsApp, Telegram) does on transfer — those regional differences are flattened, and ELA loses its discriminative power. This limitation is not specific to ELA; it applies to compression-history forensics in general, and it motivates a shift toward metadata- and provenance-based methods.

### 2.4 Content Provenance and C2PA

The **C2PA** standard embeds a signed *manifest* inside the image file. The manifest records assertions about the image's creation and editing history and is bound to the image by a chain of cryptographic hashes: the asset bytes are hashed into a `c2pa.hash.data` assertion; the assertions are hashed into a *claim*; and the claim is signed using **COSE (CBOR Object Signing and Encryption)** with an X.509 certificate. Verifying this chain proves three things: that the claim was signed by the holder of the certificate, that the assertions have not been swapped, and that the image bytes have not changed since signing.

Crucially, most tools that "support" C2PA only detect that a manifest is *present*. They do not perform the cryptographic verification, so they cannot detect a forged manifest or an image that was edited after signing. This gap is the opportunity that ForenSight's C2PA verifier addresses.

### 2.5 Related Tools and Gap Analysis

Autopsy/TSK excel at recovery and file-system analysis but do not perform C2PA verification or provenance-based AI detection. Adobe's Content Credentials verifier validates C2PA but performs no disk recovery or chain-of-custody management. General manipulation detectors are often ML-based and opaque. No widely available single tool combines **recovery + cryptographic provenance verification + explainable assessment + chain of custody**. ForenSight occupies precisely this gap, not by inventing new algorithms, but by integrating current, standards-based technology into one transparent, evidentially sound workflow.

---

## Chapter 3: Methodology

### 3.1 Development Approach

The project followed an iterative, test-driven approach. Each capability was implemented as an independent module with automated tests, then integrated. A distinctive part of the methodology was **validation-driven refinement**: the tool was repeatedly run against independent third-party reference data, and every discrepancy with a reference tool (Autopsy) or a known-answer file (NIST, C2PA test files) was treated as a defect, diagnosed, fixed, and locked in with a regression test. Nine such refinements are documented.

### 3.2 Requirements

**Functional requirements:** carve JPEG/PNG/BMP/GIF from disk images; classify recovered images as live/deleted/unallocated; extract EXIF and detect editing/generator signatures; detect and cryptographically verify C2PA credentials; compute an explainable integrity-and-provenance score; maintain a hash-linked audit log; generate a PDF forensic report; verify source integrity by hash re-computation.

**Non-functional requirements:** transparency (no unexplained results), robustness (must never crash on malformed input or corrupt the audit chain), evidential soundness (UTC timestamps, complete hashes), and graceful degradation (optional dependencies such as TSK must not be mandatory).

### 3.3 Technology Stack

Python 3.12; PyQt6 (desktop GUI); SQLite (case database); pytsk3 / The Sleuth Kit (file-system parsing, optional); Pillow (image decoding); ReportLab (PDF reporting); the `cryptography` and `cbor2` libraries (C2PA signature verification, optional). Optional dependencies degrade gracefully when absent.

### 3.4 Validation Data

Independent, third-party datasets were used so that results are not self-confirming:
- **NIST** `L0_Graphic.dd` — reference disk image with known image content (carving accuracy).
- **DFTT** `8-jpeg-search.dd` and related NTFS/FAT images — deleted-file recovery (cross-checked against Autopsy 4.22.1).
- **C2PA public test files** (Adobe reference suite) and a genuine **OpenAI** Content-Credentials image — C2PA verification.

---

## Chapter 4: System Design and Implementation

### 4.1 Architecture Overview

ForenSight is organised into a graphical layer (PyQt6), a service layer that orchestrates forensic operations, an engine layer of independent analysers, and a persistence layer (SQLite plus an append-only audit log). Database writes are single-threaded to keep the case store consistent, while long operations (carving, hashing) run on worker threads.

[[CHART:architecture]]
*Figure 1: ForenSight layered system architecture.*

The operational workflow, from evidence import through to report generation, is shown in Figure 2. Every stage writes to the hash-linked chain-of-custody audit log, so the custody record is produced automatically as a by-product of the analysis rather than maintained separately.

[[CHART:flowchart]]
*Figure 2: ForenSight operational workflow, with every stage recorded in the chain-of-custody audit log.*

### 4.2 Image Carving

The carver scans a source in two passes. The first pass locates validated file-signature headers; the second reconstructs each candidate and, critically, only advances its "already covered" marker when the candidate **actually decodes as an image**. This prevents a large invalid blob from masking a valid file that begins inside it — a defect discovered on DFTT data and corrected (Refinement 6). Each recovered file is validated (signature, minimum size, structural decode) and quarantined if invalid rather than discarded.

### 4.3 Deleted-File Attribution

Allocation is determined by an **offset-based** method equivalent to that used by Autopsy/TSK. The file system's data runs are read as absolute byte ranges; a carved file is then classified by whether the byte offset it was carved from falls within a live file's clusters (allocated), a deleted file's clusters (deleted), or neither (unallocated), with live ownership winning on overlap. A key fix (Refinement 8) resolves deleted NTFS entries whose metadata pointer (`meta_addr`) is still present even though the primary metadata object is gone — the same resolution Autopsy performs — so that deleted files are attributed rather than skipped.

### 4.4 Provenance and Integrity Analysis

Provenance analysis is rule-based and transparent. It scans a bounded metadata region (never pixel data, to avoid coincidental byte collisions) for C2PA container markers, the C2PA `digitalSourceType` AI declaration, known generator signatures (OpenAI, Google, Adobe Firefly, Midjourney, Stable Diffusion and others), and editing-application signatures drawn from a single shared signature module. Because a name-list can never be complete, a **presence-based fallback** flags non-camera application software even when the specific editor is unknown (Refinement 3).

Findings feed an **Integrity and Provenance Score** (0–100) in which each triggered signal contributes a documented weight and is tagged as a *fact* (declared by metadata or proven cryptographically) or an *indicator* (suggestive only). Signals with near-universal base rates, such as generic JPEG re-compression, are reported for context but scored zero, so the triage bands remain meaningful (Refinements 5 and 7).

### 4.5 Cryptographic C2PA Verification

The C2PA verifier is the project's headline technical contribution at implementation level. It parses the JUMBF manifest (reassembling manifests split across multiple JPEG APP11 segments), extracts the COSE_Sign1 claim signature and the signer's X.509 certificate chain, and performs four checks:

1. **Signature validity** — the claim signature is verified against the leaf certificate's public key, supporting ECDSA (ES256/384/512), RSA (PSS and PKCS#1) and Ed25519, converting COSE raw signatures to DER as required.
2. **Signer identity** — the certificate subject and issuer are extracted, and whether the certificate is self-signed (not independently attributable).
3. **Assertion binding** — each assertion referenced by the claim is re-hashed and compared to the value the claim committed to, so assertions cannot be swapped.
4. **Asset integrity** — the `c2pa.hash.data` assertion is recomputed over the actual asset bytes (excluding the manifest's own region), proving whether the image was edited after the credential was created.

A valid signature over bytes that no longer match is scored as post-signing tampering (a strong indicator); a signature that fails outright is scored as a forged or corrupted manifest. Both are recorded in the audit log. The dependencies are optional; without them the tool falls back to certificate string inspection.

### 4.6 Chain of Custody and Reporting

Every action is recorded as an audit event whose hash incorporates the previous event's hash, forming a chain in which any alteration to a past event is detectable. Timestamps are recorded in UTC to avoid timezone ambiguity. Examiner identity (name and ID) is attributed to actions. A PDF report presents the case metadata, each recovered image with its full SHA-256 hash and allocation status, the integrity assessment, and the verifiable audit chain, concluding with an examiner declaration.

---

## Chapter 5: Results and Evaluation

### 5.1 Carving Accuracy (NIST reference image)

On the NIST `L0_Graphic.dd` reference image, carving achieved **100% precision** (every recovered file was a valid, byte-complete image at its correct dimensions, with no false positives) and **80% recall** (four of five files). The single miss was a TIFF image, a format outside the supported carving signatures and documented as scoped future work. On the DFTT `8-jpeg-search.dd` image, the over-carve fix raised recall from five of six to **six of six**.

[[CHART:results]]
*Figure 3: Carving accuracy on third-party reference images. Aggregate detector precision and recall (Section 5.5) are pending completion of the labelled corpus.*

### 5.2 Deleted-File Attribution (cross-validated against Autopsy)

On the DFTT `8-jpeg-search.dd` NTFS image, ForenSight initially reported zero deleted files while Autopsy 4.22.1 correctly identified two. After the offset-based allocation and deleted-metadata resolution refinements, ForenSight classified the **same two deleted files as Autopsy** (`file6.jpg` and `file7.hmm`), with the remaining files correctly attributed as allocated. This constitutes cross-validation against the de-facto reference implementation on identical evidence.

### 5.3 C2PA Verification (validated against two independent issuers)

The verifier was validated against genuine production credentials from two independent issuers, exercising different algorithms, chain depths, header encodings and container formats:

- **OpenAI GPT Image** (PNG, C2PA 2.2): correctly reported a valid ES256 signature; signer *OpenAI Media Service, OpenAI OpCo, LLC*; a CA-issued two-certificate chain via *Trufo C2PA Claim Signing CA*; verified assertion binding; and an intact asset. A single flipped pixel byte was then correctly reported as post-signing tampering.
- **Adobe / C2PA reference suite** (JPEG, C2PA 1.x, known-answer files): the valid file verified with a PS256 (RSA-PSS) signature over a three-certificate chain; the bad-signature file was correctly reported *signature invalid*; and the altered-data file was correctly reported as *valid signature but asset edited after signing*.

Because these are the specification authors' own known-answer conformance files, matching every expected result is strong, signer-agnostic evidence of correctness. Real-data testing additionally exposed and corrected four specification-conformance defects (C2PA v2 assertion field names, assertion-hash scope, multi-segment manifest reassembly, and the legacy `x5chain` header label) that the synthetic tests could not reveal.

### 5.4 Robustness and Testing

The system is covered by **183 automated tests**, including **103 malformed-input robustness tests** that feed zero-byte files, truncated images, garbage, mislabelled files and large blobs through every analyser, the carver, and the full analysis pipeline. In every case the tool degrades gracefully — returning a result or recording *insufficient data* — and, importantly, the chain-of-custody audit chain remains valid after processing hostile input.

### 5.5 Aggregate Detector Evaluation (in progress)

An evaluation harness has been implemented to measure the rule-based detector's aggregate precision, recall and F1 across a labelled corpus of real, AI-generated, edited and messaging-transferred images, together with a per-signal ablation and a transferred-image false-positive rate. Running this harness on a fully populated corpus is the final planned evaluation step; the framework and its outputs (confusion matrix, per-task metrics, CSV export) are complete and smoke-tested.

*[Table placeholder — to be completed once the labelled corpus is populated:]*

| Task | Precision | Recall | F1 |
|---|---|---|---|
| AI detection (provenance) | — | — | — |
| Manipulation detection | — | — | — |
| Transferred-image false-positive rate | — | — | — |

---

## Chapter 6: Limitations and Future Work

**Metadata dependence.** Provenance-based detection works only where provenance is present. An adversary who strips metadata, or a messaging platform that re-compresses and discards it, leaves nothing to analyse. This is an inherent property of metadata-based methods, not a defect specific to this tool, and it is stated openly.

**Transfer versus editing.** Because messaging platforms re-compress images uniformly, ForenSight cannot reliably distinguish a benignly forwarded image from a maliciously edited one once metadata is gone. A promising direction is encoder-fingerprinting (quantisation-table and sub-sampling signatures characteristic of specific platforms), which is proposed as future work.

**Fragmented files.** Signature carving reconstructs contiguous files; heavily fragmented files are not fully recovered, consistent with the known limits of signature carving.

**C2PA trust.** The verifier proves internal consistency and authorship by the embedded certificate, but does not yet check that certificate against the official C2PA trust list, so it cannot by itself establish that the signer is a trusted authority. Trust-list validation is identified as the natural next enhancement.

**Pixel-level AI detection.** A generalisable, court-defensible pixel-level classifier for metadata-stripped AI images remains an open research problem and is outside the scope of this rule-based tool.

---

## Chapter 7: Conclusion

ForenSight demonstrates that current, standards-based technologies — file carving, The Sleuth Kit, C2PA, COSE/X.509 cryptography and hash-linked auditing — can be integrated into a single, transparent, evidentially sound tool that addresses a genuinely critical problem: the recovery and authentication of image evidence. The three objectives were met: images (including deleted ones) are recovered and correctly attributed, validated against NIST data and cross-validated against Autopsy; provenance is assessed transparently and C2PA credentials are cryptographically verified, validated against real credentials from two independent issuers; and a tamper-evident chain of custody underpins the whole workflow, which is protected by 183 automated tests. The project's honest treatment of its own boundaries — where metadata-based detection ends — is itself a contribution, defining clearly where this approach stops and where complementary techniques must begin. The remaining work is measurement (the aggregate detector evaluation) and dissemination, not further core engineering.

---

## Chapter 8: References

*(To be formatted to your department's required citation style, e.g. IEEE.)*

1. Coalition for Content Provenance and Authenticity (C2PA), *C2PA Technical Specification*.
2. B. Carrier, *File System Forensic Analysis*, Addison-Wesley.
3. The Sleuth Kit and Autopsy — B. Carrier, https://www.sleuthkit.org.
4. National Institute of Standards and Technology (NIST), *Computer Forensic Reference Data Sets (CFReDS)*.
5. Digital Forensics Tool Testing (DFTT) reference images.
6. IETF RFC 8152, *CBOR Object Signing and Encryption (COSE)*.
7. IETF RFC 5280, *Internet X.509 Public Key Infrastructure Certificate and CRL Profile*.
8. ISO/IEC 19566-5, *JPEG Universal Metadata Box Format (JUMBF)*.
9. European Union, *Artificial Intelligence Act*, Article 50 (transparency obligations).
10. N. Krawetz, "A Picture's Worth: Digital Image Analysis and Forensics" (Error Level Analysis).
