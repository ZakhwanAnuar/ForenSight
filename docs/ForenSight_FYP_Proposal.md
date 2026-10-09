# ForenSight: A Digital Forensic Tool for Image Recovery, Content-Provenance Verification, and Chain-of-Custody Preservation

**Final Year Project Proposal**

Author: Muhammad Zakhwan Bin Shamsul Anuar
Student ID: CS01085237
Institution: Universiti Tenaga Nasional (UNITEN)

---

## 1. Introduction and Project Overview

Digital images are among the most common and most persuasive forms of evidence in modern investigations. They appear in cases that range from fraud, harassment and workplace misconduct to the most serious criminal matters. The evidential value of an image, however, rests on two separate questions. The first is whether the image can be recovered at all, because storage devices frequently delete, overwrite and fragment files. The second is whether the recovered image can be trusted, because consumer editing applications and, more recently, generative artificial intelligence have made it very easy to alter an image or to create a convincing one from nothing.

A third requirement sits above both of these and is the theme that unifies this project: the preservation of the chain of custody. In any forensic process, every action taken on a piece of evidence must be recorded in a documented, tamper-evident manner, so that the origin and handling of the evidence can be demonstrated and defended. If that record can be silently altered, or if it is incomplete, the evidence may be ruled inadmissible regardless of how sound the underlying analysis was. The chain of custody is therefore not an optional feature but the foundation that makes the rest of the work meaningful.

This proposal describes ForenSight, a desktop digital-forensic application that brings these three concerns into a single, transparent workflow. ForenSight recovers images (including deleted ones) from storage media, assesses whether each image is authentic, edited, or AI-generated, cryptographically verifies embedded content-provenance credentials, and records every operation in a hash-linked chain-of-custody audit trail that underpins an automatically generated forensic report. The project does not seek to invent new forensic algorithms. Its contribution, appropriate to the degree level, is the careful integration of current, standards-based technologies into one coherent, explainable, and evidentially sound tool.

## 2. Problem Statement and Motivation

The motivation for this project comes from three specific weaknesses in current practice.

**2.1 Fragmented tooling breaks the chain of custody.** Image recovery, image-authenticity analysis, and chain-of-custody management are usually performed by separate tools. An investigator may carve images with one utility, examine metadata with another, and keep custody records in a spreadsheet or a written log. Every transfer of evidence between tools is a point at which the chain of custody can be weakened, because the handling record is no longer produced automatically and consistently by the system that performs the work. Consolidating these steps into one tool that logs every action reduces that risk directly.

**2.2 Manipulation detection is often opaque.** Many manipulation-detection tools rely on machine-learning classifiers that return a probability with no explanation of how it was reached. In an evidential context this is a serious limitation, because an examiner must be able to explain to a court precisely why an image was flagged. A result that cannot be explained is difficult to defend and easy to challenge. There is a clear need for detection logic that is transparent and that separates verifiable facts from interpretive indicators.

**2.3 Provenance is detected but not verified.** The industry has responded to the rise of synthetic media with the C2PA standard, also known as Content Credentials, which embeds a cryptographically signed record of an image's origin and editing history inside the file itself. Generative services such as OpenAI's image models and Adobe Firefly now attach these credentials, and regulation such as Article 50 of the European Union Artificial Intelligence Act points in the same direction. However, most tools that claim to support C2PA only detect that a credential is present. They do not cryptographically verify the signature, the certificate, or the binding between the credential and the image. As a result they cannot tell a genuine, unbroken credential apart from one that has been copied onto a different image, altered, or forged, and they cannot prove whether an image was edited after it was signed. This gap between detecting provenance and verifying it is the central technical opportunity that ForenSight addresses.

**2.4 An honest boundary.** It is important to state at the outset that provenance-based and metadata-based detection can only work where such data is present. An adversary who deliberately strips metadata, or a messaging platform that re-compresses an image and discards its metadata during transfer, leaves nothing for these techniques to analyse. This is an inherent property of metadata-based methods rather than a defect of any particular tool. Recognising and clearly documenting this boundary is part of the motivation, because it defines exactly where this approach is effective and where complementary techniques would be required.

## 3. Aim

The aim of this project is to design and implement an integrated, transparent, and evidentially sound digital-forensic desktop tool that recovers images (including deleted ones) from storage media, assesses their authenticity and provenance in an explainable manner, cryptographically verifies C2PA content-provenance credentials, and preserves a tamper-evident chain of custody across the entire workflow.

## 4. Objectives

The project is organised around three measurable objectives.

**Objective 1: Image recovery with allocation attribution.**
To develop signature-based image carving that recovers JPEG, PNG, BMP, and GIF images from raw disk images, and to classify each recovered image as allocated (live), deleted, or unallocated by parsing the source file system. Success is measured by carving precision and recall against a recognised reference disk image, and by agreement with an established reference tool on the classification of deleted files.

**Objective 2: Explainable provenance and integrity assessment with cryptographic C2PA verification.**
To design a transparent, rule-based assessment that detects AI-generation and editing markers in image metadata, and that cryptographically verifies C2PA Content Credentials, including verification of the signature, the signer certificate, the assertion binding, and the asset hash, so that post-signing tampering can be proven. Success is measured by correct classification against known-answer C2PA reference files and genuine production credentials, and by the assessment tagging every finding as a verifiable fact or an interpretive indicator.

**Objective 3: Chain-of-custody preservation and forensic reporting.**
To develop a hash-linked chain-of-custody audit trail in which each recorded action incorporates the hash of the previous action, so that any later alteration of the record is detectable, and to generate an automated forensic report that presents recovered evidence, hashes, assessments, and the verifiable audit chain. Success is measured by the ability to detect any tampering with the audit record and by the completeness and traceability of the generated report.

## 5. Scope

**In scope.** ForenSight is a single-user desktop application for the Windows platform. It processes raw disk images in the common `.dd` and `.raw` formats, and also accepts loose image files supplied directly by the examiner. Image carving supports the JPEG, PNG, BMP, and GIF formats. Provenance and integrity analysis operate on established metadata standards, including C2PA Content Credentials, EXIF, XMP, and recognised generator and editor signatures. Error Level Analysis is provided as an optional visual aid to support manual inspection of a selected image, and is deliberately excluded from the automated score. The chain-of-custody and reporting functions cover the full workflow from evidence import to report generation.

**Out of scope.** The project deliberately uses no machine learning and no pixel-level statistical classifier of any kind. This is a design decision rather than an omission: black-box classifiers return a probability that cannot be explained to a court and do not generalise reliably across the constantly changing landscape of generative models, whereas an evidential tool must be able to justify every decision it makes. All detection in ForenSight is therefore rule-based and fully explainable. Validation of C2PA signer certificates against the official C2PA trust list, which would establish not only that a signature is internally valid but also that the signer is an independently trusted authority, is identified as future work rather than a deliverable of this project. Recovery of heavily fragmented files beyond the limits of signature carving is likewise out of scope.

## 6. Proposed Solution and System Overview

ForenSight is structured as four layers: a graphical user interface, a service layer that orchestrates forensic operations, an engine layer of independent analysers, and a persistence layer consisting of a case database and an append-only audit log. The main capabilities are described below.

[[CHART:architecture]]
*Figure 1: ForenSight layered system architecture.*

**6.1 Image carving and recovery.** The carver scans a source in two passes. The first pass locates and validates file-signature headers, and the second reconstructs each candidate file. A candidate only suppresses the region behind it once it has been confirmed to decode as a genuine image, which prevents a large invalid block of data from hiding a valid image that begins inside it. Every recovered file is validated by signature, minimum size, and structural decoding, and any file that fails validation is quarantined rather than discarded, so that no recovered bytes are lost.

**6.2 Deleted-file attribution.** Allocation is determined by an offset-based method equivalent to that used by The Sleuth Kit and Autopsy. The data runs of every file in the source file system are read as absolute byte ranges, and a recovered file is classified according to whether the offset it was carved from falls within the clusters of a live file, the clusters of a deleted file, or neither. Where a deleted entry retains a pointer to its metadata even though the primary metadata object has been released, ForenSight resolves that pointer in the same way a professional reference tool does, so that deleted files are correctly attributed rather than skipped.

**6.3 Provenance and integrity analysis.** Analysis is rule-based and transparent. The tool scans a bounded metadata region of each image, never the pixel data, for C2PA container markers, the C2PA declaration of generative origin, recognised generator signatures (such as those of OpenAI, Google, and Adobe Firefly), and editing-application signatures. Because a fixed list of names can never be complete, the tool also applies a presence-based fallback that flags non-camera application software even when the specific editor is unknown. Every finding contributes a documented weight to an Integrity and Provenance Score and is labelled as a fact, meaning it is declared by metadata or proven cryptographically, or as an indicator, meaning it is suggestive and requires examiner interpretation. Signals with a very high base rate, such as ordinary re-compression, are reported for context but are not scored, so that the classification bands remain meaningful.

**6.4 Cryptographic C2PA verification.** This is the distinguishing technical component of the tool. ForenSight parses the embedded C2PA manifest, including manifests that are split across multiple segments of a JPEG file, extracts the signature structure and the signer's certificate chain, and performs four checks. It verifies that the claim signature is cryptographically valid against the signer's certificate, supporting the common signature algorithms in use. It extracts the signer's identity and determines whether the certificate is self-signed and therefore not independently attributable. It confirms that each assertion referenced by the claim still hashes to the value the claim committed to, so that assertions cannot be swapped. Finally, it recomputes the asset hash over the actual image bytes and compares it to the signed value, which proves whether the image was edited after the credential was created. A valid signature over bytes that no longer match is reported as post-signing tampering, and a signature that fails outright is reported as a forged or corrupted manifest. Both outcomes are recorded in the chain of custody.

**6.5 Chain of custody and reporting.** Every action performed by the tool is recorded as an audit event whose hash incorporates the hash of the previous event, forming a chain in which any alteration to a past event becomes detectable. Timestamps are recorded in Coordinated Universal Time to remove any ambiguity of timezone, and the identity of the examiner is attributed to each action. The tool generates a forensic report that presents the case details, each recovered image together with its full cryptographic hash and allocation status, the integrity and provenance assessment, and the verifiable audit chain, ending with an examiner declaration.

**6.6 Supplementary visual aid (Error Level Analysis).** ForenSight provides a dedicated page on which the examiner can view an image alongside its Error Level Analysis map. This technique re-saves the image at a known quality and amplifies the per-pixel compression difference, so that a region with a different compression history, such as content spliced in from another source, can stand out visually against a uniformly compressed background. This is offered strictly as a visual aid for a human examiner and is deliberately excluded from the Integrity and Provenance Score, because a bright region can arise from ordinary texture, edges, or prior recompression as easily as from an edit, and the technique carries no meaning on an image that has been uniformly recompressed, for example by a messaging platform. Presenting it as a clearly labelled aid, separate from the score, keeps the distinction between a suggestive hint and defensible proof explicit throughout the tool.

## 7. Methodology

The project follows an iterative and test-driven methodology. Each capability is implemented as an independent module with its own automated tests and is then integrated into the whole. A distinctive element of the methodology is validation-driven refinement. The tool is repeatedly run against independent, third-party reference data, and any discrepancy between its output and that of a reference tool, or any deviation from a known correct answer, is treated as a defect, diagnosed, corrected, and then locked in place with a regression test so that it cannot recur.

**7.1 Development phases.** The work proceeds through the following phases: requirements analysis and research; design of the architecture and data model; implementation of the carving and recovery engine; implementation of the provenance, integrity, and cryptographic verification engines; implementation of the chain of custody and reporting; integration and hardening against malformed input; validation against third-party data; and finally aggregate evaluation and documentation.

**7.2 Tools and technologies.** The tool is written in Python. The graphical interface uses the PyQt6 framework, and case data is stored in an SQLite database. File-system parsing uses The Sleuth Kit through its Python binding, image decoding uses the Pillow library, report generation uses the ReportLab library, and cryptographic verification uses established cryptography and encoding libraries. Dependencies that are not essential to the core function, such as the file-system parser, are optional, and the tool degrades gracefully when they are absent.

**7.3 Validation data.** To ensure that results are not self-confirming, validation uses independent datasets. A reference disk image from the National Institute of Standards and Technology is used to measure carving accuracy. Disk images from the Digital Forensics Tool Testing project are used to validate deleted-file recovery, with the results cross-checked against the Autopsy reference tool. The public C2PA test files and a genuine content-provenance image produced by a commercial generative service are used to validate the cryptographic verification component.

## 8. Expected Outcomes and Deliverables

The project is expected to deliver the following: a working desktop application that performs image recovery, provenance and integrity assessment, cryptographic C2PA verification, and chain-of-custody preservation within a single workflow; a suite of automated tests, including tests that confirm graceful behaviour on malformed and hostile input; validated results demonstrating carving accuracy against a reference image, agreement with a reference tool on deleted-file recovery, and correct C2PA verification against genuine credentials; an automated forensic report generator; and full project documentation, including a record of the validation-driven refinements and an honest statement of the tool's limitations.

## 9. Significance and Contribution

ForenSight addresses a genuinely critical problem, namely the recovery and authentication of image evidence and the preservation of its chain of custody, rather than a cosmetic one. Its significance lies in three areas. First, by consolidating recovery, analysis, verification, and custody into one tool, it keeps the chain of custody intact across the entire process, which fragmented tooling cannot guarantee. Second, by making its assessment fully explainable and by separating facts from indicators, it produces results that are defensible in an evidential setting. ForenSight uses no machine learning of any kind, so every point that contributes to its score is a documented rule that an examiner can inspect and justify, in direct contrast to the black-box classifiers common in this space. Third, by cryptographically verifying content-provenance credentials rather than merely detecting them, it can prove whether an image is authentic, was edited after signing, or carries a forged credential, which is a capability that few available tools provide. The project also contributes an honest and precisely documented account of where metadata-based detection reaches its limit, which is valuable in itself because it defines the boundary at which other techniques must take over.

## 10. Project Timeline

The project is planned across the following stages, to be scheduled across the project period: requirements analysis and background research; system design; implementation of the recovery engine; implementation of the provenance, integrity, and verification engines; implementation of the chain of custody and reporting; integration, robustness hardening, and testing; validation against third-party data and aggregate evaluation; and preparation of the final report and demonstration.

[[CHART:gantt]]
*Figure 2: Indicative project timeline (Gantt chart).*

## 11. References

1. Coalition for Content Provenance and Authenticity (C2PA), C2PA Technical Specification.
2. B. Carrier, File System Forensic Analysis, Addison-Wesley.
3. The Sleuth Kit and Autopsy, B. Carrier, available at the sleuthkit.org.
4. National Institute of Standards and Technology (NIST), Computer Forensic Reference Data Sets.
5. Digital Forensics Tool Testing (DFTT) reference images.
6. IETF RFC 8152, CBOR Object Signing and Encryption (COSE).
7. IETF RFC 5280, Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List Profile.
8. ISO/IEC 19566-5, JPEG Universal Metadata Box Format (JUMBF).
9. European Union, Artificial Intelligence Act, Article 50, transparency obligations for AI-generated content.
