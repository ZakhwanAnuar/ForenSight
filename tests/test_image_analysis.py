"""Image-forensics tests: validation, EXIF, JPEG, recompression, file-type."""
from forensight import (exif_engine, jpeg_analyzer, file_type_analyzer,
                        thumbnail_engine, file_validator, integrity_analyzer,
                        recompression_analyzer)
from forensight.integrity_analyzer import AnalysisBundle


def test_valid_file_accepted(valid_jpeg):
    result = file_validator.validate_recovered_file(valid_jpeg, "JPEG")
    assert result.is_valid
    assert not result.is_suspicious


def test_small_file_quarantined(tmp_path):
    small = tmp_path / "tiny.jpg"
    small.write_bytes(b"\xFF\xD8\xFF" + b"\x00" * 50)  # valid sig, tiny
    result = file_validator.validate_recovered_file(small, "JPEG")
    assert result.is_suspicious
    assert result.reason == file_validator.SIZE_BELOW_THRESHOLD


def test_invalid_signature_flagged(tmp_path):
    bad = tmp_path / "bad.jpg"
    bad.write_bytes(b"NOTAJPEG" + b"\x00" * 6000)
    result = file_validator.validate_recovered_file(bad, "JPEG")
    assert not result.is_valid


def test_exif_missing_is_not_available(valid_jpeg):
    result = exif_engine.extract_exif(valid_jpeg)
    # Pillow-written JPEG has no camera EXIF.
    assert result.make == exif_engine.NOT_AVAILABLE


def test_recompression_analyzer_runs(valid_jpeg):
    jr = jpeg_analyzer.analyze_jpeg(valid_jpeg)
    res = recompression_analyzer.analyze(jr)
    assert res.is_jpeg
    assert isinstance(res.recompressed, bool)


def test_thumbnail_compare_no_thumbnail(valid_jpeg):
    # A Pillow-written JPEG has no embedded thumbnail -> comparison unavailable.
    res = thumbnail_engine.compare_thumbnail(valid_jpeg)
    assert not res.available and not res.mismatch


def test_jpeg_analysis(valid_jpeg):
    res = jpeg_analyzer.analyze_jpeg(valid_jpeg)
    assert res.is_jpeg
    assert res.quantization_tables >= 1
    assert res.estimated_quality is not None


def test_file_type_match(valid_jpeg):
    res = file_type_analyzer.analyze_file_type(valid_jpeg)
    assert res["result"] == file_type_analyzer.MATCH


def test_file_type_mismatch(tmp_path):
    # PDF bytes with a .jpg extension.
    fake = tmp_path / "holiday.jpg"
    fake.write_bytes(b"%PDF-1.4\n" + b"\x00" * 100)
    res = file_type_analyzer.analyze_file_type(fake)
    assert res["result"] == file_type_analyzer.MISMATCH
    assert res["detected_type"] == "PDF"


def test_thumbnail_states(valid_jpeg, tmp_path):
    res = thumbnail_engine.recover_thumbnail(valid_jpeg, tmp_path / "thumbs")
    assert res.state in (thumbnail_engine.THUMBNAIL_RECOVERED,
                         thumbnail_engine.NO_EMBEDDED_THUMBNAIL,
                         thumbnail_engine.EXTRACTION_FAILED)


def test_assessment_insufficient_data():
    assess = integrity_analyzer.assess(AnalysisBundle())
    assert assess.outcome == integrity_analyzer.INSUFFICIENT_DATA


def test_assessment_flags_mismatch():
    bundle = AnalysisBundle(file_type={"result": "MISMATCH", "extension": ".jpg",
                                       "detected_type": "PDF"})
    assess = integrity_analyzer.assess(bundle)
    assert assess.outcome in (integrity_analyzer.POTENTIAL_MANIPULATION,
                              integrity_analyzer.STRONG_INDICATORS)
    assert any("mismatch" in i.lower() for i in assess.indicators)


def test_manipulation_score_mismatch_is_high():
    bundle = AnalysisBundle(file_type={"result": "MISMATCH", "extension": ".jpg",
                                       "detected_type": "PDF"})
    a = integrity_analyzer.assess(bundle)
    assert a.score == 40 and a.outcome == integrity_analyzer.STRONG_INDICATORS
    assert a.score_label() == "40/100"


def test_score_capped_at_100():
    from forensight import exif_engine
    from forensight.provenance_analyzer import ProvenanceResult
    ex = exif_engine.ExifResult(); ex.raw = {"x": "1"}
    ex.indicators = ["image-processing software present", "timestamp inconsistency"]
    prov = ProvenanceResult(detected=True, ai_generated=True,
                            standard="C2PA", generator="Test AI")
    bundle = AnalysisBundle(exif=ex, provenance=prov,
                            file_type={"result": "MISMATCH", "extension": ".jpg",
                                       "detected_type": "PDF"})
    a = integrity_analyzer.assess(bundle)   # 20+10+40+60 = 130 -> capped at 100
    assert a.score == 100


def test_insufficient_data_score_is_na():
    a = integrity_analyzer.assess(AnalysisBundle())
    assert a.outcome == integrity_analyzer.INSUFFICIENT_DATA
    assert a.score_label() == "N/A"


# -- content provenance (C2PA / AI-generation metadata) -------------------
def test_provenance_detects_c2pa_ai_source(tmp_path):
    from forensight import provenance_analyzer
    f = tmp_path / "ai.jpg"
    f.write_bytes(b"\xFF\xD8\xFF" + b"..jumbf..c2pa.." * 3
                  + b"dc:format...trainedAlgorithmicMedia..." + b"\x00" * 200)
    r = provenance_analyzer.analyze_provenance(f)
    assert r.detected and r.ai_generated
    assert "AI-GENERATED" in r.summary().upper()


def test_provenance_detects_generator_name(tmp_path):
    from forensight import provenance_analyzer
    f = tmp_path / "grok.jpg"
    f.write_bytes(b"header c2pa jumbf ...Grok Imagine... trailer")
    r = provenance_analyzer.analyze_provenance(f)
    assert r.ai_generated and r.generator == "xAI Grok Imagine"


def test_provenance_identifies_google_not_grok(tmp_path):
    from forensight import provenance_analyzer
    # A Google/Gemini manifest whose binary blobs also contain the byte run
    # 'gRoK' (as a real Gemini image did) must NOT be attributed to Grok.
    f = tmp_path / "gemini.jpg"
    f.write_bytes(b"jumbf c2pa \x00gRoKC\x9f\x34 binary noise "
                  b"claim_generator Google C2PA Core Generator "
                  b"SynthID watermark trainedAlgorithmicMedia")
    r = provenance_analyzer.analyze_provenance(f)
    assert r.ai_generated
    assert "Grok" not in r.generator and "Google" in r.generator


def test_provenance_ignores_binary_token_noise(tmp_path):
    from forensight import provenance_analyzer
    # Lower-case 'grok' bytes in binary noise with no C2PA => not a detection.
    f = tmp_path / "noise.jpg"
    f.write_bytes(b"\xFF\xD8\xFF random gRoKC\x00 hash-like bytes" + b"\x00" * 80)
    r = provenance_analyzer.analyze_provenance(f)
    assert not r.ai_generated and r.generator == ""


def test_provenance_detects_editing_app(tmp_path):
    from forensight import provenance_analyzer
    f = tmp_path / "edited.jpg"
    f.write_bytes(b"\xFF\xD8\xFF ...Software MeituPic 9.2... pixels")
    r = provenance_analyzer.analyze_provenance(f)
    assert r.detected and not r.ai_generated and r.editor == "Meitu"


def test_ml_detector_degrades_gracefully():
    # Without TensorFlow (or model file), the ML fallback disables itself and
    # returns None instead of crashing - ForenSight keeps working rule-based.
    from forensight import ml_detector
    r = ml_detector.predict_ai_probability("does_not_exist.jpg")
    assert r is None or (isinstance(r, float) and 0.0 <= r <= 1.0)


def test_exif_software_editor_is_flagged():
    # An EXIF "Software" tag naming an editor (e.g. Adobe Express) must be flagged
    # as an image-processing indicator - not silently reported as No Anomalies.
    ex = exif_engine.ExifResult()
    ex.software = "Adobe Express Photos 6.7.1.0 (Windows)"
    ex.raw = {"Software": ex.software}
    ex.indicators = exif_engine._build_indicators(ex)
    assert any("software" in i.lower() for i in ex.indicators)
    a = integrity_analyzer.assess(AnalysisBundle(exif=ex))
    assert a.outcome == integrity_analyzer.POTENTIAL_MANIPULATION


def test_exif_camera_software_not_flagged():
    # A camera/phone firmware "Software" tag must NOT be treated as editing.
    ex = exif_engine.ExifResult()
    ex.software = "iPhone 14 Pro 17.2"
    ex.raw = {"Software": ex.software}
    ex.indicators = exif_engine._build_indicators(ex)
    assert not any("software" in i.lower() for i in ex.indicators)


def test_jpeg_quality_extreme_is_informational_not_scored():
    # Very high (or very low) JPEG quality is NOT manipulation evidence -
    # professional exports/scans are high quality - so it must be reported as
    # context but must not raise the score or the band.
    jr = jpeg_analyzer.JpegResult()
    jr.is_jpeg = True
    jr.estimated_quality = 98.5
    jr.assessment = "Very high quality / low compression"
    a = integrity_analyzer.assess(AnalysisBundle(jpeg=jr))
    assert a.score == 0
    assert a.outcome == integrity_analyzer.NO_SIGNIFICANT_ANOMALIES


def test_editing_software_not_double_counted():
    # The same editing-software fact detected by BOTH the EXIF Software tag and
    # the provenance metadata scan must be scored ONCE (20 -> Processing
    # Detected), not twice (40 -> wrongly Strong Indicators).
    from forensight import config
    from forensight.provenance_analyzer import ProvenanceResult
    ex = exif_engine.ExifResult()
    ex.software = "Adobe Express Photos 6.7.1.0"; ex.raw = {"Software": ex.software}
    ex.indicators = exif_engine._build_indicators(ex)
    prov = ProvenanceResult(detected=True, editor="Adobe Express")
    a = integrity_analyzer.assess(AnalysisBundle(exif=ex, provenance=prov))
    assert a.score == config.SCORE_EXIF_SOFTWARE          # 20, counted once
    assert a.outcome == integrity_analyzer.POTENTIAL_MANIPULATION


def test_unknown_editor_flagged_by_presence_fallback():
    # Presence-based fallback: an editor NOT in the known list, with no camera
    # make, still gets flagged because the Software names a non-camera app.
    ex = exif_engine.ExifResult()
    ex.software = "Fantastic Photo Editor Pro 3.2"   # not in _EDITOR_HINTS
    ex.raw = {"Software": ex.software}
    ex.indicators = exif_engine._build_indicators(ex)
    assert any("non-camera application" in i.lower() for i in ex.indicators)
    a = integrity_analyzer.assess(AnalysisBundle(exif=ex))
    assert a.outcome == integrity_analyzer.POTENTIAL_MANIPULATION


def test_camera_firmware_code_not_flagged_by_fallback():
    # A device firmware code with a recognised camera Make must stay clean.
    ex = exif_engine.ExifResult()
    ex.software = "G991BXXU5DVK1"; ex.make = "samsung"; ex.model = "SM-G991B"
    ex.raw = {"Software": ex.software}
    ex.indicators = exif_engine._build_indicators(ex)
    assert not any("software" in i.lower() for i in ex.indicators)


def test_editor_signature_ignored_in_pixel_data(tmp_path):
    # Regression: a short editor name (e.g. "GIMP") occurring by chance in an
    # uncompressed BMP's PIXEL data must NOT be flagged - only names in the
    # metadata region count. (Reproduces a real false positive on NIST data.)
    from forensight import provenance_analyzer
    import struct
    w = h = 8
    pixels = b"..GIMP.." + b"\x90" * (w * h * 3)          # "GIMP" inside pixels
    offbits = 54
    dib = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(pixels), 2835,
                      2835, 0, 0)
    bmp = b"BM" + struct.pack("<IHHI", 14 + len(dib) + len(pixels), 0, 0,
                              offbits) + dib + pixels
    f = tmp_path / "photo.bmp"; f.write_bytes(bmp)
    r = provenance_analyzer.analyze_provenance(f)
    assert r.editor == "" and not r.ai_generated  # pixel-data "GIMP" ignored


def test_editor_signature_detected_in_metadata(tmp_path):
    # Control: the same name in the metadata region (a JPEG header, before the
    # start-of-scan marker) IS detected.
    from forensight import provenance_analyzer
    f = tmp_path / "edited.jpg"
    f.write_bytes(b"\xFF\xD8\xFF\xE1 Exif Software GIMP 2.10 "
                  b"\xFF\xDA scandata GIMP more scandata")
    r = provenance_analyzer.analyze_provenance(f)
    assert r.editor == "GIMP"


def test_ml_ai_probability_never_affects_score():
    # The ML classifier is experimental and DISPLAY-ONLY: a confident ML result
    # must not contribute to the rule-based Integrity & Provenance Score, must not
    # appear as a weighted indicator, and must not drive the classification band.
    from forensight import jpeg_analyzer
    bundle = AnalysisBundle(ml_ai_probability=0.99)
    a = integrity_analyzer.assess(bundle)
    assert a.score == 0
    assert a.outcome == integrity_analyzer.INSUFFICIENT_DATA
    assert not any("ML image classifier" in i for i in a.indicators)


def test_ml_does_not_inflate_a_rule_based_score():
    # A discriminative rule signal sets the score; the ML must add nothing to it.
    from forensight import config
    bundle = AnalysisBundle(
        file_type={"result": "MISMATCH", "extension": ".jpg", "detected_type": "PDF"},
        ml_ai_probability=1.0)
    a = integrity_analyzer.assess(bundle)
    assert a.score == config.SCORE_FILETYPE_MISMATCH      # ML adds nothing
    assert a.outcome == integrity_analyzer.STRONG_INDICATORS


def test_recompression_alone_is_informational_not_flagged():
    # Re-compression has a ~100% base rate on processed images, so on its own it
    # must NOT flag the image: it stays "No Anomalies", with re-compression noted
    # only as context. This keeps the triage bands discriminative.
    bundle = AnalysisBundle(recompressed=True, recompression_quality=80.0)
    a = integrity_analyzer.assess(bundle)
    assert a.score == 0
    assert a.outcome == integrity_analyzer.NO_SIGNIFICANT_ANOMALIES
    assert any("re-compression" in i.lower() for i in a.indicators)  # still reported


def test_recompression_does_not_lift_a_discriminative_signal():
    # Recompression contributes nothing even alongside a real indicator.
    from forensight import config
    ex = exif_engine.ExifResult(); ex.raw = {"x": "1"}
    ex.indicators = ["EXIF timestamp inconsistency"]
    bundle = AnalysisBundle(exif=ex, recompressed=True, recompression_quality=80.0)
    a = integrity_analyzer.assess(bundle)
    assert a.score == config.SCORE_EXIF_TIMESTAMP         # timestamp only, +0 recompress


def test_allocation_classify_logic():
    from forensight import allocation
    # Offset-based: a carved file is classified by whether its byte offset falls
    # in a live extent, a deleted extent, or neither.
    live = [(1000, 2000, False)]        # a live file occupies bytes 1000..2000
    deleted = [(1000, 2000, True)]      # a deleted file occupies the same range
    assert allocation.classify(1500, live) == allocation.ALLOCATED
    assert allocation.classify(1500, deleted) == allocation.DELETED
    assert allocation.classify(5000, live) == allocation.UNALLOCATED   # no owner
    assert allocation.classify(1500, []) == allocation.UNALLOCATED     # empty map
    assert allocation.classify(1500, None) == allocation.UNKNOWN       # no fs


def test_allocation_live_wins_on_overlap():
    from forensight import allocation
    # A stale deleted extent overlapping a live one must not override the live
    # owner (the cluster is currently allocated).
    amap = [(1000, 2000, True), (1000, 2000, False)]
    assert allocation.classify(1500, amap) == allocation.ALLOCATED


def test_allocation_map_none_for_non_filesystem(tmp_path):
    from forensight import allocation
    blob = tmp_path / "raw.bin"
    blob.write_bytes(b"\x00" * 4096)   # not a filesystem
    assert allocation.build_allocation_map(blob) is None


def test_provenance_self_signed_is_flagged(tmp_path):
    from forensight import provenance_analyzer
    f = tmp_path / "grok.jpg"
    f.write_bytes(b"jumbf c2pa Grok Imagine trainedAlgorithmicMedia "
                  b"Self-signed ephemeral CA (Content Authenticity SDK) LOCAL USE")
    r = provenance_analyzer.analyze_provenance(f)
    assert r.ai_generated and r.self_signed
    assert r.trust == provenance_analyzer.TRUST_SELF_SIGNED
    assert "NOT independently verifiable" in r.summary()


def test_provenance_ca_issued_is_attributed(tmp_path):
    from forensight import provenance_analyzer
    f = tmp_path / "gemini.jpg"
    f.write_bytes(b"jumbf c2pa trainedAlgorithmicMedia Google C2PA Core Generator "
                  b"Google LLC Google C2PA Media Services 1P ICA Root CA G3")
    r = provenance_analyzer.analyze_provenance(f)
    assert r.ai_generated and not r.self_signed
    assert r.trust == provenance_analyzer.TRUST_CA_ISSUED and r.signer == "Google LLC"


def test_editing_app_scores_potential():
    from forensight.provenance_analyzer import ProvenanceResult
    prov = ProvenanceResult(detected=True, editor="CapCut")
    a = integrity_analyzer.assess(AnalysisBundle(provenance=prov))
    assert a.outcome == integrity_analyzer.POTENTIAL_MANIPULATION
    assert any("editing software" in i.lower() for i in a.indicators)


def test_provenance_c2pa_without_ai_is_informational(tmp_path):
    from forensight import provenance_analyzer
    f = tmp_path / "camera.jpg"
    f.write_bytes(b"..c2pa jumbf manifest signed by a camera device..")
    r = provenance_analyzer.analyze_provenance(f)
    assert r.detected and not r.ai_generated  # provenance present, no AI claim


def test_provenance_clean_image_has_none(valid_jpeg):
    from forensight import provenance_analyzer
    r = provenance_analyzer.analyze_provenance(valid_jpeg)
    assert not r.detected and not r.ai_generated


def test_manipulation_score_ai_provenance_is_strong():
    from forensight.provenance_analyzer import ProvenanceResult
    prov = ProvenanceResult(detected=True, ai_generated=True,
                            standard="C2PA Content Credentials", generator="xAI Grok")
    a = integrity_analyzer.assess(AnalysisBundle(provenance=prov))
    assert a.score == 60 and a.outcome == integrity_analyzer.STRONG_INDICATORS
    assert any("AI-generated" in i for i in a.indicators)
