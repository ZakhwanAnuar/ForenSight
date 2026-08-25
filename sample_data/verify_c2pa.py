"""Quick CLI to cryptographically verify a real C2PA image with ForenSight.

Usage:
    python sample_data/verify_c2pa.py path/to/image.jpg

Prints the full verification verdict: whether a manifest is present, whether the
COSE_Sign1 signature is cryptographically valid, the signer certificate, whether
the asset was edited after signing, and every verification note.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the repo root without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from forensight import c2pa_verifier as cv           # noqa: E402
from forensight import provenance_analyzer as pa     # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    path = argv[1]
    if not Path(path).is_file():
        print(f"Not a file: {path}")
        return 2

    print(f"== ForenSight C2PA verification: {path} ==\n")

    ver = cv.verify_file(path)
    if not ver.libraries_available:
        print("cryptography / cbor2 not installed - run: pip install cryptography cbor2")
        return 1
    if not ver.present:
        print("No C2PA / Content Credentials manifest found in this file.")
        print("(Try an image from https://contentcredentials.org/verify or an "
              "Adobe Firefly / Content Credentials export.)")
        return 0

    print(f"Manifest present     : yes  (label: {ver.manifest_label or 'n/a'})")
    print(f"Parsed OK            : {ver.parsed}")
    print(f"Claim generator      : {ver.claim_generator or 'n/a'}")
    print(f"Signature algorithm  : {ver.sig_alg or 'n/a'}")
    print(f"Signature VALID      : {ver.signature_valid}")
    print(f"Signer subject       : {ver.signer_subject or 'n/a'}")
    print(f"Signer issuer        : {ver.signer_issuer or 'n/a'}")
    print(f"Self-signed          : {ver.self_signed}")
    print(f"Certs in chain       : {ver.cert_count}")
    print(f"Assertions bound     : {ver.assertions_bound}")
    print(f"Asset-hash present   : {ver.asset_hash_present}")
    print(f"Asset-hash VALID     : {ver.asset_hash_valid}")
    print(f"Edited after signing : {ver.tampered_after_signing}")
    if ver.error:
        print(f"Note (error)         : {ver.error}")
    print("\nVerdict:")
    print(f"  {ver.summary()}")
    print("\nVerification notes:")
    for note in ver.notes:
        print(f"  - {note}")

    # Show how the full provenance layer reads it (trust band + score input).
    prov = pa.analyze_provenance(path)
    print("\nProvenance layer:")
    print(f"  summary : {prov.summary()}")
    print(f"  trust   : {prov.trust}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
