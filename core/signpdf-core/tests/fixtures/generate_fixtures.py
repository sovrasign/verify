#!/usr/bin/env python3
"""Generate real-world-style PDF fixtures for signpdf-core robustness tests.

Unlike `container::make_sample_pdf` (a toy with a classic xref *table* and only
inline objects), these fixtures mimic what modern producers (Acrobat, qpdf,
most libraries) actually emit:

  * cross-reference **streams** (not classic xref tables)
  * **object streams** (compressed objects) for the catalog/pages/etc.
  * (acroform fixture) a pre-existing /AcroForm whose **/Fields is an indirect
    reference** to an array holding an existing text field.

The /Fields-as-indirect-reference shape is the one that silently broke our
incremental signer (it dropped all pre-existing form fields). Keeping these as
committed fixtures lets the Rust tests guard the regression without a Python
dependency at test time.

Requires: pikepdf (bundles qpdf). Run from anywhere:

    python generate_fixtures.py
"""
from pathlib import Path

import pikepdf
from pikepdf import Array, Dictionary, Name, Pdf, String

HERE = Path(__file__).resolve().parent

HELV = Dictionary(Type=Name.Font, Subtype=Name.Type1, BaseFont=Name.Helvetica)
OSM = pikepdf.ObjectStreamMode.generate


def _page(pdf: Pdf, text: str):
    page = pdf.add_blank_page(page_size=(612, 792))
    page.Resources = Dictionary(Font=Dictionary(F1=pdf.make_indirect(HELV.copy())))
    stream = f"BT /F1 18 Tf 72 740 Td ({text}) Tj ET".encode("latin-1")
    page.Contents = pdf.make_stream(stream)
    return page


def make_plain(path: Path) -> None:
    """A modern PDF: one page, xref stream + object streams, no AcroForm."""
    pdf = Pdf.new()
    _page(pdf, "Hello real-world PDF (xref stream + object streams)")
    pdf.save(path, object_stream_mode=OSM, compress_streams=True)


def make_acroform(path: Path) -> None:
    """A modern PDF with a pre-existing AcroForm.

    The single existing widget is a text field, and crucially /Fields is an
    *indirect reference* to its array (the real-world shape that exposed the
    dropped-fields bug).
    """
    pdf = Pdf.new()
    page = _page(pdf, "Existing AcroForm text field below:")

    field = pdf.make_indirect(
        Dictionary(
            FT=Name.Tx,
            T=String("existing_name"),
            V=String("Jane Doe"),
            Type=Name.Annot,
            Subtype=Name.Widget,
            Rect=Array([72, 690, 320, 712]),
            F=4,
            DA=String("/Helv 0 Tf 0 g"),
            P=page.obj,
        )
    )
    page.Annots = Array([field])

    # /Fields as an INDIRECT reference (not a direct array).
    fields_ref = pdf.make_indirect(Array([field]))
    acro = pdf.make_indirect(
        Dictionary(
            Fields=fields_ref,
            DR=Dictionary(Font=Dictionary(Helv=pdf.make_indirect(HELV.copy()))),
            DA=String("/Helv 0 Tf 0 g"),
            NeedAppearances=True,
        )
    )
    pdf.Root.AcroForm = acro
    pdf.save(path, object_stream_mode=OSM, compress_streams=True)


def main() -> None:
    plain = HERE / "real_plain.pdf"
    acro = HERE / "real_acroform.pdf"
    make_plain(plain)
    make_acroform(acro)
    for p in (plain, acro):
        print(f"wrote {p} ({p.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
