from __future__ import annotations

from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.config import Settings
from app.exports.model import build_model

FONT_DIR = Path(__file__).resolve().parent / "fonts"
PAGE = landscape(A4)

SECTIONS = (
    "Chiffres clés",
    "Actions par logiciel",
    "Points de vigilance",
    "Synthèse par poste",
    "Plan d'action détaillé",
)


def build_pdf(db: Session, settings: Settings) -> bytes:
    model = build_model(db, settings)
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=PAGE,
        leftMargin=1.3 * cm,
        rightMargin=1.3 * cm,
        topMargin=1.3 * cm,
        bottomMargin=1.5 * cm,
        title="Plan de mise à jour",
    )

    def footer(canvas, doc) -> None:
        _register_fonts()
        canvas.saveState()
        canvas.setFont("DejaVu", 8)
        canvas.setFillColor(colors.HexColor("#5C6B76"))
        canvas.drawString(1.3 * cm, 0.7 * cm, model["date"])
        canvas.drawRightString(PAGE[0] - 1.3 * cm, 0.7 * cm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story_for(model), onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def story_for(model: dict) -> list:
    _register_fonts()
    styles = _styles()
    story = [
        Paragraph("Plan de mise à jour du parc", styles["title"]),
        Paragraph(f"Édité le {model['date']} (heure de Paris)", styles["meta"]),
        Spacer(1, 0.3 * cm),
    ]
    story.append(Paragraph(SECTIONS[0], styles["h"]))
    chiffres = model["chiffres"]
    story.append(
        _table(
            [
                ["Postes analysés", "À jour", "À mettre à jour", "Critiques", "Actions"],
                [
                    str(chiffres["analyses"]),
                    str(chiffres["a_jour"]),
                    str(chiffres["a_mettre_a_jour"]),
                    str(chiffres["critiques"]),
                    str(chiffres["actions"]),
                ],
            ],
            styles,
        )
    )
    story.append(Paragraph(SECTIONS[1], styles["h"]))
    rows = [["Logiciel", "Version courante", "Dernière publiée", "À jour", "En retard"]]
    for item in model["logiciels"]:
        rows.append(
            [
                item["nom"],
                item["courante"],
                str(item["publiee"]),
                str(item["a_jour"]),
                str(item["en_retard"]),
            ]
        )
    if len(rows) == 1:
        rows.append(["Aucun logiciel reconnu", "—", "—", "—", "—"])
    story.append(_table(rows, styles))
    story.append(Paragraph(SECTIONS[2], styles["h"]))
    for line in model["vigilance"]:
        story.append(Paragraph("• " + escape(line), styles["body"]))
    story.append(Paragraph(SECTIONS[3], styles["h"]))
    synthese = [["Poste", "Service", "Priorité", "À jour", "Actions"]]
    for poste in model["postes"]:
        synthese.append(
            [
                poste["nom"],
                poste["service"],
                poste["priorite_libelle"],
                poste["a_jour"],
                str(poste["nombre"]),
            ]
        )
    if len(synthese) == 1:
        synthese.append(["Aucun poste", "—", "—", "—", "—"])
    story.append(_table(synthese, styles))
    story.append(Paragraph(SECTIONS[4], styles["h"]))
    if not model["postes"]:
        story.append(Paragraph("Aucune action à détailler.", styles["body"]))
    for poste in model["postes"]:
        story.append(Paragraph(escape(poste["nom"]), styles["poste"]))
        story.append(
            Paragraph(
                f'<link href="{escape(poste["lien"])}">Fiche GLPI</link>',
                styles["body"],
            )
        )
        if not poste["actions"]:
            story.append(Paragraph("Aucune action.", styles["body"]))
            continue
        for action in poste["actions"]:
            title = escape(action["titre"])
            if action["url"]:
                title = f'<link href="{escape(action["url"])}">{title}</link>'
            detail = escape(action["detail"]) if action["detail"] else ""
            story.append(Paragraph(f"{title} — {detail}" if detail else title, styles["body"]))
    return story


def _register_fonts() -> None:
    if "DejaVu" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("DejaVu", str(FONT_DIR / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("DejaVu-Bold", str(FONT_DIR / "DejaVuSans-Bold.ttf")))


def _styles() -> dict[str, ParagraphStyle]:
    return {
        "title": ParagraphStyle("titre", fontName="DejaVu-Bold", fontSize=16, leading=20, textColor=colors.HexColor("#1B2832")),
        "meta": ParagraphStyle("meta", fontName="DejaVu", fontSize=9, leading=12, textColor=colors.HexColor("#5C6B76")),
        "h": ParagraphStyle("section", fontName="DejaVu-Bold", fontSize=12, leading=16, spaceBefore=12, spaceAfter=6, textColor=colors.HexColor("#0F6E6B")),
        "poste": ParagraphStyle("poste", fontName="DejaVu-Bold", fontSize=10, leading=13, spaceBefore=8),
        "body": ParagraphStyle("corps", fontName="DejaVu", fontSize=8.5, leading=11),
        "cell": ParagraphStyle("cellule", fontName="DejaVu", fontSize=8, leading=10),
        "head": ParagraphStyle("entete", fontName="DejaVu-Bold", fontSize=8, leading=10, textColor=colors.white),
    }


def _table(rows: list[list[str]], styles: dict[str, ParagraphStyle]) -> Table:
    prepared = []
    for index, row in enumerate(rows):
        style = styles["head"] if index == 0 else styles["cell"]
        prepared.append([Paragraph(escape(str(value)), style) for value in row])
    table = Table(prepared, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B2832")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFB")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D5DEE6")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table

