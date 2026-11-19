from __future__ import annotations

from io import BytesIO

from openpyxl import load_workbook
from reportlab.platypus import Paragraph, Table

from app.exports.pdf import SECTIONS, story_for
from tests.conftest import login


def test_classeur_formules_liens_et_couleurs(client, admin):
    login(client, "admin", "motdepasse-admin")
    response = client.get("/exports/excel")
    assert response.status_code == 200
    book = load_workbook(BytesIO(response.content))
    assert book.sheetnames[:2] == ["PC – actions à faire", "Plan d'action par PC"]
    pc = book["PC – actions à faire"]
    assert pc.freeze_panes == "B2"
    assert pc.auto_filter.ref.startswith("A1:")
    assert pc["A1"].value == "Poste"
    assert "Tout est à jour ?" in [cell.value for cell in pc[1]]
    assert any(cell.hyperlink is not None and "computer.form.php?id=" in cell.hyperlink.target for row in pc.iter_rows(min_row=2) for cell in row)
    plan = book["Plan d'action par PC"]
    assert str(plan["A2"].value).startswith("='PC – actions à faire'!A2")
    assert "TEXTJOIN" in str(plan["L2"].value)
    assert "CHAR(10)" in str(plan["L2"].value)
    validations = list(plan.data_validations.dataValidation)
    assert validations
    assert "Listes" in validations[0].formula1
    assert book["Listes"].sheet_state == "hidden"


def test_pdf_sections_et_pied_de_page(client, admin, app):
    login(client, "admin", "motdepasse-admin")
    db = app.state.SessionLocal()
    try:
        from app.exports.model import build_model

        model = build_model(db, app.state.settings)
        story = story_for(model)
    finally:
        db.close()
    text = _plain(story)
    for title in SECTIONS:
        assert title in text
    assert "Fiche GLPI" in text

    response = client.get("/exports/pdf")
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")
    assert b"/Page" in response.content
    assert len(response.content) > 2000


def test_export_refuse_sans_session(client):
    response = client.get("/exports/excel", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/connexion"


def _plain(story) -> str:
    parts = []
    for item in story:
        if isinstance(item, Paragraph):
            parts.append(item.getPlainText())
        elif isinstance(item, Table):
            for row in item._cellvalues:
                for cell in row:
                    if isinstance(cell, Paragraph):
                        parts.append(cell.getPlainText())
    return "\n".join(parts)
