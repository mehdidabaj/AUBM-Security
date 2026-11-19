from __future__ import annotations

from io import BytesIO

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from sqlalchemy.orm import Session

from app.config import Settings
from app.exports.model import build_model

SHEET_PC = "PC – actions à faire"
SHEET_PLAN = "Plan d'action par PC"

HEADER_FILL = PatternFill("solid", fgColor="1B2832")
HEADER_FONT = Font(color="FFFFFF", bold=True, name="Calibri")
FILLS = {
    "critique": PatternFill("solid", fgColor="FECACA"),
    "important": PatternFill("solid", fgColor="FED7AA"),
    "faible": PatternFill("solid", fgColor="BFDBFE"),
    "a_jour": PatternFill("solid", fgColor="A7F3D0"),
}
LINK_FONT = Font(color="0F6E6B", underline="single", name="Calibri")
WRAP = Alignment(wrap_text=True, vertical="center")

FIXED = [
    "Poste",
    "Service",
    "Lieu",
    "Dernière remontée agent",
    "Version agent",
    "Dernier inventaire",
    "Tout est à jour ?",
    "Priorité",
    "Nombre d'actions",
    "Autres actions",
    "Lien GLPI",
]


def build_workbook(db: Session, settings: Settings) -> bytes:
    model = build_model(db, settings)
    book = Workbook()
    sheet = book.active
    sheet.title = SHEET_PC
    labels = [item["label"] for item in model["produits"]]
    headers = FIXED + labels
    sheet.append(headers)
    for index, poste in enumerate(model["postes"], start=2):
        values = [
            poste["nom"],
            poste["service"],
            poste["lieu"],
            poste["agent_contact"],
            poste["agent_version"],
            poste["inventaire"],
            poste["a_jour"],
            poste["priorite_libelle"],
            poste["nombre"],
            poste["autres"],
            poste["lien"],
        ]
        for product in model["produits"]:
            cell = poste["cellules"].get(product["slug"])
            values.append(cell["texte"] if cell else "")
        sheet.append(values)
        _paint(sheet, index, poste, len(FIXED), model["produits"])
        link = sheet.cell(index, 11)
        link.hyperlink = poste["lien"]
        link.font = LINK_FONT
    _decorate(sheet, len(headers), len(model["postes"]))
    _plan(book, model)
    _lists(book)
    buffer = BytesIO()
    book.save(buffer)
    return buffer.getvalue()


def _paint(sheet, row: int, poste: dict, fixed: int, produits: list[dict]) -> None:
    priority = sheet.cell(row, 8)
    fill = FILLS.get(poste["priorite"])
    if fill is not None:
        priority.fill = fill
    up = sheet.cell(row, 7)
    up.fill = FILLS["a_jour"] if poste["a_jour"] == "Oui" else FILLS["important"]
    for offset, product in enumerate(produits, start=fixed + 1):
        cell_data = poste["cellules"].get(product["slug"])
        if not cell_data:
            continue
        cell = sheet.cell(row, offset)
        cell.fill = FILLS.get(cell_data["severite"], FILLS["a_jour"])
        cell.alignment = WRAP
        if cell_data["url"]:
            cell.hyperlink = cell_data["url"]
            cell.font = LINK_FONT


def _decorate(sheet, columns: int, rows: int) -> None:
    for cell in sheet[1]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    sheet.freeze_panes = "B2"
    sheet.auto_filter.ref = f"A1:{get_column_letter(columns)}{max(rows + 1, 2)}"
    sheet.row_dimensions[1].height = 30
    for index in range(1, columns + 1):
        sheet.column_dimensions[get_column_letter(index)].width = 22
    sheet.column_dimensions["A"].width = 18
    sheet.column_dimensions["J"].width = 36


def _plan(book: Workbook, model: dict) -> None:
    sheet = book.create_sheet(SHEET_PLAN)
    headers = FIXED + ["À faire", "État", "Technicien", "Date"]
    sheet.append(headers)
    product_count = len(model["produits"])
    first_product = len(FIXED) + 1
    for index in range(2, len(model["postes"]) + 2):
        for column in range(1, len(FIXED) + 1):
            letter = get_column_letter(column)
            cell = sheet.cell(index, column)
            cell.value = f"='{SHEET_PC}'!{letter}{index}"
            if column == 11:
                cell.value = f'=HYPERLINK(\'{SHEET_PC}\'!{letter}{index},\'{SHEET_PC}\'!{letter}{index})'
                cell.font = LINK_FONT
        todo = sheet.cell(index, len(FIXED) + 1)
        todo.value = _textjoin(index, first_product, product_count)
        todo.alignment = WRAP
        sheet.cell(index, len(FIXED) + 2).value = "À faire"
    _decorate(sheet, len(headers), len(model["postes"]))
    sheet.column_dimensions["L"].width = 42
    if model["postes"]:
        validation = DataValidation(type="list", formula1="=Listes!$A$1:$A$3", allow_blank=False)
        validation.error = "Choisissez À faire, En cours ou Fait."
        validation.errorTitle = "État"
        last = len(model["postes"]) + 1
        column = get_column_letter(len(FIXED) + 2)
        validation.add(f"{column}2:{column}{last}")
        sheet.add_data_validation(validation)


def _textjoin(row: int, first: int, count: int) -> str:
    if count == 0:
        return '=""'
    parts = []
    for offset in range(count):
        letter = get_column_letter(first + offset)
        ref = f"'{SHEET_PC}'!{letter}{row}"
        header = f"'{SHEET_PC}'!{letter}$1"
        parts.append(f'IF({ref}="","",{header}&" : "&{ref})')
    return "=TEXTJOIN(CHAR(10),TRUE," + ",".join(parts) + ")"


def _lists(book: Workbook) -> None:
    sheet = book.create_sheet("Listes")
    for index, value in enumerate(("À faire", "En cours", "Fait"), start=1):
        sheet.cell(index, 1).value = value
    sheet.sheet_state = "hidden"
