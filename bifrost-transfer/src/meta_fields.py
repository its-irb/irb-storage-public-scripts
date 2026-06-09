from __future__ import annotations
from enum import Enum
import flet as ft
from bifrost_frontend.frontend import (
    C_SURFACE2, C_BORDER, C_PRIMARY, C_TEXT, C_TEXT_DIM, C_ACCENT,
    styled_field,
)


class FieldType(Enum):
    TEXT          = "text"
    UNISELECT     = "uniselect"
    MULTISELECT   = "multiselect"
    MULTIFREETEXT = "multifreetext"
    DATE          = "date"
    NUMBER        = "number"


TAG_PROFILES: dict[str, list[tuple]] = {
    "IRB Standard": [
        ("Project",          "project_name",     FieldType.TEXT, False, None, None),
        ("Host machine",     "compute_node",      FieldType.TEXT, False, None, None),
        ("Sample type",      "sample_type",       FieldType.TEXT, False, None, None),
        ("Input data type",  "input_data_type",   FieldType.TEXT, False, None, None),
        ("Output data type", "output_data_type",  FieldType.TEXT, False, None, None),
        ("Requested by",     "requested_by",      FieldType.TEXT, False, None, None),
        ("Research group",   "research_group",    FieldType.TEXT, False, None, None),
    ],
    "Histopathology": [
        ("Owner", "owner", FieldType.UNISELECT, False, [
            "Eduard Batlle", "Direna Alonso-Curbelo", "Alexandra Avgustinova", "Roger Gomis",
            "Cayetano González", "Nuria López-Bigas", "Angel R. Nebreda", "Antoni Riera",
            "Fran Supek", "Salvador Aznar Benitah", "Xavier Salvatella",
            "Ana Victoria Lechuga-Vieco", "Manuel Palacín", "Lluis Ribas",
            "Alejo Rodríguez-Fraticelli", "Stefanie Wculek", "Antonio Zorzano",
            "Marco Milán", "Patrick Aloy", "Toni Gabaldón", "Jens Lüders",
            "María Macías", "Cristina Mayor-Ruiz", "Raúl Méndez",
            "Francesc Posas/ Eulalia de Nadal", "Modesto Orozco", "Ferran Azorin",
            "Jordi Casanova", "Miquel Coll",
        ], None),
        ("Users",         "users",         FieldType.MULTIFREETEXT, False, None,
         "Enter Linux usernames, add each one separately"),
        ("Date",          "date",          FieldType.DATE,      False, None, None),
        ("Provider",      "provider",      FieldType.UNISELECT, False,
         ["Histopathology IRB Core Facility"], None),
        ("Instrument",    "instrument",    FieldType.UNISELECT, False,
         ["Phenoimager", "Nanozoomer"], None),
        ("Species",       "species",       FieldType.UNISELECT, False,
         ["mouse", "human", "rat", "pig", "cow"], None),
        ("Sample Type",   "sample_type",   FieldType.UNISELECT, False,
         ["tissue section", "organoid", "cell pellet"], None),
        ("Sample Origin", "sample_origin", FieldType.TEXT, False, None,
         "Specify the biological source depending on the sample type:\n"
         "- For Tissue: enter tissue type (e.g., Lung, Colon)\n"
         "- For Organoid: enter organoid type/model (e.g., Colorectal Organoid)\n"
         "- For Cell Pellet: enter cell line origin (e.g., HeLa, HEK293)"),
        ("Magnification", "magnification", FieldType.UNISELECT, False,
         ["20x", "40x"], None),
        ("Channels",      "channels",      FieldType.UNISELECT, False, [
            "Brightfield", "DAPI", "DAPI + 488", "DAPI + 568", "DAPI + 647",
            "DAPI + 488 + 568", "DAPI + 488 + 647", "DAPI + 568 + 647",
            "DAPI + 488 + 568 + 647", "4plex", "5plex", "6plex",
        ], None),
    ],
}


def build_meta_fields(
    profile_name: str,
    page: ft.Page,
    fields_dict: dict,
) -> ft.Column:
    """Builds Flet controls for TAG_PROFILES[profile_name].

    Clears and repopulates fields_dict in-place: key → control with .value.
    Returns a ft.Column ready to insert into the widget tree.
    Does NOT call page.update() — that is the caller's responsibility.
    """
    fields_dict.clear()
    col = ft.Column(spacing=10)

    for item in TAG_PROFILES[profile_name]:
        label        = item[0]
        key          = item[1]
        field_type   = item[2]
        allow_custom = item[3]
        options_list = item[4]
        helper       = item[5] if len(item) > 5 else None

        if field_type == FieldType.UNISELECT:
            CUSTOM_KEY = "__custom__"

            custom_tf = ft.TextField(
                hint_text="Custom value...",
                bgcolor=C_SURFACE2,
                border_color=C_BORDER,
                focused_border_color=C_PRIMARY,
                color=C_TEXT,
                text_size=12,
                border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                expand=True,
                visible=False,
            )
            hidden_tf = ft.TextField(visible=False, value="")

            def make_uniselect(dd_ref, custom_ref, hidden_ref):
                def _on_select(e):
                    val = dd_ref.value
                    if val == CUSTOM_KEY:
                        custom_ref.visible = True
                        hidden_ref.value = custom_ref.value or ""
                    else:
                        custom_ref.visible = False
                        hidden_ref.value = val or ""
                    page.update()

                def _on_custom_change(e):
                    hidden_ref.value = custom_ref.value or ""

                dd_ref.on_select   = _on_select
                custom_ref.on_change = _on_custom_change

            dd = ft.Dropdown(
                options=(
                    [ft.DropdownOption(key="", text="")] +
                    [ft.DropdownOption(key=opt, text=opt) for opt in options_list] +
                    ([ft.DropdownOption(key=CUSTOM_KEY, text="✏️ Custom value...")]
                     if allow_custom else [])
                ),
                value="",
                bgcolor=C_SURFACE2,
                border_color=C_BORDER,
                focused_border_color=C_PRIMARY,
                color=C_TEXT,
                text_size=13,
                border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                expand=True,
            )
            make_uniselect(dd, custom_tf, hidden_tf)
            fields_dict[key] = hidden_tf
            col.controls.append(ft.Column(
                [ft.Text(label, size=12, color=C_TEXT_DIM), dd, custom_tf, hidden_tf],
                spacing=4,
            ))

        elif field_type == FieldType.MULTISELECT:
            selected_vals = {"s": set()}
            chips_row = ft.Row(wrap=True, spacing=6, run_spacing=6)
            hidden_tf = ft.TextField(visible=False, value="")
            fields_dict[key] = hidden_tf

            def make_multiselect(sel, chips, dd_ref, hidden, opts, custom):
                def _sync():
                    chips.controls.clear()
                    for v in sorted(sel["s"]):
                        def make_delete(val):
                            def _del(e):
                                sel["s"].discard(val)
                                _sync()
                                page.update()
                            return _del
                        chips.controls.append(ft.Chip(
                            label=ft.Text(v, size=12, color=C_TEXT),
                            bgcolor=f"{C_ACCENT}22",
                            on_delete=make_delete(v),
                            delete_icon_color=C_TEXT_DIM,
                        ))
                    hidden.value = ":".join(sorted(sel["s"]))
                    dd_ref.options = [
                        ft.DropdownOption(
                            key=opt, text=opt,
                            content=ft.Row([
                                ft.Icon(ft.Icons.CHECK, size=14, color=C_ACCENT,
                                        visible=opt in sel["s"]),
                                ft.Text(opt, size=12, color=C_TEXT),
                            ]),
                        )
                        for opt in opts
                    ]

                def _on_select(e):
                    val = dd_ref.value
                    if val and val not in sel["s"]:
                        sel["s"].add(val)
                    dd_ref.value = None
                    _sync()
                    page.update()

                dd_ref.on_select = _on_select

                if custom:
                    ctf = ft.TextField(
                        hint_text="Custom value...",
                        bgcolor=C_SURFACE2, border_color=C_BORDER,
                        focused_border_color=C_PRIMARY, color=C_TEXT,
                        text_size=12, border_radius=6,
                        content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                        expand=True,
                    )
                    def _add_custom(e):
                        val = ctf.value.strip()
                        if val and val not in sel["s"]:
                            sel["s"].add(val)
                            ctf.value = ""
                            _sync()
                            page.update()
                    return ctf, _add_custom
                return None, None

            options_dd = ft.Dropdown(
                options=[ft.DropdownOption(key=opt, text=opt) for opt in options_list],
                hint_text="Select...",
                bgcolor=C_SURFACE2, border_color=C_BORDER,
                focused_border_color=C_PRIMARY, color=C_TEXT,
                text_size=12, border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                expand=True,
            )
            custom_tf2, add_custom_fn = make_multiselect(
                selected_vals, chips_row, options_dd, hidden_tf, options_list, allow_custom
            )
            col_controls = [ft.Text(label, size=12, color=C_TEXT_DIM), options_dd, chips_row]
            if allow_custom and custom_tf2:
                col_controls.insert(2, ft.Row([
                    custom_tf2,
                    ft.IconButton(icon=ft.Icons.ADD, icon_color=C_PRIMARY,
                                  icon_size=18, on_click=add_custom_fn),
                ], spacing=4))
            col_controls.append(hidden_tf)
            col.controls.append(ft.Column(col_controls, spacing=6))

        elif field_type == FieldType.MULTIFREETEXT:
            selected_vals = {"s": set()}
            chips_row = ft.Row(wrap=True, spacing=6, run_spacing=6)
            hidden_tf = ft.TextField(visible=False, value="")
            fields_dict[key] = hidden_tf

            def make_multifreetext(sel, chips, hidden):
                def _sync():
                    chips.controls.clear()
                    for v in sorted(sel["s"]):
                        def make_delete(val):
                            def _del(e):
                                sel["s"].discard(val)
                                _sync()
                                page.update()
                            return _del
                        chips.controls.append(ft.Chip(
                            label=ft.Text(v, size=12, color=C_TEXT),
                            bgcolor=f"{C_ACCENT}22",
                            on_delete=make_delete(v),
                            delete_icon_color=C_TEXT_DIM,
                        ))
                    hidden.value = ":".join(sorted(sel["s"]))

                input_tf = ft.TextField(
                    hint_text="Add value...",
                    bgcolor=C_SURFACE2, border_color=C_BORDER,
                    focused_border_color=C_PRIMARY, color=C_TEXT,
                    text_size=12, border_radius=6,
                    content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                    expand=True,
                )

                def _add(e):
                    val = input_tf.value.strip()
                    if val and val not in sel["s"]:
                        sel["s"].add(val)
                        input_tf.value = ""
                        _sync()
                        page.update()

                input_tf.on_submit = _add
                return input_tf, _add

            input_tf, add_fn = make_multifreetext(selected_vals, chips_row, hidden_tf)
            field_col = ft.Column([
                ft.Text(label, size=12, color=C_TEXT_DIM),
                ft.Row([
                    input_tf,
                    ft.IconButton(icon=ft.Icons.ADD, icon_color=C_PRIMARY,
                                  icon_size=18, on_click=add_fn),
                ], spacing=4),
                chips_row,
                hidden_tf,
            ], spacing=6)
            if helper:
                field_col.controls.append(
                    ft.Text(helper, size=11, color=C_TEXT_DIM, italic=True)
                )
            col.controls.append(field_col)

        elif field_type == FieldType.DATE:
            def make_date_picker(tf):
                def _on_change(e):
                    if e.control.value:
                        d = e.control.value.astimezone()
                        tf.value = f"{d.year}-{d.month:02d}-{d.day:02d}"
                        page.update()
                picker = ft.DatePicker(on_change=_on_change, locale=ft.Locale("en", "GB"))
                page.overlay.append(picker)
                def _open(e):
                    picker.open = True
                    page.update()
                return _open

            date_tf = ft.TextField(
                read_only=True,
                bgcolor=C_SURFACE2, border_color=C_BORDER,
                focused_border_color=C_PRIMARY, color=C_TEXT,
                text_size=13, border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=12, vertical=8),
                expand=True,
            )
            open_fn = make_date_picker(date_tf)
            date_tf.on_click = open_fn
            fields_dict[key] = date_tf
            col.controls.append(ft.Column([
                ft.Text(label, size=12, color=C_TEXT_DIM),
                ft.Row([
                    date_tf,
                    ft.IconButton(icon=ft.Icons.CALENDAR_MONTH, icon_color=C_PRIMARY,
                                  icon_size=18, on_click=open_fn),
                ], spacing=4),
            ], spacing=4))

        else:  # TEXT (y NUMBER, actualmente sin usar)
            tf, c = styled_field(label)
            fields_dict[key] = tf
            tf.expand = True
            col.controls.append(c)
            if helper:
                c.controls.append(
                    ft.Text(helper, size=11, color=C_TEXT_DIM, italic=True)
                )

    return col
