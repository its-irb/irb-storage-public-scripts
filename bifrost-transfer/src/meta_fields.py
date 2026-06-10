from __future__ import annotations
from collections.abc import Callable
from enum import Enum
import flet as ft
from bifrost_frontend.frontend import (
    C_SURFACE, C_SURFACE2, C_BORDER, C_PRIMARY, C_TEXT, C_TEXT_DIM, C_ACCENT,
    styled_field,
)


LAB_ACRONYMS: dict[str, str] = {
    "ccl": "Eduard Batlle",
    "itpc": "Direna Alonso-Curbelo",
    "pce": "Alexandra Avgustinova",
    "gccm": "Roger Gomis",
    "cdl": "Cayetano González",
    "bbg": "Nuria López-Bigas",
    "sccl": "Angel R. Nebreda",
    "are": "Antoni Riera",
    "gds": "Fran Supek",
    "scc": "Salvador Aznar Benitah",
    "lmb": "Xavier Salvatella",
    "mtx": "Ana Victoria Lechuga-Vieco",
    "aatd": "Manuel Palacín",
    "gtl": "Lluis Ribas",
    "qscd": "Alejo Rodríguez-Fraticelli",
    "iibl": "Stefanie Wculek",
    "mitmet": "Antonio Zorzano",
    "dgcl": "Marco Milán",
    "sbnb": "Patrick Aloy",
    "lcg": "Toni Gabaldón",
    "mocpd": "Jens Lüders",
    "scma": "María Macías",
    "tpddd": "Cristina Mayor-Ruiz",
    "tcccd": "Raúl Méndez",
    "csg": "Francesc Posas / Eulalia de Nadal",
    "mmb": "Modesto Orozco",
    "csf": "Ferran Azorin",
    "dmd": "Jordi Casanova",
    "pnacmm": "Miquel Coll"
}


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
            (acr, f"{name} ({acr})") for acr, name in sorted(LAB_ACRONYMS.items(), key=lambda x: x[1])
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
    prefill_values: dict[str, str] | None = None,
) -> ft.Column:
    """Builds Flet controls for TAG_PROFILES[profile_name].

    Clears and repopulates fields_dict in-place: key → control with .value.
    Returns a ft.Column ready to insert into the widget tree.
    Does NOT call page.update() — that is the caller's responsibility.
    """
    _pre = prefill_values or {}
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

            def _make_opt(opt):
                if isinstance(opt, tuple):
                    return ft.DropdownOption(key=opt[0], text=opt[1])
                return ft.DropdownOption(key=opt, text=opt)

            dd = ft.Dropdown(
                options=(
                    [ft.DropdownOption(key="", text="")] +
                    [_make_opt(opt) for opt in options_list] +
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
            if key in _pre:
                v = _pre[key]
                option_keys = {
                    opt[0] if isinstance(opt, tuple) else opt
                    for opt in options_list
                }
                if v not in option_keys:
                    dd.options.append(ft.DropdownOption(key=v, text=f"{v} *"))
                dd.value = v
                hidden_tf.value = v
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
                    return ctf, _add_custom, _sync
                return None, None, _sync

            options_dd = ft.Dropdown(
                options=[ft.DropdownOption(key=opt, text=opt) for opt in options_list],
                hint_text="Select...",
                bgcolor=C_SURFACE2, border_color=C_BORDER,
                focused_border_color=C_PRIMARY, color=C_TEXT,
                text_size=12, border_radius=6,
                content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                expand=True,
            )
            custom_tf2, add_custom_fn, sync_fn = make_multiselect(
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
            if key in _pre and _pre[key]:
                for item in [x for x in _pre[key].split(":") if x]:
                    selected_vals["s"].add(item)
                sync_fn()

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
                return input_tf, _add, _sync

            input_tf, add_fn, sync_fn = make_multifreetext(selected_vals, chips_row, hidden_tf)
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
            if key in _pre and _pre[key]:
                for item in [x for x in _pre[key].split(":") if x]:
                    selected_vals["s"].add(item)
                sync_fn()

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
            if key in _pre:
                date_tf.value = _pre[key]

        else:  # TEXT (y NUMBER, actualmente sin usar)
            tf, c = styled_field(label)
            fields_dict[key] = tf
            tf.expand = True
            col.controls.append(c)
            if helper:
                c.controls.append(
                    ft.Text(helper, size=11, color=C_TEXT_DIM, italic=True)
                )
            if key in _pre:
                tf.value = _pre[key]

    return col


def detect_profile(tags: dict[str, str]) -> str | None:
    """Devuelve el perfil cuyas keys son superconjunto de las keys de tags.

    Criterio: set(tags.keys()) ⊆ profile_keys.
    Si varios califican, devuelve el de mayor solapamiento.
    Devuelve None si ninguno encaja o si tags está vacío.
    """
    if not tags:
        return None
    tag_keys = set(tags.keys())
    best_name: str | None = None
    best_score = -1
    for profile_name, fields in TAG_PROFILES.items():
        profile_keys = {item[1] for item in fields}
        if tag_keys <= profile_keys:
            score = len(tag_keys & profile_keys)
            if score > best_score:
                best_score = score
                best_name = profile_name
    return best_name


def build_lab_filter_widget(
    page: ft.Page,
    on_select: Callable[[str | None], None],
) -> tuple[ft.Control, Callable]:
    """Widget de filtro de laboratorio con búsqueda en tiempo real.

    Returns:
        (widget, clear_fn) — el widget Flet y una función para resetear el filtro.
    """
    state = {"acronym": None}

    suggestions_col = ft.Column(spacing=2, tight=True, scroll=ft.ScrollMode.AUTO, height=160)
    suggestions_container = ft.Container(
        content=suggestions_col,
        bgcolor=C_SURFACE,
        border=ft.Border.all(1, C_BORDER),
        border_radius=6,
        padding=ft.Padding.all(4),
        visible=False,
    )

    def _matches(query: str) -> list[tuple[str, str]]:
        q = query.lower()
        return [
            (acr, name) for acr, name in LAB_ACRONYMS.items()
            if q in acr.lower() or q in name.lower()
        ]

    def _render_suggestions(matches: list[tuple[str, str]]) -> None:
        suggestions_col.controls.clear()
        if not matches:
            suggestions_col.controls.append(
                ft.Container(
                    content=ft.Text("No results", size=12, color=C_TEXT_DIM, italic=True),
                    padding=ft.Padding.symmetric(horizontal=8, vertical=6),
                )
            )
        else:
            for acr, name in matches:
                label = f"{name} ({acr})"
                suggestions_col.controls.append(
                    ft.Container(
                        content=ft.Text(label, size=12, color=C_TEXT),
                        bgcolor=C_SURFACE2,
                        border_radius=4,
                        padding=ft.Padding.symmetric(horizontal=8, vertical=6),
                        ink=True,
                        on_click=lambda e, a=acr, l=label: _select(a, l),
                    )
                )
        suggestions_container.visible = True
        page.update()

    def _select(acronym: str, label: str) -> None:
        state["acronym"] = acronym
        search_tf.value = label
        suggestions_container.visible = False
        clear_btn.visible = True
        page.update()
        on_select(acronym)

    def _on_change(e) -> None:
        query = (search_tf.value or "").strip()
        if not query:
            suggestions_container.visible = False
            page.update()
            return
        _render_suggestions(_matches(query))

    def _on_focus(e) -> None:
        query = (search_tf.value or "").strip()
        if query and state["acronym"] is None:
            _render_suggestions(_matches(query))

    def _clear(e=None) -> None:
        state["acronym"] = None
        search_tf.value = ""
        suggestions_col.controls.clear()
        suggestions_container.visible = False
        clear_btn.visible = False
        page.update()
        on_select(None)

    search_tf = ft.TextField(
        hint_text="Filter by lab…",
        bgcolor=C_SURFACE2,
        border_color=C_BORDER,
        focused_border_color=C_PRIMARY,
        color=C_TEXT,
        hint_style=ft.TextStyle(color=C_TEXT_DIM),
        border_radius=6,
        content_padding=ft.Padding.symmetric(horizontal=10, vertical=8),
        text_size=12,
        expand=True,
        on_change=_on_change,
        on_focus=_on_focus,
    )

    clear_btn = ft.IconButton(
        icon=ft.Icons.CLOSE,
        icon_color=C_TEXT_DIM,
        icon_size=16,
        visible=False,
        on_click=_clear,
        tooltip="Clear filter",
    )

    widget = ft.Column(
        [
            ft.Row(
                [search_tf, clear_btn],
                spacing=4,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            suggestions_container,
        ],
        spacing=4,
        tight=True,
    )

    return widget, _clear
