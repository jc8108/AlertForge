"""
AlertForge - a lightweight note-taking / triage tool for SOC analysts.

Workflow: paste raw JSON log(s) -> parse to auto-extract key fields ->
write analysis -> insert an escalation template or false-positive
response (auto-filled from the parsed fields) -> assemble final ticket
text -> copy to clipboard and paste into your ticketing system.

Run:      python app.py
Build:    pyinstaller --onefile --windowed --name AlertForge app.py
          then copy field_mappings.json next to the built exe.
          (see README.md for full instructions)
"""

import json
import os
import re
import shutil
import sys
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import ttk, messagebox, filedialog, simpledialog
from tkinter import font as tkfont

from parser_core import (
    DB, FieldMapper, fill_template, CANONICAL_FIELDS, TRANSFORMS, INCIDENT_STATUSES,
    find_unresolved_tag_spans, remove_unresolved_tags, sanitize_text, SANITIZE_CATEGORIES, SANITIZE_CATEGORY_LABELS,
    TEXT_TOOL_OPERATIONS, apply_text_tools, virustotal_url,
    find_misspelled_word_spans, spelling_suggestions,
)


APP_TITLE = "AlertForge"
APP_VERSION = "1.0"
APP_TAGLINE = "Your cybersecurity workbench."

CATEGORY_TO_LABEL = {"escalation": "Escalation", "false_positive": "False Positive"}
LABEL_TO_CATEGORY = {v: k for k, v in CATEGORY_TO_LABEL.items()}

FONT_FAMILY = "Segoe UI"
MONO_FAMILY = "Consolas"

# Rich-text formatting tags available in the Notes tab only (Bold / Italic /
# Underline / Strikethrough / Heading toolbar). Each note's body is stored
# as {"alertforge_rich_text": 1, "runs": [{"text": ..., "styles": [...]}]}
# in the same 'body' column notes have always used - see
# _note_body_from_editor / _note_body_to_editor. Notes saved before this
# feature existed are plain text and load back in unformatted.
NOTE_STYLE_TAGS = ("bold", "italic", "bold_italic", "underline", "strike", "heading")

# Adjustable UI text size (A-/A+ in the header, or Ctrl+-/Ctrl+=/Ctrl+0).
# All ttk styles and the plain tk.Text boxes scale off this one value.
FONT_SIZE_DEFAULT = 12
FONT_SIZE_MIN = 8
FONT_SIZE_MAX = 20
FONT_SIZE_STEP = 1

# Simple light theme + a dark-blue theme, applied to both ttk styles and
# the plain tk.Text widgets (which ttk styling doesn't reach).
THEMES = {
    "light": {
        "bg": "#f3f5fa",
        "panel": "#ffffff",
        "fg": "#1b2430",
        "muted_fg": "#5b6470",
        "accent": "#2f6fed",
        "accent_active": "#1d4fc4",
        "accent_fg": "#ffffff",
        "border": "#d7dce4",
        "text_bg": "#ffffff",
        "text_fg": "#1b2430",
        "select_bg": "#dce8ff",
        "tree_bg": "#ffffff",
        "tree_alt": "#f2f5fb",
        "danger": "#c62828",
    },
    "dark": {
        "bg": "#0c1526",
        "panel": "#11213b",
        "fg": "#e7edf7",
        "muted_fg": "#93a4c2",
        "accent": "#4f8dfd",
        "accent_active": "#6fa8ff",
        "accent_fg": "#08101f",
        "border": "#23324f",
        "text_bg": "#0a1424",
        "text_fg": "#e7edf7",
        "select_bg": "#1f3a63",
        "tree_bg": "#0f1c32",
        "tree_alt": "#132540",
        "danger": "#ff6b6b",
    },
}


def base_dir():
    """Directory the app's data files live in - works both when run as a
    plain script and when frozen into a PyInstaller onefile exe."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


DB_PATH = os.path.join(base_dir(), "alertforge.db")
MAPPING_PATH = os.path.join(base_dir(), "field_mappings.json")


def _migrate_legacy_db_filename():
    """One-time migration: this app used to be called SOC Notes and
    stored its data in soc_notes.db. If that file is still sitting next
    to the exe/script and the new alertforge.db hasn't been created yet,
    copy it over so existing templates/incidents/notes/sanitize keywords
    aren't orphaned by the rename - the app just keeps working under its
    new name with all your existing data intact. Safe to run every
    launch: once alertforge.db exists, this is a no-op."""
    legacy_path = os.path.join(base_dir(), "soc_notes.db")
    if os.path.exists(legacy_path) and not os.path.exists(DB_PATH):
        shutil.copy2(legacy_path, DB_PATH)


_migrate_legacy_db_filename()

FIELD_LABELS = {
    "user": "User / Account",
    "domain": "Domain",
    "host": "Host / Device",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "process": "Process",
    "cmdline": "Command Line",
    "parent_process": "Parent Process",
    "parent_cmdline": "Parent Command Line",
    "timestamp": "Timestamp",
    "event_id": "Event ID / Type",
    "event_type": "Event Category",
    "result": "Result",
    "location": "Location",
    "device_os": "Device OS",
}


def field_label(key):
    """Human-friendly label for a field key. Known cross-source fields use
    FIELD_LABELS; anything source-specific (geoip_city, process_sha256,
    rule_name, etc.) is auto-humanized."""
    if key in FIELD_LABELS:
        return FIELD_LABELS[key]
    label = key.replace("_", " ").strip()
    label = re.sub(r"\bgeoip\b", "GeoIP", label, flags=re.IGNORECASE)
    label = re.sub(r"\bip\b", "IP", label, flags=re.IGNORECASE)
    label = re.sub(r"\bpid\b", "PID", label, flags=re.IGNORECASE)
    label = re.sub(r"\bsha(1|256)\b", r"SHA\1", label, flags=re.IGNORECASE)
    label = re.sub(r"\bmd5\b", "MD5", label, flags=re.IGNORECASE)
    label = re.sub(r"\bos\b", "OS", label, flags=re.IGNORECASE)
    return label[:1].upper() + label[1:] if label else key


class WrapToolbar(ttk.Frame):
    """A horizontal row of widgets (buttons, labels, entries, etc.) that
    automatically wraps onto additional rows when there isn't enough
    width to show everything on one line, instead of letting the extra
    widgets run off the edge and become invisible with no way to reach
    them - the problem that shows up when the window (or a split pane
    inside it) gets narrow, e.g. side-by-side with a browser window, or
    the app is used less than full-screen.

    Add widgets with .add(widget, padx, pady) instead of packing them
    directly onto this frame; wrapping is recalculated automatically
    whenever this frame is resized.

    Implementation note: every widget is positioned directly with
    .place(x=, y=, width=, height=) on this frame itself - not pack()
    and not grid(). Two earlier implementations both had real bugs:
    - grid(row=row, column=col, ...) sizes each COLUMN to fit the widest
      widget ever placed in that column across every row, so a wide
      button landing in column 0 on one row would silently stretch
      column 0 on every other row too (visible gap after the Notes
      tab's "B" bold button).
    - A second version tried per-row pack()-based sub-Frames, with each
      widget packed into its row's frame via pack(in_=row_frame, ...).
      That widget's real Tk parent stays this WrapToolbar (not
      row_frame), which is a documented, legal Tk pattern - but in
      practice, inside a ttk.Notebook tab with this class's own
      destroy-and-rebuild-every-reflow behavior, the row frames and
      their contents would end up with correct, sane geometry
      (winfo_ismapped() even reported 1) while never actually being
      painted on screen - nothing thrown, no exception, just an empty
      strip on screen confirmed via a live Xvfb/screenshot test. Rather
      than chase that further, .place() sidesteps the whole class of
      problem: every widget's real parent, geometry manager, AND master
      are all this same frame, with no cross-widget/cross-frame
      reparenting trick involved anywhere.

    Since .place() doesn't report a size back to the parent the way
    pack/grid do, this frame's own height is set explicitly to the
    total height used by the last reflow."""

    # Every live WrapToolbar registers itself here so reflow_all() can
    # force-recompute every instance at once - needed because a toolbar
    # sitting inside a ttk.Notebook tab that hasn't been selected yet is
    # never actually mapped, so it can report winfo_width()==1 forever
    # and never receive a real <Configure> event of its own even after
    # the tab is later selected (switching tabs doesn't necessarily
    # change ITS width, just its visibility) - which used to leave it
    # permanently empty. reflow_all() is called on every tab switch (see
    # SOCNotesApp._on_tab_changed) as a belt-and-suspenders fix for that.
    _instances = []

    def __init__(self, parent, padding=0, **kwargs):
        super().__init__(parent, **kwargs)
        self._items = []
        # 'padding' used to be forwarded to ttk.Frame's own padding
        # option, which only affects children managed via pack/grid -
        # place() ignores it entirely, so it's parsed here instead and
        # applied as a manual inset on every placed widget below.
        self._pad_x, self._pad_y = self._parse_padding(padding)
        self.bind("<Configure>", self._reflow)
        WrapToolbar._instances.append(self)

    @staticmethod
    def _parse_padding(padding):
        if isinstance(padding, (tuple, list)):
            vals = list(padding)
        else:
            vals = [padding]
        vals = [int(v) for v in vals]
        if len(vals) == 1:
            return vals[0], vals[0]
        return vals[0], vals[1]

    def add(self, widget, padx=3, pady=2):
        self._items.append((widget, padx, pady))
        self.after_idle(self._reflow)
        return widget

    @staticmethod
    def _pad_lr(padx):
        if isinstance(padx, (tuple, list)):
            return padx[0], padx[1]
        return padx, padx

    @classmethod
    def reflow_all(cls):
        """Force every live WrapToolbar to recompute its layout right
        now, regardless of whether it has received its own <Configure>
        event yet. Safe to call even if some tracked instances have
        since been destroyed (e.g. a tab that was rebuilt) - those are
        skipped and pruned from the registry."""
        alive = []
        for inst in cls._instances:
            try:
                if inst.winfo_exists():
                    inst._reflow()
                    alive.append(inst)
            except tk.TclError:
                pass
        cls._instances = alive

    def _reflow(self, event=None):
        if not self._items:
            return
        width = self.winfo_width()
        if width <= 1:
            # Not mapped yet (e.g. living inside a notebook tab that
            # hasn't been selected, or called before the window has any
            # real geometry) - fall back to the toplevel window's width
            # so widgets still get laid out (just without an accurate
            # wrap point) instead of staying completely invisible. A
            # later real <Configure>, or reflow_all() on the next tab
            # switch, will redo this with the toolbar's own true width.
            width = self.winfo_toplevel().winfo_width()
            if width <= 1:
                width = 100000  # absolute fallback: one unwrapped row
        avail = max(1, width - 2 * self._pad_x)

        x = 0
        y = self._pad_y
        row_h = 0
        for widget, padx, pady in self._items:
            pad_l, pad_r = self._pad_lr(padx)
            pad_t, pad_b = self._pad_lr(pady)
            req_w = widget.winfo_reqwidth()
            req_h = widget.winfo_reqheight()
            slot_w = pad_l + req_w + pad_r
            if x > 0 and x + slot_w > avail:
                y += row_h
                x = 0
                row_h = 0
            widget.place(x=self._pad_x + x + pad_l, y=y + pad_t, width=req_w, height=req_h)
            x += slot_w
            row_h = max(row_h, pad_t + req_h + pad_b)
        total_height = y + row_h + self._pad_y
        self.configure(height=total_height)


class SOCNotesApp(tk.Tk):
    # Sentinel value for the Workspace tab's profile-override dropdown -
    # never a real profile id/label, so it can't collide with one.
    PROFILE_OVERRIDE_AUTO = "Auto-detect (recommended)"
    # Sentinel label for the Query Builder tab's "any profile" query
    # templates - stored as profile_id "" in the DB.
    QUERY_GENERIC_PROFILE_LABEL = "(Generic - any profile)"

    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("1280x820")
        # Kept deliberately low (rather than the old 1000x650) so the
        # window can actually shrink down to fit a half-monitor
        # split-screen layout - this app is commonly run side-by-side
        # with a browser/ticketing system, not full-screen.
        self.minsize(640, 480)

        try:
            self.db = DB(DB_PATH)
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not open database:\n{e}")
            raise

        try:
            self.mapper = FieldMapper(MAPPING_PATH)
        except Exception as e:
            messagebox.showerror(
                "Field Mapping Error",
                f"Could not load field_mappings.json:\n{e}\n\n"
                f"Log parsing will be unavailable until this is fixed.",
            )
            self.mapper = None

        self.extracted = {k: "" for k in CANONICAL_FIELDS}
        self.field_order = list(CANONICAL_FIELDS)
        self.current_incident_id = None
        self.current_incident_title = None

        # ---- theming setup ----
        self._text_widgets = []
        # Prose boxes (Analysis/Output/Notes/Template) that get live
        # spell-check underlines - populated by _enable_spellcheck() as
        # each box is built in _build_ui().
        self._spellcheck_widgets = set()
        self._spellcheck_after_ids = {}
        self.theme_name = "dark"
        self.font_size = FONT_SIZE_DEFAULT
        self.option_add("*Font", (FONT_FAMILY, self.font_size))
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self._build_menu()
        self._build_ui()
        self._refresh_template_lists()
        self._refresh_incident_list()
        self._apply_theme("dark")
        # Force the pending style/geometry recalculation to run now rather
        # than waiting for the first idle cycle after mainloop() starts -
        # on Windows, ttk styles applied before the window is ever mapped
        # can otherwise render with default OS colors until something
        # (like toggling Dark Mode) forces a redraw.
        self.update_idletasks()
        # Every WrapToolbar scheduled its own first reflow via
        # after_idle() while it was being built, but tabs other than the
        # one selected by default aren't mapped yet at that point, so
        # winfo_width() reports 1 and those toolbars end up with nothing
        # packed into them at all. Force a real reflow of everything now
        # that the window has its final geometry, then again once
        # mainloop() actually starts (belt-and-suspenders for any
        # platform/timing quirk where update_idletasks() alone doesn't
        # fully settle notebook-tab geometry).
        WrapToolbar.reflow_all()
        self.after(50, WrapToolbar.reflow_all)

        # Ctrl+=/Ctrl+-/Ctrl+0 work from anywhere in the app, not just
        # when a particular widget has focus.
        self.bind_all("<Control-equal>", lambda e: self._increase_font_size())
        self.bind_all("<Control-plus>", lambda e: self._increase_font_size())
        self.bind_all("<Control-minus>", lambda e: self._decrease_font_size())
        self.bind_all("<Control-KP_Add>", lambda e: self._increase_font_size())
        self.bind_all("<Control-KP_Subtract>", lambda e: self._decrease_font_size())
        self.bind_all("<Control-0>", lambda e: self._reset_font_size())

        # Right-click edit menu (Cut/Copy/Paste/Select All, plus
        # Undo/Redo on Text boxes and spelling suggestions on the 4
        # spell-check-enabled boxes) - bound at the widget-class level so
        # every Text and Entry widget in the app gets it automatically,
        # without touching each individual widget's creation code.
        self.bind_class("Text", "<Button-3>", self._show_edit_context_menu)
        self.bind_class("TEntry", "<Button-3>", self._show_edit_context_menu)
        self.bind_class("Entry", "<Button-3>", self._show_edit_context_menu)

    # ------------------------------------------------------------------
    # Theming
    # ------------------------------------------------------------------

    def _toggle_dark_mode(self):
        self._apply_theme("dark" if self.dark_mode_var.get() else "light")

    def _apply_theme(self, name):
        self.theme_name = name
        p = THEMES[name]
        style = self.style
        size = self.font_size
        title_size = size + 14

        self.option_add("*Font", (FONT_FAMILY, size))
        self.configure(bg=p["bg"])

        style.configure(".", background=p["bg"], foreground=p["fg"], font=(FONT_FAMILY, size))
        style.configure("TFrame", background=p["bg"])
        style.configure("Header.TFrame", background=p["panel"])
        style.configure("TLabel", background=p["bg"], foreground=p["fg"], font=(FONT_FAMILY, size))
        style.configure("TLabelframe", background=p["bg"], foreground=p["fg"], bordercolor=p["border"])
        style.configure("TLabelframe.Label", background=p["bg"], foreground=p["fg"], font=(FONT_FAMILY, size, "bold"))

        if hasattr(self, "title_label"):
            self.title_label.configure(
                text=APP_TITLE, background=p["panel"], foreground=p["accent"],
                font=(FONT_FAMILY, title_size, "bold"),
            )
        if hasattr(self, "version_label"):
            self.version_label.configure(
                text=f"v{APP_VERSION}", background=p["panel"], foreground=p["muted_fg"],
                font=(FONT_FAMILY, size),
            )
        if hasattr(self, "subtitle_label"):
            self.subtitle_label.configure(
                text=APP_TAGLINE, background=p["panel"], foreground=p["muted_fg"],
                font=(FONT_FAMILY, size),
            )
        style.configure("Subtitle.TLabel", background=p["panel"], foreground=p["muted_fg"], font=(FONT_FAMILY, size))
        style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted_fg"], font=(FONT_FAMILY, size))
        style.configure("Section.TLabel", background=p["bg"], foreground=p["fg"], font=(FONT_FAMILY, size, "bold"))

        style.configure(
            "TButton", background=p["panel"], foreground=p["fg"], font=(FONT_FAMILY, size),
            padding=(10, 6), borderwidth=1, relief="flat", bordercolor=p["border"],
        )
        style.map(
            "TButton",
            background=[("active", p["select_bg"]), ("disabled", p["panel"])],
            foreground=[("disabled", p["muted_fg"])],
        )
        style.configure(
            "Accent.TButton", background=p["accent"], foreground=p["accent_fg"],
            font=(FONT_FAMILY, size, "bold"), padding=(12, 7), borderwidth=0, relief="flat",
        )
        style.map("Accent.TButton", background=[("active", p["accent_active"])])

        # Notes-tab formatting toolbar buttons - labels hint at what each
        # one does (B is bold, I is italic, U is underlined).
        style.configure("NoteBold.TButton", font=(FONT_FAMILY, size, "bold"))
        style.configure("NoteItalic.TButton", font=(FONT_FAMILY, size, "italic"))
        style.configure("NoteUnderline.TButton", font=(FONT_FAMILY, size, "underline"))

        style.configure("TCheckbutton", background=p["bg"], foreground=p["fg"], font=(FONT_FAMILY, size))
        style.map("TCheckbutton", background=[("active", p["bg"])])
        style.configure("Toggle.TCheckbutton", background=p["panel"], foreground=p["fg"], font=(FONT_FAMILY, size))
        style.map("Toggle.TCheckbutton", background=[("active", p["panel"])])
        style.configure("TRadiobutton", background=p["bg"], foreground=p["fg"], font=(FONT_FAMILY, size))
        style.map("TRadiobutton", background=[("active", p["bg"])])

        style.configure("TEntry", fieldbackground=p["text_bg"], foreground=p["text_fg"], insertcolor=p["text_fg"], bordercolor=p["border"])
        style.configure("TCombobox", fieldbackground=p["text_bg"], foreground=p["text_fg"], background=p["panel"], bordercolor=p["border"], arrowcolor=p["fg"])
        style.map("TCombobox", fieldbackground=[("readonly", p["text_bg"])], foreground=[("readonly", p["text_fg"])])

        style.configure("TNotebook", background=p["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=p["panel"], foreground=p["fg"], padding=(14, 8), font=(FONT_FAMILY, size))
        style.map(
            "TNotebook.Tab",
            background=[("selected", p["accent"])],
            foreground=[("selected", p["accent_fg"])],
        )

        style.configure("TPanedwindow", background=p["bg"])
        style.configure("TSeparator", background=p["border"])

        style.configure(
            "Treeview", background=p["tree_bg"], fieldbackground=p["tree_bg"], foreground=p["fg"],
            rowheight=max(20, size + 14), font=(FONT_FAMILY, size), borderwidth=0,
        )
        style.configure("Treeview.Heading", background=p["panel"], foreground=p["fg"], font=(FONT_FAMILY, size, "bold"), relief="flat")
        style.map(
            "Treeview.Heading", background=[("active", p["select_bg"])],
        )
        style.map(
            "Treeview",
            background=[("selected", p["select_bg"])],
            foreground=[("selected", p["fg"])],
        )

        # tk core widgets (Text) aren't reached by ttk styling. Each entry
        # in self._text_widgets is (widget, font_family, size_offset) - a
        # couple of compact preview boxes (Field Mappings test/advanced
        # panes) run one point smaller than the base size by design, so
        # they keep that relative offset as the base size changes.
        for widget, family, offset in self._text_widgets:
            widget.configure(
                background=p["text_bg"], foreground=p["text_fg"],
                insertbackground=p["text_fg"], selectbackground=p["select_bg"],
                selectforeground=p["fg"], highlightthickness=1,
                highlightbackground=p["border"], highlightcolor=p["accent"],
                relief="flat", font=(family, max(FONT_SIZE_MIN, size + offset)),
            )

        # Spell-check squiggle - a colored underline on misspelled words,
        # applied to whichever box(es) are in _spellcheck_widgets
        # (currently just Analysis - see _enable_spellcheck). underlinefg
        # needs Tk 8.6.10+; older Tk falls back to a plain red word.
        for widget in self._spellcheck_widgets:
            try:
                widget.tag_configure("misspelled", underline=True, underlinefg=p["danger"])
            except tk.TclError:
                widget.tag_configure("misspelled", underline=True, foreground=p["danger"])

        # Notes tab: Bold/Italic/Underline/Strikethrough/Heading tags,
        # rebuilt at the current base size so they track the app-wide
        # A-/A+ font size control like everything else.
        if hasattr(self, "note_body_text"):
            self._configure_note_style_tags()

        # Ticket output box: bold+yellow highlight for unresolved
        # #tag/{field}/[field] placeholders, rebuilt at the current base
        # size so it tracks the app-wide A-/A+ font size control too.
        if hasattr(self, "output_text"):
            self._configure_output_tag_style()

        # Sanitize Logs tab: bold+green highlight over exactly the spans
        # sanitize_text() changed, rebuilt at the current base size for
        # the same reason as the two tag styles above.
        if hasattr(self, "sanitize_output_text"):
            self._configure_sanitize_tag_style()

        for tree in (
            getattr(self, "fields_tree", None),
            getattr(self, "tmpl_tree", None),
            getattr(self, "incidents_tree", None),
            getattr(self, "notes_tree", None),
            getattr(self, "sanitize_keywords_tree", None),
            getattr(self, "mapping_tree", None),
        ):
            if tree is not None:
                tree.tag_configure("evenrow", background=p["tree_bg"], foreground=p["fg"])
                tree.tag_configure("oddrow", background=p["tree_alt"], foreground=p["fg"])

        # VT overlay labels (see _sync_vt_overlays) track their own
        # color/font directly rather than through ttk styles - rebuild
        # their position/color/font here too so they follow theme/font
        # size changes exactly like every other themed widget in the app.
        if hasattr(self, "fields_tree"):
            self.after_idle(self._sync_vt_overlays)

        # native popups (dropdown lists, menus) - best effort, some
        # platforms render these natively and ignore a few of these
        self.option_add("*TCombobox*Listbox.background", p["text_bg"])
        self.option_add("*TCombobox*Listbox.foreground", p["text_fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", p["select_bg"])
        self.option_add("*TCombobox*Listbox.selectForeground", p["fg"])
        self.option_add("*Menu.background", p["panel"])
        self.option_add("*Menu.foreground", p["fg"])
        self.option_add("*Menu.activeBackground", p["select_bg"])
        self.option_add("*Menu.activeForeground", p["fg"])

    @staticmethod
    def _zebra_tags(index):
        return ("evenrow",) if index % 2 == 0 else ("oddrow",)

    # ------------------------------------------------------------------
    # Font size (A-/A+ in the header, or Ctrl+-/Ctrl+=/Ctrl+0)
    # ------------------------------------------------------------------

    def _set_font_size(self, size):
        size = max(FONT_SIZE_MIN, min(FONT_SIZE_MAX, size))
        if size == self.font_size:
            return
        self.font_size = size
        self._apply_theme(self.theme_name)
        if hasattr(self, "font_size_var"):
            self.font_size_var.set(f"{self.font_size}pt")

    def _increase_font_size(self):
        self._set_font_size(self.font_size + FONT_SIZE_STEP)

    def _decrease_font_size(self):
        self._set_font_size(self.font_size - FONT_SIZE_STEP)

    def _reset_font_size(self):
        self._set_font_size(FONT_SIZE_DEFAULT)

    # ------------------------------------------------------------------
    # Right-click edit menu (Cut/Copy/Paste/Select All/Undo/Redo) + spell-check
    # ------------------------------------------------------------------

    def _show_edit_context_menu(self, event):
        widget = event.widget
        is_text = isinstance(widget, tk.Text)
        if not is_text and not isinstance(widget, (tk.Entry, ttk.Entry)):
            return
        try:
            disabled = str(widget.cget("state")) == "disabled"
        except tk.TclError:
            disabled = False

        # Reposition the cursor to the click point, unless the click
        # landed inside the current selection - moving it there would
        # otherwise wipe out a selection the analyst is about to Copy/Cut.
        click_in_selection = False
        try:
            if is_text and widget.tag_ranges("sel"):
                sel_start, sel_end = widget.tag_ranges("sel")
                click_index = widget.index(f"@{event.x},{event.y}")
                if widget.compare(sel_start, "<=", click_index) and widget.compare(click_index, "<", sel_end):
                    click_in_selection = True
            elif not is_text and widget.selection_present():
                click_index = widget.index(f"@{event.x}")
                if widget.index("sel.first") <= click_index < widget.index("sel.last"):
                    click_in_selection = True
        except tk.TclError:
            click_in_selection = False

        if not click_in_selection and not disabled:
            try:
                widget.focus_set()
                if is_text:
                    widget.mark_set("insert", f"@{event.x},{event.y}")
                else:
                    widget.icursor(f"@{event.x}")
            except tk.TclError:
                pass

        p = THEMES[self.theme_name]
        menu = tk.Menu(
            self, tearoff=0, background=p["panel"], foreground=p["fg"],
            activebackground=p["select_bg"], activeforeground=p["fg"],
        )

        # If this box has spell-check enabled and the click landed on a
        # word flagged "misspelled", offer suggestions + "Add to
        # Dictionary" above the usual cut/copy/paste items.
        if is_text and widget in self._spellcheck_widgets:
            try:
                index = widget.index(f"@{event.x},{event.y}")
                tag_range = widget.tag_prevrange("misspelled", f"{index}+1c")
            except tk.TclError:
                tag_range = None
            if (
                tag_range
                and widget.compare(tag_range[0], "<=", index)
                and widget.compare(index, "<", tag_range[1])
            ):
                word = widget.get(*tag_range)
                suggestions = spelling_suggestions(word)
                if suggestions:
                    for s in suggestions:
                        menu.add_command(
                            label=s,
                            command=lambda w=widget, r=tag_range, s=s: self._apply_spelling_suggestion(w, r, s),
                        )
                else:
                    menu.add_command(label="No suggestions", state="disabled")
                menu.add_command(
                    label=f'Add "{word}" to Dictionary',
                    command=lambda w=word: self._add_to_dictionary(w),
                )
                menu.add_separator()

        if is_text:
            try:
                undo_supported = bool(widget.cget("undo"))
            except tk.TclError:
                undo_supported = False
            if undo_supported:
                menu.add_command(label="Undo", command=lambda: self._safe_edit_action(widget, "undo"))
                menu.add_command(label="Redo", command=lambda: self._safe_edit_action(widget, "redo"))
                menu.add_separator()

        menu.add_command(
            label="Cut", state="disabled" if disabled else "normal",
            command=lambda: widget.event_generate("<<Cut>>"),
        )
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(
            label="Paste", state="disabled" if disabled else "normal",
            command=lambda: widget.event_generate("<<Paste>>"),
        )
        menu.add_separator()
        menu.add_command(label="Select All", command=lambda: self._select_all_in_widget(widget))

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    @staticmethod
    def _select_all_in_widget(widget):
        widget.focus_set()
        if isinstance(widget, tk.Text):
            widget.tag_add("sel", "1.0", "end-1c")
            widget.mark_set("insert", "end-1c")
        else:
            widget.selection_range(0, "end")
            widget.icursor("end")

    @staticmethod
    def _safe_edit_action(widget, action_name):
        try:
            if action_name == "undo":
                widget.edit_undo()
            else:
                widget.edit_redo()
        except tk.TclError:
            pass

    def _enable_spellcheck(self, widget):
        """Turn on live spell-check underlines for one prose Text box.

        Scoped deliberately to just the Analysis box - raw logs, JSON
        paths, Sanitize boxes, and Ticket Output/Notes/Template editor
        are all excluded (either full of legitimate non-dictionary
        tokens that would just add noise, or - per the analyst's own
        preference - simply not needed there).
        """
        self._spellcheck_widgets.add(widget)
        widget.bind("<<Modified>>", self._on_prose_text_modified, add="+")
        self.after_idle(lambda: self._run_spellcheck(widget))

    def _on_prose_text_modified(self, event=None):
        widget = event.widget
        if not widget.edit_modified():
            return
        widget.edit_modified(False)
        if widget not in self._spellcheck_widgets:
            return
        after_id = self._spellcheck_after_ids.pop(widget, None)
        if after_id is not None:
            try:
                self.after_cancel(after_id)
            except tk.TclError:
                pass
        self._spellcheck_after_ids[widget] = self.after(500, lambda: self._run_spellcheck(widget))

    def _run_spellcheck(self, widget):
        self._spellcheck_after_ids.pop(widget, None)
        if not widget.winfo_exists():
            return
        widget.tag_remove("misspelled", "1.0", "end")
        text = widget.get("1.0", "end-1c")
        if not text.strip():
            return
        known = self._custom_dictionary_words()
        for start, end, _word in find_misspelled_word_spans(text, known_words=known):
            widget.tag_add("misspelled", f"1.0+{start}c", f"1.0+{end}c")

    def _custom_dictionary_words(self):
        try:
            return [w["word"] for w in self.db.list_custom_dictionary_words()]
        except Exception:
            return []

    def _apply_spelling_suggestion(self, widget, range_, replacement):
        start, end = range_
        widget.delete(start, end)
        widget.insert(start, replacement)
        self._run_spellcheck(widget)

    def _add_to_dictionary(self, word):
        try:
            self.db.add_custom_dictionary_word(word)
        except Exception:
            pass
        for widget in self._spellcheck_widgets:
            if widget.winfo_exists():
                self._run_spellcheck(widget)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Incident", command=self.new_incident)
        file_menu.add_command(label="Save Incident", command=self.save_incident)
        file_menu.add_separator()
        file_menu.add_command(label="Export Output", command=self.export_output)
        file_menu.add_separator()
        file_menu.add_command(label="Backup Database", command=self.backup_database)
        file_menu.add_command(label="Restore Database", command=self.restore_database)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Increase Font Size", command=self._increase_font_size, accelerator="Ctrl+=")
        view_menu.add_command(label="Decrease Font Size", command=self._decrease_font_size, accelerator="Ctrl+-")
        view_menu.add_command(label="Reset Font Size", command=self._reset_font_size, accelerator="Ctrl+0")
        menubar.add_cascade(label="View", menu=view_menu)

        self.config(menu=menubar)

    def backup_database(self):
        """Copy the live alertforge.db (templates, incidents, notes - not
        field_mappings.json, which has its own export/import) to a
        location the analyst chooses, as a simple point-in-time backup."""
        path = filedialog.asksaveasfilename(
            defaultextension=".db", filetypes=[("SQLite Database", "*.db")],
            initialfile="alertforge_backup.db",
        )
        if not path:
            return
        try:
            self.db.conn.commit()
            shutil.copy2(DB_PATH, path)
        except OSError as e:
            messagebox.showerror("Backup Failed", f"Could not create backup:\n{e}")
            return
        messagebox.showinfo("Backup Created", f"Database backed up to:\n{path}")

    def restore_database(self):
        """Replace the live database with a previously backed-up .db
        file. Closes the current connection before copying over
        alertforge.db so the file isn't held open, then reopens it and
        refreshes every tab that reads from the DB."""
        path = filedialog.askopenfilename(filetypes=[("SQLite Database", "*.db"), ("All files", "*.*")])
        if not path:
            return
        if not messagebox.askyesno(
            "Restore Database",
            "This will replace ALL current templates, incidents, and notes "
            "with the contents of the selected backup file. This cannot be "
            "undone.\n\nContinue?",
        ):
            return
        try:
            self.db.close()
            shutil.copy2(path, DB_PATH)
        except OSError as e:
            messagebox.showerror("Restore Failed", f"Could not restore database:\n{e}")
        finally:
            self.db = DB(DB_PATH)
        self.current_incident_id = None
        self.current_incident_title = None
        self._refresh_template_lists()
        self._refresh_incident_list()
        self._refresh_notes_list()
        messagebox.showinfo("Restored", "Database restored. The app has been refreshed with the restored data.")

    def _build_ui(self):
        header = ttk.Frame(self, padding=(16, 12), style="Header.TFrame")
        header.pack(fill=tk.X)
        # Plain tk.Label, not ttk.Label - ttk's "AppTitle.TLabel" style
        # reliably applies its font at first render, but on at least some
        # Windows/Tk builds a *later* style.configure() font change (e.g.
        # from the A-/A+ controls) doesn't visibly propagate to an
        # already-mapped ttk.Label using that style, even though every
        # other ttk-styled widget in the app (buttons, tabs, tree
        # headings) updates correctly the same way. A plain tk.Label's
        # font is set directly via .configure() in _apply_theme below
        # (the same pattern already used for the tk.Text boxes, which
        # ttk styling never reaches at all), sidestepping that quirk
        # entirely so the title reliably tracks the app-wide font size.
        self.title_label = tk.Label(header, text=APP_TITLE, borderwidth=0, highlightthickness=0)
        self.title_label.pack(side=tk.LEFT)
        # Version number, small and muted, right after the title - so
        # anyone reporting an issue (or checking whether they're on the
        # latest build after a SharePoint update) can see at a glance
        # what they're running without opening a separate About dialog.
        # Plain tk.Label for the same font-size-tracking reason as
        # title_label/subtitle_label (see comment above).
        self.version_label = tk.Label(header, text=f"v{APP_VERSION}", borderwidth=0, highlightthickness=0)
        self.version_label.pack(side=tk.LEFT, padx=(6, 0))
        # Tagline next to the title - plain tk.Label for the same reason
        # as title_label above (guaranteed to track font-size changes).
        self.subtitle_label = tk.Label(header, text=APP_TAGLINE, borderwidth=0, highlightthickness=0)
        self.subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        self.dark_mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            header, text="Dark Mode", variable=self.dark_mode_var,
            command=self._toggle_dark_mode, style="Toggle.TCheckbutton",
        ).pack(side=tk.RIGHT)

        font_size_frame = ttk.Frame(header, style="Header.TFrame")
        font_size_frame.pack(side=tk.RIGHT, padx=(0, 16))
        ttk.Button(font_size_frame, text="A-", width=3, command=self._decrease_font_size).pack(side=tk.LEFT)
        self.font_size_var = tk.StringVar(value=f"{self.font_size}pt")
        ttk.Label(font_size_frame, textvariable=self.font_size_var, style="Subtitle.TLabel", width=5, anchor="center").pack(side=tk.LEFT, padx=2)
        ttk.Button(font_size_frame, text="A+", width=3, command=self._increase_font_size).pack(side=tk.LEFT)

        ttk.Separator(self, orient="horizontal").pack(fill=tk.X)

        self.notebook = ttk.Notebook(self, padding=(6, 6))
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.workspace_tab = ttk.Frame(self.notebook)
        self.templates_tab = ttk.Frame(self.notebook)
        self.query_tab = ttk.Frame(self.notebook)
        self.incidents_tab = ttk.Frame(self.notebook)
        self.notes_tab = ttk.Frame(self.notebook)
        self.sanitize_tab = ttk.Frame(self.notebook)
        self.texttools_tab = ttk.Frame(self.notebook)
        self.mapping_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.workspace_tab, text="Incident Workspace")
        self.notebook.add(self.templates_tab, text="Templates")
        self.notebook.add(self.query_tab, text="Query Builder")
        self.notebook.add(self.incidents_tab, text="Incidents")
        self.notebook.add(self.notes_tab, text="Notes")
        self.notebook.add(self.sanitize_tab, text="Sanitize Logs")
        self.notebook.add(self.texttools_tab, text="Text Tools")
        self.notebook.add(self.mapping_tab, text="Field Mappings (Advanced)")

        self._build_workspace_tab()
        self._build_templates_tab()
        self._build_query_tab()
        self._build_incidents_tab()
        self._build_notes_tab()
        self._build_sanitize_tab()
        self._build_texttools_tab()
        self._build_mapping_tab()

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        self._last_tab_index = self.notebook.index(self.notebook.select())

    def _on_tab_changed(self, event):
        new_index = self.notebook.index(self.notebook.select())
        if self._last_tab_index == self.notebook.index(self.notes_tab):
            # Leaving the Notes tab - autosave whatever's open in the
            # editor rather than requiring an explicit Save Note click.
            self._note_autosave()
            self._refresh_notes_list()
            if self._selected_note_id and str(self._selected_note_id) in self.notes_tree.get_children():
                self.notes_tree.selection_set(str(self._selected_note_id))
        if new_index == 0:
            self._refresh_template_combo()
        self._last_tab_index = new_index
        # A tab that hasn't been selected before is only just now being
        # mapped for the first time, so any WrapToolbar living inside it
        # may have missed its own real <Configure> event entirely (it
        # would have seen winfo_width()==1 the one time it tried to
        # reflow while still unmapped). Force every toolbar to recompute
        # now that this tab's real geometry exists.
        self.after_idle(WrapToolbar.reflow_all)

    # ---- Incident Workspace tab ----

    def _build_workspace_tab(self):
        top = WrapToolbar(self.workspace_tab, padding=(8, 8))
        top.pack(fill=tk.X)

        top.add(ttk.Button(top, text="New Incident", command=self.new_incident, style="Accent.TButton"), padx=0)
        top.add(ttk.Button(top, text="Save Incident", command=self.save_incident, style="Accent.TButton"), padx=6)
        top.add(ttk.Button(top, text="Clear All", command=self.clear_all), padx=6)
        self.incident_status_var = tk.StringVar(value="Unsaved incident")
        top.add(ttk.Label(top, textvariable=self.incident_status_var, style="Muted.TLabel"), padx=10)

        paned = ttk.PanedWindow(self.workspace_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # ---- left: raw logs + extracted fields ----
        left = ttk.Frame(paned)
        paned.add(left, weight=1)

        ttk.Label(left, text="Paste Logs:", style="Section.TLabel").pack(anchor="w", pady=(0, 2))
        self.raw_logs_text = tk.Text(left, height=14, wrap="none", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.raw_logs_text.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self._text_widgets.append((self.raw_logs_text, MONO_FAMILY, 0))

        btn_row = WrapToolbar(left)
        btn_row.pack(fill=tk.X, pady=(0, 6))
        btn_row.add(ttk.Button(btn_row, text="Parse Logs", command=self.parse_logs, style="Accent.TButton"), padx=0)
        btn_row.add(ttk.Button(btn_row, text="Clear Logs", command=lambda: self.raw_logs_text.delete("1.0", tk.END)), padx=6)
        btn_row.add(ttk.Label(btn_row, text="Profile:"), padx=(10, 0))
        self.profile_override_var = tk.StringVar(value=self.PROFILE_OVERRIDE_AUTO)
        # Readonly so an analyst can only ever pick from real, currently-
        # loaded profiles (kept in sync by _refresh_mapping_tree, the same
        # place the Field Mappings tab's own profile list is refreshed) -
        # never a stale/free-typed profile name. Defaults to Auto-detect,
        # the normal behavior; only needs to be touched when auto-detect
        # picks the wrong profile for a log (two profiles sharing generic
        # field names, a brand new log type, etc.).
        self.profile_override_combo = ttk.Combobox(
            btn_row, textvariable=self.profile_override_var, state="readonly", width=26
        )
        self.profile_override_combo["values"] = [self.PROFILE_OVERRIDE_AUTO]
        btn_row.add(self.profile_override_combo, padx=4)
        self.parse_status_var = tk.StringVar(value="No logs parsed yet.")
        btn_row.add(ttk.Label(btn_row, textvariable=self.parse_status_var, style="Muted.TLabel"), padx=10)

        ttk.Label(left, text="Extracted fields:", style="Section.TLabel").pack(anchor="w", pady=(4, 2))
        columns = ("field", "value", "vt")
        self.fields_tree = ttk.Treeview(left, columns=columns, show="headings", height=10)
        self.fields_tree.heading("field", text="Field")
        self.fields_tree.heading("value", text="Value")
        self.fields_tree.heading("vt", text="")
        self.fields_tree.column("field", width=150, anchor="w")
        self.fields_tree.column("value", width=320, anchor="w")
        # Narrow and non-stretching - just wide enough for the "VT" link
        # text, never eats space from the Value column as the pane resizes.
        self.fields_tree.column("vt", width=48, anchor="center", stretch=False)
        self.fields_tree.pack(fill=tk.BOTH, expand=True, pady=(2, 0))
        # Clicking a row's Value cell copies just that value to the
        # clipboard - a quick way to grab one IP/hash/hostname without
        # selecting the text by hand. Clicking a row's VT cell (only
        # populated when the value is - in its entirety - an IP or a
        # file hash) opens a VirusTotal lookup for that value in the
        # default browser. Row selection still happens too (this doesn't
        # replace the Treeview's own click handling).
        self.fields_tree.bind("<Button-1>", self._on_fields_tree_click)

        # ttk.Treeview can only style a whole ROW (via tags), never one
        # cell differently from the rest of that same row - so to make
        # just the "VT" cell look like a real hyperlink (accent color,
        # underlined, hand cursor) while leaving Field/Value alone, a
        # small pool of real tk.Label widgets is placed exactly on top of
        # each VT-eligible cell's pixel position via .place(), reused and
        # repositioned every time the tree's content, scroll position, or
        # selection changes (see _sync_vt_overlays). This is the standard
        # workaround for "styled/interactive content in one Treeview
        # cell" - ttk has no native support for it.
        self._vt_overlay_labels = []
        self._vt_tooltip = None
        for seq in (
            "<Configure>", "<MouseWheel>", "<Button-4>", "<Button-5>",
            "<KeyPress-Up>", "<KeyPress-Down>", "<KeyPress-Prior>", "<KeyPress-Next>",
            "<KeyPress-Home>", "<KeyPress-End>", "<<TreeviewSelect>>",
        ):
            self.fields_tree.bind(seq, lambda e: self.after_idle(self._sync_vt_overlays))
        self._populate_fields_tree()

        # ---- right: analysis + templates + output ----
        right = ttk.Frame(paned)
        paned.add(right, weight=1)

        analysis_header = ttk.Frame(right)
        analysis_header.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(analysis_header, text="Analysis:", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(analysis_header, text="Copy Analysis", command=self.copy_analysis).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(analysis_header, text="Clear Analysis", command=lambda: self.analysis_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=(6, 0))
        self.analysis_text = tk.Text(right, height=8, wrap="word", undo=True, font=(FONT_FAMILY, 10), borderwidth=0)
        self.analysis_text.pack(fill=tk.BOTH, expand=False, pady=(2, 6))
        self._text_widgets.append((self.analysis_text, FONT_FAMILY, 0))
        self._enable_spellcheck(self.analysis_text)
        # Live-highlights unresolved #tag/{field}/[field] placeholders
        # typed directly into Analysis, same as the Ticket Output box -
        # bound add="+" alongside the spell-check handler above, which
        # owns checking/resetting the widget's <<Modified>> flag (see
        # _on_analysis_text_modified's docstring for why this one doesn't
        # repeat that check).
        self.analysis_text.bind("<<Modified>>", self._on_analysis_text_modified, add="+")

        tmpl_row = WrapToolbar(right)
        tmpl_row.pack(fill=tk.X, pady=(0, 4))
        tmpl_row.add(ttk.Label(tmpl_row, text="Template:"), padx=0)
        self.template_combo_var = tk.StringVar()
        # Kept narrow (rather than a very wide fixed width) so this whole
        # row still fits - or cleanly wraps via WrapToolbar - in a
        # half-monitor split-screen layout; the readonly Combobox still
        # shows the full label in its dropdown list even when the
        # closed-state field itself is too narrow to show all of it.
        self.template_combo = ttk.Combobox(tmpl_row, textvariable=self.template_combo_var, state="readonly", width=22)
        # The closed-state field stays narrow (above), but the dropdown
        # POPUP list widens to fit the longest template name every time
        # it's opened, so long names are never cut off just because the
        # row itself has to stay compact - see _widen_template_combo_popdown.
        self.template_combo.configure(postcommand=self._widen_template_combo_popdown)
        tmpl_row.add(self.template_combo, padx=6)
        tmpl_row.add(ttk.Button(tmpl_row, text="Insert Filled Template", command=self.insert_filled_template, style="Accent.TButton"), padx=4)

        insert_row = WrapToolbar(right)
        insert_row.pack(fill=tk.X, pady=(0, 4))
        insert_row.add(ttk.Label(insert_row, text="Insert:"), padx=0)
        insert_row.add(ttk.Button(insert_row, text="Analysis", command=self.insert_analysis), padx=3)
        insert_row.add(ttk.Button(insert_row, text="Extracted Fields Summary", command=self.insert_field_summary), padx=3)
        insert_row.add(ttk.Button(insert_row, text="Raw Log", command=self.insert_raw_log), padx=3)

        out_btn_row = WrapToolbar(right)
        out_btn_row.pack(fill=tk.X, pady=(0, 6))
        out_btn_row.add(ttk.Button(out_btn_row, text="Copy Output to Clipboard", command=self.copy_output, style="Accent.TButton"), padx=0)
        out_btn_row.add(ttk.Button(out_btn_row, text="Resolve #Tags in Output", command=self.resolve_tags_in_output), padx=6)
        out_btn_row.add(ttk.Button(out_btn_row, text="Remove Unresolved Tags", command=self.remove_unresolved_tags_in_output), padx=6)
        out_btn_row.add(ttk.Button(out_btn_row, text="Clear Output", command=lambda: self.output_text.delete("1.0", tk.END)), padx=6)

        ttk.Label(right, text="Ticket Output:", style="Section.TLabel").pack(anchor="w", pady=(0, 2))
        self.output_text = tk.Text(right, height=14, wrap="word", undo=True, font=(FONT_FAMILY, 10), borderwidth=0)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self._text_widgets.append((self.output_text, FONT_FAMILY, 0))
        # Live-highlights unresolved #tag/{field}/[field] placeholders in
        # bold yellow - <<Modified>> fires on typing, pasting (any
        # method), Undo/Redo, and every programmatic insert/delete this
        # app does to the box, so one binding covers all of those.
        self.output_text.bind("<<Modified>>", self._on_output_modified)

        self._refresh_template_combo()

    def _populate_fields_tree(self):
        for row in self.fields_tree.get_children():
            self.fields_tree.delete(row)
        for i, key in enumerate(self.field_order):
            value = self.extracted.get(key, "")
            # Plain "VT" text as a fallback in the real Treeview cell -
            # this is what's visible for a split second before the
            # colored/underlined overlay label (see _sync_vt_overlays)
            # gets positioned on top of it, and stays visible if that
            # overlay is ever late/absent for some reason, so the row
            # never goes silently blank. No arrow glyph here on purpose:
            # not every font on every Windows install has one, and it
            # rendered as a broken/missing glyph rather than degrading
            # gracefully - the color+underline+hand-cursor of the overlay
            # communicates "clickable" reliably instead.
            vt_text = "VT" if virustotal_url(value) else ""
            self.fields_tree.insert(
                "", tk.END, iid=key, values=(field_label(key), value, vt_text),
                tags=self._zebra_tags(i),
            )
        self.after_idle(self._sync_vt_overlays)

    def _vt_overlay_pool(self, count):
        """Returns a list of at least `count` reusable tk.Label overlay
        widgets (creating new ones as needed, never destroying old ones -
        they're just hidden with place_forget() and reused next time)."""
        while len(self._vt_overlay_labels) < count:
            lbl = tk.Label(self.fields_tree, text="VT", borderwidth=0, highlightthickness=0, cursor="hand2")
            lbl.bind("<Button-1>", self._on_vt_overlay_click)
            lbl.bind("<Enter>", self._on_vt_overlay_enter)
            lbl.bind("<Leave>", self._on_vt_overlay_leave)
            self._vt_overlay_labels.append(lbl)
        return self._vt_overlay_labels

    def _sync_vt_overlays(self):
        """Repositions (or hides) every VT overlay label so each one sits
        exactly on top of a currently-VISIBLE, VT-eligible row's 'vt'
        cell - called after the Extracted Fields table is rebuilt, and on
        every event that could change which rows are visible or selected
        (resize, scroll, keyboard navigation, selection change - see the
        bindings in _build_workspace_tab). A Treeview has no single
        "scrolled" event, so this over-subscribes to plausible triggers
        rather than risk a stale/misplaced overlay."""
        if not hasattr(self, "fields_tree") or not self.fields_tree.winfo_exists():
            return
        p = THEMES[self.theme_name]
        selected = set(self.fields_tree.selection())
        eligible = []
        for i, key in enumerate(self.field_order):
            if virustotal_url(self.extracted.get(key, "")):
                bbox = self.fields_tree.bbox(key, column="vt")
                if bbox:
                    eligible.append((key, bbox, i))
        labels = self._vt_overlay_pool(len(eligible))
        for idx, lbl in enumerate(labels):
            if idx >= len(eligible):
                lbl.place_forget()
                lbl._vt_key = None
                continue
            key, (x, y, w, h), row_idx = eligible[idx]
            bg = p["select_bg"] if key in selected else (p["tree_bg"] if row_idx % 2 == 0 else p["tree_alt"])
            lbl.configure(text="VT", background=bg, foreground=p["accent"], font=(FONT_FAMILY, self.font_size, "underline"))
            lbl._vt_key = key
            lbl.place(x=x, y=y, width=w, height=h)
        self._hide_vt_tooltip()

    def _open_vt_link(self, key):
        """Opens a VirusTotal lookup for field `key`'s current value in
        the default browser, or reports why it can't (blank, or not a
        recognized IP/hash) in the status line."""
        value = self.extracted.get(key, "")
        url = virustotal_url(value)
        if not url:
            self.parse_status_var.set(
                f"{field_label(key)} isn't a plain IP address or file hash - no VirusTotal lookup available."
            )
            return
        webbrowser.open(url)
        self.parse_status_var.set(f"Opened VirusTotal lookup for {value} in your browser.")

    def _on_vt_overlay_click(self, event):
        key = getattr(event.widget, "_vt_key", None)
        if key:
            self._open_vt_link(key)

    def _on_vt_overlay_enter(self, event):
        key = getattr(event.widget, "_vt_key", None)
        if not key:
            return
        url = virustotal_url(self.extracted.get(key, ""))
        if url:
            self._show_vt_tooltip(event.widget, url)

    def _on_vt_overlay_leave(self, event):
        self._hide_vt_tooltip()

    def _show_vt_tooltip(self, widget, text):
        """A small borderless popup showing the exact URL a VT link
        points to, positioned just below the hovered cell - so an
        analyst can see where they're about to be sent before clicking,
        the same way a browser's status bar previews a link target."""
        self._hide_vt_tooltip()
        p = THEMES[self.theme_name]
        tip = tk.Toplevel(self)
        tip.overrideredirect(True)
        tip.attributes("-topmost", True)
        x = widget.winfo_rootx()
        y = widget.winfo_rooty() + widget.winfo_height() + 2
        tip.geometry(f"+{x}+{y}")
        tk.Label(
            tip, text=text, background=p["panel"], foreground=p["fg"],
            font=(FONT_FAMILY, max(FONT_SIZE_MIN, self.font_size - 1)),
            borderwidth=1, relief="solid", padx=6, pady=3,
        ).pack()
        self._vt_tooltip = tip

    def _hide_vt_tooltip(self):
        tip = getattr(self, "_vt_tooltip", None)
        if tip is not None:
            try:
                tip.destroy()
            except tk.TclError:
                pass
            self._vt_tooltip = None

    def _on_fields_tree_click(self, event):
        """Clicking the 'Value' column of the Extracted Fields table
        copies just that field's value to the clipboard - handy for
        grabbing a single IP/hash/hostname to paste elsewhere without
        selecting the text by hand. The 'VT' column's own click handling
        normally happens on the overlay label sitting on top of it (see
        _on_vt_overlay_click) - the '#3' case here is just a fallback for
        the rare moment an eligible row's overlay hasn't been positioned
        yet. Clicking the 'Field' column, a heading, or empty space does
        nothing extra; the Treeview's own row-selection behavior still
        happens either way."""
        if self.fields_tree.identify_region(event.x, event.y) != "cell":
            return
        col = self.fields_tree.identify_column(event.x)
        key = self.fields_tree.identify_row(event.y)
        if not key:
            return
        if col == "#3":
            self._open_vt_link(key)
            return
        if col != "#2":
            return
        value = self.extracted.get(key, "")
        if not value:
            self.parse_status_var.set(f"{field_label(key)} is blank - nothing to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        shown = value if len(value) <= 60 else value[:57] + "..."
        self.parse_status_var.set(f"Copied {field_label(key)} to clipboard: {shown}")

    def parse_logs(self):
        if self.mapper is None:
            messagebox.showerror("Field Mapping Error", "field_mappings.json failed to load; parsing is unavailable.")
            return
        raw = self.raw_logs_text.get("1.0", tk.END)
        forced_profile_id = None
        override_label = self.profile_override_var.get()
        if override_label and override_label != self.PROFILE_OVERRIDE_AUTO:
            forced_profile_id = self._mapping_profile_id_by_label.get(override_label)
        result = self.mapper.parse(raw, forced_profile_id=forced_profile_id)
        self.extracted = result["canonical"]
        self.field_order = result.get("field_order", list(CANONICAL_FIELDS))
        self._populate_fields_tree()
        if result["label"]:
            status = f"Detected: {result['label']}"
        else:
            status = "Could not parse input."
        if result["warnings"]:
            status += "  |  " + " ".join(result["warnings"])
        self.parse_status_var.set(status)
        if not result["matched"] and result["label"]:
            messagebox.showinfo(
                "Unrecognized Log Format",
                "No known log profile matched this log, so generic field "
                "matching was used. Review the extracted fields for "
                "accuracy, and consider adding a profile for this log "
                "source in the 'Field Mappings' tab.",
            )

    def _context_data(self):
        data = dict(self.extracted)
        # Makes the analyst's free-form analysis text available as
        # #analysis / {analysis} in templates - most useful for "Insert
        # Filled Template", so a template can pull in whatever's already
        # been typed in the Analysis box instead of the analyst re-typing
        # or copy/pasting it in by hand.
        data["analysis"] = self.analysis_text.get("1.0", tk.END).strip()
        return data

    def _auto_title(self):
        bits = []
        if self.extracted.get("event_type"):
            bits.append(self.extracted["event_type"])
        who = self.extracted.get("host") or self.extracted.get("user")
        if who:
            bits.append(who)
        if bits:
            return " - ".join(bits)
        return "Incident " + datetime.now().strftime("%Y-%m-%d %H:%M")

    def insert_filled_template(self):
        sel = self.template_combo_var.get()
        tid = self._template_id_by_label.get(sel)
        if not tid:
            messagebox.showwarning("No Template Selected", "Choose a template first.")
            return
        tmpl = self.db.get_template(tid)
        if not tmpl:
            return
        filled = fill_template(tmpl["body"], self._context_data())
        self._append_output(f"{filled}\n")

    def insert_analysis(self):
        text = self.analysis_text.get("1.0", tk.END).strip()
        if text:
            text = fill_template(text, self._context_data())
            self._append_output(f"{text}\n")

    def insert_field_summary(self):
        lines = [f"{field_label(k)}: {self.extracted[k]}" for k in self.field_order if self.extracted.get(k)]
        if not lines and self.raw_logs_text.get("1.0", tk.END).strip():
            # Nothing parsed yet, but there's a log pasted and waiting -
            # parse it automatically rather than making the analyst click
            # Parse Logs first just to reach this summary.
            self.parse_logs()
            lines = [f"{field_label(k)}: {self.extracted[k]}" for k in self.field_order if self.extracted.get(k)]
        if not lines:
            messagebox.showinfo("Nothing to Insert", "No extracted fields yet - parse a log first.")
            return
        self._append_output("_____________\nAlert Details:\n\n" + "\n".join(lines) + "\n")

    def insert_raw_log(self):
        # Same separator/header/blank-line format as Extracted Fields
        # Summary - this is the fallback an analyst reaches for when a log
        # doesn't have fields worth extracting, so the two should look
        # consistent in the final ticket write-up.
        raw = self.raw_logs_text.get("1.0", tk.END).strip()
        if raw:
            self._append_output("_____________\nAlert Details:\n\n" + f"{raw}\n")

    def resolve_tags_in_output(self):
        """Re-run #tag / {field} substitution against the current output
        text using whatever fields are currently parsed. Lets an analyst
        type tags like #source_ip directly into their notes and resolve
        them in place, not just when inserting a template."""
        text = self.output_text.get("1.0", tk.END)
        filled = fill_template(text, self._context_data())
        if filled != text:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, filled.rstrip("\n") + "\n" if text.strip() else filled)
            self.parse_status_var.set("Tags resolved in output.")
        else:
            self.parse_status_var.set("No recognized tags found to resolve.")

    def remove_unresolved_tags_in_output(self):
        """Delete every #tag/{field}/[field] placeholder still sitting
        unresolved in the output box (the same ones flagged yellow by
        _highlight_unresolved_tags) instead of leaving them as stray
        literal text - for a placeholder that just isn't going to be
        filled in (an analyst typed #analysis into a template that
        didn't end up needing it, say) rather than one that's missing a
        value it should have."""
        text = self.output_text.get("1.0", tk.END)
        cleaned = remove_unresolved_tags(text, self._known_tag_fields())
        if cleaned != text:
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, cleaned.rstrip("\n") + "\n" if text.strip() else cleaned)
            self.parse_status_var.set("Removed unresolved tags from output.")
        else:
            self.parse_status_var.set("No unresolved tags found to remove.")

    def _append_output(self, text):
        if self.output_text.get("1.0", tk.END).strip():
            self.output_text.insert(tk.END, "\n" + text)
        else:
            self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)

    def copy_analysis(self):
        text = self.analysis_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.parse_status_var.set("Analysis copied to clipboard.")

    def copy_output(self):
        text = self.output_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.parse_status_var.set("Output copied to clipboard.")

    def export_output(self):
        text = self.output_text.get("1.0", tk.END)
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)

    def new_incident(self):
        self.current_incident_id = None
        self.current_incident_title = None
        self.raw_logs_text.delete("1.0", tk.END)
        self.analysis_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.extracted = {k: "" for k in CANONICAL_FIELDS}
        self.field_order = list(CANONICAL_FIELDS)
        self._populate_fields_tree()
        self.parse_status_var.set("No logs parsed yet.")
        self.incident_status_var.set("Unsaved incident")
        # Reset the profile override back to Auto-detect - otherwise a
        # profile forced for the previous incident's log would silently
        # keep being forced onto whatever unrelated log gets pasted next.
        self.profile_override_var.set(self.PROFILE_OVERRIDE_AUTO)

    def clear_all(self):
        """Clear the raw logs, extracted fields, analysis, and output
        boxes in one shot. Unlike New Incident, this does NOT detach from
        whatever incident is currently loaded (its id/title are left
        alone) - it's just a quick way to wipe the workspace and start
        typing again, e.g. after copying the output elsewhere. Use New
        Incident instead if you want a completely fresh, unsaved
        incident."""
        self.raw_logs_text.delete("1.0", tk.END)
        self.analysis_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.extracted = {k: "" for k in CANONICAL_FIELDS}
        self.field_order = list(CANONICAL_FIELDS)
        self._populate_fields_tree()
        self.parse_status_var.set("No logs parsed yet.")

    def save_incident(self):
        # A brand-new incident gets an auto-generated title (event type +
        # host/user). An incident that's already been saved keeps
        # whatever title it currently has - including one the analyst set
        # via Rename - instead of silently overwriting it with a
        # recomputed auto-title on every save.
        title = self.current_incident_title if (self.current_incident_id and self.current_incident_title) else self._auto_title()
        raw_logs = self.raw_logs_text.get("1.0", tk.END)
        analysis = self.analysis_text.get("1.0", tk.END)
        output = self.output_text.get("1.0", tk.END)
        extracted_json = json.dumps({"canonical": self.extracted, "field_order": self.field_order})

        if self.current_incident_id:
            self.db.update_incident(self.current_incident_id, title, raw_logs, analysis, output, extracted_json)
        else:
            self.current_incident_id = self.db.add_incident(title, raw_logs, analysis, output, extracted_json)

        self.current_incident_title = title
        self._refresh_incident_list()
        self.incident_status_var.set(f"Saved: {title}")
        messagebox.showinfo("Saved", f"Incident '{title}' saved.")

    def load_incident_into_workspace(self, incident):
        self.current_incident_id = incident["id"]
        self.current_incident_title = incident["title"]
        self.raw_logs_text.delete("1.0", tk.END)
        self.raw_logs_text.insert(tk.END, incident["raw_logs"] or "")
        self.analysis_text.delete("1.0", tk.END)
        self.analysis_text.insert(tk.END, incident["analysis"] or "")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, incident["output"] or "")
        try:
            stored = json.loads(incident["extracted_json"] or "{}")
            if isinstance(stored, dict) and "canonical" in stored:
                self.extracted = stored.get("canonical", {})
                self.field_order = stored.get("field_order") or list(self.extracted.keys()) or list(CANONICAL_FIELDS)
            else:
                self.extracted = stored if isinstance(stored, dict) else {}
                self.field_order = list(self.extracted.keys()) or list(CANONICAL_FIELDS)
            for k in CANONICAL_FIELDS:
                self.extracted.setdefault(k, "")
        except json.JSONDecodeError:
            self.extracted = {k: "" for k in CANONICAL_FIELDS}
            self.field_order = list(CANONICAL_FIELDS)
        self._populate_fields_tree()
        self.incident_status_var.set(f"Loaded: {incident['title']}")
        self.parse_status_var.set("Loaded saved incident.")
        self.notebook.select(self.workspace_tab)

    # ---- Templates tab ----

    def _build_templates_tab(self):
        top = WrapToolbar(self.templates_tab, padding=(8, 8))
        top.pack(fill=tk.X)
        top.add(ttk.Label(top, text="Filter:"), padx=0)
        self.tmpl_filter_var = tk.StringVar(value="all")
        for label, val in [("All", "all"), ("Escalation", "escalation"), ("False Positive", "false_positive")]:
            top.add(ttk.Radiobutton(top, text=label, value=val, variable=self.tmpl_filter_var, command=self._refresh_template_tree), padx=4)
        top.add(ttk.Button(top, text="New", command=self._new_template), padx=(20, 3))
        top.add(ttk.Button(top, text="Delete", command=self._delete_template), padx=3)
        top.add(ttk.Button(top, text="Export...", command=self._export_templates), padx=(20, 3))
        top.add(ttk.Button(top, text="Import...", command=self._import_templates), padx=3)

        paned = ttk.PanedWindow(self.templates_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        columns = ("category", "name", "alert_type")
        self.tmpl_tree = ttk.Treeview(left, columns=columns, show="headings", height=20)
        self.tmpl_tree.heading("category", text="Category")
        self.tmpl_tree.heading("name", text="Name")
        self.tmpl_tree.heading("alert_type", text="Alert Type")
        self.tmpl_tree.column("category", width=100)
        self.tmpl_tree.column("name", width=220)
        self.tmpl_tree.column("alert_type", width=120)
        self.tmpl_tree.pack(fill=tk.BOTH, expand=True)
        self.tmpl_tree.bind("<<TreeviewSelect>>", self._on_template_select)

        right = ttk.Frame(paned)
        paned.add(right, weight=2)

        form = ttk.Frame(right)
        form.pack(fill=tk.X, pady=4)
        ttk.Label(form, text="Category:").grid(row=0, column=0, sticky="w")
        self.tmpl_category_var = tk.StringVar(value="Escalation")
        ttk.Combobox(form, textvariable=self.tmpl_category_var, values=["Escalation", "False Positive"], state="readonly", width=16).grid(row=0, column=1, padx=4, sticky="w")
        ttk.Label(form, text="Name:").grid(row=0, column=2, sticky="w", padx=(12, 0))
        self.tmpl_name_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.tmpl_name_var, width=35).grid(row=0, column=3, padx=4, sticky="w")
        ttk.Label(form, text="Alert Type:").grid(row=0, column=4, sticky="w", padx=(12, 0))
        self.tmpl_alert_type_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.tmpl_alert_type_var, width=20).grid(row=0, column=5, padx=4, sticky="w")

        common_fields = ", ".join("{%s}" % k for k in CANONICAL_FIELDS)
        help_text = (
            "Body supports two placeholder styles: {field} (shows [field] if "
            "missing - use for things that must be filled in) and #field "
            "(inline tag, e.g. \"from #source_ip\" - left as-is if the field "
            "isn't available, so plain text with '#' is never corrupted). "
            "Common cross-source fields work for any log type: "
            f"{common_fields}. Source-specific fields (e.g. #geoip_city, "
            "#device_compliant, #rule_name, #forward_to, #process_sha256, "
            "#process_signing_status) become available after parsing a log "
            "of that type - check the Extracted Fields table in the Incident "
            "Workspace tab for the exact names. Add your own fields for a new "
            "alert type in the Field Mappings tab. #analysis / {analysis} "
            "pulls in whatever's currently typed in the Analysis box, so a "
            "template can fold your write-up in directly when you click "
            "'Insert Filled Template'."
        )
        ttk.Label(right, text=help_text, wraplength=650, justify="left", style="Muted.TLabel").pack(anchor="w", pady=(6, 2))
        self.tmpl_body_text = tk.Text(right, height=22, wrap="word", undo=True, font=(FONT_FAMILY, 10), borderwidth=0)
        self.tmpl_body_text.pack(fill=tk.BOTH, expand=True)
        self._text_widgets.append((self.tmpl_body_text, FONT_FAMILY, 0))

        save_row = ttk.Frame(right)
        save_row.pack(fill=tk.X, pady=6)
        ttk.Button(save_row, text="Save Template", command=self._save_template, style="Accent.TButton").pack(side=tk.LEFT)

        self._selected_template_id = None

    def _refresh_template_lists(self):
        self._refresh_template_tree()
        self._refresh_template_combo()

    def _refresh_template_tree(self):
        for row in self.tmpl_tree.get_children():
            self.tmpl_tree.delete(row)
        cat = self.tmpl_filter_var.get()
        for i, t in enumerate(self.db.list_templates(cat)):
            self.tmpl_tree.insert(
                "", tk.END, iid=str(t["id"]),
                values=(CATEGORY_TO_LABEL.get(t["category"], t["category"]), t["name"], t["alert_type"] or ""),
                tags=self._zebra_tags(i),
            )

    def _widen_template_combo_popdown(self):
        """Widen just the Template combobox's dropdown POPUP list (not
        the closed-state field, which stays narrow on purpose so the row
        fits a split-screen layout - see where template_combo is
        created) to fit the longest currently-listed template name, so a
        long name is never cut off just because the row itself has to
        stay compact. ttk::combobox has no public option for a
        popup-only width, so this reaches into its internal popdown
        window - a well-known, widely-used workaround for this exact
        limitation.

        Setting the internal listbox's -width alone is NOT enough: ttk
        sizes the popdown as a real toplevel window via `wm geometry`,
        computed from the closed-state combobox width, in
        ttk::combobox::PostPosition - and that runs AFTER -postcommand
        fires, so it clips/overrides a wider listbox back down to the
        narrow field width. Confirmed live (screenshot) that widening
        only the listbox left the visible popup unchanged. The fix is to
        also re-widen the popdown toplevel itself via `wm geometry`,
        scheduled slightly after PostPosition has already run (via
        after()) so our geometry change is the one that sticks.
        Everything is wrapped in try/except so a ttk internals
        difference on some platform/version can never crash the app;
        worst case the popup just stays at its default width."""
        try:
            values = self.template_combo["values"]
            longest = max((len(v) for v in values), default=22)
            popdown = self.template_combo.tk.eval(f"ttk::combobox::PopdownWindow {self.template_combo}")
            listbox = f"{popdown}.f.l"
            self.template_combo.tk.call(listbox, "configure", "-width", max(22, longest + 2))

            def _fix_popdown_geometry():
                try:
                    req_w = int(self.template_combo.tk.call("winfo", "reqwidth", listbox))
                    cur_geo = self.template_combo.tk.call("wm", "geometry", popdown)
                    m = re.match(r"(\d+)x(\d+)\+(-?\d+)\+(-?\d+)", cur_geo)
                    if m:
                        w, h, x, y = m.groups()
                        new_w = max(int(w), req_w + 20)
                        self.template_combo.tk.call("wm", "geometry", popdown, f"{new_w}x{h}+{x}+{y}")
                except tk.TclError:
                    pass

            self.template_combo.after(10, _fix_popdown_geometry)
        except tk.TclError:
            pass

    def _refresh_template_combo(self):
        templates = self.db.list_templates()
        self._template_id_by_label = {}
        labels = []
        for t in templates:
            label = f"[{CATEGORY_TO_LABEL.get(t['category'], t['category'])}] {t['name']}"
            labels.append(label)
            self._template_id_by_label[label] = t["id"]
        self.template_combo["values"] = labels
        if labels and self.template_combo_var.get() not in labels:
            self.template_combo_var.set(labels[0])

    def _on_template_select(self, event):
        sel = self.tmpl_tree.selection()
        if not sel:
            return
        tid = int(sel[0])
        t = self.db.get_template(tid)
        if not t:
            return
        self._selected_template_id = tid
        self.tmpl_category_var.set(CATEGORY_TO_LABEL.get(t["category"], "Escalation"))
        self.tmpl_name_var.set(t["name"])
        self.tmpl_alert_type_var.set(t["alert_type"] or "")
        self.tmpl_body_text.delete("1.0", tk.END)
        self.tmpl_body_text.insert(tk.END, t["body"])

    def _new_template(self):
        self._selected_template_id = None
        self.tmpl_category_var.set("Escalation")
        self.tmpl_name_var.set("")
        self.tmpl_alert_type_var.set("")
        self.tmpl_body_text.delete("1.0", tk.END)

    def _save_template(self):
        name = self.tmpl_name_var.get().strip()
        if not name:
            messagebox.showwarning("Missing Name", "Enter a template name.")
            return
        category = LABEL_TO_CATEGORY.get(self.tmpl_category_var.get(), "escalation")
        alert_type = self.tmpl_alert_type_var.get().strip()
        body = self.tmpl_body_text.get("1.0", tk.END).rstrip("\n")

        if self._selected_template_id:
            self.db.update_template(self._selected_template_id, category, name, alert_type, body)
        else:
            self._selected_template_id = self.db.add_template(category, name, alert_type, body)

        self._refresh_template_lists()
        messagebox.showinfo("Saved", f"Template '{name}' saved.")

    def _delete_template(self):
        sel = self.tmpl_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a template to delete.")
            return
        tid = int(sel[0])
        t = self.db.get_template(tid)
        if not t:
            return
        if messagebox.askyesno("Delete Template", f"Delete '{t['name']}'? This cannot be undone."):
            self.db.delete_template(tid)
            self._new_template()
            self._refresh_template_lists()

    def _export_templates(self):
        """Export the selected templates, or every template if none are
        selected, to a JSON file another analyst can import."""
        sel = self.tmpl_tree.selection()
        ids = [int(s) for s in sel] if sel else None
        data = self.db.export_templates(ids)
        if not data:
            messagebox.showinfo("Nothing to Export", "No templates to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON file", "*.json")],
            initialfile="alertforge_templates.json",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"templates": data}, f, indent=2)
        messagebox.showinfo("Exported", f"Exported {len(data)} template(s) to:\n{path}")

    def _import_templates(self):
        """Import templates from a JSON file shared by another analyst.
        Templates are matched by name - a name that already exists is
        skipped unless the analyst chooses to overwrite it."""
        path = filedialog.askopenfilename(filetypes=[("JSON file", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            messagebox.showerror("Import Failed", f"Could not read that file:\n{e}")
            return
        templates = raw.get("templates") if isinstance(raw, dict) else raw
        if not isinstance(templates, list):
            messagebox.showerror("Import Failed", "That file doesn't look like an AlertForge templates export.")
            return

        imported, skipped = self.db.import_templates(templates)
        if skipped:
            overwrite = messagebox.askyesno(
                "Duplicate Template Names",
                f"{len(skipped)} template(s) already exist by name and were skipped:\n"
                + ", ".join(skipped)
                + "\n\nOverwrite them with the imported versions?",
            )
            if overwrite:
                to_overwrite = [t for t in templates if isinstance(t, dict) and (t.get("name") or "").strip() in skipped]
                more_imported, _ = self.db.import_templates(to_overwrite, overwrite=True)
                imported += more_imported
                skipped = []

        self._refresh_template_lists()
        msg = f"Imported {imported} template(s)."
        if skipped:
            msg += f" Skipped {len(skipped)} duplicate(s)."
        messagebox.showinfo("Import Complete", msg)

    # ---- Query Builder tab (LEQL / KQL) ----

    def _build_query_tab(self):
        paned = ttk.PanedWindow(self.query_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # ---- left: paste/parse a log, then pick + insert a query ----
        left = ttk.Frame(paned)
        paned.add(left, weight=2)

        ttk.Label(left, text="Paste Logs:", style="Section.TLabel").pack(anchor="w", pady=(0, 2))
        self.query_raw_text = tk.Text(left, height=8, wrap="none", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.query_raw_text.pack(fill=tk.BOTH, expand=False, pady=(0, 4))
        self._text_widgets.append((self.query_raw_text, MONO_FAMILY, 0))

        parse_row = WrapToolbar(left)
        parse_row.pack(fill=tk.X, pady=(0, 4))
        parse_row.add(ttk.Button(parse_row, text="Parse Logs", command=self._query_parse_logs, style="Accent.TButton"), padx=0)
        parse_row.add(ttk.Label(parse_row, text="Profile:"), padx=(16, 0))
        self.query_profile_override_var = tk.StringVar(value=self.PROFILE_OVERRIDE_AUTO)
        self.query_profile_override_combo = ttk.Combobox(
            parse_row, textvariable=self.query_profile_override_var, state="readonly", width=26,
        )
        self.query_profile_override_combo["values"] = [self.PROFILE_OVERRIDE_AUTO]
        parse_row.add(self.query_profile_override_combo, padx=4)
        parse_row.add(ttk.Button(parse_row, text="Clear", command=self._query_clear), padx=6)

        self.query_parse_status_var = tk.StringVar(value="No logs parsed yet.")
        ttk.Label(left, textvariable=self.query_parse_status_var, style="Muted.TLabel", wraplength=460, justify="left").pack(anchor="w", pady=(0, 4))

        ttk.Label(left, text="Extracted Fields:", style="Section.TLabel").pack(anchor="w", pady=(4, 2))
        efcolumns = ("field", "value")
        self.query_fields_tree = ttk.Treeview(left, columns=efcolumns, show="headings", height=7)
        self.query_fields_tree.heading("field", text="Field")
        self.query_fields_tree.heading("value", text="Value")
        self.query_fields_tree.column("field", width=140)
        self.query_fields_tree.column("value", width=300)
        self.query_fields_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        # Clicking a row's Value cell copies just that value to the
        # clipboard - same convenience as the Extracted Fields table in
        # Incident Workspace (see _on_fields_tree_click). No VT-link
        # column here, so this is a plain single-column click check.
        self.query_fields_tree.bind("<Button-1>", self._on_query_fields_tree_click)

        pick_row = WrapToolbar(left)
        pick_row.pack(fill=tk.X, pady=(0, 4))
        pick_row.add(ttk.Label(pick_row, text="Syntax:"), padx=0)
        self.query_syntax_var = tk.StringVar(value="kql")
        pick_row.add(
            ttk.Radiobutton(pick_row, text="KQL (Sentinel)", value="kql", variable=self.query_syntax_var, command=self._refresh_query_template_combo),
            padx=4,
        )
        pick_row.add(
            ttk.Radiobutton(pick_row, text="LEQL (Rapid7)", value="leql", variable=self.query_syntax_var, command=self._refresh_query_template_combo),
            padx=4,
        )

        tmpl_pick_row = WrapToolbar(left)
        tmpl_pick_row.pack(fill=tk.X, pady=(0, 4))
        tmpl_pick_row.add(ttk.Label(tmpl_pick_row, text="Query Template:"), padx=0)
        self.query_pick_var = tk.StringVar()
        self.query_pick_combo = ttk.Combobox(tmpl_pick_row, textvariable=self.query_pick_var, state="readonly", width=38)
        tmpl_pick_row.add(self.query_pick_combo, padx=4)
        tmpl_pick_row.add(ttk.Button(tmpl_pick_row, text="Insert Filled Query", command=self._insert_filled_query, style="Accent.TButton"), padx=(12, 0))

        out_header = ttk.Frame(left)
        out_header.pack(fill=tk.X, pady=(4, 2))
        ttk.Label(out_header, text="Query:", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(out_header, text="Copy Query to Clipboard", command=self._copy_query_output).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(out_header, text="Clear", command=lambda: self.query_output_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=(6, 0))
        self.query_output_text = tk.Text(left, height=8, wrap="word", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.query_output_text.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self._text_widgets.append((self.query_output_text, MONO_FAMILY, 0))

        # ---- right: manage the query template library ----
        right = ttk.Frame(paned)
        paned.add(right, weight=1)

        ttk.Label(right, text="Manage Query Templates", style="Section.TLabel").pack(anchor="w", pady=(0, 4))

        mgmt_btn_row = WrapToolbar(right)
        mgmt_btn_row.pack(fill=tk.X, pady=(0, 4))
        mgmt_btn_row.add(ttk.Button(mgmt_btn_row, text="New", command=self._new_query_template), padx=0)
        mgmt_btn_row.add(ttk.Button(mgmt_btn_row, text="Delete", command=self._delete_query_template), padx=3)
        mgmt_btn_row.add(ttk.Button(mgmt_btn_row, text="Export...", command=self._export_query_templates), padx=(20, 3))
        mgmt_btn_row.add(ttk.Button(mgmt_btn_row, text="Import...", command=self._import_query_templates), padx=3)

        qcolumns = ("syntax", "profile", "label")
        self.query_tmpl_tree = ttk.Treeview(right, columns=qcolumns, show="headings", height=9)
        self.query_tmpl_tree.heading("syntax", text="Syntax")
        self.query_tmpl_tree.heading("profile", text="Profile")
        self.query_tmpl_tree.heading("label", text="Label")
        self.query_tmpl_tree.column("syntax", width=55)
        self.query_tmpl_tree.column("profile", width=150)
        self.query_tmpl_tree.column("label", width=170)
        self.query_tmpl_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 6))
        self.query_tmpl_tree.bind("<<TreeviewSelect>>", self._on_query_template_select)

        qform = ttk.Frame(right)
        qform.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(qform, text="Syntax:").grid(row=0, column=0, sticky="w")
        self.qtmpl_syntax_var = tk.StringVar(value="kql")
        ttk.Combobox(qform, textvariable=self.qtmpl_syntax_var, values=["kql", "leql"], state="readonly", width=8).grid(row=0, column=1, padx=4, sticky="w")
        ttk.Label(qform, text="Profile:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.qtmpl_profile_var = tk.StringVar(value=self.QUERY_GENERIC_PROFILE_LABEL)
        self.qtmpl_profile_combo = ttk.Combobox(qform, textvariable=self.qtmpl_profile_var, state="readonly", width=32)
        self.qtmpl_profile_combo.grid(row=1, column=1, padx=4, pady=(4, 0), sticky="w")

        ttk.Label(right, text="Label:").pack(anchor="w")
        self.qtmpl_label_var = tk.StringVar()
        ttk.Entry(right, textvariable=self.qtmpl_label_var, width=40).pack(anchor="w", fill=tk.X, pady=(0, 4))

        qhelp = (
            "Body supports {field}/#field placeholders resolved against "
            "whatever was just parsed on the left, same syntax as "
            "Templates (e.g. #user, #host, #src_ip, #process_sha256 - "
            "check Extracted Fields for exact names). "
            "'(Generic - any profile)' templates always show up in the "
            "picker regardless of which log type is detected; a "
            "profile-specific one only shows up for that profile."
        )
        ttk.Label(right, text=qhelp, wraplength=340, justify="left", style="Muted.TLabel").pack(anchor="w", pady=(0, 4))
        self.qtmpl_body_text = tk.Text(right, height=10, wrap="word", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.qtmpl_body_text.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self._text_widgets.append((self.qtmpl_body_text, MONO_FAMILY, 0))

        ttk.Button(right, text="Save Query Template", command=self._save_query_template, style="Accent.TButton").pack(anchor="w", pady=(0, 4))

        self._selected_query_template_id = None
        self.query_extracted = {}
        self.query_field_order = []
        self.query_detected_profile_id = ""
        self._refresh_query_profile_choices()
        self._refresh_query_template_tree()
        self._refresh_query_template_combo()

    def _query_parse_logs(self):
        """Parse whatever's pasted on the left using the exact same
        FieldMapper.parse() logic as the Incident Workspace tab - kept
        entirely separate from Workspace's own extracted-fields state,
        since this tab is a standalone scratch area for building a query,
        not tied to whichever incident happens to be open."""
        if self.mapper is None:
            messagebox.showerror("Field Mapping Error", "field_mappings.json failed to load; parsing is unavailable.")
            return
        raw = self.query_raw_text.get("1.0", tk.END)
        forced_profile_id = None
        override_label = self.query_profile_override_var.get()
        if override_label and override_label != self.PROFILE_OVERRIDE_AUTO:
            forced_profile_id = self._mapping_profile_id_by_label.get(override_label)
        result = self.mapper.parse(raw, forced_profile_id=forced_profile_id)
        self.query_extracted = result["canonical"]
        self.query_field_order = result.get("field_order", list(CANONICAL_FIELDS))
        self.query_detected_profile_id = forced_profile_id or self._mapping_profile_id_by_label.get(result["label"], "") or ""
        self._auto_select_query_syntax_for_profile()
        self._populate_query_fields_tree()
        if result["label"]:
            status = f"Detected: {result['label']}"
        else:
            status = "Could not parse input."
        if result["warnings"]:
            status += "  |  " + " ".join(result["warnings"])
        self.query_parse_status_var.set(status)
        self._refresh_query_template_combo()

    def _auto_select_query_syntax_for_profile(self):
        """If the just-detected/forced profile has query templates in only
        one of LEQL/KQL, switch the syntax toggle to match it.

        Rapid7 profiles and Sentinel profiles are disjoint in practice (a
        Rapid7 log's profile has LEQL templates, a Sentinel log's profile
        has KQL templates, essentially never both) - but the syntax
        toggle defaults to KQL and stays wherever the analyst last left
        it. The picker itself (_refresh_query_template_combo) always
        shows every query for whichever syntax is selected, not just ones
        scoped to this profile, so this isn't about avoiding an empty
        list - it's just landing on the syntax an analyst most likely
        wants to start from after parsing a given log, saving a click.
        Left alone if the profile has templates in both syntaxes
        (analyst's own choice wins) or in neither (nothing to switch
        to)."""
        profile_id = self.query_detected_profile_id
        if not profile_id:
            return
        current_syntax = self.query_syntax_var.get()
        other_syntax = "kql" if current_syntax == "leql" else "leql"
        has_current = any(
            r["profile_id"] == profile_id
            for r in self.db.list_query_templates(syntax=current_syntax)
        )
        if has_current:
            return
        has_other = any(
            r["profile_id"] == profile_id
            for r in self.db.list_query_templates(syntax=other_syntax)
        )
        if has_other:
            self.query_syntax_var.set(other_syntax)

    def _populate_query_fields_tree(self):
        for row in self.query_fields_tree.get_children():
            self.query_fields_tree.delete(row)
        i = 0
        for k in self.query_field_order:
            v = self.query_extracted.get(k, "")
            if not v:
                continue
            self.query_fields_tree.insert("", tk.END, iid=k, values=(field_label(k), v), tags=self._zebra_tags(i))
            i += 1

    def _on_query_fields_tree_click(self, event):
        """Clicking the 'Value' column of the Query Builder's Extracted
        Fields table copies that field's KEY (not its value) to the
        clipboard - deliberately different from Incident Workspace's own
        Extracted Fields table (_on_fields_tree_click), which copies the
        value. Here the analyst is usually writing/editing a query
        template body, so what's actually useful to paste is the raw
        field name itself (e.g. "src_ip") to drop into a #src_ip or
        {src_ip} placeholder - not the one-off value that happened to be
        in the log just parsed."""
        if self.query_fields_tree.identify_region(event.x, event.y) != "cell":
            return
        col = self.query_fields_tree.identify_column(event.x)
        key = self.query_fields_tree.identify_row(event.y)
        if not key or col != "#2":
            return
        self.clipboard_clear()
        self.clipboard_append(key)
        self.query_parse_status_var.set(f"Copied field key to clipboard: {key}")

    def _query_clear(self):
        self.query_raw_text.delete("1.0", tk.END)
        self.query_extracted = {}
        self.query_field_order = []
        self.query_detected_profile_id = ""
        self._populate_query_fields_tree()
        self.query_parse_status_var.set("No logs parsed yet.")
        self.query_profile_override_var.set(self.PROFILE_OVERRIDE_AUTO)
        self._refresh_query_template_combo()

    def _refresh_query_profile_choices(self):
        """Populate the query-template edit form's Profile dropdown with
        every real profile (by label) plus the generic/any-profile
        choice, and keep a label<->id mapping in both directions."""
        labels = [self.QUERY_GENERIC_PROFILE_LABEL]
        self._query_profile_label_to_id = {self.QUERY_GENERIC_PROFILE_LABEL: ""}
        self._query_profile_id_to_label = {"": self.QUERY_GENERIC_PROFILE_LABEL}
        if self.mapper is not None:
            for profile in self.mapper.config.get("profiles", []):
                labels.append(profile["label"])
                self._query_profile_label_to_id[profile["label"]] = profile["id"]
                self._query_profile_id_to_label[profile["id"]] = profile["label"]
        if hasattr(self, "qtmpl_profile_combo"):
            self.qtmpl_profile_combo["values"] = labels
            if self.qtmpl_profile_var.get() not in labels:
                self.qtmpl_profile_var.set(self.QUERY_GENERIC_PROFILE_LABEL)

    def _refresh_query_template_combo(self):
        """Populate the left-hand picker with EVERY query template for the
        selected syntax, across every profile - not just whichever
        profile the just-parsed log happened to match. Query Builder is
        meant to let an analyst pivot into a related query even if it
        isn't the one their current log would auto-suggest (e.g. parse a
        sign-in log, then still see every other KQL query - device
        process, device network, USB copy, etc. - to jump into), so this
        deliberately does NOT filter by query_detected_profile_id.
        query_detected_profile_id is still used elsewhere (see
        _auto_select_query_syntax_for_profile) just to pick a sensible
        starting LEQL/KQL toggle, not to narrow this list."""
        if not hasattr(self, "query_pick_combo"):
            return
        syntax = self.query_syntax_var.get()
        rows = self.db.list_query_templates(syntax=syntax)
        self._query_pick_id_by_label = {}
        labels = []
        for r in rows:
            if r["profile_id"]:
                profile_label = self._query_profile_id_to_label.get(r["profile_id"], r["profile_id"])
                prefix = f"[{profile_label}] "
            else:
                prefix = "[Generic] "
            label = f"{prefix}{r['label']}"
            labels.append(label)
            self._query_pick_id_by_label[label] = r["id"]
        self.query_pick_combo["values"] = labels
        if labels and self.query_pick_var.get() not in labels:
            self.query_pick_var.set(labels[0])
        elif not labels:
            self.query_pick_var.set("")

    def _insert_filled_query(self):
        label = self.query_pick_var.get()
        qid = self._query_pick_id_by_label.get(label)
        if not qid:
            messagebox.showwarning("No Query Template Selected", "Choose a query template first.")
            return
        tmpl = self.db.get_query_template(qid)
        if not tmpl:
            return
        filled = fill_template(tmpl["body"], self.query_extracted)
        # Replaces whatever's already in the output box rather than
        # appending - unlike Templates' Insert Filled Template (which
        # builds a ticket write-up out of several pieces), a query is a
        # single self-contained thing to run, so inserting a new one
        # almost always means starting over, not stacking onto the last
        # pick. Use Copy (or select-all + copy) before picking a
        # different query if you want to keep the old one around.
        self.query_output_text.delete("1.0", tk.END)
        self.query_output_text.insert(tk.END, filled)
        self.query_output_text.see("1.0")

    def _copy_query_output(self):
        text = self.query_output_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.query_parse_status_var.set("Query copied to clipboard.")

    def _refresh_query_template_tree(self):
        for row in self.query_tmpl_tree.get_children():
            self.query_tmpl_tree.delete(row)
        for i, t in enumerate(self.db.list_query_templates()):
            profile_label = self._query_profile_id_to_label.get(t["profile_id"], t["profile_id"] or self.QUERY_GENERIC_PROFILE_LABEL)
            self.query_tmpl_tree.insert(
                "", tk.END, iid=str(t["id"]),
                values=(t["syntax"].upper(), profile_label, t["label"]),
                tags=self._zebra_tags(i),
            )

    def _on_query_template_select(self, event):
        sel = self.query_tmpl_tree.selection()
        if not sel:
            return
        qid = int(sel[0])
        t = self.db.get_query_template(qid)
        if not t:
            return
        self._selected_query_template_id = qid
        self.qtmpl_syntax_var.set(t["syntax"])
        self.qtmpl_profile_var.set(self._query_profile_id_to_label.get(t["profile_id"], self.QUERY_GENERIC_PROFILE_LABEL))
        self.qtmpl_label_var.set(t["label"])
        self.qtmpl_body_text.delete("1.0", tk.END)
        self.qtmpl_body_text.insert(tk.END, t["body"])

    def _new_query_template(self):
        self._selected_query_template_id = None
        self.qtmpl_syntax_var.set("kql")
        self.qtmpl_profile_var.set(self.QUERY_GENERIC_PROFILE_LABEL)
        self.qtmpl_label_var.set("")
        self.qtmpl_body_text.delete("1.0", tk.END)

    def _save_query_template(self):
        label = self.qtmpl_label_var.get().strip()
        if not label:
            messagebox.showwarning("Missing Label", "Enter a label for this query template.")
            return
        syntax = self.qtmpl_syntax_var.get()
        profile_id = self._query_profile_label_to_id.get(self.qtmpl_profile_var.get(), "")
        body = self.qtmpl_body_text.get("1.0", tk.END).rstrip("\n")

        if self._selected_query_template_id:
            self.db.update_query_template(self._selected_query_template_id, syntax, profile_id, label, body)
        else:
            self._selected_query_template_id = self.db.add_query_template(syntax, profile_id, label, body)

        self._refresh_query_template_tree()
        self._refresh_query_template_combo()
        messagebox.showinfo("Saved", f"Query template '{label}' saved.")

    def _delete_query_template(self):
        sel = self.query_tmpl_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a query template to delete.")
            return
        qid = int(sel[0])
        t = self.db.get_query_template(qid)
        if not t:
            return
        if messagebox.askyesno("Delete Query Template", f"Delete '{t['label']}'? This cannot be undone."):
            self.db.delete_query_template(qid)
            self._new_query_template()
            self._refresh_query_template_tree()
            self._refresh_query_template_combo()

    def _export_query_templates(self):
        """Export the selected query templates, or every one if none are
        selected, to a JSON file another analyst can import."""
        sel = self.query_tmpl_tree.selection()
        ids = [int(s) for s in sel] if sel else None
        data = self.db.export_query_templates(ids)
        if not data:
            messagebox.showinfo("Nothing to Export", "No query templates to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON file", "*.json")],
            initialfile="alertforge_query_templates.json",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"query_templates": data}, f, indent=2)
        messagebox.showinfo("Exported", f"Exported {len(data)} query template(s) to:\n{path}")

    def _import_query_templates(self):
        """Import query templates from a JSON file shared by another
        analyst. Matched by (syntax, label) - a match that already exists
        is skipped unless the analyst chooses to overwrite it."""
        path = filedialog.askopenfilename(filetypes=[("JSON file", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            messagebox.showerror("Import Failed", f"Could not read that file:\n{e}")
            return
        query_templates = raw.get("query_templates") if isinstance(raw, dict) else raw
        if not isinstance(query_templates, list):
            messagebox.showerror("Import Failed", "That file doesn't look like an AlertForge query templates export.")
            return

        imported, skipped = self.db.import_query_templates(query_templates)
        if skipped:
            overwrite = messagebox.askyesno(
                "Duplicate Query Template Labels",
                f"{len(skipped)} query template(s) already exist by label and were skipped:\n"
                + ", ".join(skipped)
                + "\n\nOverwrite them with the imported versions?",
            )
            if overwrite:
                to_overwrite = [t for t in query_templates if isinstance(t, dict) and (t.get("label") or "").strip() in skipped]
                more_imported, _ = self.db.import_query_templates(to_overwrite, overwrite=True)
                imported += more_imported
                skipped = []

        self._refresh_query_template_tree()
        self._refresh_query_template_combo()
        msg = f"Imported {imported} query template(s)."
        if skipped:
            msg += f" Skipped {len(skipped)} duplicate(s)."
        messagebox.showinfo("Import Complete", msg)

    # ---- Incidents tab ----

    def _build_incidents_tab(self):
        top = WrapToolbar(self.incidents_tab, padding=(8, 8))
        top.pack(fill=tk.X)
        top.add(ttk.Label(top, text="Search:"), padx=0)
        self.incident_search_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.incident_search_var, width=30)
        top.add(entry, padx=4)
        entry.bind("<Return>", lambda e: self._refresh_incident_list())
        top.add(ttk.Button(top, text="Search", command=self._refresh_incident_list), padx=3)
        top.add(ttk.Button(top, text="Refresh", command=lambda: (self.incident_search_var.set(""), self._refresh_incident_list())), padx=3)

        top.add(ttk.Label(top, text="Status:"), padx=(20, 0))
        self.incident_status_filter_var = tk.StringVar(value="All")
        status_filter_combo = ttk.Combobox(
            top, textvariable=self.incident_status_filter_var,
            values=["All"] + INCIDENT_STATUSES, state="readonly", width=14,
        )
        status_filter_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_incident_list())
        top.add(status_filter_combo, padx=4)

        top.add(ttk.Button(top, text="Load Selected", command=self._load_selected_incident, style="Accent.TButton"), padx=(20, 3))
        top.add(ttk.Button(top, text="Rename Selected", command=self._rename_selected_incident), padx=3)
        top.add(ttk.Button(top, text="Delete Selected", command=self._delete_selected_incident), padx=3)

        top.add(ttk.Label(top, text="Set Status:"), padx=(20, 0))
        self.incident_status_set_var = tk.StringVar(value=INCIDENT_STATUSES[0])
        status_set_combo = ttk.Combobox(
            top, textvariable=self.incident_status_set_var,
            values=INCIDENT_STATUSES, state="readonly", width=14,
        )
        top.add(status_set_combo, padx=4)
        top.add(ttk.Button(top, text="Apply Status", command=self._apply_status_to_selected), padx=3)

        columns = ("title", "status", "updated_at")
        self.incidents_tree = ttk.Treeview(self.incidents_tab, columns=columns, show="headings", height=25)
        self.incidents_tree.heading("title", text="Title")
        self.incidents_tree.heading("status", text="Status")
        self.incidents_tree.heading("updated_at", text="Last Updated (UTC)")
        self.incidents_tree.column("title", width=420)
        self.incidents_tree.column("status", width=110)
        self.incidents_tree.column("updated_at", width=200)
        self.incidents_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.incidents_tree.bind("<Double-1>", lambda e: self._load_selected_incident())

    def _refresh_incident_list(self):
        for row in self.incidents_tree.get_children():
            self.incidents_tree.delete(row)
        search = self.incident_search_var.get().strip() or None
        status_filter = self.incident_status_filter_var.get()
        status = None if status_filter in ("All", "all") else status_filter
        for i, inc in enumerate(self.db.list_incidents(search, status)):
            self.incidents_tree.insert(
                "", tk.END, iid=str(inc["id"]),
                values=(inc["title"] or "", inc.get("status") or "Open", inc["updated_at"] or ""),
                tags=self._zebra_tags(i),
            )

    def _apply_status_to_selected(self):
        """Set the chosen status on every currently-selected incident row
        (the treeview supports multi-select, so an analyst can triage
        several incidents at once)."""
        sel = self.incidents_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select one or more incidents to update.")
            return
        status = self.incident_status_set_var.get()
        for iid in sel:
            self.db.update_incident_status(int(iid), status)
        self._refresh_incident_list()

    def _load_selected_incident(self):
        sel = self.incidents_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select an incident to load.")
            return
        incident = self.db.get_incident(int(sel[0]))
        if incident:
            self.load_incident_into_workspace(incident)

    def _rename_selected_incident(self):
        """Give a saved incident a memorable title (ticket number, short
        description, etc.) without touching its logs/analysis/output.
        If the renamed incident happens to be the one currently loaded in
        the workspace, keep the workspace in sync so a later 'Save
        Incident' doesn't overwrite the new name with an auto-title."""
        sel = self.incidents_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select an incident to rename.")
            return
        iid = int(sel[0])
        incident = self.db.get_incident(iid)
        if not incident:
            return
        new_title = simpledialog.askstring(
            "Rename Incident", "New title:", initialvalue=incident["title"] or "", parent=self,
        )
        if new_title is None:
            return
        new_title = new_title.strip()
        if not new_title:
            messagebox.showwarning("Empty Title", "Title can't be empty.")
            return
        self.db.rename_incident(iid, new_title)
        if self.current_incident_id == iid:
            self.current_incident_title = new_title
            self.incident_status_var.set(f"Saved: {new_title}")
        self._refresh_incident_list()

    def _delete_selected_incident(self):
        sel = self.incidents_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select an incident to delete.")
            return
        iid = int(sel[0])
        if messagebox.askyesno("Delete Incident", "Delete this saved incident? This cannot be undone."):
            self.db.delete_incident(iid)
            self._refresh_incident_list()

    # ---- Notes tab ----
    # A quick-reference spot for KB articles, saved queries, or anything
    # else worth keeping handy - separate from Incidents, which track
    # actual case work (logs/analysis/output tied to one alert).

    def _build_notes_tab(self):
        top = WrapToolbar(self.notes_tab, padding=(8, 8))
        top.pack(fill=tk.X)
        top.add(ttk.Label(top, text="Search:"), padx=0)
        self.notes_search_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.notes_search_var, width=30)
        top.add(entry, padx=4)
        entry.bind("<Return>", lambda e: self._run_notes_search())
        top.add(ttk.Button(top, text="Search", command=self._run_notes_search), padx=3)
        top.add(ttk.Button(top, text="Refresh", command=lambda: (self.notes_search_var.set(""), self._run_notes_search())), padx=3)
        top.add(ttk.Button(top, text="New Note", command=self._new_note, style="Accent.TButton"), padx=(20, 3))
        top.add(ttk.Button(top, text="Delete", command=self._delete_note), padx=3)
        top.add(ttk.Button(top, text="Export", command=self._export_notes), padx=(20, 3))
        top.add(ttk.Button(top, text="Import", command=self._import_notes), padx=3)

        paned = ttk.PanedWindow(self.notes_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        columns = ("title", "updated_at")
        self.notes_tree = ttk.Treeview(left, columns=columns, show="headings", height=25)
        self.notes_tree.heading("title", text="Title")
        self.notes_tree.heading("updated_at", text="Last Updated (UTC)")
        self.notes_tree.column("title", width=220)
        self.notes_tree.column("updated_at", width=150)
        self.notes_tree.pack(fill=tk.BOTH, expand=True)
        self.notes_tree.bind("<<TreeviewSelect>>", self._on_note_select)

        right = ttk.Frame(paned)
        paned.add(right, weight=2)

        form = ttk.Frame(right)
        form.pack(fill=tk.X, pady=4)
        ttk.Label(form, text="Title:").pack(side=tk.LEFT)
        self.note_title_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.note_title_var, width=50).pack(side=tk.LEFT, padx=4)

        ttk.Label(
            right,
            text="A quick-reference spot for KB articles, saved queries, or anything "
            "else worth keeping handy - separate from Incidents, which track actual "
            "case work.",
            wraplength=650, justify="left", style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 4))

        note_toolbar = WrapToolbar(right)
        note_toolbar.pack(fill=tk.X, pady=(0, 4))
        note_toolbar.add(ttk.Button(note_toolbar, text="B", width=3, style="NoteBold.TButton", command=self._note_toggle_bold), padx=0)
        note_toolbar.add(ttk.Button(note_toolbar, text="I", width=3, style="NoteItalic.TButton", command=self._note_toggle_italic), padx=3)
        note_toolbar.add(ttk.Button(note_toolbar, text="U", width=3, style="NoteUnderline.TButton", command=self._note_toggle_underline), padx=3)
        note_toolbar.add(ttk.Button(note_toolbar, text="S", width=3, command=self._note_toggle_strike), padx=3)
        note_toolbar.add(ttk.Button(note_toolbar, text="Heading", command=self._note_toggle_heading), padx=(10, 3))
        note_toolbar.add(ttk.Button(note_toolbar, text="Clear Formatting", command=self._note_clear_formatting), padx=3)
        note_toolbar.add(ttk.Label(note_toolbar, text="Select text, then click a button to format it.", style="Muted.TLabel"), padx=(10, 0))

        self.note_body_text = tk.Text(right, wrap="word", undo=True, font=(FONT_FAMILY, 10), borderwidth=0)
        self.note_body_text.pack(fill=tk.BOTH, expand=True)
        self._text_widgets.append((self.note_body_text, FONT_FAMILY, 0))

        save_row = ttk.Frame(right)
        save_row.pack(fill=tk.X, pady=6)
        ttk.Button(save_row, text="Save Note", command=self._save_note, style="Accent.TButton").pack(side=tk.LEFT)
        ttk.Button(save_row, text="Copy Note", command=self._copy_note).pack(side=tk.LEFT, padx=6)
        self.note_status_var = tk.StringVar(value="")
        ttk.Label(save_row, textvariable=self.note_status_var, style="Muted.TLabel").pack(side=tk.LEFT, padx=10)

        self._selected_note_id = None
        self._note_loaded_title = ""
        self._note_loaded_body = ""
        self._refresh_notes_list()

    # ---- Notes tab: rich-text formatting (Bold/Italic/Underline/
    # Strikethrough/Heading toolbar) ----
    #
    # Formatting is scoped to this one tk.Text widget on purpose - every
    # other text box in the app (Analysis, Templates, Output, etc.) stays
    # plain text. A note's body is stored as a small JSON envelope of
    # (text, styles) runs in the same 'body' column notes have always
    # used, so no database schema change was needed; a note saved before
    # this feature existed is just plain text and loads back in
    # unformatted rather than erroring out (see _note_body_to_editor).

    def _configure_note_style_tags(self):
        """(Re)build the note-formatting fonts/tags at the current base
        font size, so Bold/Italic/Underline/Strikethrough/Heading track
        the app-wide A-/A+ font size control like everything else. Bold
        and italic are combined into one of four mutually-exclusive tags
        (regular/bold/italic/bold_italic) because a tk.Text tag's font
        option is one whole font spec, not independently stackable
        weight/slant knobs; underline, strikethrough, and heading don't
        touch the font family so they layer on top of whichever of those
        four is active."""
        size = self.font_size
        self._note_bold_font = tkfont.Font(family=FONT_FAMILY, size=size, weight="bold")
        self._note_italic_font = tkfont.Font(family=FONT_FAMILY, size=size, slant="italic")
        self._note_bold_italic_font = tkfont.Font(family=FONT_FAMILY, size=size, weight="bold", slant="italic")
        self._note_heading_font = tkfont.Font(family=FONT_FAMILY, size=size + 5, weight="bold")

        t = self.note_body_text
        t.tag_configure("bold", font=self._note_bold_font)
        t.tag_configure("italic", font=self._note_italic_font)
        t.tag_configure("bold_italic", font=self._note_bold_italic_font)
        t.tag_configure("underline", underline=True)
        t.tag_configure("strike", overstrike=True)
        t.tag_configure("heading", font=self._note_heading_font)
        # Search-match highlighting shares this widget too - a distinct
        # orange from the yellow "unresolved tag" and green "sanitized"
        # highlights used elsewhere, so "this is where your search term
        # is" is never confused with either of those meanings.
        t.tag_configure("search_match", background="#ffa94d", foreground="#08101f")
        # Heading should visually win when it overlaps bold/italic text,
        # and underline/strike should always show through regardless of
        # which weight/slant tag is active underneath them. search_match
        # is raised last so a highlighted match stays visible no matter
        # what formatting the text underneath it has.
        t.tag_raise("heading")
        t.tag_raise("underline")
        t.tag_raise("strike")
        t.tag_raise("search_match")

    def _configure_output_tag_style(self):
        """(Re)build the bold+yellow-highlight font/tag used to flag
        unresolved #tag / {field} / [field] placeholders in the ticket
        output box AND the Analysis box (same tag/style in both, so a tag
        typed straight into Analysis is flagged just as visibly as one
        left unresolved in Output), rebuilt at the current base size so
        it tracks the app-wide A-/A+ font size control like everything
        else. Fixed yellow/black colors (rather than theme colors) are
        used on purpose, like a real highlighter marker, so it stays
        equally visible in both Dark Mode and the light theme."""
        size = self.font_size
        self._unresolved_tag_font = tkfont.Font(family=FONT_FAMILY, size=size, weight="bold")
        for widget in (self.output_text, self.analysis_text):
            widget.tag_configure(
                "unresolved_tag", font=self._unresolved_tag_font,
                background="#f5d90a", foreground="#000000",
            )

    def _configure_sanitize_tag_style(self):
        """(Re)build the bold+green-highlight font/tag used to mark
        exactly what sanitize_text() changed in the Sanitize Logs tab's
        output box, rebuilt at the current base size so it tracks the
        app-wide A-/A+ font size control like everything else. Uses
        MONO_FAMILY (the sanitize boxes are monospace, unlike output_text)
        and a fixed green - distinct on purpose from the yellow used for
        unresolved-tag highlighting elsewhere, so "this was redacted" is
        never visually confused with "this still needs attention"."""
        size = self.font_size
        self._sanitize_tag_font = tkfont.Font(family=MONO_FAMILY, size=size, weight="bold")
        self.sanitize_output_text.tag_configure(
            "sanitize_changed", font=self._sanitize_tag_font,
            background="#8be9a8", foreground="#08101f",
        )

    def _known_tag_fields(self):
        """Field names recognized as real #tag/[field] placeholders -
        every field name defined across EVERY field-mapping profile (not
        just whichever one happens to be currently parsed), plus the
        common cross-source baseline and 'analysis'. A template is
        written once but reused across many log types, so #geoip_city,
        #process_signing_status, etc. need to be recognized as real
        placeholders as soon as they're defined in field_mappings.json -
        not only after that specific profile has just been parsed, which
        is what caused those tags to stay unhighlighted even though
        they're perfectly valid field names. Keeps the unresolved-tag
        highlighter from flagging unrelated hashtags or bracketed text
        (ticket numbers, '[redacted]', etc.), the same way
        fill_template() avoids corrupting them."""
        known = set(CANONICAL_FIELDS) | set(self.field_order) | {"analysis"}
        if self.mapper is not None:
            for profile in self.mapper.config.get("profiles", []):
                known.update(profile.get("fields", {}).keys())
        return known

    def _highlight_unresolved_tags(self, widget=None):
        """Scan `widget` (the ticket output box by default, or the
        Analysis box) for #tag / {field} / [field] placeholders that
        haven't been resolved yet and bold+highlight them in yellow, so
        it's obvious at a glance what still needs attention before this
        goes into a ticket."""
        widget = widget if widget is not None else self.output_text
        widget.tag_remove("unresolved_tag", "1.0", tk.END)
        text = widget.get("1.0", tk.END)
        for start, end in find_unresolved_tag_spans(text, self._known_tag_fields()):
            widget.tag_add("unresolved_tag", f"1.0+{start}c", f"1.0+{end}c")

    def _on_analysis_text_modified(self, event=None):
        """Bound (add="+") on the Analysis box's <<Modified>> alongside
        _on_prose_text_modified (the spell-check handler, bound first via
        _enable_spellcheck) - that handler already owns checking and
        resetting the widget's modified flag, so this one deliberately
        does NOT repeat that check: <<Modified>> only fires on a real
        content change, and by the time any add="+" handler for this
        event runs, the flag may already read False if an earlier-bound
        handler reset it first, so re-checking it here would cause this
        handler to be silently skipped. Just re-highlights unresolved
        tags unconditionally every time this fires."""
        self._highlight_unresolved_tags(self.analysis_text)

    def _on_output_modified(self, event=None):
        """Bound to <<Modified>> on the output box, which fires on any
        change to its contents - typing, pasting (any method), Undo/Redo,
        and every programmatic insert/delete this app does (inserting a
        template, Resolve #Tags, Clear Output, loading a saved incident).
        One handler here covers all of those instead of re-highlighting
        after each individually."""
        if not self.output_text.edit_modified():
            return
        self._highlight_unresolved_tags()
        self.output_text.edit_modified(False)

    def _note_selection_range(self):
        try:
            start = self.note_body_text.index("sel.first")
            end = self.note_body_text.index("sel.last")
        except tk.TclError:
            start = end = None
        if not start or self.note_body_text.compare(start, "==", end):
            self.note_status_var.set("Select some text first, then click a formatting button.")
            return None
        return start, end

    def _note_char_weight_slant(self, index):
        tags = self.note_body_text.tag_names(index)
        bold = "bold" in tags or "bold_italic" in tags
        italic = "italic" in tags or "bold_italic" in tags
        return bold, italic

    def _note_set_weight_slant(self, start, end, bold, italic):
        for t in ("bold", "italic", "bold_italic"):
            self.note_body_text.tag_remove(t, start, end)
        if bold and italic:
            self.note_body_text.tag_add("bold_italic", start, end)
        elif bold:
            self.note_body_text.tag_add("bold", start, end)
        elif italic:
            self.note_body_text.tag_add("italic", start, end)

    def _note_toggle_weight_or_slant(self, axis):
        """axis is 'bold' or 'italic'. Standard toolbar-toggle behavior:
        if any character in the selection lacks the style, turn it on
        for the whole selection; if every character already has it, turn
        it off for the whole selection."""
        rng = self._note_selection_range()
        if not rng:
            return
        start, end = rng
        text = self.note_body_text

        idx = start
        per_char = []
        all_on = True
        while text.compare(idx, "<", end):
            bold, italic = self._note_char_weight_slant(idx)
            current = bold if axis == "bold" else italic
            if not current:
                all_on = False
            per_char.append((idx, bold, italic))
            idx = text.index(f"{idx}+1c")
        if not per_char:
            return
        new_value = not all_on

        # Apply in contiguous same-style batches rather than one tag call
        # per character, so this stays fast on longer notes.
        batch_start, batch_bold, batch_italic = per_char[0][0], per_char[0][1], per_char[0][2]
        if axis == "bold":
            batch_bold = new_value
        else:
            batch_italic = new_value
        for idx2, bold, italic in per_char[1:]:
            if axis == "bold":
                bold = new_value
            else:
                italic = new_value
            if (bold, italic) != (batch_bold, batch_italic):
                self._note_set_weight_slant(batch_start, idx2, batch_bold, batch_italic)
                batch_start, batch_bold, batch_italic = idx2, bold, italic
        self._note_set_weight_slant(batch_start, end, batch_bold, batch_italic)

    def _note_toggle_bold(self):
        self._note_toggle_weight_or_slant("bold")

    def _note_toggle_italic(self):
        self._note_toggle_weight_or_slant("italic")

    def _note_toggle_simple_tag(self, tag):
        """For independent boolean-style tags (underline, strikethrough):
        add the tag to the whole selection if any character lacks it,
        otherwise remove it from the whole selection."""
        rng = self._note_selection_range()
        if not rng:
            return
        start, end = rng
        text = self.note_body_text
        fully_tagged = True
        idx = start
        while text.compare(idx, "<", end):
            if tag not in text.tag_names(idx):
                fully_tagged = False
                break
            idx = text.index(f"{idx}+1c")
        if fully_tagged:
            text.tag_remove(tag, start, end)
        else:
            text.tag_add(tag, start, end)

    def _note_toggle_underline(self):
        self._note_toggle_simple_tag("underline")

    def _note_toggle_strike(self):
        self._note_toggle_simple_tag("strike")

    def _note_toggle_heading(self):
        """Heading is block-level - it expands the selection out to cover
        every full line it touches, same as most note-taking apps."""
        rng = self._note_selection_range()
        if not rng:
            return
        start, end = rng
        text = self.note_body_text
        line_start = text.index(f"{start} linestart")
        line_end = text.index(f"{end} lineend")
        if "heading" in text.tag_names(line_start):
            text.tag_remove("heading", line_start, line_end)
        else:
            text.tag_add("heading", line_start, line_end)

    def _note_clear_formatting(self):
        rng = self._note_selection_range()
        if not rng:
            return
        start, end = rng
        for tag in NOTE_STYLE_TAGS:
            self.note_body_text.tag_remove(tag, start, end)
        self.note_status_var.set("Formatting cleared.")

    def _note_body_from_editor(self):
        """Serialize the editor's text plus its style tags into the JSON
        envelope stored in the 'body' column - a list of (text, styles)
        runs, built from tk.Text's own dump() so tag boundaries are
        exactly what's on screen."""
        events = self.note_body_text.dump("1.0", "end-1c", tag=True, text=True)
        runs = []
        active = set()
        buf = []

        def flush():
            if buf:
                runs.append({"text": "".join(buf), "styles": sorted(active)})
                buf.clear()

        for kind, value, _index in events:
            if kind == "tagon" and value in NOTE_STYLE_TAGS:
                flush()
                active.add(value)
            elif kind == "tagoff" and value in NOTE_STYLE_TAGS:
                flush()
                active.discard(value)
            elif kind == "text":
                buf.append(value)
        flush()
        return json.dumps({"alertforge_rich_text": 1, "runs": runs})

    def _note_body_to_editor(self, raw):
        """Load a stored note body into the editor. Notes saved by this
        version carry the JSON envelope from _note_body_from_editor;
        notes saved before rich text existed are just plain text, so
        anything that isn't that envelope is inserted as plain
        unformatted text instead of erroring out."""
        self.note_body_text.delete("1.0", tk.END)
        data = None
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and "runs" in parsed:
                    data = parsed
            except json.JSONDecodeError:
                data = None
        if data is None:
            self.note_body_text.insert(tk.END, raw or "")
            return
        for run in data.get("runs", []):
            start = self.note_body_text.index("end-1c")
            self.note_body_text.insert(tk.END, run.get("text", ""))
            end = self.note_body_text.index("end-1c")
            for style in run.get("styles", []):
                if style in NOTE_STYLE_TAGS:
                    self.note_body_text.tag_add(style, start, end)

    def _refresh_notes_list(self):
        for row in self.notes_tree.get_children():
            self.notes_tree.delete(row)
        for i, n in enumerate(self.db.list_notes(self.notes_search_var.get().strip() or None)):
            self.notes_tree.insert(
                "", tk.END, iid=str(n["id"]), values=(n["title"] or "", n["updated_at"] or ""),
                tags=self._zebra_tags(i),
            )

    def _run_notes_search(self):
        """Runs when Search/Refresh is clicked or Enter is pressed in the
        Notes search box. Refreshes the filtered list as before, and also
        re-applies match highlighting to whatever note is currently open
        in the editor - so if that note's already open, the highlight
        updates immediately without having to click it again."""
        self._refresh_notes_list()
        self._highlight_note_search_matches()

    def _highlight_note_search_matches(self):
        """Highlight every occurrence of the current Notes search term
        inside the note body open in the editor, and scroll to the first
        hit. Filtering the list only tells you WHICH notes match (e.g. a
        Windows event code) - this shows exactly WHERE in the note it is
        once you open it, instead of making you re-read the whole thing."""
        t = self.note_body_text
        t.tag_remove("search_match", "1.0", tk.END)
        term = self.notes_search_var.get().strip()
        if not term:
            return
        start = "1.0"
        first_hit = None
        while True:
            pos = t.search(term, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(term)}c"
            t.tag_add("search_match", pos, end)
            if first_hit is None:
                first_hit = pos
            start = end
        if first_hit:
            t.see(first_hit)
            t.mark_set(tk.INSERT, first_hit)

    def _on_note_select(self, event):
        sel = self.notes_tree.selection()
        if not sel:
            return
        nid = int(sel[0])
        if nid == self._selected_note_id:
            return
        # Autosave whatever was open before switching to the newly
        # clicked note, so a note isn't left half-edited without an
        # explicit Save Note click.
        self._note_autosave()
        n = self.db.get_note(nid)
        if not n:
            return
        self._selected_note_id = nid
        self.note_title_var.set(n["title"])
        self._note_body_to_editor(n["body"] or "")
        self._note_loaded_title = n["title"] or ""
        self._note_loaded_body = n["body"] or ""
        self.note_status_var.set("")
        self._highlight_note_search_matches()
        self._refresh_notes_list()
        if str(nid) in self.notes_tree.get_children():
            self.notes_tree.selection_set(str(nid))

    def _new_note(self):
        self._selected_note_id = None
        self.note_title_var.set("")
        self.note_body_text.delete("1.0", tk.END)
        self.note_body_text.tag_remove("search_match", "1.0", tk.END)
        self.note_status_var.set("")
        self._note_loaded_title = ""
        self._note_loaded_body = ""

    def _note_autosave(self):
        """Silently save whatever's currently open in the Notes editor -
        called when the analyst switches to a different note or leaves
        the Notes tab, so edits aren't lost without an explicit Save Note
        click. Unlike a manual save, this stays quiet: an empty title
        means there's nothing worth saving yet, so it just does nothing
        instead of popping up the 'Missing Title' warning, and it skips
        the write entirely if nothing has actually changed since the
        note was loaded (or last saved), so switching notes back and
        forth without editing doesn't keep bumping 'Last Updated'."""
        title = self.note_title_var.get().strip()
        if not title:
            return
        body = self._note_body_from_editor()
        if title == self._note_loaded_title and body == self._note_loaded_body:
            return
        if self._selected_note_id:
            self.db.update_note(self._selected_note_id, title, body)
        elif self.note_body_text.get("1.0", "end-1c").strip():
            # Only auto-create a brand-new note if there's real body text -
            # a bare title typed in and then tabbed away from shouldn't
            # spawn an empty note.
            self._selected_note_id = self.db.add_note(title, body)
        else:
            return
        self._note_loaded_title = title
        self._note_loaded_body = body
        self.note_status_var.set(f"Autosaved '{title}'.")

    def _save_note(self):
        title = self.note_title_var.get().strip()
        if not title:
            messagebox.showwarning("Missing Title", "Enter a note title.")
            return
        body = self._note_body_from_editor()
        if self._selected_note_id:
            self.db.update_note(self._selected_note_id, title, body)
        else:
            self._selected_note_id = self.db.add_note(title, body)
        self._note_loaded_title = title
        self._note_loaded_body = body
        self._refresh_notes_list()
        self.notes_tree.selection_set(str(self._selected_note_id))
        self.note_status_var.set(f"Saved '{title}'.")

    def _delete_note(self):
        sel = self.notes_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a note to delete.")
            return
        nid = int(sel[0])
        n = self.db.get_note(nid)
        if not n:
            return
        if messagebox.askyesno("Delete Note", f"Delete note '{n['title']}'? This cannot be undone."):
            self.db.delete_note(nid)
            self._new_note()
            self._refresh_notes_list()

    def _copy_note(self):
        text = self.note_body_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.note_status_var.set("Note copied to clipboard.")

    def _export_notes(self):
        """Export the selected notes, or every note if none are selected,
        to a JSON file another analyst can import."""
        sel = self.notes_tree.selection()
        ids = [int(s) for s in sel] if sel else None
        data = self.db.export_notes(ids)
        if not data:
            messagebox.showinfo("Nothing to Export", "No notes to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON file", "*.json")],
            initialfile="alertforge_notes.json",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"notes": data}, f, indent=2)
        messagebox.showinfo("Exported", f"Exported {len(data)} note(s) to:\n{path}")

    def _import_notes(self):
        """Import notes from a JSON file shared by another analyst. Notes
        are matched by title - a title that already exists is skipped
        unless the analyst chooses to overwrite it."""
        path = filedialog.askopenfilename(filetypes=[("JSON file", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            messagebox.showerror("Import Failed", f"Could not read that file:\n{e}")
            return
        notes = raw.get("notes") if isinstance(raw, dict) else raw
        if not isinstance(notes, list):
            messagebox.showerror("Import Failed", "That file doesn't look like an AlertForge notes export.")
            return

        imported, skipped = self.db.import_notes(notes)
        if skipped:
            overwrite = messagebox.askyesno(
                "Duplicate Note Titles",
                f"{len(skipped)} note(s) already exist by title and were skipped:\n"
                + ", ".join(skipped)
                + "\n\nOverwrite them with the imported versions?",
            )
            if overwrite:
                to_overwrite = [n for n in notes if isinstance(n, dict) and (n.get("title") or "").strip() in skipped]
                more_imported, _ = self.db.import_notes(to_overwrite, overwrite=True)
                imported += more_imported
                skipped = []

        self._refresh_notes_list()
        msg = f"Imported {imported} note(s)."
        if skipped:
            msg += f" Skipped {len(skipped)} duplicate(s)."
        messagebox.showinfo("Import Complete", msg)

    # ---- Sanitize Logs tab ----

    def _build_sanitize_tab(self):
        ttk.Label(
            self.sanitize_tab,
            text="Redact sensitive values from pasted logs before sharing them outside "
            "the team. Every value any category below catches is replaced with the "
            "same plain word REDACTED (not a numbered placeholder), so nothing about "
            "the real value can be reconstructed from the output. The summary below "
            "the output still reports how many distinct values each category caught. "
            "This is heuristic/best-effort - review the output before sharing it.",
            wraplength=1100, justify="left", style="Muted.TLabel", padding=(8, 8, 8, 0),
        ).pack(anchor="w", fill=tk.X)

        cat_row = WrapToolbar(self.sanitize_tab, padding=(8, 4))
        cat_row.pack(fill=tk.X)
        cat_row.add(ttk.Label(cat_row, text="Detect:", style="Section.TLabel"), padx=(0, 6))
        self.sanitize_category_vars = {}
        for cat in SANITIZE_CATEGORIES:
            var = tk.BooleanVar(value=True)
            self.sanitize_category_vars[cat] = var
            cat_row.add(ttk.Checkbutton(cat_row, text=SANITIZE_CATEGORY_LABELS[cat], variable=var), padx=6)

        paned = ttk.PanedWindow(self.sanitize_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))

        # ---- left: paste logs to sanitize ----
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        ttk.Label(left, text="Paste Logs to Sanitize:", style="Section.TLabel").pack(anchor="w", pady=(0, 2))
        self.sanitize_input_text = tk.Text(left, wrap="none", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.sanitize_input_text.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self._text_widgets.append((self.sanitize_input_text, MONO_FAMILY, 0))

        left_btn_row = WrapToolbar(left)
        left_btn_row.pack(fill=tk.X, pady=(0, 6))
        left_btn_row.add(ttk.Button(left_btn_row, text="Sanitize", command=self._do_sanitize, style="Accent.TButton"), padx=0)
        left_btn_row.add(ttk.Button(left_btn_row, text="Clear", command=lambda: self.sanitize_input_text.delete("1.0", tk.END)), padx=6)

        # ---- right: sanitized output ----
        right = ttk.Frame(paned)
        paned.add(right, weight=1)
        out_header = ttk.Frame(right)
        out_header.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(out_header, text="Sanitized Output:", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(out_header, text="Copy to Clipboard", command=self._copy_sanitized_output).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(out_header, text="Clear", command=lambda: self.sanitize_output_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=(6, 0))
        self.sanitize_output_text = tk.Text(right, wrap="none", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.sanitize_output_text.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self._text_widgets.append((self.sanitize_output_text, MONO_FAMILY, 0))

        self.sanitize_status_var = tk.StringVar(value="Paste logs and click Sanitize.")
        ttk.Label(
            right, textvariable=self.sanitize_status_var, style="Muted.TLabel",
            wraplength=500, justify="left",
        ).pack(anchor="w", pady=(0, 4))

        ttk.Separator(self.sanitize_tab, orient="horizontal").pack(fill=tk.X, padx=8)

        # ---- custom keyword find/replace list (persisted, reusable across
        # sessions - company names, internal project codenames, etc. that
        # no generic pattern above could know about) ----
        kw_frame = ttk.Frame(self.sanitize_tab, padding=(8, 8))
        kw_frame.pack(fill=tk.X)
        ttk.Label(
            kw_frame,
            text="Custom Find/Replace (applied before the categories above; exact "
            "replacement text you choose, not an auto-numbered placeholder):",
            style="Section.TLabel", wraplength=1100, justify="left",
        ).pack(anchor="w", pady=(0, 4))

        kw_body = ttk.Frame(kw_frame)
        kw_body.pack(fill=tk.X)

        kw_left = ttk.Frame(kw_body)
        kw_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        columns = ("keyword", "replacement")
        self.sanitize_keywords_tree = ttk.Treeview(kw_left, columns=columns, show="headings", height=6)
        self.sanitize_keywords_tree.heading("keyword", text="Keyword")
        self.sanitize_keywords_tree.heading("replacement", text="Replacement")
        self.sanitize_keywords_tree.column("keyword", width=220)
        self.sanitize_keywords_tree.column("replacement", width=220)
        self.sanitize_keywords_tree.pack(fill=tk.BOTH, expand=True)
        self.sanitize_keywords_tree.bind("<<TreeviewSelect>>", self._on_sanitize_keyword_select)
        # Delete/Backspace with a row selected in the list deletes it
        # directly, without having to reach for the Delete button.
        self.sanitize_keywords_tree.bind("<Delete>", lambda e: self._delete_sanitize_keyword())
        self.sanitize_keywords_tree.bind("<BackSpace>", lambda e: self._delete_sanitize_keyword())

        kw_right = ttk.Frame(kw_body, padding=(12, 0, 0, 0))
        kw_right.pack(side=tk.LEFT, fill=tk.Y)
        form = ttk.Frame(kw_right)
        form.pack(anchor="w")
        ttk.Label(form, text="Keyword:").grid(row=0, column=0, sticky="w", pady=2)
        self.sanitize_keyword_var = tk.StringVar()
        sanitize_keyword_entry = ttk.Entry(form, textvariable=self.sanitize_keyword_var, width=30)
        sanitize_keyword_entry.grid(row=0, column=1, padx=4, pady=2)
        ttk.Label(form, text="Replacement:").grid(row=1, column=0, sticky="w", pady=2)
        self.sanitize_replacement_var = tk.StringVar()
        sanitize_replacement_entry = ttk.Entry(form, textvariable=self.sanitize_replacement_var, width=30)
        sanitize_replacement_entry.grid(row=1, column=1, padx=4, pady=2)
        # Pressing Enter in either field adds/saves the keyword directly,
        # so an analyst can type a keyword, Tab/click to Replacement, type
        # the replacement, and hit Enter - without needing to reach for
        # the mouse to click the Save button.
        sanitize_keyword_entry.bind("<Return>", lambda e: self._save_sanitize_keyword())
        sanitize_replacement_entry.bind("<Return>", lambda e: self._save_sanitize_keyword())

        # Plain fixed-layout row (not WrapToolbar) on purpose: this is a
        # small, never-more-than-3-button row that doesn't need reflow
        # wrapping, and packing the buttons directly guarantees all three
        # (including Delete) render immediately rather than waiting on a
        # WrapToolbar's first <Configure>/after_idle reflow pass.
        kw_btn_row = ttk.Frame(kw_right)
        kw_btn_row.pack(anchor="w", pady=(6, 0))
        ttk.Button(kw_btn_row, text="Add / Save", command=self._save_sanitize_keyword, style="Accent.TButton").pack(side=tk.LEFT)
        ttk.Button(kw_btn_row, text="New", command=self._new_sanitize_keyword).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(kw_btn_row, text="Delete Selected", command=self._delete_sanitize_keyword).pack(side=tk.LEFT, padx=(6, 0))

        ttk.Label(
            kw_right,
            text="To delete: select a row above and press Delete or Backspace "
            "(or click the 'Delete Selected' button below), or just type the "
            "exact keyword into the Keyword field and click 'Delete Selected' "
            "without selecting a row.",
            style="Muted.TLabel", wraplength=300, justify="left",
        ).pack(anchor="w", pady=(4, 0))

        self._selected_sanitize_keyword_id = None
        self._refresh_sanitize_keywords_list()

    def _refresh_sanitize_keywords_list(self):
        for row in self.sanitize_keywords_tree.get_children():
            self.sanitize_keywords_tree.delete(row)
        for i, kw in enumerate(self.db.list_sanitize_keywords()):
            self.sanitize_keywords_tree.insert(
                "", tk.END, iid=str(kw["id"]), values=(kw["keyword"], kw["replacement"]),
                tags=self._zebra_tags(i),
            )

    def _on_sanitize_keyword_select(self, event):
        sel = self.sanitize_keywords_tree.selection()
        if not sel:
            return
        kid = int(sel[0])
        kw = self.db.get_sanitize_keyword(kid)
        if not kw:
            return
        self._selected_sanitize_keyword_id = kid
        self.sanitize_keyword_var.set(kw["keyword"])
        self.sanitize_replacement_var.set(kw["replacement"])

    def _new_sanitize_keyword(self):
        self._selected_sanitize_keyword_id = None
        self.sanitize_keyword_var.set("")
        self.sanitize_replacement_var.set("")

    def _save_sanitize_keyword(self):
        keyword = self.sanitize_keyword_var.get().strip()
        replacement = self.sanitize_replacement_var.get().strip()
        if not keyword or not replacement:
            messagebox.showwarning("Missing Info", "Enter both a keyword and a replacement.")
            return
        if self._selected_sanitize_keyword_id:
            self.db.update_sanitize_keyword(self._selected_sanitize_keyword_id, keyword, replacement)
        else:
            self._selected_sanitize_keyword_id = self.db.add_sanitize_keyword(keyword, replacement)
        self._refresh_sanitize_keywords_list()
        self.sanitize_keywords_tree.selection_set(str(self._selected_sanitize_keyword_id))

    def _delete_sanitize_keyword(self):
        sel = self.sanitize_keywords_tree.selection()
        kid = int(sel[0]) if sel else None
        if kid is None:
            # Nothing picked in the list - fall back to whatever keyword
            # text is currently typed into the form, so "type the
            # keyword, click Delete" works without first having to click
            # its row in the list above.
            typed = self.sanitize_keyword_var.get().strip()
            if typed:
                match = next(
                    (kw for kw in self.db.list_sanitize_keywords() if kw["keyword"].lower() == typed.lower()),
                    None,
                )
                if match:
                    kid = match["id"]
        if kid is None:
            messagebox.showwarning(
                "No Selection",
                "Select a keyword from the list above (or type its exact name into the Keyword field) to delete.",
            )
            return
        kw = self.db.get_sanitize_keyword(kid)
        if not kw:
            return
        if messagebox.askyesno("Delete Keyword", f"Delete the custom replacement for '{kw['keyword']}'?"):
            self.db.delete_sanitize_keyword(kid)
            self._new_sanitize_keyword()
            self._refresh_sanitize_keywords_list()

    def _do_sanitize(self):
        text = self.sanitize_input_text.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Nothing to Sanitize", "Paste some log text first.")
            return
        categories = {cat: var.get() for cat, var in self.sanitize_category_vars.items()}
        keyword_pairs = [(kw["keyword"], kw["replacement"]) for kw in self.db.list_sanitize_keywords()]
        sanitized, counts, spans = sanitize_text(text, categories=categories, keyword_pairs=keyword_pairs)
        self.sanitize_output_text.delete("1.0", tk.END)
        self.sanitize_output_text.insert("1.0", sanitized)
        self.sanitize_output_text.tag_remove("sanitize_changed", "1.0", tk.END)
        for start, end in spans:
            self.sanitize_output_text.tag_add("sanitize_changed", f"1.0+{start}c", f"1.0+{end}c")
        summary = ", ".join(
            f"{SANITIZE_CATEGORY_LABELS[cat]}: {counts[cat]}" for cat in SANITIZE_CATEGORIES if counts[cat]
        )
        self.sanitize_status_var.set(f"Replaced - {summary}" if summary else "Nothing matched to redact.")

    def _copy_sanitized_output(self):
        text = self.sanitize_output_text.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Nothing to Copy", "Sanitize some logs first.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.sanitize_status_var.set("Sanitized output copied to clipboard.")

    # ---- Text Tools tab ----
    # A general-purpose scratch pad of text-munging operations that have
    # nothing to do with the structured log parsing/sanitizing above -
    # decoding an obfuscated blob, pulling out just the IOCs, or defanging
    # a URL before it goes in a ticket. Any number of operations can be
    # checked at once; apply_text_tools() (parser_core.py) runs whichever
    # ones are selected in one fixed, sensible order - decode first, then
    # extract, then clean up, then defang last - regardless of the order
    # the checkboxes happen to be ticked in, so the result is always the
    # same for a given set of selections.

    def _build_texttools_tab(self):
        ttk.Label(
            self.texttools_tab,
            text="Paste any text below, check one or more operations, and click Apply. "
            "Checked operations always run in the order listed here - decode (Base64/Hex/"
            "URL), then extract (Email/IP/File Path), then clean up (whitespace/sort/"
            "dedupe), then Defang last - no matter which order you check them in, so "
            "results are always predictable. Checking any combination of Extract Email "
            "Addresses, Extract IP Addresses, and Extract File Names/Paths pulls all the "
            "checked kinds of value out of the same input and combines them, rather than "
            "feeding one's output into the other and coming up empty.",
            wraplength=1100, justify="left", style="Muted.TLabel", padding=(8, 8, 8, 0),
        ).pack(anchor="w", fill=tk.X)

        op_row = WrapToolbar(self.texttools_tab, padding=(8, 4))
        op_row.pack(fill=tk.X)
        op_row.add(ttk.Label(op_row, text="Operations:", style="Section.TLabel"), padx=(0, 6))
        self.texttool_vars = {}
        for key, label, _func in TEXT_TOOL_OPERATIONS:
            var = tk.BooleanVar(value=False)
            self.texttool_vars[key] = var
            op_row.add(ttk.Checkbutton(op_row, text=label, variable=var), padx=6)

        paned = ttk.PanedWindow(self.texttools_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))

        # ---- left: paste text to process ----
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        ttk.Label(left, text="Paste Text:", style="Section.TLabel").pack(anchor="w", pady=(0, 2))
        self.texttool_input_text = tk.Text(left, wrap="none", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.texttool_input_text.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self._text_widgets.append((self.texttool_input_text, MONO_FAMILY, 0))

        left_btn_row = WrapToolbar(left)
        left_btn_row.pack(fill=tk.X, pady=(0, 6))
        left_btn_row.add(ttk.Button(left_btn_row, text="Apply", command=self._do_text_tools, style="Accent.TButton"), padx=0)
        left_btn_row.add(ttk.Button(left_btn_row, text="Clear", command=lambda: self.texttool_input_text.delete("1.0", tk.END)), padx=6)

        # ---- right: result ----
        right = ttk.Frame(paned)
        paned.add(right, weight=1)
        out_header = ttk.Frame(right)
        out_header.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(out_header, text="Result:", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(out_header, text="Copy to Clipboard", command=self._copy_texttool_output).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(out_header, text="Clear", command=lambda: self.texttool_output_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=(6, 0))
        self.texttool_output_text = tk.Text(right, wrap="none", undo=True, font=(MONO_FAMILY, 10), borderwidth=0)
        self.texttool_output_text.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self._text_widgets.append((self.texttool_output_text, MONO_FAMILY, 0))

        self.texttool_status_var = tk.StringVar(value="Paste text, check one or more operations above, and click Apply.")
        ttk.Label(
            right, textvariable=self.texttool_status_var, style="Muted.TLabel",
            wraplength=500, justify="left",
        ).pack(anchor="w", pady=(0, 4))

    def _do_text_tools(self):
        text = self.texttool_input_text.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Nothing to Process", "Paste some text first.")
            return
        selected = [key for key, var in self.texttool_vars.items() if var.get()]
        if not selected:
            messagebox.showinfo("No Operation Selected", "Check at least one operation above.")
            return
        result = apply_text_tools(text, selected)
        self.texttool_output_text.delete("1.0", tk.END)
        self.texttool_output_text.insert("1.0", result)
        applied = ", ".join(label for key, label, _func in TEXT_TOOL_OPERATIONS if key in selected)
        if result.strip():
            self.texttool_status_var.set(f"Applied: {applied}")
        else:
            self.texttool_status_var.set(f"Applied: {applied} (nothing left in the result).")

    def _copy_texttool_output(self):
        text = self.texttool_output_text.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Nothing to Copy", "Run an operation first.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.texttool_status_var.set("Result copied to clipboard.")

    # ---- Field Mappings tab ----

    def _build_mapping_tab(self):
        info = (
            "Field mappings control how pasted JSON logs are recognized and turned "
            "into fields like user, host, process, etc. Add a field to an existing "
            "profile, or create a brand-new profile for a log/alert type that isn't "
            "recognized yet - once a field is mapped here it's immediately usable "
            "as {field} or #field in your templates."
        )
        ttk.Label(self.mapping_tab, text=info, wraplength=1150, justify="left", padding=(8, 6), style="Muted.TLabel").pack(anchor="w")

        paned = ttk.PanedWindow(self.mapping_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))

        # ---- left: list of profiles and their fields ----
        left = ttk.Frame(paned)
        paned.add(left, weight=1)
        ttk.Label(left, text="Existing profiles and their fields:", style="Section.TLabel").pack(anchor="w", pady=(0, 2))
        self.mapping_tree = ttk.Treeview(left, columns=("path",), show="tree headings", height=24)
        self.mapping_tree.heading("#0", text="Profile / Field")
        self.mapping_tree.heading("path", text="JSON Key / Path")
        self.mapping_tree.column("#0", width=230)
        self.mapping_tree.column("path", width=300)
        self.mapping_tree.pack(fill=tk.BOTH, expand=True, pady=(2, 4))
        self.mapping_tree.bind("<<TreeviewSelect>>", self._on_mapping_tree_select)

        reorder_row = WrapToolbar(left)
        reorder_row.pack(anchor="w", fill=tk.X, pady=(0, 4))
        reorder_row.add(ttk.Button(reorder_row, text="Move Field Up", command=lambda: self._move_selected_mapping_field(-1)), padx=0)
        reorder_row.add(ttk.Button(reorder_row, text="Move Field Down", command=lambda: self._move_selected_mapping_field(1)), padx=6)
        reorder_row.add(ttk.Button(reorder_row, text="Rename Selected Profile", command=self._rename_selected_profile), padx=6)

        ttk.Button(left, text="Delete Selected Profile/Field", command=self._delete_selected_mapping).pack(anchor="w")

        map_io_row = WrapToolbar(left)
        map_io_row.pack(anchor="w", fill=tk.X, pady=(6, 0))
        map_io_row.add(ttk.Button(map_io_row, text="Export Profile(s)...", command=self._export_mapping_profiles), padx=0)
        map_io_row.add(ttk.Button(map_io_row, text="Import Profile(s)...", command=self._import_mapping_profiles), padx=6)

        # ---- right: add field / create profile / advanced ----
        right = ttk.Frame(paned)
        paned.add(right, weight=1)

        add_frame = ttk.LabelFrame(right, text="Add / Update a Field", padding=8)
        add_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(add_frame, text="Profile:").grid(row=0, column=0, sticky="w")
        self.map_target_profile_var = tk.StringVar()
        self.map_target_profile_combo = ttk.Combobox(add_frame, textvariable=self.map_target_profile_var, state="readonly", width=36)
        self.map_target_profile_combo.grid(row=0, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(add_frame, text="Field name:").grid(row=1, column=0, sticky="w")
        self.map_field_name_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.map_field_name_var, width=28).grid(row=1, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(add_frame, text="JSON key / path:").grid(row=2, column=0, sticky="w")
        self.map_field_path_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.map_field_path_var, width=36).grid(row=2, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(add_frame, text="Transform (optional):").grid(row=3, column=0, sticky="w")
        self.map_transform_var = tk.StringVar(value="(none)")
        ttk.Combobox(add_frame, textvariable=self.map_transform_var, values=["(none)"] + list(TRANSFORMS.keys()), state="readonly", width=28).grid(row=3, column=1, sticky="w", padx=4, pady=2)

        help_txt = (
            "Examples: \"userPrincipalName\" (top-level key), \"source_json.ClientIP\" "
            "(nested), \"Parameters[Name=ForwardTo].Value\" (find a Name/Value pair in "
            "a list - common in O365/Rapid7 audit logs), \"signing_chain[0].subject\" "
            "(list index). Type literal:Some Text instead of a path for a fixed value."
        )
        ttk.Label(add_frame, text=help_txt, wraplength=380, justify="left", style="Muted.TLabel").grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 4))

        ttk.Button(add_frame, text="Add / Update Field", command=self._add_or_update_field, style="Accent.TButton").grid(row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))

        new_profile_frame = ttk.LabelFrame(right, text="Create a New Profile (for a new alert/log type)", padding=8)
        new_profile_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(new_profile_frame, text="Profile name:").grid(row=0, column=0, sticky="w")
        self.new_profile_label_var = tk.StringVar()
        ttk.Entry(new_profile_frame, textvariable=self.new_profile_label_var, width=32).grid(row=0, column=1, sticky="w", padx=4, pady=2)
        ttk.Label(new_profile_frame, text="Detect by JSON key(s):").grid(row=1, column=0, sticky="w")
        self.new_profile_keys_var = tk.StringVar()
        ttk.Entry(new_profile_frame, textvariable=self.new_profile_keys_var, width=32).grid(row=1, column=1, sticky="w", padx=4, pady=2)
        ttk.Label(
            new_profile_frame,
            text="Comma-separated JSON key names that uniquely identify this log/alert "
            "type (e.g. a field name only this source has). After creating it, add its "
            "fields above.",
            wraplength=380, justify="left", style="Muted.TLabel",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 4))
        ttk.Button(new_profile_frame, text="Create Profile", command=self._create_new_profile, style="Accent.TButton").grid(row=3, column=0, sticky="w")

        self.mapping_test_visible = False
        self.mapping_test_btn = ttk.Button(right, text="Show Test a Sample Log", command=self._toggle_mapping_test)
        self.mapping_test_btn.pack(anchor="w", pady=(0, 4))

        self.mapping_test_frame = ttk.Frame(right)
        ttk.Label(
            self.mapping_test_frame,
            text="Paste a sample log below and click Preview to see which profile "
            "matches and what fields would be extracted - without switching to "
            "the Incident Workspace tab.",
            wraplength=380, justify="left", style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 4))
        self.mapping_test_input = tk.Text(self.mapping_test_frame, height=6, wrap="none", undo=True, font=(MONO_FAMILY, 9), borderwidth=0)
        self.mapping_test_input.pack(fill=tk.BOTH, expand=False, pady=(0, 4))
        self._text_widgets.append((self.mapping_test_input, MONO_FAMILY, -1))
        test_btn_row = WrapToolbar(self.mapping_test_frame)
        test_btn_row.pack(fill=tk.X, pady=(0, 4))
        test_btn_row.add(ttk.Button(test_btn_row, text="Preview", command=self._preview_sample_log, style="Accent.TButton"), padx=0)
        test_btn_row.add(ttk.Button(test_btn_row, text="Clear", command=self._clear_mapping_test), padx=6)
        self.mapping_test_output = tk.Text(self.mapping_test_frame, height=10, wrap="word", font=(MONO_FAMILY, 9), borderwidth=0, state="disabled")
        self.mapping_test_output.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self._text_widgets.append((self.mapping_test_output, MONO_FAMILY, -1))

        self.mapping_advanced_visible = False
        self.mapping_advanced_btn = ttk.Button(right, text="Show Advanced: Raw JSON", command=self._toggle_mapping_advanced)
        self.mapping_advanced_btn.pack(anchor="w")

        self.mapping_advanced_frame = ttk.Frame(right)
        self.mapping_text = tk.Text(self.mapping_advanced_frame, wrap="none", undo=True, height=14, font=(MONO_FAMILY, 10), borderwidth=0)
        self.mapping_text.pack(fill=tk.BOTH, expand=True, pady=(4, 4))
        self._text_widgets.append((self.mapping_text, MONO_FAMILY, 0))
        adv_btn_row = WrapToolbar(self.mapping_advanced_frame)
        adv_btn_row.pack(fill=tk.X)
        adv_btn_row.add(ttk.Button(adv_btn_row, text="Reload from File", command=self._reload_mapping_file), padx=0)
        adv_btn_row.add(ttk.Button(adv_btn_row, text="Save Raw JSON", command=self._save_mapping_file), padx=6)

        self._refresh_mapping_tree()

    def _toggle_mapping_advanced(self):
        self.mapping_advanced_visible = not self.mapping_advanced_visible
        if self.mapping_advanced_visible:
            self._reload_mapping_file()
            self.mapping_advanced_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
            self.mapping_advanced_btn.config(text="Hide Advanced: Raw JSON")
        else:
            self.mapping_advanced_frame.pack_forget()
            self.mapping_advanced_btn.config(text="Show Advanced: Raw JSON")

    def _toggle_mapping_test(self):
        self.mapping_test_visible = not self.mapping_test_visible
        if self.mapping_test_visible:
            self.mapping_test_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
            self.mapping_test_btn.config(text="Hide Test a Sample Log")
        else:
            self.mapping_test_frame.pack_forget()
            self.mapping_test_btn.config(text="Show Test a Sample Log")

    def _preview_sample_log(self):
        """Parse whatever's pasted in the test box using the live field
        mappings config and show the detected profile + extracted fields
        + warnings, mirroring parse_logs() on the Workspace tab but
        without touching the real workspace state."""
        if self.mapper is None:
            messagebox.showerror("Field Mapping Error", "field_mappings.json failed to load; preview is unavailable.")
            return
        raw = self.mapping_test_input.get("1.0", tk.END)
        result = self.mapper.parse(raw)

        lines = []
        if result["label"]:
            lines.append(f"Detected profile: {result['label']}")
        else:
            lines.append("Detected profile: none (could not parse input)")
        lines.append(f"Matched: {'yes' if result['matched'] else 'no (generic fallback used)'}")
        if result["warnings"]:
            lines.append("")
            lines.append("Warnings:")
            for w in result["warnings"]:
                lines.append(f"  - {w}")
        lines.append("")
        lines.append("Extracted fields:")
        any_field = False
        for k in result["field_order"]:
            v = result["canonical"].get(k, "")
            if v:
                lines.append(f"  {field_label(k)}: {v}")
                any_field = True
        if not any_field:
            lines.append("  (none)")

        self.mapping_test_output.config(state="normal")
        self.mapping_test_output.delete("1.0", tk.END)
        self.mapping_test_output.insert(tk.END, "\n".join(lines))
        self.mapping_test_output.config(state="disabled")

    def _clear_mapping_test(self):
        self.mapping_test_input.delete("1.0", tk.END)
        self.mapping_test_output.config(state="normal")
        self.mapping_test_output.delete("1.0", tk.END)
        self.mapping_test_output.config(state="disabled")

    def _get_profile_by_id(self, pid):
        if self.mapper is None:
            return None
        for p in self.mapper.config.get("profiles", []):
            if p["id"] == pid:
                return p
        return None

    def _refresh_mapping_tree(self):
        for row in self.mapping_tree.get_children():
            self.mapping_tree.delete(row)
        self._mapping_profile_id_by_label = {}
        labels = []
        if self.mapper is None:
            return
        row_idx = 0
        for profile in self.mapper.config.get("profiles", []):
            pid = profile["id"]
            label = profile["label"]
            self._mapping_profile_id_by_label[label] = pid
            labels.append(label)
            detect_summary = "detects: " + ", ".join(profile.get("detect_keys", []))
            self.mapping_tree.insert("", tk.END, iid=pid, text=label, values=(detect_summary,), open=False, tags=self._zebra_tags(row_idx))
            row_idx += 1
            for field_name, spec in profile.get("fields", {}).items():
                self.mapping_tree.insert(pid, tk.END, iid=f"{pid}::{field_name}", text=field_name, values=(spec or "(not mapped)",), tags=self._zebra_tags(row_idx))
                row_idx += 1
        self.map_target_profile_combo["values"] = labels
        if labels and self.map_target_profile_var.get() not in labels:
            self.map_target_profile_var.set(labels[0])

        # Workspace tab's manual profile-override dropdown - kept in sync
        # here too so a profile that gets renamed/deleted in the Field
        # Mappings tab never leaves a stale/dangling choice selected.
        if hasattr(self, "profile_override_combo"):
            override_values = [self.PROFILE_OVERRIDE_AUTO] + labels
            self.profile_override_combo["values"] = override_values
            if self.profile_override_var.get() not in override_values:
                self.profile_override_var.set(self.PROFILE_OVERRIDE_AUTO)

        # Query Builder tab's profile-override dropdown and its query
        # template edit form's Profile choices - same staleness concern
        # as the Workspace dropdown above.
        if hasattr(self, "query_profile_override_combo"):
            override_values = [self.PROFILE_OVERRIDE_AUTO] + labels
            self.query_profile_override_combo["values"] = override_values
            if self.query_profile_override_var.get() not in override_values:
                self.query_profile_override_var.set(self.PROFILE_OVERRIDE_AUTO)
        self._refresh_query_profile_choices()

    def _on_mapping_tree_select(self, event):
        sel = self.mapping_tree.selection()
        if not sel:
            return
        iid = sel[0]
        if "::" in iid:
            pid, field_name = iid.split("::", 1)
            profile = self._get_profile_by_id(pid)
            if not profile:
                return
            self.map_target_profile_var.set(profile["label"])
            self.map_field_name_var.set(field_name)
            spec = profile["fields"].get(field_name, "")
            if "::" in spec and not spec.startswith("literal:"):
                path, transform = spec.split("::", 1)
                if transform in TRANSFORMS:
                    self.map_field_path_var.set(path)
                    self.map_transform_var.set(transform)
                else:
                    self.map_field_path_var.set(spec)
                    self.map_transform_var.set("(none)")
            else:
                self.map_field_path_var.set(spec)
                self.map_transform_var.set("(none)")
        else:
            profile = self._get_profile_by_id(iid)
            if profile:
                self.map_target_profile_var.set(profile["label"])
            self.map_field_name_var.set("")
            self.map_field_path_var.set("")
            self.map_transform_var.set("(none)")

    def _add_or_update_field(self):
        if self.mapper is None:
            return
        label = self.map_target_profile_var.get()
        pid = self._mapping_profile_id_by_label.get(label)
        if not pid:
            messagebox.showwarning("No Profile Selected", "Choose or create a profile first.")
            return
        profile = self._get_profile_by_id(pid)
        if not profile:
            return
        field_name_raw = self.map_field_name_var.get().strip()
        if not field_name_raw:
            messagebox.showwarning("Missing Field Name", "Enter a field name.")
            return
        field_name = re.sub(r"\W+", "_", field_name_raw).strip("_").lower()
        if not field_name:
            messagebox.showwarning("Invalid Field Name", "Field name must contain letters, numbers, or underscores.")
            return
        path = self.map_field_path_var.get().strip()
        if not path:
            messagebox.showwarning("Missing JSON Key", "Enter the JSON key or path to pull this field from.")
            return
        transform = self.map_transform_var.get()
        if transform and transform != "(none)" and not path.startswith("literal:"):
            spec = f"{path}::{transform}"
        else:
            spec = path
        profile["fields"][field_name] = spec
        self.mapper.save_config(self.mapper.config)
        self._refresh_mapping_tree()
        new_iid = f"{pid}::{field_name}"
        self.mapping_tree.item(pid, open=True)
        self.mapping_tree.selection_set(new_iid)
        self.mapping_tree.see(new_iid)
        messagebox.showinfo("Saved", f"Field '{field_name}' saved to '{profile['label']}'. It's now usable as {{{field_name}}} or #{field_name} in templates.")

    def _create_new_profile(self):
        if self.mapper is None:
            return
        label = self.new_profile_label_var.get().strip()
        keys_raw = self.new_profile_keys_var.get().strip()
        if not label:
            messagebox.showwarning("Missing Name", "Enter a profile name.")
            return
        detect_keys = [k.strip() for k in keys_raw.split(",") if k.strip()]
        if not detect_keys:
            messagebox.showwarning("Missing Detect Keys", "Enter at least one JSON key that identifies this log type.")
            return
        existing_ids = {p["id"] for p in self.mapper.config.get("profiles", [])}
        base_id = re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_") or "profile"
        pid = base_id
        n = 2
        while pid in existing_ids:
            pid = f"{base_id}_{n}"
            n += 1
        new_profile = {
            "id": pid,
            "label": label,
            "detect_keys": detect_keys,
            "fields": {k: "" for k in CANONICAL_FIELDS},
        }
        self.mapper.config.setdefault("profiles", []).insert(0, new_profile)
        self.mapper.save_config(self.mapper.config)
        self._refresh_mapping_tree()
        self.map_target_profile_var.set(label)
        self.mapping_tree.item(pid, open=True)
        self.mapping_tree.selection_set(pid)
        self.new_profile_label_var.set("")
        self.new_profile_keys_var.set("")
        messagebox.showinfo(
            "Profile Created",
            f"Profile '{label}' created with the standard baseline fields (blank). "
            f"Now use 'Add / Update Field' above to map its real JSON keys - each one "
            f"you add becomes usable as a placeholder in your templates.",
        )

    def _move_selected_mapping_field(self, direction):
        """Moves the currently selected field up (direction=-1) or down
        (direction=+1) within its profile's field order. A profile's
        'fields' dict is an ordinary Python dict, so its key order IS its
        display order - both here in the mapping_tree and, more
        importantly, in the Extracted Fields table after a log is parsed
        (parse() builds field_order straight from
        list(profile["fields"].keys())). New fields always get appended
        to the end when added, so without a way to move them, anything
        added after the fact (like a commonly-wanted Timestamp) is stuck
        at the bottom forever instead of grouped with related fields
        near the top."""
        if self.mapper is None:
            return
        sel = self.mapping_tree.selection()
        if not sel or "::" not in sel[0]:
            messagebox.showwarning("No Field Selected", "Select a field (not a profile) to reorder.")
            return
        pid, field_name = sel[0].split("::", 1)
        profile = self._get_profile_by_id(pid)
        if not profile:
            return
        keys = list(profile["fields"].keys())
        if field_name not in keys:
            return
        idx = keys.index(field_name)
        new_idx = idx + direction
        if new_idx < 0 or new_idx >= len(keys):
            # Already at the top/bottom - nothing to do. No popup for
            # this since it's a harmless, easily-repeated action (unlike
            # delete, which is destructive and worth confirming).
            return
        keys[idx], keys[new_idx] = keys[new_idx], keys[idx]
        profile["fields"] = {k: profile["fields"][k] for k in keys}
        self.mapper.save_config(self.mapper.config)
        self._refresh_mapping_tree()
        new_iid = f"{pid}::{field_name}"
        self.mapping_tree.item(pid, open=True)
        self.mapping_tree.selection_set(new_iid)
        self.mapping_tree.see(new_iid)

    def _rename_selected_profile(self):
        """Renames a profile's display LABEL only - its id (used
        internally to link saved incidents, query templates, and the
        profile-override dropdowns to this profile) never changes, so
        renaming is always safe and never breaks anything already
        pointing at this profile. Every place a profile label is shown
        (Field Mappings tree, Workspace/Query Builder profile-override
        dropdowns, Query Builder's template picker/profile choices) is
        refreshed immediately via _refresh_mapping_tree()."""
        if self.mapper is None:
            return
        sel = self.mapping_tree.selection()
        if not sel or "::" in sel[0]:
            messagebox.showwarning("No Profile Selected", "Select a profile (not a field) to rename.")
            return
        pid = sel[0]
        profile = self._get_profile_by_id(pid)
        if not profile:
            return
        new_label = simpledialog.askstring(
            "Rename Profile", "New name for this profile:",
            initialvalue=profile["label"], parent=self,
        )
        if new_label is None:
            return
        new_label = new_label.strip()
        if not new_label:
            messagebox.showwarning("Invalid Name", "Profile name can't be blank.")
            return
        if new_label == profile["label"]:
            return
        # Every dropdown that lists profiles (Workspace/Query Builder
        # profile-override, Query Builder's own template-editor Profile
        # choice) is keyed by label, so two profiles sharing one label
        # would make those dropdowns ambiguous - block it up front rather
        # than let it silently collide later.
        if any(p["label"] == new_label for p in self.mapper.config.get("profiles", []) if p["id"] != pid):
            messagebox.showwarning("Name Already Used", f"Another profile is already named '{new_label}'. Choose a different name.")
            return
        profile["label"] = new_label
        self.mapper.save_config(self.mapper.config)
        self._refresh_mapping_tree()
        if hasattr(self, "query_tmpl_tree"):
            # Manage Query Templates' tree caches each row's profile
            # label at the time it was last drawn - refresh it too so a
            # renamed profile doesn't leave stale names sitting there
            # until the next unrelated edit.
            self._refresh_query_template_tree()
        self.mapping_tree.item(pid, open=True)
        self.mapping_tree.selection_set(pid)
        self.mapping_tree.see(pid)
        messagebox.showinfo("Renamed", f"Profile renamed to '{new_label}'.")

    def _delete_selected_mapping(self):
        if self.mapper is None:
            return
        sel = self.mapping_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a profile or field to delete.")
            return
        iid = sel[0]
        if "::" in iid:
            pid, field_name = iid.split("::", 1)
            profile = self._get_profile_by_id(pid)
            if not profile:
                return
            if messagebox.askyesno("Delete Field", f"Delete field '{field_name}' from '{profile['label']}'?"):
                profile["fields"].pop(field_name, None)
                self.mapper.save_config(self.mapper.config)
                self._refresh_mapping_tree()
        else:
            profile = self._get_profile_by_id(iid)
            if not profile:
                return
            if messagebox.askyesno("Delete Profile", f"Delete the entire '{profile['label']}' profile? This cannot be undone."):
                self.mapper.config["profiles"] = [p for p in self.mapper.config.get("profiles", []) if p["id"] != iid]
                self.mapper.save_config(self.mapper.config)
                self._refresh_mapping_tree()

    def _selected_mapping_profile_ids(self):
        """Profile ids implied by the current tree selection - selecting a
        field row counts as selecting its parent profile."""
        ids = set()
        for iid in self.mapping_tree.selection():
            ids.add(iid.split("::", 1)[0])
        return ids

    def _export_mapping_profiles(self):
        """Export the selected profile(s), or every profile if none are
        selected, to a JSON file another analyst can import - the
        standard way to hand off a custom log-type mapping."""
        if self.mapper is None:
            return
        ids = self._selected_mapping_profile_ids()
        data = self.mapper.export_profiles(ids or None)
        if not data:
            messagebox.showinfo("Nothing to Export", "No profiles to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON file", "*.json")],
            initialfile="alertforge_field_mappings.json",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"profiles": data}, f, indent=2)
        messagebox.showinfo("Exported", f"Exported {len(data)} profile(s) to:\n{path}")

    def _import_mapping_profiles(self):
        """Import field-mapping profiles from a JSON file shared by another
        analyst. Profiles are matched by id - an id that already exists is
        skipped unless the analyst chooses to overwrite it."""
        if self.mapper is None:
            return
        path = filedialog.askopenfilename(filetypes=[("JSON file", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            messagebox.showerror("Import Failed", f"Could not read that file:\n{e}")
            return
        profiles = raw.get("profiles") if isinstance(raw, dict) else raw
        if not isinstance(profiles, list):
            messagebox.showerror("Import Failed", "That file doesn't look like an AlertForge field mappings export.")
            return

        imported, skipped = self.mapper.import_profiles(profiles)
        if skipped:
            overwrite = messagebox.askyesno(
                "Duplicate Profiles",
                f"{len(skipped)} profile(s) already exist with the same id and were skipped:\n"
                + ", ".join(skipped)
                + "\n\nOverwrite them with the imported versions?",
            )
            if overwrite:
                to_overwrite = [p for p in profiles if isinstance(p, dict) and p.get("id") in skipped]
                more_imported, _ = self.mapper.import_profiles(to_overwrite, overwrite=True)
                imported += more_imported
                skipped = []

        self._refresh_mapping_tree()
        msg = f"Imported {imported} profile(s)."
        if skipped:
            msg += f" Skipped {len(skipped)} duplicate(s)."
        messagebox.showinfo("Import Complete", msg)

    def _reload_mapping_file(self):
        if self.mapper is None:
            return
        self.mapping_text.delete("1.0", tk.END)
        try:
            self.mapping_text.insert(tk.END, self.mapper.raw_text())
        except Exception as e:
            messagebox.showerror("Error", f"Could not read field_mappings.json:\n{e}")

    def _save_mapping_file(self):
        if self.mapper is None:
            return
        raw = self.mapping_text.get("1.0", tk.END)
        try:
            self.mapper.save_raw(raw)
        except json.JSONDecodeError as e:
            messagebox.showerror("Invalid JSON", f"Could not save - JSON is invalid:\n{e}")
            return
        self._refresh_mapping_tree()
        messagebox.showinfo("Saved", "field_mappings.json updated.")


def main():
    app = SOCNotesApp()
    app.mainloop()


if __name__ == "__main__":
    main()

