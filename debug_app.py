"""
Temporary diagnostic script - prints progress at each startup step so we
can see exactly where AlertForge silently fails. Run this instead of
app.py:

    python debug_app.py

Safe to delete once the real problem is found.
"""

import os
import shutil
import sys
import traceback

# Always start from a clean bytecode cache: this script does `import app`,
# and Python will silently reuse a stale __pycache__/app.*.pyc left over
# from an earlier version of app.py if one exists, even though the .py
# source file has since changed. That produces confusing
# "AttributeError: object has no attribute '_some_method'" errors that
# have nothing to do with the actual app code. Wiping the cache here (and
# telling Python not to write a new one) makes this script immune to that.
sys.dont_write_bytecode = True
_here = os.path.dirname(os.path.abspath(__file__))
shutil.rmtree(os.path.join(_here, "__pycache__"), ignore_errors=True)


def log(msg):
    print(f"[debug] {msg}", flush=True)


try:
    log("importing tkinter...")
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    log("tkinter imported OK")

    log("importing parser_core...")
    from parser_core import DB, FieldMapper, fill_template, CANONICAL_FIELDS, TRANSFORMS
    log("parser_core imported OK")

    log("importing app...")
    import app
    log("app module imported OK")

    log("creating Tk root via app.SOCNotesApp.__new__ + manual step-through...")

    # Step through SOCNotesApp.__init__ manually so we can log between
    # each stage instead of it happening all at once inside __init__.
    log("calling tk.Tk.__init__ (this creates the actual OS window)...")
    root = tk.Tk.__new__(app.SOCNotesApp)
    tk.Tk.__init__(root)
    log("tk.Tk.__init__ done - a blank window should exist now")

    root.title(app.APP_TITLE)
    root.geometry("1280x820")
    root.minsize(1000, 650)
    log("title/geometry set")

    log(f"opening database at {app.DB_PATH!r}...")
    root.db = DB(app.DB_PATH)
    log("database opened OK")

    log(f"loading field mappings at {app.MAPPING_PATH!r}...")
    try:
        root.mapper = FieldMapper(app.MAPPING_PATH)
        log("field mappings loaded OK")
    except Exception as e:
        log(f"field mappings FAILED to load: {e!r} (app would continue with mapper=None)")
        root.mapper = None

    root.extracted = {k: "" for k in CANONICAL_FIELDS}
    root.field_order = list(CANONICAL_FIELDS)
    root.current_incident_id = None
    root._text_widgets = []
    root.theme_name = "light"
    root.option_add("*Font", (app.FONT_FAMILY, 10))
    root.style = ttk.Style(root)
    try:
        root.style.theme_use("clam")
        log("ttk theme set to 'clam' OK")
    except tk.TclError as e:
        log(f"ttk theme_use('clam') failed (non-fatal): {e!r}")

    log("building menu...")
    root._build_menu()
    log("menu built OK")

    log("building main UI (tabs, widgets)...")
    root._build_ui()
    log("UI built OK")

    log("refreshing template lists...")
    root._refresh_template_lists()
    log("template lists refreshed OK")

    log("refreshing incident list...")
    root._refresh_incident_list()
    log("incident list refreshed OK")

    log("applying light theme...")
    root._apply_theme("light")
    log("theme applied OK")

    log("ALL SETUP STEPS SUCCEEDED. Window should be visible now.")
    log("calling root.mainloop() - the window should stay open until you close it.")
    root.mainloop()
    log("mainloop() RETURNED - this only happens after the window is closed.")

except SystemExit:
    raise
except BaseException:
    log("!!! EXCEPTION RAISED !!!")
    traceback.print_exc()
    print("\nPress Enter to close this window...")
    input()
