"""Runs the real window code with a fake Tk module (no display needed).

It builds every widget, presses Choose and Scan through the same callbacks a user would trigger,
and drains the event queue the way the timer does. This catches wiring bugs in the window code
(NameErrors, bad callbacks, queue handling) that the pure-Python tests cannot see.
It does NOT check visual layout or real mouse behaviour; that still needs a manual run on Windows.
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests.fixtures.generate import build_fixtures

_VARS = []


class FakeVar:
    def __init__(self, value=""):
        self._v = value
        _VARS.append(self)

    def get(self):
        return self._v

    def set(self, v):
        self._v = v

    def trace_add(self, *_a, **_k):
        pass


class FakeRoot:
    def __init__(self):
        self.callbacks = []
        self.clipboard = ""

    def title(self, *_a):
        pass

    def geometry(self, *_a):
        pass

    def minsize(self, *_a):
        pass

    def configure(self, *_a, **_k):
        pass

    def after(self, ms, fn):
        self.callbacks.append(fn)

    def mainloop(self):
        pass

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, s):
        self.clipboard += s

    def destroy(self):
        pass


class Widget(mock.MagicMock):
    """Any Tk widget: records its constructor kwargs so tests can find buttons by label."""


def _fake_tk(root, widgets):
    tk = mock.MagicMock(name="tkinter")
    tk.Tk.return_value = root
    tk.StringVar = FakeVar
    tk.BooleanVar = FakeVar

    def make(*args, **kwargs):
        w = Widget(name="widget")
        w.kwargs = kwargs
        widgets.append(w)
        return w

    for name in ("Frame", "Label", "Button", "Checkbutton", "Entry", "LabelFrame", "Toplevel"):
        getattr(tk, name).side_effect = make
    tk.ttk = mock.MagicMock(name="ttk")
    tk.ttk.Progressbar.side_effect = make
    tk.scrolledtext = mock.MagicMock(name="scrolledtext")
    tk.scrolledtext.ScrolledText.side_effect = make
    tk.filedialog = mock.MagicMock(name="filedialog")
    tk.messagebox = mock.MagicMock(name="messagebox")
    return tk


class WindowLogicTests(unittest.TestCase):
    def test_choose_scan_and_drain_completes_a_real_scan(self):
        from imagehunter.ui import app

        fx = {f.filename: f for f in build_fixtures()}["appended_zip.png"]
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                src = Path(tmp) / "appended_zip.png"
                src.write_bytes(fx.data)
                _VARS.clear()
                root = FakeRoot()
                widgets = []
                tk = _fake_tk(root, widgets)
                tk.filedialog.askopenfilename.return_value = str(src)
                with mock.patch.dict(sys.modules, {"tkinter": tk, "tkinter.filedialog": tk.filedialog,
                                                   "tkinter.messagebox": tk.messagebox,
                                                   "tkinter.scrolledtext": tk.scrolledtext,
                                                   "tkinter.ttk": tk.ttk}):
                    self.assertEqual(app.run_gui(), 0)

                def button(label):
                    return next(w for w in widgets if w.kwargs.get("text") == label)

                # Choose image, the same callback the button runs.
                button("Choose image...").kwargs["command"]()
                self.assertTrue(any(v.get() == str(src) for v in _VARS))

                # Press Scan: start_scan is passed to config() on the Scan button.
                scan = button("Scan")
                start = [c.kwargs["command"] for c in scan.config.call_args_list
                         if "command" in c.kwargs][-1]
                start()

                # Drain the timer callbacks until the worker reports a result.
                deadline = time.time() + 60
                finished = False
                while time.time() < deadline and not finished:
                    pending, root.callbacks = root.callbacks, []
                    for fn in pending:
                        fn()
                    finished = any(isinstance(v.get(), str) and v.get().startswith("Scan finished")
                                   for v in _VARS)
                    if not pending:
                        time.sleep(0.05)
                self.assertTrue(finished, "scan did not finish in the window logic")

                # The console received real, live lines for the scan.
                console_text = "".join(str(c.args[1]) for w in widgets
                                       for c in w.insert.call_args_list if len(c.args) > 1)
                self.assertIn("SHA-256 calculation completed", console_text)
                self.assertIn("HTML report written", console_text)

                # Result buttons become usable only after the scan.
                self.assertEqual(button("Open HTML Report").config.call_args_list[-1].kwargs["state"], "normal")
                self.assertEqual(button("Scan").config.call_args_list[-1].kwargs["state"], "normal")
            finally:
                os.chdir(cwd)

    def test_result_buttons_disabled_before_any_scan(self):
        from imagehunter.ui import app
        root = FakeRoot()
        widgets = []
        tk = _fake_tk(root, widgets)
        with mock.patch.dict(sys.modules, {"tkinter": tk, "tkinter.filedialog": tk.filedialog,
                                           "tkinter.messagebox": tk.messagebox,
                                           "tkinter.scrolledtext": tk.scrolledtext,
                                           "tkinter.ttk": tk.ttk}):
            app.run_gui()
        for label in ("Open HTML Report", "Export JSON Report", "View Confirmed Flags"):
            btn = next(w for w in widgets if w.kwargs.get("text") == label)
            # set_buttons(False) ran during construction, so the last state call must be disabled.
            self.assertEqual(btn.config.call_args_list[-1].kwargs["state"], "disabled")

    def test_missing_tkinter_returns_error_code_without_crash(self):
        from imagehunter.ui import app
        with mock.patch.dict(sys.modules, {"tkinter": None}):
            self.assertEqual(app.run_gui(), 1)


if __name__ == "__main__":
    unittest.main()
