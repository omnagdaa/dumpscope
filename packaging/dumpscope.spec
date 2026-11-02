# Build with: uv run --group package pyinstaller --noconfirm packaging/dumpscope.spec
import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = os.path.dirname(SPECPATH)

# Qt pieces the app never uses. PyInstaller works from imports, but these still
# arrive as plugins or as dependencies of the plugins.
UNUSED = (
    "Qt6Quick", "Qt6Qml", "Qt6Pdf", "Qt6Network", "Qt6OpenGL", "Qt6VirtualKeyboard",
    "qgif", "qjpeg", "qtiff", "qwebp", "qicns", "qtga", "qwbmp", "qpdf",
    "qvirtualkeyboard", "qtvirtualkeyboard", "plugins/tls", "plugins\\tls",
    "plugins/networkinformation", "plugins\\networkinformation",
    "plugins/generic", "plugins\\generic", "plugins/egldeviceintegrations",
    "plugins/xcbglintegrations", "plugins/platforminputcontexts",
    "plugins/sqldrivers", "plugins\\sqldrivers",
    # The GTK theme plugin would drag the whole of GTK in from the build machine.
    "qgtk3", "qeglfs", "qlinuxfb", "qminimal", "qvkkhrdisplay", "qvnc", "EglFS",
)


# What only the GTK plugin needed; PyInstaller collected it before the plugin was dropped.
GTK = ("libgtk", "libgdk", "libcairo", "libpango", "libatk", "libatspi", "libglycin", "librsvg",
       "libepoxy", "libharfbuzz", "libxml2", "libicu", "libfribidi", "libgraphite2", "libthai",
       "libdatrie", "libpixman", "libjpeg", "libtiff", "libwebp", "liblcms", "libseccomp")


def wanted(entry):
    name = entry[0].replace("\\", "/")
    if "/" not in name and name.startswith(GTK):     # top level only: Qt keeps its own ICU
        return False
    return (not any(part in entry[0] for part in UNUSED)
            and "/translations/" not in name and "__pycache__" not in name)


a = Analysis(
    [os.path.join(ROOT, "main.py")],
    pathex=[ROOT],
    datas=[
        (os.path.join(ROOT, "core", "vol_plugins"), "core/vol_plugins"),
        (os.path.join(ROOT, "packaging", "dumpscope.svg"), "packaging"),
        *collect_data_files("volatility3", include_py_files=True),
        *copy_metadata("dumpscope"),
    ],
    # vol3 discovers its plugins by walking its package folder for .py files,
    # so they must stay on disk as source and be listed here for their imports.
    hiddenimports=collect_submodules("volatility3", filter=lambda n: not n.startswith(("volatility3.symbols", "volatility3.plugins")))
    + collect_submodules("Crypto"),
    module_collection_mode={"volatility3": "py"},
    excludes=["tkinter", "pytest", "_pytest", "pip", "setuptools", "wheel", "pydoc_data",
              "lib2to3", "ensurepip", "PyQt6.QtNetwork", "PyQt6.QtQml", "PyQt6.QtQuick"],
)
a.binaries = [e for e in a.binaries if wanted(e)]
a.datas = [e for e in a.datas if wanted(e)]

pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="dumpscope",
    console=False,          # no terminal window on Windows
    icon=os.path.join(ROOT, "packaging", "dumpscope.ico" if sys.platform == "win32" else "dumpscope.icns"),
    strip=sys.platform.startswith("linux"),
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="dumpscope", strip=sys.platform.startswith("linux"))

if sys.platform == "darwin":
    app = BUNDLE(coll, name="DumpScope.app", bundle_identifier="io.github.omnagdaa.dumpscope",
                 icon=os.path.join(ROOT, "packaging", "dumpscope.icns"))
