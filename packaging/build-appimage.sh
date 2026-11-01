#!/bin/sh
# Wraps the PyInstaller output (dist/dumpscope) into dist/DumpScope-x86_64.AppImage.
# Usage: packaging/build-appimage.sh path/to/appimagetool
# With no tool given it stops after preparing build/DumpScope.AppDir.
set -eu
tool=${1:+$(realpath "$1")}
cd "$(dirname "$0")/.."

appdir=build/DumpScope.AppDir
rm -rf "$appdir"
mkdir -p "$appdir/usr/lib"
cp -a dist/dumpscope "$appdir/usr/lib/dumpscope"
cp packaging/dumpscope.desktop packaging/dumpscope.svg "$appdir/"
cat > "$appdir/AppRun" <<'RUN'
#!/bin/sh
exec "$(dirname "$(readlink -f "$0")")/usr/lib/dumpscope/dumpscope" "$@"
RUN
chmod +x "$appdir/AppRun"

[ -n "$tool" ] || exit 0
# Extract-and-run: build machines and containers often have no FUSE.
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" "$appdir" dist/DumpScope-x86_64.AppImage
