#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${1:-poetry_add_commands.sh}"

python3 - "$OUT_FILE" <<'PY'
import ast
import os
import sys
from pathlib import Path

out_file = Path(sys.argv[1]).resolve()
root = Path(".").resolve()

IGNORE_DIRS = {
    ".git", ".hg", ".svn",
    ".venv", "venv", "env",
    "__pycache__", "build", "dist",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "node_modules",
}

IGNORE_FILE_PARTS = {
    "site-packages",
    "dist-packages",
}

IGNORE_NAME_PREFIXES = (
    "test_",
)

IGNORE_NAMES = {
    "conftest.py",
}

COMMON_NAME_MAP = {
    "yaml": "pyyaml",
    "PIL": "pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "OpenSSL": "pyopenssl",
    "Crypto": "pycryptodome",
    "fitz": "pymupdf",
    "Image": "pillow",
}

# Standardbibliothek
stdlib = set(sys.builtin_module_names)
if hasattr(sys, "stdlib_module_names"):
    stdlib |= set(sys.stdlib_module_names)

# Lokale Top-Level-Module/Pakete im Projekt erkennen
local_modules = set()
for child in root.iterdir():
    name = child.name
    if name in IGNORE_DIRS:
        continue
    if child.is_dir():
        if (child / "__init__.py").exists():
            local_modules.add(name)
    elif child.is_file() and child.suffix == ".py":
        local_modules.add(child.stem)

imports = set()

def should_skip_file(path: Path) -> bool:
    parts = set(path.parts)
    if parts & IGNORE_DIRS:
        return True
    if any(part in IGNORE_FILE_PARTS for part in path.parts):
        return True
    if path.name in IGNORE_NAMES:
        return True
    if path.name.startswith(IGNORE_NAME_PREFIXES):
        return True
    return False

for pyfile in root.rglob("*.py"):
    if should_skip_file(pyfile):
        continue

    try:
        source = pyfile.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            source = pyfile.read_text(encoding="latin-1")
        except Exception:
            continue
    except Exception:
        continue

    try:
        tree = ast.parse(source, filename=str(pyfile))
    except Exception:
        continue

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top:
                    imports.add(top)

        elif isinstance(node, ast.ImportFrom):
            # relative imports ignorieren: from .foo import bar
            if node.level and node.level > 0:
                continue
            if node.module:
                top = node.module.split(".")[0]
                if top:
                    imports.add(top)

# filtern
final_packages = []
seen = set()

for name in sorted(imports, key=str.lower):
    if not name:
        continue
    if name.startswith("_"):
        continue
    if name in stdlib:
        continue
    if name in local_modules:
        continue

    pkg = COMMON_NAME_MAP.get(name, name)

    if pkg not in seen:
        seen.add(pkg)
        final_packages.append(pkg)

lines = [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "",
    "# automatisch erzeugt",
]

for pkg in final_packages:
    lines.append(f"poetry add {pkg}")

lines.append("")

out_file.write_text("\n".join(lines), encoding="utf-8")
os.chmod(out_file, 0o755)

print(f"Erzeugt: {out_file}")
print(f"Pakete: {len(final_packages)}")
for pkg in final_packages:
    print(pkg)
PY

echo
echo "Fertig. Ausführen mit:"
echo "  bash \"$OUT_FILE\""