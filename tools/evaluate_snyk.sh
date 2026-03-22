#!/usr/bin/env bash

# Deaktiviert "fail fast":
# Das Skript bricht nicht automatisch bei Fehlern ab.
# Wichtig, wenn der Exit-Code später bewusst ausgewertet wird.
set +e

# $1 = Pfad zur SBOM-Datei
# Dieser Parameter wird typischerweise von einem übergeordneten Adapter übergeben.

# Aufruf der Snyk CLI:
# - sbom test: führt einen Vulnerability-Scan auf Basis einer SBOM durch
# - --experimental: Feature ist (noch) experimentell
# - --file="$1": Übergabe des SBOM-Pfads
# - --json: Ausgabe im JSON-Format für Weiterverarbeitung
/usr/local/bin/snyk sbom test \
  --experimental \
  --file="$1" \
  --json