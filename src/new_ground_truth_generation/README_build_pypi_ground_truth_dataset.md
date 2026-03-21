# Build Ground Truth Dataset & SBOM (OSV-basiert)

## 1. Zielsetzung und Einordnung

Dieses Skript dient der **Erzeugung eines belastbaren Ground-Truth-Datensatzes** für die
**Evaluation von Software-Composition-Analysis-(SCA)-Tools** und Vulnerability-Scannern
(z. B. Dependency-Track).

Der Fokus liegt **ausschließlich auf Vulnerabilities** und deren **korrekter Zuordnung
zu konkreten Komponenten und Versionen**.

Das Tool ist **kein allgemeiner SBOM-Generator** und **kein vollständiger Vulnerability-Katalog**,
sondern ein **Evaluationswerkzeug** mit klar definiertem Scope.

---

## 2. Erzeugte Artefakte

Das Skript erzeugt **zwei strikt konsistente Artefakte**:

1. **Ground-Truth-Datensatz (CSV)**
   - enthält alle Vulnerabilities pro ausgewählter Komponente und Version
   - dient als Referenz („Goldstandard“) für TP/FP/FN-Berechnungen

2. **CycloneDX-SBOM (JSON)**
   - enthält exakt dieselben Komponenten und Versionen
   - ist direkt in Dependency-Track importierbar
   - dient als Eingabe für zu evaluierende Scanner

**Zentrale Invariante:**

> Jede Vulnerability im Ground-Truth-Datensatz bezieht sich auf genau eine Komponente
> und genau eine Version, die auch in der SBOM enthalten ist – und umgekehrt.

---

## 3. Grundprinzip der Ground Truth

### 3.1 Warum OSV?

OSV (Open Source Vulnerabilities) wird als **primäre Datenquelle** verwendet, weil OSV:

- paketbasiert arbeitet (nicht nur CPE-basiert)
- versionsspezifische Betroffenheit explizit modelliert
- mehrere Advisory-Formate konsolidiert (OSV, GHSA, PYSEC, CVE)
- eine konsistente API für automatisierte Auswertung bietet

OSV fungiert damit als **Referenzmodell für „korrekte Zuordnung“**.

---

### 3.2 Definition von „Ground Truth“ in diesem Projekt

In diesem Kontext bedeutet *Ground Truth* **nicht**:

- alle weltweit existierenden CVEs
- alle historischen Versionen eines Pakets
- alle denkbaren Fehlkonfigurationen

Sondern präzise:

> Für jede ausgewählte Komponente und **eine konkret ausgewählte Version**
> enthält der Datensatz **alle Vulnerabilities, die OSV zum Build-Zeitpunkt
> als diese Version betreffend ausweist**.

Diese Definition ist:
- klar
- überprüfbar
- reproduzierbar
- fair gegenüber zu evaluierenden Tools

---

## 4. Datenbeschaffung – detaillierte Methodik

### 4.1 Auswahl relevanter Komponenten

Als Startmenge dient die Liste der **meistgenutzten PyPI-Pakete der letzten 30 Tage**:

- Quelle: *Top PyPI Packages (30 days)*
- Zweck: Abbildung realistisch verbreiteter Software
- Vermeidung künstlicher Testfälle mit geringer Praxisrelevanz

Aus der Liste werden bewusst **mehr Kandidaten geladen als benötigt** (`samples * 5`),
um spätere Filtereffekte auszugleichen.

---

### 4.2 Ermittlung aller OSV-Vulnerabilities pro Paket

Für jedes Kandidatenpaket wird die OSV-API abgefragt:

