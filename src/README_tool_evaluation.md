# Vulnerability Evaluation Framework


## Architekurüberblick

                      ┌──────────────────────────┐
                      │  Ground Truth Generator  │
                      │  (OSV-based)             │
                      └───────────┬──────────────┘
                                  │
              Ground Truth (CSV)  │   SBOM (CycloneDX)
                                  │
                                  ▼
        ┌───────────────────────────────────────────────────┐
        │            Vulnerability Evaluation Framework     │
        │                                                   │
        │  ┌───────────────┐     ┌──────────────────────┐   │
        │  │ Ground Truth  │     │  Tool Adapter Layer  │   │
        │  │   Loader      │     │──────────────────────│   │
        │  └───────┬───────┘     │  Dependency-Track    │   │
        │          │             │  OSV Scanner         │   │
        │          │             │  GitHub Advisory DB  │   │
        │          │             │  Evaltech Detector   │   │
        │          │             └─────────┬────────────┘   │
        │          │                       │                │
        │          ▼                       ▼                │
        │   ┌───────────────────────────────────────────┐   │
        │   │        Normalized Finding Model           │   │
        │   │ (ecosystem, component, version, vuln-id)  │   │
        │   └───────────────────┬───────────────────────┘   │
        │                       │                           │
        │                       ▼                           │
        │   ┌───────────────────────────────────────────┐   │
        │   │            Evaluation Engine              │   │
        │   │      TP / FP / FN Computation             │   │
        │   └───────────────────┬───────────────────────┘   │
        │                       │                           │
        │                       ▼                           │
        │   ┌───────────────────────────────────────────┐   │
        │   │   FP Heuristic Engine (optional)          │   │ 
        │   │   (Evaltech only)                         │   │
        │   └───────────────────┬───────────────────────┘   │
        │                       │                           │
        │                       ▼                           │
        │   ┌───────────────────────────────────────────┐   │               
        │   │  Tables, Metrics, Heuristic Quality       │   │
        │   └───────────────────────────────────────────┘   │
        └───────────────────────────────────────────────────┘



## 1. Zielsetzung und Einordnung

Dieses Projekt stellt ein **tool-agnostisches Evaluationsframework** zur Verfügung, mit dem
**Vulnerability-Scanner und SCA-Tools** systematisch gegen einen **Ground-Truth-Datensatz**
evaluiert werden können.

Der Fokus liegt **ausschließlich auf Vulnerabilities** und deren **korrekter Zuordnung**
zu:

- Ökosystem
- Komponente
- Version
- Vulnerability (OSV / CVE)

Das Framework ist **kein Scanner** und **kein SBOM-Generator**, sondern ein
**Evaluations- und Vergleichswerkzeug**.

---

## 2. Zentrale Artefakte

### 2.1 Ground Truth (CSV)

Der Ground-Truth-Datensatz dient als **Goldstandard** für die Evaluation.

Er enthält pro Zeile genau eine Vulnerability-Zuordnung:

- Ecosystem
- Component
- Version
- OSV-ID
- optionales CVE-Alias
- is_vulnerable = true

**Definition der Ground Truth**

> Für jede ausgewählte Komponente und genau eine Version enthält der Datensatz
> alle Vulnerabilities, die OSV **zum Build-Zeitpunkt** als diese Version betreffend ausweist.

---

### 2.2 SBOM (CycloneDX)

Die erzeugte SBOM:

- enthält **exakt dieselben Komponenten und Versionen** wie die Ground Truth
- ist direkt in Dependency-Track importierbar
- dient als Eingabe für zu evaluierende Tools

**Invariante**

> Jede Vulnerability der Ground Truth bezieht sich auf eine Komponente, die
> auch in der SBOM enthalten ist – und umgekehrt.

---

## 3. Unterstützte Scanner (Adapter)

Das Framework nutzt ein **Adapter-Prinzip**, um unterschiedliche Scanner einheitlich
auszuwerten.

### 3.1 Aktuell integrierte Adapter

| Adapter | Beschreibung |
|------|-------------|
| Dependency-Track | Klassischer SBOM-basierter SCA-Scanner |
| OSV | OSV als eigenständiger Scanner |
| GitHub Advisory DB | GitHub Security Advisories (GHSA) |
| Evaltech | Post-Processing von Dependency-Track mit FP-Heuristik |

Alle Adapter liefern **normalisierte Findings** im gleichen internen Modell.

---

## 4. Evaltech Vulnerability Detector

Der **Evaltech Detector** ist **kein eigenständiger Scanner**.

### Architektur

1. SBOM wird in Dependency-Track importiert
2. Dependency-Track liefert Findings
3. Evaltech:
   - übernimmt alle DT-Findings unverändert
   - bewertet jedes Finding mit einer FP-Heuristik
   - markiert Findings optional als heuristisch False Positive

**Wichtig**

- Evaltech entfernt **keine Findings**
- Evaltech verändert **nicht** die Tool-Erkennung
- Evaltech ergänzt ausschließlich **Heuristik-Metadaten**

---

## 5. False-Positive-Heuristik

Die FP-Heuristik analysiert u. a.:

- Ökosystem-Konsistenz
- Namensübereinstimmung
- CPE-Übereinstimmung
- Fremdprodukte (OS, Browser, Server, Appliances)
- Execution Context vs. Library

### 5.1 FP-Class (Subtype)

| FP-Class | Bedeutung |
|--------|----------|
| ecosystem | CVE gehört zu anderem Ökosystem |
| foreign | CVE betrifft fremdes Produkt |
| name | Komponentenname nicht im Advisory |
| cpe | CPEs passen nicht zur Komponente |
| types | Typ-Pakete (`@types/*`) |

Ein Finding ohne FP-Class gilt als **heuristisch korrekt**.

---

## 6. Evaluationsmetriken

### 6.1 Klassische Metriken

| Metrik | Bedeutung |
|------|----------|
| TP | True Positives |
| FP | False Positives |
| FN | False Negatives |

Abgeleitet:

- Recall = TP / (TP + FN)
- Overlap Rate = TP / (TP + FP)

---

### 6.2 Heuristic Quality Matrix (Evaltech)

Diese Matrix bewertet **die Heuristik**, nicht den Scanner.

| Kennzahl | Bedeutung |
|--------|----------|
| HTP | FP korrekt erkannt |
| HFN | FP übersehen |
| HFP | TP fälschlich als FP markiert |
| HTN | TP korrekt nicht markiert |

Abgeleitete Kennzahlen:

- Heuristic Precision = HTP / (HTP + HFP)
- Heuristic Recall = HTP / (HTP + HFN)

Diese Metriken werden **nur erzeugt**, wenn der Adapter eine FP-Heuristik unterstützt.

---

## 7. Report – Tabellen und Bedeutung

### 7.1 Gemeinsame Spalten

| Spalte | Bedeutung |
|------|----------|
| # | Laufende Nummer |
| Ecosystem | z. B. pypi, npm |
| Component | Normalisierter Paketname |
| Version | Exakte Version |
| CVE-ID | CVE-Alias (falls vorhanden) |
| OSV-ID | Primäre Advisory-ID |
| Description | Beschreibung aus dem Tool |

---

### 7.2 Zusätzliche Heuristik-Spalten

| Spalte | Bedeutung |
|------|----------|
| FP-Class | Subtyp der Heuristik |
| FP-Reason | Textuelle Begründung |
| Heuristic-FP | yes / no |

---

## 8. Tabellen im Detail

### 8.1 False Positives (tool findings not in Ground Truth)

- Vom Tool gemeldet
- Nicht in der Ground Truth
- Kandidaten für:
  - Überdetektion
  - Fehlzuordnung
  - ungenaue Heuristiken

---

### 8.2 False Negatives (Ground Truth missed by tool)

- In Ground Truth vorhanden
- Vom Tool **nicht** gemeldet

**Warum ist die Description leer?**

- FN haben kein Tool-Finding
- Descriptions stammen ausschließlich aus Tool-Daten
- Keine implizite Anreicherung aus OSV (methodisch sauber)

---

### 8.3 True Positives (Correct Matches)

- Tool-Finding stimmt exakt mit Ground Truth überein

---

### 8.4 Findings marked as FP by heuristic

- Alle Findings, die heuristisch als FP markiert wurden
- Unabhängig davon, ob sie TP oder FP im Ground-Truth-Sinn sind

Diese Tabelle ist zentral für die Bewertung der Heuristik.

---

## 9. Methodische Klarstellung

- Ground Truth entscheidet über TP / FP / FN
- Heuristik entscheidet über Markierung
- Beides wird **strikt getrennt**

> Heuristik ist eine Hypothese – keine Wahrheit.

---

## 10. Erweiterbarkeit

Das Framework ist vorbereitet für:

- weitere Ökosysteme (npm, maven, nuget)
- weitere Scanner mit offener API
- zusätzliche Heuristiken
- alternative Ground-Truth-Definitionen

---

## 11. Fazit

- Ergebnisse sind reproduzierbar und transparent
- Heuristiken sind messbar
- Scanner sind vergleichbar
- Methodische Trennung bleibt jederzeit nachvollziehbar
