# Rechtsgrundlagen-Review — Protokoll (W4, ADR-0018)

Stand: 2026-07-13 — **W4 ABGESCHLOSSEN: Alle 154 Checks mit BEIDEN Vermerken
(Gründer + legal-reviewer) durch das Vier-Augen-Gate (Batches Nr. 1–10)**.
Abschnitt A ebenfalls mit beiden Vermerken abgeschlossen. Merge-Gate nach
ADR-0018 erfüllt. Nr. 1 umfasst 14 Checks nach Umzug GCP-NR1-005 → GCP-NR9-008.
Befund 2 vollständig abgearbeitet (Punkt 2: `nis2umsvo_refs` entfernt, 13.07.).

**Kampagnen-Bilanz (Erstprüfungen):** 154 Checks geprüft, 128 Beanstandungen in
10 Batches (Nr. 1: 10, Nr. 2: 13, Nr. 3: 12, Nr. 4: 17+6, Nr. 5: 19+2, Nr. 6: 14+1,
Nr. 7: 7, Nr. 8: 15, Nr. 9: 14+2, Nr. 10: 13+1) — alle umgesetzt und nachgeprüft.
Wiederkehrende Befund-Muster: (1) Texte behaupteten mehr als geprüft,
(2) Proxy-/Heuristik-Positivnachweise, (3) stille Fehlerpfade (except/pass),
(4) Nicht-Anwendbarkeit als Mangel, (5) veraltete Tool-Listen, (6) invertierte
oder strukturell leere Prüfkriterien (u. a. AZ-NR7-001: falsche API — meldete
IMMER einen Mangel). Gesammelte Folge-Aufgaben (API-Ausbauten, Mapping-
Erweiterungen mit eigenem Gate) sind in den Batch-Verläufen dokumentiert.

Regel (ADR-0018): Jede Änderung an Mapping, Checks oder rechtlich formulierenden
Reporttexten braucht vor dem Merge **beide** Review-Vermerke — (a) Gründer,
(b) Agent `legal-reviewer`. Ohne beide Vermerke kein Merge nach `main`.

## Primärquelle

| Eigenschaft | Wert |
|---|---|
| Gesetz | BSI-Gesetz (BSIG) i. d. F. des NIS2UmsuCG |
| Fundstelle | § 30 „Risikomanagementmaßnahmen besonders wichtiger Einrichtungen und wichtiger Einrichtungen" |
| Quelle | <https://www.gesetze-im-internet.de/bsig_2025/__30.html> |
| Abgerufen am | 2026-07-11 (zweifach abgerufen, Wortlaut kreuzgeprüft) |
| In Kraft seit | 06.12.2025 |

## Befund 1: Vier Normtexte zitierten die NIS2-Richtlinie statt des BSIG

Das Mapping (`nis2scan/engine/mapping/bsig_30.py`) und die `BSIG_30_TEXT`-
Konstanten der Check-Module (werden in **jedes Finding** gestempelt) trugen bei
Nr. 4, 7, 8 und 9 den Wortlaut von **Art. 21 Abs. 2 der NIS2-Richtlinie
(EU) 2022/2555**, nicht den des deutschen §30 Abs. 2 BSIG. Korrigiert auf den
Primärquellen-Wortlaut (Mapping-Release 2026.05 → **2026.07**, ADR-0013):

| Nr. | Vorher (Richtlinien-Wortlaut) | Jetzt (BSIG-Wortlaut, wörtlich) |
|---|---|---|
| 4 | „… Beziehungen **zwischen den einzelnen Einrichtungen und ihren** unmittelbaren Anbietern …" | „… Beziehungen **zu** unmittelbaren Anbietern oder Diensteanbietern" |
| 7 | „Grundlegende Verfahren im Bereich der **Cyberhygiene** und Schulungen …" | „grundlegende **Schulungen und Sensibilisierungsmaßnahmen** im Bereich der Sicherheit in der Informationstechnik" |
| 8 | „Konzepte und Verfahren für den Einsatz von **Kryptografie und gegebenenfalls Verschlüsselung**" | „Konzepte und **Prozesse** für den Einsatz von **kryptographischen Verfahren**" |
| 9 | „… Konzepte für die Zugriffskontrolle und für das **Management von Anlagen**" | „**Erstellung von Konzepten** für die Sicherheit des Personals, die Zugriffskontrolle und für die **Verwaltung von IKT-Systemen, -Produkten und -Prozessen**" |

Nr. 1, 2, 3, 5, 6, 10 stimmten bereits wörtlich überein (jetzt ebenfalls mit
Quellenstruktur belegt).

### Umgesetzte Änderungen (Review-Gegenstand)

1. `Rechtsquelle`-Struktur (Fundstelle, URL, Abrufdatum, wörtliches Zitat) an
   allen 10 `Bsig30Area`-Einträgen; Konsistenz `law_text_de` == Zitat wird
   per Test erzwungen (`tests/test_mapping/test_quellen.py`).
2. `law_text_de` aller 10 Bereiche = wörtlicher Normtext.
3. `BSIG_30_TEXT`-Konstanten in 27 Check-Modulen angeglichen (3 stimmten schon).
4. `MAPPING_VERSION` = 2026.07.

## Befund 2: Offene Punkte für den Review (nicht geändert)

| # | Punkt | Empfehlung |
|---|---|---|
| 1 | **Produkt-Labels** `title_de` weichen teils vom Gesetzeswortlaut ab: Nr. 7 „Grundlegende Cyberhygiene und Schulungen" (Gesetz: Schulungen/Sensibilisierung; „Cyberhygiene" ist Richtlinien-Vokabular), Nr. 9 „Zugriffskontrolle und Asset-Management" (Gesetz: Verwaltung von IKT-Systemen, -Produkten und -Prozessen). Labels erscheinen in Reports, UI, CLAUDE.md. | **ERLEDIGT 2026-07-12** (Gründerentscheid: an Gesetz angleichen). Nr. 7 → „Grundlegende Schulungen und Sensibilisierung", Nr. 9 → „Personalsicherheit, Zugriffskontrolle und IKT-Verwaltung"; Downstream-Kopien (`scanner.py`, `CLAUDE.md`, `README`, Skill `nis2-mapping`) nachgezogen, Feld-Doku `title_de` korrigiert. |
| 2 | **`nis2umsvo_refs`** („Anhang I, x.y") sind bisher **ohne Quellennachweis** — Existenz und Fundstellen der NIS2UmsVO-Anhänge wurden noch nicht gegen eine Primärquelle geprüft. | **ERLEDIGT 2026-07-13 — ENTFERNT.** Recherche (legal-reviewer, Primärquellen recht.bund.de/gesetze-im-internet.de/BSI/EUR-Lex): Eine deutsche „NIS2UmsVO" mit „Anhang I" existiert nicht als verkündete Norm (§ 30 Abs. 5 BSIG-Ermächtigung bislang nicht ausgeschöpft); die EU-DVO 2024/2690 gilt nur für bestimmte digitale Anbieter und hat eine abweichende Anhang-Struktur. Alle Referenzen aus Mapping, Finding-Schema (totes Feld `nis2umsvo_ref`), README, Doku und Skills entfernt. Wiederaufnahme erst nach Verkündung einer Konkretisierungs-VO mit wortgetreuem Quellennachweis. **Vier-Augen-Vermerke:** legal-reviewer PASS (Nachprüfung 13.07.2026); Gründer-Freigabe per Session-Chat 13.07.2026. |
| 3 | **ISO-27001-Referenzen** sind Fachzuordnungen, keine Rechtsquellen — Zuordnungsqualität ist Teil des Check-für-Check-Reviews (Batch je §30-Nr.). | Im Batch-Review mitprüfen. |
| 4 | **`description_de`/`abdeckung_de`/`attestierungspunkte`** sind eigene Formulierungen (keine Zitate) — auf Aussagen prüfen, die über den cloud-technischen Teilaspekt hinausgehen (ADR-0009/0012). | Batch-Review. |
| 5 | **Rechtsstand-String** `„BSIG i. d. F. des NIS2UmsuCG, in Kraft seit 06.12.2025"` — Datum gegen BGBl-Fundstelle verifizieren und BGBl-Zitat ergänzen. | **ERLEDIGT 2026-07-12:** RECHTSSTAND ergänzt um „(BGBl. 2025 I Nr. 301)". Fundstelle bereits in der Teil-A-Zweitprüfung gegen recht.bund.de verifiziert (BSI-PM 05.12.2025 als Sekundärbestätigung); punktuelle Bestätigung in der nächsten Reviewer-Runde vorgemerkt. |

## Befund 3: In der Zweitprüfung (2026-07-12) gefundene Text-Abweichungen — korrigiert

Der `legal-reviewer` beanstandete in der Erstprüfung zwei Beschreibungstexte mit
Rechtsbezug (über den reinen Normtext hinaus). Beide sind korrigiert:

| # | Stelle | Vorher | Jetzt |
|---|---|---|---|
| B2 | Nr. 2 `description_de` | „Beinhaltet die BSI-Meldepflichten nach §32 BSIG." (stellt § 32 fälschlich als Bestandteil der Maßnahme Nr. 2 dar) | „… muss zudem die Meldepflichten nach § 32 BSIG berücksichtigen." (§ 32 als eigenständige Pflicht) |
| B3 | Nr. 10 `description_de` + `attestierungspunkte[0]` | „Multi-Faktor-Authentifizierung für alle Zugänge …" (überschießend, ohne die Normalternative) | „Multi-Faktor- oder kontinuierliche Authentifizierung für Zugänge …"; Attestierungspunkt als Nachweis mit dokumentiertem Geltungsbereich |

## Review-Vermerke

### A. Normtext-Abgleich (dieses Dokument, Mapping 2026.07)

| Reviewer | Ergebnis | Datum | Vermerk |
|---|---|---|---|
| Gründer (V. Vulpe) | ☑ PASS | 2026-07-12 | Freigabe per Session-Chat auf Basis der Befund-/Verlaufszusammenfassungen (Label-Entscheid Nr. 7/9 selbst getroffen). |
| Agent `legal-reviewer` | ☑ PASS | 2026-07-12 | Erstprüfung FAIL (B1 Labels Nr. 7/9, B2 Nr. 2, B3 Nr. 10); nach Korrektur Nachprüfung PASS. Normtext/Zitate/Quellenrang/Rechtsstand aller 10 Bereiche verifiziert (Primärquelle zweifach abgerufen). Offen (nicht Teil A): `nis2umsvo_refs` unbelegt, BGBl-Zitat zum Rechtsstand ergänzen. |

### B. Batch-Review der Checks (je §30-Nr. über alle Provider, ADR-0018)

| §30 Nr. | Checks | Gründer | legal-reviewer | Status |
|---|---|---|---|---|
| 1 | AWS 5 / AZ 5 / GCP 4 | ☑ 2026-07-12¹ | ☑ PASS 2026-07-12 | **abgeschlossen** |
| 2 | AWS 5 / AZ 5 / GCP 5 | ☑ 2026-07-12¹ | ☑ PASS 2026-07-12 | **abgeschlossen** |
| 3 | AWS 7 / AZ 7 / GCP 7 | ☑ 2026-07-12¹ | ☑ PASS 2026-07-12 | **abgeschlossen** |
| 4 | AWS 5 / AZ 5 / GCP 5 | ☑ 2026-07-13² | ☑ PASS 2026-07-13 | **abgeschlossen** |
| 5 | AWS 5 / AZ 5 / GCP 5 | ☑ 2026-07-13² | ☑ PASS 2026-07-13 | **abgeschlossen** |
| 6 | AWS 4 / AZ 4 / GCP 4 | ☑ 2026-07-13² | ☑ PASS 2026-07-13 | **abgeschlossen** |
| 7 | AWS 2 / AZ 2 / GCP 2 | ☑ 2026-07-13² | ☑ PASS 2026-07-13 | **abgeschlossen** |
| 8 | AWS 7 / AZ 6 / GCP 6 | ☑ 2026-07-13² | ☑ PASS 2026-07-13 | **abgeschlossen** |
| 9 | AWS 7 / AZ 7 / GCP 8 | ☑ 2026-07-13² | ☑ PASS 2026-07-13 | **abgeschlossen** |
| 10 | AWS 5 / AZ 5 / GCP 5 | ☑ 2026-07-13² | ☑ PASS 2026-07-13 | **abgeschlossen** |

¹ Gründer-Freigabe per Session-Chat vom 12.07.2026 auf Basis der
Verlaufsabschnitte und Befund-Zusammenfassungen dieses Protokolls.

² Gründer-Freigabe per Session-Chat vom 13.07.2026 auf Basis der
Verlaufsabschnitte (Batches Nr. 4–10) und der Kampagnen-Bilanz.

#### Batch Nr. 1 — Verlauf (2026-07-12)

- **Arbeitsweise** (`docs/arbeitsweise.md`): Sonnet-Worker extrahierte das mechanische
  Dossier `docs/review/w4-batch-nr1-dossier.md` (15 Checks, ohne Bewertung);
  Urteil durch `legal-reviewer` + Orchestrator; Umsetzung wortgetreu nach Vorgabe.
- **Erstprüfung FAIL:** 9 von 15 Checks beanstandet (B-Nr.1-1 … B-Nr.1-10).
  Kernbefunde: Texte behaupteten mehr als geprüft (AWS-NR1-002/-004, AZ-NR1-004/-005,
  GCP-NR1-003); Nicht-Anwendbarkeit als Mangel (AWS-NR1-003, AZ-NR1-003 → Vorbehalt +
  Severity LOW); AZ-NR1-002-Filter widersprach der eigenen Remediation (Initiativen
  zählten nicht — Logik-Fix); GCP-NR1-003-Logik auf `allServices` verschärft;
  **GCP-NR1-005 (VPC Service Controls) → Nr. 9 umgezogen als GCP-NR9-008**
  (außerhalb der Nr.-1-Abdeckungsgrenze; Zuordnung zu Nr. 9 durch Mapping gedeckt).
- **Nachprüfung PASS** (legal-reviewer, 2026-07-12): alle zehn Beanstandungen
  geschlossen, keine neuen Rechtsprobleme. Nicht-blockierende Hinweise H-1–H-7
  im Vermerk (u. a. `abdeckung_de` Nr. 1 in späterem Mapping-Release erweitern;
  GCP-NR4-005-Mangeltext im Nr.-4-Batch regulär mitprüfen).
- Die sechs unveränderten PASS-Checks: AWS-NR1-001/-005, AZ-NR1-001, GCP-NR1-001/-002/-004.

#### Batch Nr. 2 — Verlauf (2026-07-12)

- Dossier: `docs/review/w4-batch-nr2-dossier.md`. **Erstprüfung FAIL:** 11 von 15 Checks,
  13 Beanstandungen (B-Nr.2-1 … B-Nr.2-13). Kernbefunde: Texte behaupteten Sicherheits-/
  Feature-Bezüge, die nicht geprüft werden (AWS-NR2-001/-004, AZ-NR2-004/-005,
  GCP-NR2-002/-004); zwei Proxy-Checks mit unverifizierten Positivnachweisen
  (AZ-NR2-002 „Sentinel Analytics Rules" ohne Sentinel-API; AZ-NR2-003 Namens-Heuristik) —
  auf ehrlichen Scope zurückgeschnitten, echter API-Ausbau als Folge-Aufgabe geflaggt;
  **GCP-NR2-005-Logikfehler:** eingebaute `_Required`/`_Default`-Sinks ließen den Check
  praktisch immer bestehen — Logik-Fix (Built-ins ausgeschlossen, nur Export-Ziele zählen).
- **B-Nr.2-12 (Mapping):** `abdeckung_de` Nr. 2 um technische Reaktions-/Analysebausteine
  erweitert (Reviewer-Wortlaut); ADR-0018-Gate für den neuen String in der Nachprüfung
  ausdrücklich bestanden.
- **Nachprüfung PASS** (legal-reviewer, 2026-07-12, nach Umsetzung B-Nr.2-1…13).
  Offener Integrationslauf-Punkt: Live-Verifikation `_Required`/`_Default` (nicht blockierend).

#### Batch Nr. 3 — Verlauf (2026-07-12)

- Dossier: `docs/review/w4-batch-nr3-dossier.md`. **Erstprüfung FAIL:** 12 von 21 Checks,
  12 Beanstandungen (B-Nr.3-1 … B-Nr.3-12). Kernbefunde: **AWS-NR3-003 (Object Lock)
  konnte unverifizierte Positivnachweise ausstellen** (jeder fehlerfreie API-Call galt als
  aktiviert) — Logik-Fix: Antwortinhalt wird ausgewertet, Fehlererkennung über
  ClientError-Code statt String-Match; **AZ-NR3-006 gab unbekannte Zustände als geprüften
  Mangel mit falscher audit_evidence aus** — Fail-safe-Fix (accounts_checked, CheckError
  statt stillem pass); AZ-NR3-001/-002 verschluckten Exceptions ohne errors-Eintrag;
  AZ-NR3-005 behauptete eine Replikationsprüfung, die nicht stattfindet (auf
  Vault-Existenz zurückgeschnitten); GCP-NR3-007 „Health Checks" prüfte nur Zonen-Existenz;
  objektive ISO-Fehlzuordnung A.5.29/A.5.30 korrigiert; diverse Überbehauptungen
  („regelmäßig", „wiederherstellbar", „vor Ransomware geschützt") normiert.
- **Nachprüfung PASS** (legal-reviewer, 2026-07-12); Resthinweise (Formulierungskosmetik)
  ebenfalls umgesetzt.

#### Batch Nr. 4 — Verlauf (2026-07-12/13)

- Dossier: `docs/review/w4-batch-nr4-dossier.md`. **Erstprüfung FAIL:** 12 von 15 Checks,
  17 Beanstandungen; **Nachprüfung** mit 6 Restpunkten (R-1…R-5 + CA-Paginierung);
  **finale Nachprüfung PASS** (2026-07-13). Kernbefunde: GCP-NR4-001 meldete Google-
  verwaltete Service-Agents systematisch als externe HIGH-Mangel (Teilstring-Heuristik →
  strukturierte Suffix-Prüfung); AWS-NR4-004 erkannte `Principal: "*"` und nackte
  Account-IDs nicht (jetzt CRITICAL ohne Condition / HIGH mit Condition); AWS-NR4-002
  prüfte nur us-east-1, attestierte account-weit; AccessDenied wurde als Mangel
  ausgegeben (→ CheckError); pruefgrenzen widersprachen teils diametral der Prüflogik
  (GCP-NR4-004). Vormerkung H-7 aus Batch 1 geschlossen (PASS). BGBl-Fundstelle
  im RECHTSSTAND punktuell mitbestätigt.

#### Batch Nr. 5 — Verlauf (2026-07-12/13)

- Dossier: `docs/review/w4-batch-nr5-dossier.md`. **Erstprüfung FAIL:** alle 15 Checks,
  19 Beanstandungen; **Nachprüfung** mit 2 Restpunkten (B-Nr.5-20/-21, einer erst durch
  den site_config-Fallback sichtbar geworden); **finale Nachprüfung PASS** (2026-07-13).
  Kernbefunde: verifizierte falsche Positivnachweise durch veraltete Deprecation-Listen
  (Lambda: nodejs18.x/python3.9/ruby3.2/nodejs20.x; App Service: DOTNETCORE-Familie,
  Docker pauschal positiv) und lexikografischen GKE-Versionsvergleich („1.28.9" ≥
  „1.28.15"); GCP-NR5-001-Positivnachweis war nur bei gefundenen Schwachstellen
  erreichbar (→ DISCOVERY-Occurrences); netFrameworkVersion-Zweig invertiert (CLR-
  Version v4.0 = aktuelles .NET 4.8 galt als veraltet — Zweig entfernt); stille
  Fehlerpfade → CheckError; NA-als-Mangel-Muster mit Vorbehalt + Severity-Senkung.
  Folge-Aufgaben (API-Ausbauten, Mapping-Erweiterung iso27001_controls Nr. 5) geflaggt.

#### Batch Nr. 6 — Verlauf (2026-07-13)

- Dossier: `docs/review/w4-batch-nr6-dossier.md`. **Erstprüfung FAIL:** alle 12 Checks,
  14 Beanstandungen; **Nachprüfung** mit 1 Restpunkt + 4 Beobachtungen; **finale
  Nachprüfung PASS** (2026-07-13). Kernbefunde: defekter Exception-Handler in
  AWS-NR6-002 (jede Exception entkam beiden Handlern); AWS-NR6-003 attestierte
  „Score ≥80 %" ohne Score-Abruf (→ ehrlicher Tool-Schwellwert + ACTIVE-Filter +
  Paginierung); AZ-NR6-001 fabrizierte Mangel-Evidenz aus 0/1-Defaults (→ CheckError);
  stille Zustell-/Fehlerpfade (AWS-NR6-001, AZ-NR6-004) explizit gemacht;
  GCP-Texte behaupteten nie geprüfte Lock-/SHA-Aspekte (→ ehrlicher Scope).
  **Querschnittsfund:** CheckError-Modell verwarf übergebene check_id/region still —
  Felder additiv ergänzt (vor Schema-Freeze). Folge-Aufgaben: Score-Berechnung via
  DescribeStandardsControls, Activity-Log-Export-Verknüpfung, retentionPolicy.isLocked,
  SHA-Quellen-Verifikation, Mapping Nr. 6 um A.8.15 (eigenes Gate).

#### Batch Nr. 7 — Verlauf (2026-07-13)

- Dossier: `docs/review/w4-batch-nr7-dossier.md`. **Erstprüfung FAIL:** 4 von 6 Checks,
  7 Beanstandungen; **Nachprüfung PASS** (2026-07-13). Kernbefund (schwerster der
  Kampagne): AZ-NR7-001 fragte eine API ab, die den behaupteten Prüfgegenstand
  strukturell nicht enthält (Graph v1.0 ohne „password"-Konfiguration) — der Check
  meldete IMMER einen Mangel, auch bei korrekt konfigurierter Sperrliste; Umbau auf
  Graph groupSettings („Password Rule Settings"). Weiter: AZ-NR7-002 zählte jede
  enabled-CA-Policy als Baseline (jetzt nur MFA-Grant-Controls); GCP-NR7-001
  „erzwingt" ohne Enforce-Prüfung; GCP-NR7-002 ignorierte validationState; drei
  ISO-Fehlzuordnungen (→ A.8.5/A.8.9/A.6.8, Gründerentscheid A.6.8 per Chat).
  Zentrale Batch-Frage positiv beantwortet: kein Check-Text behauptet Schulungs-/
  Awareness-Prüfung — Indiz-Zuordnung zu Nr. 7 sauber. Beide AWS-Checks ohne
  Rechtsbeanstandung. Ab diesem Batch laufen Zweitprüfungen auf Opus 4.8
  (Fable-Wochenlimit erschöpft; gleicher Prüfauftrag/Checkliste).

#### Batch Nr. 8 — Verlauf (2026-07-13)

- Dossier: `docs/review/w4-batch-nr8-dossier.md`. **Erstprüfung FAIL:** 15 von 19 Checks,
  15 Beanstandungen; **Nachprüfung PASS** (2026-07-13). Kernbefunde: AZ-NR8-005
  attestierte „TLS ≥ 1.2" ohne die Version je auszulesen (site_config-Muster aus
  Batch 5 → get_configuration-Fallback); AWS-NR8-005-Allow-List meldete objektiv
  sichere Policies als Mangel (→ Deny-List; Protokollprüfung maßgeblich in -006,
  jetzt inkl. NLB); Positivnachweis bei leerer Verschlüsselungsregel (→ CheckError);
  Predefined-SSL-Policies mit TLS 1.0 entgingen der Prüfung; CSEK-Disks als
  „Google-verwaltet" fehlgemeldet; fabrizierte ssl_mode-Werte; ISO einheitlich
  „A.8.24 Verwendung von Kryptographie". Deny-List-Umbau ausdrücklich als
  fail-safe-konform bestätigt (NOT_APPLICABLE + offengelegte Prüfgrenze).

#### Batch Nr. 9 — Verlauf (2026-07-13)

- Dossier: `docs/review/w4-batch-nr9-dossier.md`. **Erstprüfung FAIL:** 13 von 22 Checks,
  14 Beanstandungen + 3 Permissions-Hinweise; **zwei Nachprüfungs-Runden** (Listen-
  Constraint-Erkennung; danach vom Reviewer selbst korrigierter allowAll-Punkt seines
  eigenen Fix-Vorschlags — allowAll neutralisiert Listen-Constraints und zählt nicht
  als Durchsetzung); **finale Nachprüfung PASS** (2026-07-13). Kernbefunde: falsche
  Positivnachweise (SSH über IPv6 ::/0 unerkannt; NSG-Plural-Feld übersehen; s3:*-
  Wildcards als „Least Privilege"; Principal:* mit Condition als sauber; Report-only-
  Policies als Durchsetzung; allUsers-IAP-Binding als Nachweis) und falsche Mangel-
  Findings (deaktivierte Firewall-Regeln; Port 443 als HIGH; Access-Key-only-User als
  MFA-Mangel). GCP-NR9-008 als Delta unverändert PASS. Terraform-Fixture für
  NR9-001-Integrationstest nachgezogen (Login-Profile).

#### Batch Nr. 10 — Verlauf (2026-07-13)

- Dossier: `docs/review/w4-batch-nr10-dossier.md`. **Erstprüfung FAIL:** 10 von 15
  Checks, 13 Beanstandungen; **Nachprüfung** mit 1 Restpunkt (R1); **finale
  Nachprüfung PASS** (2026-07-13). Kernbefunde: direkter ADR-0012-Verstoß
  (AWS-NR10-002 behauptete wörtlich „Verstoß gegen §30 Abs. 2 Nr. 10" — gestrichen);
  AWS-NR10-004 „SES/SNS" prüfte nur SNS, TLS-Erkennung per rohem Teilstring (→
  Policy-JSON-Parsing, Deny+SecureTransport=false); **Scope-Eskalation AZ-NR10-004**:
  „Teams/Exchange TLS" prüfte nirgends TLS und adressierte den laut Mapping nicht
  prüfbaren Kommunikationssicherungs-Aspekt — Gründer-/Orchestrator-Entscheid:
  Rewidmung „Conditional Access für O365-Dienste", vom Zweitprüfer ausdrücklich als
  innerhalb der Nr.-10-Abdeckung bestätigt; exclude_users-Auswertung (AZ-NR10-001);
  Break-Glass-Zählung ≥2/1/0 (AZ-NR10-005); GCP-Paginierung über 100 Nutzer hinaus;
  einheitliche Fehlerklassifikation (Service-Disabled vs. 403→CheckError);
  GCP-NR10-005 auf Namensheuristik rewidmet.

#### Delta-Review AZ-NR9-007 — Umstellung auf Graph-Beta-Report (2026-07-14)

- Anlass: Der W4-geprüfte Stand las `sp.sign_in_activity` vom Graph-v1.0-
  servicePrincipal-Modell — das Attribut existiert dort nicht (Check konnte
  live nie ein Ergebnis liefern); zudem widersprachen die pruefgrenzen
  (Credential-Alter) der tatsächlichen Prüflogik (Sign-in-Daten).
- Neu (Branch `az-nr9-signin-activity`): letzte Anmeldung aus
  `GET /beta/reports/servicePrincipalSignInActivities`, SP-Population aus
  `GET /v1.0/servicePrincipals`; direkter REST-Zugriff über neues Modul
  `engine/providers/azure/graph.py` (httpx, @odata-Paginierung). Prüfaussage,
  title, description, severity, required_permissions unverändert.
- **Erstprüfung (538a8d6) FAIL** — legal-reviewer, 2 Beanstandungen + 4 Zweifel:
  B1 pruefgrenzen behaupteten vollständigen First-Party-Ausschluss, Code
  schloss nur den Microsoft-Services-Tenant aus; B2 Remediation zeigte auf
  App-Registrierungen statt Unternehmensanwendungen; Z1 `$top=999` über dem
  dokumentierten Seitenmaximum 100; Z2 scheinbar abschließende Ursachenliste;
  Z3 Beta-Offenlegung zu weich; Z4 stiller Lauf bei leerer Prüfpopulation.
- **Nachprüfung (5cdc101) PASS** — B1 (beide MS-Tenants, `MS_TENANT_IDS`,
  GUID-verifiziert), B2, Z1 ($top=100), Z2 („z. B."), Z3 („ohne
  Produktions-Support") umgesetzt; Z4 bleibt dokumentierter Hinweis
  (Musterlücke analog Dossier-Punkt 17, kein falscher Nachweis; spätere
  einheitliche NOT_APPLICABLE-Lösung über alle Provider vorgemerkt).
- **Merge-Bedingungen:** (a) grüner Live-Integrationslauf AZ-NR9-007 gegen
  echten Tenant nach Admin-Consent für `AuditLog.Read.All` der CI-App
  (Terraform vorbereitet, `infra/azure/oidc/main.tf`); (b) Gründer-Vermerk.
- **Gründer-Vermerk: ERTEILT (Chat-Freigabe 14.07.2026)** — nach Zweitprüfung PASS
  (Nachprüfung 5cdc101) und grünem Live-Integrationslauf (Run 29338070278,
  51/51 bestanden; AZ-NR9-007 liefert echte Graph-Ergebnisse, Admin-Consent
  AuditLog.Read.All erteilt). Beide ADR-0018-Vermerke liegen vor — Merge frei.

#### Delta-Review msgraph-sdk-Ablösung — alle Azure-Graph-Checks auf REST (2026-07-14)

- Gegenstand (Branch `msgraph-sdk-abloesung`, 843ea82 + 2de7f50): 11
  GraphServiceClient-Call-Sites in nr4/nr7/nr9/nr10 auf
  `engine/providers/azure/graph.py` (graph_get_all/graph_get) migriert;
  msgraph-sdk aus den Dependencies entfernt. Transport-Swap — gleiche
  v1.0-Endpoints, camelCase-Wire-Keys, ISO-Datums-Parsing.
- **Zweitprüfung (legal-reviewer) PASS** mit zwei Auflagen: (1) mechanischer
  Text-Invarianz-Nachweis als Anlage — ERBRACHT: `git diff -U0 main.. --
  nis2scan/` über title/description/pruefgrenzen/remediation/audit_evidence/
  expected_state/bsig_30_text/required_permissions = **0 Treffer**;
  (2) grüner Live-Integrationslauf — ERBRACHT: Run 29344788128 vom Branch,
  51/51 bestanden gegen den echten Tenant. Wire-Key-Stichproben aller Module
  gegen die Graph-v1.0-Referenz verifiziert, Fail-safe-Pfade (ADR-0016)
  unverändert, keine neuen rechtlich formulierenden Texte.
- **Bewusste Verbesserung (kein identisches Verhalten, Reviewer-Hinweis):**
  Die SDK-Aufrufe lasen nur die erste Ergebnisseite; graph_get_all folgt
  @odata.nextLink. Zählwerte und Positivnachweise können jetzt Objekte
  jenseits von Seite 1 einbeziehen — durchgehend pro Vollständigkeit.
- Nebenfix: `__version__` single-sourced (hatch dynamic; CLI und
  ADR-0019-Loader-Meldung zeigten seit 0.1.1 fälschlich 0.1.0).
- **Gründer-Vermerk: ERTEILT (Chat-Freigabe 14.07.2026 „ok, super, setze
  gerne den Vermerk", wirksam mit Erfüllung beider Auflagen).** Beide
  ADR-0018-Vermerke liegen vor — Merge frei.

#### Feature-Review Findings-Exceptions — ADR-0026 (2026-07-24)

- Gegenstand (Branch `feature/findings-exceptions`): Neues Free-Feature
  „Ausnahmen für Findings" — YAML-Datei mit Pflichtfeldern reason/expires,
  Matching check_id+resource_id (optional account/region), First-Match-wins,
  12-Monats-Warnung, Engine-Annotation (Schema 1.1.0, additiv), CLI
  `--exceptions`, Report-Sektion „Ausnahmen" + „Abgelaufene Ausnahmen",
  zweigleisiger Zähl-Ausweis und abgeleitete Zusatzsicht der Report-Schicht
  (ADR-0026 inkl. Nachtrag vom 24.07.2026). Ausnahmen wirken nie auf
  Positivnachweise/CheckError/NOT_APPLICABLE (ADR-0016).
- **Zweitprüfung (legal-reviewer) Erstdurchgang: FAIL** — F1 blockierend:
  Label „erfüllt (mit dokumentierten Ausnahmen)" verwendete das reservierte
  Ordinal-Label (ADR-0008) für eine Kundenrisikoentscheidung; Bereichs-
  Zusatzsicht ohne dokumentierte ADR-Grundlage. Auflagen F2 (Sektion-Intro
  ohne Akteur/Rechtscharakter, interne ADR-Referenz im Kundentext), F3
  (Extern-Hinweis ohne Konsequenz-Nennung; F3b Klartext-Pfad der
  Ausnahmen-Datei im Extern-Export), Hinweise F4 (Warntext misst
  Restlaufzeit) und F5 (Spaltenkopf „Abgelaufen am" semantisch schief).
- Umsetzung: „Zusatzsicht"-Formulierungen ohne Quasi-Bewertung, beide
  Gleise in einer Summary-Zeile; Intro nennt Einrichtung als Akteur und
  stellt klar, dass eine Ausnahme die Bewertung durch Auditor/Aufsicht
  nicht vorwegnimmt; Extern-Hinweis benennt Klartext-Folgen;
  metadata.exceptions_file nur noch Dateiname und EXTERN-Reduktion von
  config.exceptions_path in pseudonymize_result (Deep-Copy, ADR-0011);
  ADR-0026-Nachtrag dokumentiert die Zusatzsicht samt Wortwahl-Vorgabe.
- **Nachprüfung (legal-reviewer): PASS** — alle Auflagen erfüllt, keine
  Restbefunde; Texte innerhalb Teilaspekt-Grenze (ADR-0009), keine
  Rechtsfolgen-Aussagen (ADR-0012), Fail-safe gewahrt (ADR-0016).
  Qualitätsgates: 513 Unit-Tests grün, ruff/format/mypy strict sauber
  (durch Orchestrator unabhängig verifiziert).
- **Gründer-Vermerk: ERTEILT (Chat-Freigabe 24.07.2026 „erteilt, du hast
  mein Go").** Beide ADR-0018-Vermerke liegen vor — Merge frei.

#### Delta-Review GCP-NR4-001 — Evidence-Key-Pseudonymisierung (2026-07-24)

- Gegenstand (Branch `p1/audit-fixes`): Audit-Befund CODE-1 — der
  current_state-Key "external_members_sample" von GCP-NR4-001
  (CheckCrossProjectBindings) trug rohe externe IAM-Member-Strings (inkl.
  Service-Account-E-Mail-Adressen) am ADR-0011-Deny-List-Muster vorbei in
  den Extern-Export. Fix: Key umbenannt auf "external_member_email"
  (Deny-List-Suffix greift, Listen-Handling elementweise); bewusst
  Singular, da die Deny-List das Suffix am Stringende verlangt —
  Warnkommentar im Code ergänzt (Reviewer-Hinweis).
- **Zweitprüfung (legal-reviewer): PASS ohne Auflagen.** Textinvarianz
  aller rechtlich formulierenden Felder wortgleich gegen main verifiziert;
  neuer Test beweist die elementweise Pseudonymisierung im Extern-Export.
- **Gründer-Vermerk: ERTEILT (Chat-Vorabfreigabe 24.07.2026 „super, nimm
  es bitte mit auf", wirksam mit Delta-PASS — Präzedenz msgraph-Ablösung).**
  Beide ADR-0018-Vermerke liegen vor — Merge frei.

#### Delta-Review Audit-Runde-2-Fixes — vier Prüfgrenzen-Texte (2026-07-24)

- Gegenstand (Branch `r2/audit-fixes`): Logik-Fixes aus Audit Runde 2 mit
  Text-Folgeänderungen an vier pruefgrenzen-Feldern: AWS-NR8-004 (Filter auf
  symmetrische KMS-Schlüssel — vorher False Positives bei asymmetrischen/
  HMAC-Keys), GCP-NR8-003 (aggregated_list: globale UND regionale
  SSL-Policies; Permission compute.sslPolicies.list gegen die offizielle
  Methodenreferenz verifiziert), GCP-NR9-005 (CheckError statt Silent-Skip
  bei nicht lesbarer Bucket-IAM-Policy, ADR-0016), AWS-NR1-001
  (Gründer-Wunsch: Einschub „(alle Ressourcentypen?)" entfernt). Dazu
  S3-Pagination (4 Call-Sites) und error_type=type(e).__name__ repo-weit
  (rein technisch, keine deutschen Texte).
- **Zweitprüfung (legal-reviewer): FAIL → 1 Auflage + 2 Hinweise → alle
  umgesetzt → Nachprüfung PASS.** Auflage: AWS-NR8-004 muss auch
  CloudHSM-/externe-Schlüsselspeicher-Ursprünge und deaktivierte Schlüssel
  offenlegen (stille Lücke nach ADR-0016 Regel 2). Hinweise übernommen:
  Terminus „Positivnachweis" statt „Compliance-Nachweis"; Objekt-ACL-
  Offenlegung bei GCP-NR9-005. Transparenzvermerk des Reviewers: die
  GCP-Permission-Verifikation stützt sich auf den Koordinator-Abruf der
  Methodenreferenz (Browser), Reviewer-eigener WebFetch scheiterte an der
  Seitennavigation.
- **Gründer-Vermerk: ERTEILT (Chat-Freigabe 24.07.2026 „Vermerk erteilt,
  Tag frei").** Beide ADR-0018-Vermerke liegen vor — Merge frei.

#### Vorsorge-Review SaaS-UI-Texte — Vladis Review-Runden 1-3 (2026-07-25)

- Gegenstand (Repo `nis2scan-saas`, Branch `ui/vladi-review-fixes`):
  Neue/geänderte deutsche UI-Bedientexte des SaaS-Frontends, die
  Compliance-Sachverhalte einordnen — Fehler-Banner samt
  CHECK_ERROR_GUIDANCE_DE und Fehlermeldungs-Anzeige (Engine-Schema 1.2.0),
  „Keine Mängel bewertbar"-Hinweis, Umgebungskontext-Texte,
  Prüfgrenzen-Fußnote, PDF-Upsell-Tooltip, Backend-503-Texte,
  Einladungs-Hinweis sowie Korrektur der BSIG-§30-Kurztitel in Frontend
  und e2e-Seed auf die rechtsgeprüften title_de aus bsig_30.py (die
  Alt-Titel wie „Cyberhygiene und Schulungen" für Nr. 7 waren frei
  formuliert). Einordnung des Koordinators: UI-Bedientexte, kein
  Mapping/Check/Reporttext — Review vorsorglich nach dem Geist von
  ADR-0018.
- **Zweitprüfung (legal-reviewer): FAIL → 1 Auflage → umgesetzt →
  Nachprüfung PASS.** Auflage: e2e-Seed Nr. 3 „Aufrechterhaltung des
  Betriebs (BCM)" → exakt title_de „Aufrechterhaltung des Betriebs"
  (Seed-area_name landet als Anzeige-Titel in Dashboard/Compliance/
  Scan-Detail). Nachprüfung bestätigt 10/10 Titel-Treue in allen drei
  Fundstellen (Frontend-Fallback, Scan-Dialog, Seed). Nicht sperrender
  Hinweis: Das Check-Feld pruefgrenzen wird durch diese Runde erstmals
  Endnutzern direkt angezeigt — bei der nächsten Mapping-/Check-Änderung
  explizit unter das ADR-0018-Gate nehmen.
- **Gründer-Vermerk: nicht eingeholt** (UI-Bedientexte außerhalb des
  formalen Gate-Umfangs; Texte entstanden auf direkte Gründer-Befunde der
  Live-UI-Session 24.07.2026 und wurden dort per Hot-Reload mitverfolgt).
  Sollte der Gründer UI-Texte künftig dem formalen Gate unterstellen,
  gilt das ab dann auch für diese Kategorie.

#### Delta-Review CLI-Härtetest-Fixes — Fehlerursachen-Texte und Exit-64 (2026-07-27)

- Gegenstand (Branch `cli/haertetest-fixes`): Fixpaket aus dem
  CLI-Härtetest (5 Kundenreisen gegen echte Clouds, 10 adversarial
  bestätigte Bugs). Neue deutsche Nutzertexte: Credential-Hinweisblöcke
  (Ursache/Nächster Schritt je Provider), Fehlermeldungs-Spalte und
  „Häufigste Fehlermeldung"-Satz im Markdown-Report, sämtliche
  Vorab-Validierungsmeldungen (Region/Scope/Output/Format/Config,
  Exit-Code 64 = Bedienfehler, getrennt von der Scan-Semantik 0-3),
  PDF-Professional-Hinweis vor Scan-Beginn, deutscher
  Fingerprint-Hinweis ohne ADR-Jargon. Mapping/Checks unverändert.
- **Zweitprüfung (legal-reviewer): FAIL → 2 Auflagen → umgesetzt →
  Nachprüfung PASS.** Auflage 1: ADR-0011-Locking-Tests für beide neuen
  Renderstellen unter EXTERN (rohe Fehlermeldungen dürfen den
  Extern-Report nie erreichen) — zwei Tests ergänzt. Auflage 2: Die
  Exit-64-Invariante („Bedienfehler brechen vor jeder Scan-Arbeit ab")
  galt nicht für den späten Engine-Ladepfad der Exceptions-Datei —
  behoben durch Verhaltenskorrektur (Laden VOR dem ersten Cloud-Aufruf,
  Anwendung unverändert nach der Check-Schleife) statt Doku-Abschwächung;
  Regressionstest beweist executed == [] bei kaputter Datei.
  Nicht sperrende Hinweise vorgemerkt: tote nocredentialserror-Signatur;
  %-Beispieltabelle in getting-started.md außerhalb des Deltas.
- **Gründer-Vermerk: nicht eingeholt** (technisch-operative Fehler- und
  Bedientexte, keine rechtlich formulierenden Reporttexte; Mapping und
  Checks unverändert — Einordnung analog Vorsorge-Review SaaS-UI-Texte
  2026-07-25). Transparenz: Merge erfolgt auf dieser Grundlage; der
  Gründer kann die Einordnung nachträglich verwerfen.
