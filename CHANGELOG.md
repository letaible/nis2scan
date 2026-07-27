# Changelog

Alle nennenswerten Änderungen an nis2scan werden hier dokumentiert. Das Format
orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/).
Die vollständige Commit-Historie und die Release-Artefakte (Wheels, sdists)
stehen in den [GitHub Releases](https://github.com/letaible/nis2scan/releases).

## Unveröffentlicht

### Sicherheit

- Pseudonymisierung (Extern-Profil): 15 Lücken geschlossen, bei denen
  Ressourcen- oder Kontonamen aus Azure-/GCP-Sammel-Findings roh im
  Beschreibungstext des externen Reports erscheinen konnten (AWS war nicht
  betroffen). Die rechtlich geprüften Reporttexte selbst sind unverändert.

### Behoben

- 5 Azure-/GCP-Checks repariert, deren SDK-Aufrufe in keiner SDK-Version
  existierten und die daher bei jedem echten Scan als „Fehler" endeten
  (AZ-NR6-001 Secure Score, AZ-NR10-003 VPN-Gateway-Abfrage — jetzt mit
  Fail-safe bei Teilausfällen —, GCP-NR2-004/005 und GCP-NR6-001
  Logging-Clients). Abhängigkeits-Obergrenzen für azure-mgmt-security und
  azure-mgmt-monitor (<7.0.0) schützen Neuinstallationen vor
  inkompatiblen SDK-Versionen.

- CLI-Härtetest-Fixpaket (10 bestätigte Befunde aus Kundenreisen gegen
  echte Clouds): `permissions --format terraform/json` erzeugt bei
  Umleitung in Dateien jetzt gültige Ausgabe (kein 80-Spalten-Umbruch
  mehr); fehlende Cloud-Zugangsdaten werden deutsch erklärt (Ursache und
  nächster Schritt je Provider, Fehlermeldungen jetzt auch im
  Markdown-Report — im Extern-Profil weiterhin nie); Bedien- und
  Konfigurationsfehler brechen VOR dem Scan ab und nutzen den neuen
  Exit-Code 64 (vorher kollidierten sie mit der HIGH/CRITICAL-Semantik):
  unbekannte AWS-Region (vorher minutenlanger stiller Hänger),
  `--scope` außerhalb 1–10, `--output` auf eine existierende Datei
  (vorher ging das Scan-Ergebnis verloren), unbekanntes `--format`
  inkl. PDF-Hinweis vor Scan-Beginn, explizit angegebene fehlende
  `--config`-Datei (wurde stillschweigend ignoriert). Die
  Ausnahmen-Datei wird vor dem ersten Cloud-Aufruf geladen.

### Hinzugefügt

- `nis2scan --version` zeigt jetzt zusätzlich die Edition (Free/Professional)
  und alle installierten Plugins mit Version — bisher war nirgends sichtbar,
  welche Version und welche Lizenzart im Einsatz ist.
- Scan-Ergebnis-Vertrag 1.2.0 (additiv): `CheckOutcomeEntry.error_messages`
  transportiert die Fehlermeldungen hinter `error_count`; das EXTERN-Profil
  leert die Liste (rohe Exception-Strings können Bezeichner enthalten, die
  kein Finding nennt). Details: docs/schema-changelog.md.

### Geändert

- Release-Pipeline: Ein Tag-Push (`v*`) durchläuft jetzt die AWS-, Azure-
  und GCP-Integrationsläufe als Release-Gate, bevor auf PyPI veröffentlicht
  wird. Für kritische Hotfixes gibt es einen Notfall-Ausstieg über einen
  manuellen Workflow-Start (mit Bestätigung), der das Gate überspringt.

## 0.1.6 - 2026-07-24

### Behoben

- AWS-NR8-004 (KMS-Rotation): Asymmetrische und HMAC-Schlüssel werden nicht
  mehr fälschlich als „ohne Rotation" gemeldet (Filter auf symmetrische
  Schlüssel); die Prüfgrenzen legen die nicht bewerteten Schlüsselarten
  jetzt vollständig offen.
- GCP-NR8-003 (SSL-Policies): prüft jetzt globale und regionale Policies.
- GCP-NR9-005 (öffentliche Storage-Buckets): eine nicht lesbare
  IAM-Policy wird als Fehler erfasst statt still übersprungen (Fail-safe,
  ADR-0016).
- S3-Bucket-Auflistung paginiert vollständig (Konten mit sehr vielen
  Buckets werden nicht mehr abgeschnitten).

### Geändert

- Deutlich weniger Cloud-API-Aufrufe pro Scan: Die Provider-Session wird
  einmal pro Scan statt einmal pro Check aufgebaut (spart bei AssumeRole
  und Subscription-/Projekt-Erkennung bis zu rund 50 Netzwerk-Aufrufe pro
  Provider), und die AWS-Konto-ID wird pro Session zwischengespeichert
  (spart bis zu 180 STS-Aufrufe pro Scan).
- GCP-NR4-001: Der Evidence-Schlüssel für projektfremde IAM-Mitglieder
  heißt jetzt `external_member_email` statt `external_members_sample`,
  damit das Extern-Report-Profil diese Werte zuverlässig pseudonymisiert.
  Prüftexte und Prüflogik sind unverändert (Delta-Rechtsreview, siehe
  `docs/rechtsgrundlagen-review.md`).
- Fehlermeldungen der Checks tragen jetzt durchgängig den echten
  Ausnahmetyp statt eines festen Platzhalters.

### Sicherheit

- CI prüft Abhängigkeiten mit pip-audit und aktiviert Dependabot
  (wöchentlich) für Python-Pakete und GitHub-Actions.
- Die lokale Geheimnis-Datei `~/.nis2scan/secret` wird unter Windows auf
  den aktuellen Benutzer beschränkt (ACL-Härtung, analog zu Unix).
- Das Paket liefert jetzt einen `py.typed`-Marker mit (PEP 561).

### Dokumentation

- Neue Anleitung `docs/gcp-zugang.md`; Findings-Exceptions und die
  Exit-Codes sind jetzt in `docs/getting-started.md` dokumentiert; drei
  fehlerhafte Kommandos im README korrigiert; CLI-Smoke-Test in CI.

## 0.1.5 - 2026-07-24

### Hinzugefügt

- Findings-Exceptions (ADR-0026): dokumentierte, befristete Ausnahmen für
  Befunde, die eine Einrichtung bewusst nicht sofort beheben will. Neue
  YAML-Ausnahmen-Datei über das CLI-Flag `--exceptions`. Eine Ausnahme
  löscht einen Befund nicht: er bleibt sichtbar, zählt in allen bestehenden
  Kennzahlen weiter voll als Mangel und erscheint zusätzlich in einer
  eigenen Report-Sektion mit Vermerk, Frist und Autor. Nach Ablauf der
  Frist zählt der Befund automatisch wieder uneingeschränkt. Schema 1.1.0
  (rein additiv, siehe `docs/schema-changelog.md`).

### Behoben

CLI-Fail-safe-Hotfix, mehrere seit 0.1.0 bestehende Fehler:

- `--profile` wirkte sich seit der ersten Version nie aus: eine intern
  gleichnamige Variable überschrieb den AWS-Profilnamen, jeder CLI-Scan lief
  effektiv ohne das gewählte Profil.
- Exit-Code 3 für einen nicht aussagekräftigen Scan: endeten ausschließlich
  Checks mit Fehlern und konnte kein einziger Check erfolgreich (bestanden
  oder nicht bestanden) ausgewertet werden, meldete der Scan bisher
  fälschlich Exit-Code 0.
- `--provider` wird jetzt gegen `aws`/`azure`/`gcp` geprüft; ein Tippfehler
  lieferte vorher stillschweigend einen leeren 0/0-Report bei Exit-Code 0.
- stdout/stderr werden beim Start auf UTF-8 umgestellt, damit Umlaute und §
  auf Windows-Konsolen auch ohne gesetztes `PYTHONUTF8` korrekt erscheinen.

## 0.1.4 - 2026-07-14

### Geändert

- msgraph-sdk vollständig abgelöst: alle Microsoft-Graph-Aufrufe laufen
  jetzt über eine eigene REST-Schicht (`nis2scan/engine/providers/azure/graph.py`).
  Das entfernt rund 25.000 Dateien und 26 MB an Abhängigkeiten, wodurch
  `pip install nis2scan` in einem Standard-Windows-venv auch ohne
  `LongPathsEnabled` funktioniert.
- Die Paketversion wird jetzt ausschließlich in `nis2scan/__init__.py`
  gepflegt; `pyproject.toml` liest sie dynamisch über Hatch. Vorher meldeten
  `nis2scan --version` und der Plugin-Loader ab 0.1.1 fälschlich weiterhin
  0.1.0.

## 0.1.3 - 2026-07-14

### Behoben

- AZ-NR9-007 (verwaiste Service Principals) auf den Microsoft-Graph-Beta-
  Report `servicePrincipalSignInActivities` per direktem REST-Zugriff
  umgestellt. Das bisher gelesene SDK-Attribut existiert im aktuellen
  msgraph-sdk nicht mehr, wodurch der Check nie ein Ergebnis lieferte,
  sondern immer mit einem Laufzeitfehler endete. Erster Schritt der neuen
  Graph-REST-Schicht, die in 0.1.4 vollständig ausgebaut wurde.

## 0.1.2 - 2026-07-14

### Behoben

- Projekt-Links in der README für die PyPI-Projektbeschreibung korrigiert:
  PyPI löst repo-relative Links (`docs/`, `LICENSE`) nicht auf, jetzt
  absolute GitHub-URLs. Tote `nis2scan.de`-Links durch einen ehrlichen
  Hinweis "in Vorbereitung" mit Kontakt über GitHub Issues ersetzt.

## 0.1.1 - 2026-07-14

### Behoben

- Azure-Laufzeitbruch bei frischen Installationen behoben: ab
  azure-mgmt-resource 26 fehlt der Top-Level-Re-Export, sodass
  `from azure.mgmt.resource import ResourceManagementClient` mit einem
  ImportError scheiterte und sieben Check-Module nur noch einen CheckError
  statt eines Ergebnisses lieferten. Import jetzt über den stabilen
  Submodul-Pfad `azure.mgmt.resource.resources`.

## 0.1.0 - 2026-07-14

Erstveröffentlichung.

### Hinzugefügt

- 154 Checks über AWS, Azure und GCP, verteilt auf alle 10 Bereiche von §30
  Abs. 2 BSIG.
- Rechts-Mapping jedes Findings auf §30 BSIG und ISO 27001:2022.
- JSON- und Markdown-Reports in den Profilen `intern` (Klardaten) und
  `extern` (pseudonymisierte Identifier, ADR-0011).
- Attestierungs-Checkliste.
- Permissions-Generator (`nis2scan permissions`) für minimale IAM-/RBAC-
  Policies je Cloud-Provider.
