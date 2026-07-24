# Schema-Changelog: ScanResult-JSON-Vertrag (ADR-0021)

Jede Änderung an Modellen in `nis2scan/engine/models/` wird hier deklariert:
additiv (Minor) oder breaking (Major). Ab 1.0.0 gilt SemVer strikt.

## 1.1.0: 2026-07-23 (Findings-Exceptions, ADR-0026)

Rein additiv — keine bestehenden Felder entfernt oder umdefiniert.

**Neu:**
- `Finding.exception` (optional, Default `null`): `FindingExceptionInfo`
  (`reason`, `expires`, `author`, `ticket`) — gesetzt, wenn eine aktive,
  nicht abgelaufene Regel aus einer Ausnahmen-Datei (`--exceptions`) auf
  diesen Mangel-Befund greift. Wird ausschließlich vom Engine-seitigen
  `apply_exceptions` (nis2scan/engine/finding_exceptions.py) gesetzt, nie von
  Checks selbst, und niemals auf `status == compliant` (ADR-0016 Fail-Safe:
  eine Ausnahme akzeptiert einen dokumentierten Mangel, sie erzeugt niemals
  Konformität).
- `Finding.expired_exception` (optional, Default `null`): gleiche Struktur —
  gesetzt, wenn ein Befund nur noch von einer bereits abgelaufenen Regel
  erfasst wird (Ablauf-Hinweis, ADR-0026 Entscheidung 3). Der Mangel zählt in
  diesem Fall in allen bestehenden Zählungen ganz normal als offen mit.
- `ScanConfig.exceptions_path` (optional, Default `null`): Pfad zur
  Ausnahmen-Datei; ohne Angabe werden nie Ausnahmen angewendet (kein
  impliziter Default). Beim EXTERN-Export wird der Wert auf den bloßen
  Dateinamen reduziert (Rechts-Review F3b, 2026-07-24: lokale Pfade
  enthalten oft Benutzernamen und verlassen die Organisation nicht).
- `ScanMetadata.exceptions_file`, `.exceptions_applied`, `.exceptions_expired`
  (optional/Default `null`/`0`/`0`): Ausführungs-Metadaten des Scans —
  welche Datei verwendet wurde, wie viele Befunde annotiert wurden, und wie
  viele gematchte Regeln bereits abgelaufen waren. `exceptions_file` enthält
  von vornherein NUR den Dateinamen ohne Pfad (build_metadata; Rechts-Review
  F3b, 2026-07-24) — in beiden Profilen, damit der lokale Klartext-Pfad
  auch nicht im internen JSON der Metadaten landet.
- `ComplianceScore.exceptions_accepted_count`,
  `ComplianceSummary.exceptions_accepted_count` (Default `0`): zweigleisige,
  rein additive Zusatzauskunft pro §30-Bereich und gesamt — "davon N per
  dokumentierter Ausnahme akzeptiert". Die bestehenden Zählungen
  (`total_findings`, `failed_checks`, `critical_count` usw., sowie
  `erfuellungsgrad`/`erfuellungsgrad_gesamt`) sind NICHT umdefiniert: sie
  zählen Ausnahme-Befunde weiterhin voll als Mängel mit (keine stille
  Herausrechnung, ADR-0026 Entscheidung 4). Eine "effektive" Anzeige
  ("erfüllt (mit dokumentierten Ausnahmen)") existiert AUSSCHLIESSLICH als
  abgeleitete Darstellung in der Report-Schicht
  (`nis2scan/reporting/context.py`, Gründer-Entscheid Runde 2) — sie ist
  bewusst NICHT Teil des JSON-Vertrags und kein Feld dieses Schemas.

## 1.0.0: 2026-07-13 (FREEZE, Release 0.1)

Dedizierte Schema-Review-Session (ADR-0021) gegen die Phase-2-Bedürfnisse
(DB-Persistenz, Trend-Tracking über `finding_key`, Export-Profile).
Änderungen gegenüber 0.9.0 (pre-1.0, breaking erlaubt):

**Entfernt:**
- `ScanConfig.severity_threshold`: tote Config, wurde nie angewendet
  (Audit-Befund zu ADR-0008). Unbekannte Schlüssel in geladenen Configs
  werden von Pydantic ignoriert; alte Payloads bleiben ladbar.
- `Finding.nis2umsvo_ref`: totes Feld (wurde von keinem Check gesetzt,
  stets `null`); die referenzierte Verordnung existiert nicht als
  verkündete Norm (Rechts-Review 2026-07-13, beide ADR-0018-Vermerke).

**Neu (optional/mit Default):**
- `ScanResult.report_profile` (`"intern"` | `"extern"`, Default `"intern"`) ist der
  Export-Profil-Marker (ADR-0011): gespeichertes/exportiertes JSON ist jetzt
  selbstbeschreibend; gesetzt durch `reporting.pseudonymize.apply_profile`.
- `CheckError.check_id`, `CheckError.region` (optional): Kontextfelder;
  wurden von Checks bereits übergeben, aber vom Modell still verworfen.
- `ScanMetadata.gcp_sdk_version` (optional): Parität zu boto3/azure.

**Geändert:**
- `ScanResult.scan_timestamp` ist jetzt zeitzonenbewusst (UTC, ISO-8601 mit
  Offset) statt naiv (`datetime.utcnow()` entfernt).

**Beibehalten als DEPRECATED (Gründer-Entscheid 2026-07-13):**
- `ComplianceScore.score_percent`, `ComplianceSummary.overall_status`,
  `ComplianceSummary.overall_score_percent`: abgeleitete Werte, das
  SaaS-Repo nutzt sie noch (DB-Spalten, Router). Maßgeblich sind
  `erfuellungsgrad`/`erfuellungsgrad_gesamt` (ADR-0008).
  **Entfernung fest eingeplant für Schema 2.0** (Breaking, mit
  Migrationspfad nach ADR-0021).

## 0.9.0: Vertragsstand der W1-Vertrags-Welle (2026-07)

Basis: Outcome-Modell (ADR-0007), Positivnachweise (ADR-0006),
Erfüllungsgrad (ADR-0008), `finding_key` (ADR-0010), Prüfgrenzen und
NA-Transparenz (ADR-0016), Rechtsstand-Versionierung (ADR-0013).

## 1.2.0 (2026-07-24)

Additiv (ADR-0021, Minor):

- `CheckOutcomeEntry.error_messages: list[str]` (Default `[]`) — die
  Meldungen der CheckErrors hinter `error_count`. Bisher war nur sichtbar,
  DASS ein Check fehlschlug, nie WARUM (häufigste vermeidbare
  Support-Anfrage). Im EXTERN-Profil wird die Liste geleert
  (rohe Exception-Strings können Bezeichner enthalten, die in keinem
  Finding vorkommen und daher nicht pseudonymisiert werden können);
  `error_count` bleibt erhalten.
