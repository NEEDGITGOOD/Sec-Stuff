# Atlassian Cloud → Microsoft Sentinel (SIEM)

> **Stand:** 16.10.2026 · **Status:** Technische Recherche, kein produktiver Verbindungstest · **Geltungsbereich:** Atlassian **Cloud** (nicht Data Center/Server).
>
> **Kernaussage:** Die Integration ist möglich und über von Microsoft unterstützte **Codeless Connector Framework (CCF)**-Connectoren umsetzbar. Für Organisations-Audit-Events ist keine eigene Azure Function nötig. **Cloud Enterprise enthält Guard Standard ohne Aufpreis; Guard Premium ist für die vom jeweiligen Enterprise-Produkt unterstützten Admin- und User-Audit-Logs nicht zusätzlich erforderlich.** Die Log-Abdeckung hängt jedoch vom *Produkt* und vom *Plan* ab.

## Inhalt

1. [Was lässt sich anbinden?](#1-was-lässt-sich-anbinden)
2. [Lizenzierung und Log-Abdeckung](#2-lizenzierung-und-log-abdeckung)
3. [Architektur und Datenerfassung](#3-architektur-und-datenerfassung)
4. [Einrichtung: Organization Audit Events → Sentinel](#4-einrichtung-organization-audit-events--sentinel)
5. [Verifikation und KQL-Beispiele](#5-verifikation-und-kql-beispiele)
6. [Alternativen: Defender for Cloud Apps und Webhooks](#6-alternativen-defender-for-cloud-apps-und-webhooks)
7. [Betriebsrisiken, Retention und Kosten](#7-betriebsrisiken-retention-und-kosten)
8. [Empfehlung und Pilot-Checkliste](#8-empfehlung-und-pilot-checkliste)
9. [Quellen und Herstellerdokumentation](#9-quellen-und-herstellerdokumentation)

---

## 1. Was lässt sich anbinden?

Microsoft listet mehrere Atlassian-Datenconnectoren im [Sentinel-Connector-Verzeichnis][ms-connectors]. Die Quellen sind **nicht gleichbedeutend**: Organisationsweite Audit-Ereignisse und die separaten produktinternen Audit-APIs können unterschiedliche Events enthalten.

| Connector | Datenquelle | Authentifizierung / Voraussetzungen | Sentinel-Tabelle / Abfrage |
| --- | --- | --- | --- |
| **Atlassian Organization Audit Events (CCF)** | Atlassian Organizations Audit Events Polling API (`/events-stream`) | Organization Admin erzeugt **Organisations-API-Key** mit `read:events:admin`; Organization ID | Implementierte Tabelle: **`AtlassianAuditEvents_CL`**. Microsoft nennt in der Connector-Referenz **`AtlassianAuditEvents`**; konkrete Tabelle und optionalen Parser im Workspace prüfen. |
| **Atlassian Jira Audit (CCF)** | Jira Audit Records REST API | Berechtigung **Administer Jira**, Produkt-API-Zugang | `Jira_Audit_v2_CL` |
| **Atlassian Confluence Audit (CCF)** | Confluence Audit Records REST API | **Confluence Administrator**; bei Scoped API Tokens zusätzlich `read:audit-log:confluence` | Laut aktueller Microsoft-Connector-Referenz `ConfluenceAuditLogs` |
| Atlassian Jira Audit (Azure Functions, ältere Variante) | Jira Audit Records REST API | Jira-Zugangsdaten, eigene Azure Function und deren Betrieb | `Jira_Audit_CL` |

**Empfohlene Reihenfolge:** zuerst **Organization Audit Events (CCF)**, dann Jira-/Confluence-spezifische Connectoren **nur bei nachgewiesenen Event-Lücken** ergänzen. Bei paralleler Erfassung können Ereignisse überlappen. Niemals voraussetzen, dass eine Connector-Installation automatisch sämtliche API-Aufrufe, Seitenansichten, Inhaltsänderungen oder Aktionen sämtlicher Atlassian-Produkte protokolliert.

Beispiele für prüfenswerte Ereigniskategorien: Benutzer-/Gruppenverwaltung, Rechteänderungen, API-Token-Verwaltung, Authentifizierung, MFA-/Policy-Änderungen, App-Zugriffe und sicherheitsrelevante Admin-Aktionen. Die vollständige tatsächlich verfügbare Ereignisliste ist abhängig von Produkt und Lizenz: [Atlassian Audit Log Activities Database][atl-events-db].

**Abgrenzung:** Confluence hat ein eigenes produktinternes Audit-Log bereits in **Standard**; laut Atlassian enthält dieses beispielsweise Berechtigungs-/Konfigurationsänderungen, **nicht** die vollständige Versionsgeschichte von Inhaltsbearbeitungen. Die zentrale Organization-Audit-API besitzt eine eigene Lizenz-/Log-Abdeckung. [Confluence Audit-Log-Dokumentation][confluence-audit]

## 2. Lizenzierung und Log-Abdeckung

### 2.1 Grundsatz

- **Ohne Guard-Abonnement oder mindestens einen Enterprise-Plan** werden organisationsweite Audit-Ereignisse laut Atlassian nicht im zentralen Organisations-Audit-Log gespeichert bzw. angezeigt. Frühere Ereignisse werden durch ein späteres Upgrade **nicht nachträglich rekonstruiert**. [Atlassian: View audit log][atl-view]
- **Cloud Enterprise umfasst Guard Standard ohne zusätzliche Gebühr**, jedoch **nicht Guard Premium**. Enterprise ist ein **produktbezogener** Plan, z. B. für Jira, Confluence oder Jira Service Management. [Enterprise FAQ][atl-enterprise-faq], [Enterprise-Funktionen][atl-enterprise]
- **Guard Premium** ermöglicht laut Atlassian im zentralen Audit-Log umfassende App-Admin- und App-User-Logs **über die unterstützten Apps hinweg**. **Cloud Enterprise** deckt diese ausführlichen Events nur für die jeweiligen **Enterprise-lizenzierten Produkte** ab. [Lizenzmatrix][atl-log-matrix]
- Ein separat vorhandenes Produkt-Audit-Log ist **nicht automatisch** mit der zentralen Organisations-Audit-Datenquelle gleichzusetzen. Auch mit dem höchsten Plan gilt: *„alle verfügbaren Auditereignisse“ ist nicht „jede Interaktion“.*

### 2.2 Zentraler Organisations-Audit-Log: vereinfachte Matrix

| Lizenzsituation | Organization Admin Events | Jira App Admin Events | Jira App User Events | Confluence App Admin Events | Confluence App User Events |
| --- | :---: | :---: | :---: | :---: | :---: |
| Guard Standard | ✅ | ❌ | ❌ | ❌ | ❌ |
| Guard Standard + **Jira Cloud Premium** | ✅ | ✅ | ❌ | ❌ | ❌ |
| Guard Standard + **Confluence Cloud Premium** | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Jira Cloud Enterprise** | ✅ | ✅ | ✅ | ❌* | ❌* |
| **Confluence Cloud Enterprise** | ✅ | ❌* | ❌* | ✅ | ✅ |
| **Jira + Confluence Cloud Enterprise** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Atlassian Guard Premium** | ✅ | ✅ | ✅ | ✅ | ✅ |

\* Für das nicht mit Enterprise lizenzierte Produkt sind eventuell über andere Pläne oder über sein eigenes Produkt-Audit-Log trotzdem Ereignisse zugänglich. Die ❌-Werte oben beziehen sich auf die **zentralen umfangreichen App-Admin-/User-Logs allein aufgrund der angegebenen Lizenz**, nicht auf jede mögliche Log-Quelle.

**Jira Service Management** folgt in Atlassians zentraler Lizenzmatrix dem gleichen Schema wie Jira und Confluence. Für **Bitbucket** nennt Atlassian bereits bei Guard Standard App-Admin- und App-User-Logs; andere Produkte haben eigene Abdeckung. Eine Jira-Enterprise-Lizenz ist deshalb **keine pauschale Enterprise-Lizenz für sämtliche Atlassian-Apps**. [Hersteller-Matrix][atl-log-matrix]

### 2.3 Welche Lizenz kaufen, wenn noch keine vorhanden ist?

| Ziel | Zu vergleichende Lizenzwege | Hinweis |
| --- | --- | --- |
| Nur organisationsweite Security-/Admin-Logs | **Guard Standard** bzw. ein Cloud Enterprise-Plan | Vorab Event-Abdeckung und API-Zugriff für eure konkrete Atlassian-Konfiguration testen. |
| Zentrale umfangreiche **Jira-User- und Admin-Logs** | **Guard Premium** **oder** **Jira Cloud Enterprise** | Für dieses Ziel braucht man **nicht beide**. |
| Zentrale umfangreiche **Jira- und Confluence-User-/Admin-Logs** | **Guard Premium** **oder** **Jira + Confluence Cloud Enterprise** | Lizenzpreis/Benutzerzahl und benötigte Enterprise-Funktionen vergleichen; **Enterprise nur wegen SIEM-Logs nicht automatisch als günstigste Option ansehen**. |
| Mehrere Atlassian-Produkte mit appübergreifender Audit-Tiefe | **Guard Premium** prüfen | Enterprise erteilt Tiefe jeweils für das gekaufte Enterprise-Produkt. |
| Webhook-Versand von Organisations-Audit-Logs | **Guard Premium** **oder** Enterprise für **Jira, Confluence oder Jira Service Management** | **Guard Premium ist für Webhooks nicht zwingend nötig**, wenn die genannte Enterprise-Voraussetzung bereits erfüllt ist. |

Eine **Enterprise-Lizenz ist nicht generell technische Voraussetzung für Microsoft Sentinel**. Die konkrete Lizenzentscheidung folgt aus der benötigten Event-Abdeckung. Atlassian Enterprise ist ein Jahresvertrag mit Mindest-User-Tiers; die genauen Kosten müssen anhand des Angebots geprüft werden. [Enterprise-Plan][atl-enterprise], [Webhook-Berechtigung][atl-webhooks]

### 2.4 Retention bei Atlassian (Achtung: Dokumentationsstand)

Atlassian dokumentiert **seit 01.10.2026 bis zu 365 Tage Audit-Historie bei Guard-Abonnements**, während ohne Guard 180 Tage genannt werden. Da **Cloud Enterprise Guard Standard enthält**, ist das für Enterprise relevant. Die Microsoft-Connector-Referenz nennt teilweise noch pauschal **180 Tage**. *Atlassian-Aufbewahrung und Sentinel-/Log-Analytics-Aufbewahrung sind getrennte Einstellungen.* Die aktuelle effektive API-Historie und ein möglicher Backfill müssen im Pilot geprüft werden. [Atlassian-Lizenzmatrix][atl-log-matrix], [MS-Connector-Referenz][ms-connectors]

## 3. Architektur und Datenerfassung

### 3.1 Empfohlener Standardweg (Pull)

```text
Atlassian Cloud Organization
  └─ Organizations REST API
     GET /admin/v1/orgs/{orgId}/events-stream
     Authorization: Bearer <ORGANIZATION_API_KEY>
               │
               │ Cursor-basiertes Polling (JSON)
               ▼
Microsoft Sentinel Codeless Connector Framework (CCF)
               │
               │ DCR/DCE-basierter Datenpfad laut veröffentlichter Implementierung
               ▼
Log Analytics: AtlassianAuditEvents_CL
               │
               ├─ KQL Hunting / Analytics Rules
               ├─ Workbooks / Datenqualitätskontrollen
               └─ Incident Investigation / Correlation
```

**API:**

```http
GET https://api.atlassian.com/admin/v1/orgs/{orgId}/events-stream
Authorization: Bearer <ORGANIZATION_API_KEY>
Accept: application/json
```

Der Polling-Endpunkt unterstützt Cursor-Pagination. Er ist für sequentielles Abrufen besser geeignet als die filterreiche `/events`-Suche, deren Rate-Limits Atlassian reduziert hat. Erfordert `read:events:admin`. [Atlassian Organizations REST API][atl-events-api]

**Technischer Hinweis:** Im veröffentlichten Microsoft-Source-Code heißt das konkrete Table-Objekt **`AtlassianAuditEvents_CL`**, mit DCR-Stream `Custom-AtlassianAuditEvents_CL`. Die generierte Connector-Dokumentation nennt **`AtlassianAuditEvents`** und zeigt gleichzeitig bei „DCR support“ *No*. Die widersprüchliche Katalog-Metadatenanzeige nicht mit der technischen Implementierung verwechseln; die nach Deployment tatsächlich angelegte Tabelle, Parser und Transformationsmöglichkeiten verifizieren. [Tabellenschema][ms-table-schema], [CCF-Poller-Config][ms-poller], [Katalog][ms-connectors]

### 3.2 Optional: ergänzende Produkt-Audit-APIs

Für Jira und Confluence je nach Site separate CCF-Verbindungen einrichten. Diese nutzen **Produkt-API-Tokens und Produkt-Admin-Rechte** und sind technisch vom **Organisations-API-Key** verschieden. Mit Testevents prüfen, welche Daten die Organization-API bereits enthält und welche nur über die Produkt-API kommen. Zusätzlich an Mehrfach-Sites und Duplikate denken.

## 4. Einrichtung: Organization Audit Events → Sentinel

1. **Quellenumfang bestimmen.** Relevante Apps, Domains, Sites und Audit-Events definieren. Sichtbarkeit im Atlassian-Admin-Audit-Log und API-Berechtigung mit der gebuchten Lizenz vergleichen. Vor dem Kauf vorzugsweise Testzugang/PoC organisieren.
2. **Atlassian-Berechtigung:** Ein **Organization Admin** erstellt in [admin.atlassian.com](https://admin.atlassian.com/) unter *Organization settings → API keys* einen **scoped Organization API Key** mit ausschließlich **`read:events:admin`**. Dedizierten Integrations-Key verwenden. **Maximale Laufzeit: 1 Jahr**; Key nach Erstellung sicher speichern, Rotation und Owner definieren. [Atlassian Admin API Keys][atl-admin-api]
3. **Organization ID:** UUID z. B. aus `https://admin.atlassian.com/o/{orgId}/overview` ermitteln.
4. **Sentinel:** Microsoft Sentinel-Workspace mit ausreichenden Schreibrechten; im **Content Hub** die Solution **Atlassian Organization Audit Events** installieren und unter **Data Connectors** eine Verbindung für die Organisation erstellen. ID und API-Key hinterlegen. Für mehrere Organisationen jeweils eine getrennte Verbindung.
5. **API und Ingestion testen:** Kontrollierte Konfigurationsaktion ausführen, erwartetes Event im Atlassian-Log/API und in Sentinel prüfen; Zeitstempel, `Action`, `ActorEmail`, `EventId`, `SrcIpAddr` und Zielobjekt abgleichen.
6. **Event-Gap-Analyse:** Jira-/Confluence-Admin- und User-Aktivitäten separat gegen die Audit-Log-Aktivitätendatenbank vergleichen. Fehlende erforderliche Events gegebenenfalls über Produkt-Connectoren nachziehen.
7. **Produktionsbetrieb:** Ingestion-/API-Fehler, Delay, Kosten, Token-Ablauf und Duplikate überwachen. Keine Tokens/Organisationsdaten in öffentliche Repositories committen.

Weitere Installationshinweise: [Microsoft Sentinel Connector Directory][ms-connectors], [Microsoft Sentinel: Data Connectors konfigurieren][ms-setup].

## 5. Verifikation und KQL-Beispiele

**Nur für die veröffentlichte Organization-CCF-Tabelle** `AtlassianAuditEvents_CL`; erst nach erfolgreicher Installation ausführen. Falls im eigenen Workspace ein anderer Parser/Alias vorliegt, Query entsprechend anpassen. Die Spalten basieren auf dem [Microsoft-Tabellenschema][ms-table-schema].

**Letzte Audit-Ereignisse:**

```kusto
AtlassianAuditEvents_CL
| where TimeGenerated > ago(24h)
| project TimeGenerated, EventId, Action, ActorEmail,
          ActorId, AuthType, SrcIpAddr, CountryName,
          EventMessage, Context, Container
| order by TimeGenerated desc
| take 100
```

**Ingestion-Liveness / jüngstes Event:** *Achtung: Ein „altes“ Ereignis bedeutet nicht zwingend einen Connectorfehler, wenn niemand eine protokollierte Aktion durchgeführt hat. Zusätzlichen synthetischen Testevent oder Connector-Health-Metriken einplanen.*

```kusto
AtlassianAuditEvents_CL
| summarize LatestEvent=max(TimeGenerated),
            Events24h=countif(TimeGenerated > ago(24h)),
            Events7d=countif(TimeGenerated > ago(7d))
| extend AgeMinutes=datetime_diff('minute', now(), LatestEvent)
```

**Häufige Eventtypen für die Use-Case-Priorisierung:**

```kusto
AtlassianAuditEvents_CL
| where TimeGenerated >= ago(7d)
| summarize Events=count(), DistinctActors=dcount(ActorEmail) by Action
| top 30 by Events desc
```

**Startpunkt für Security-Use-Cases (kein produktionsreifes Detection Rule Tuning):**

```kusto
AtlassianAuditEvents_CL
| where TimeGenerated >= ago(1d)
| where Action has_any ("policy", "token", "permission", "group")
    or EventMessage has_any ("policy", "token", "permission", "group")
| project TimeGenerated, Action, ActorEmail, SrcIpAddr,
          EventMessage, Context, Container
| order by TimeGenerated desc
```

Empfohlene Detection-Kandidaten: Admin-/Gruppen-Privilegienänderungen, MFA-/Authentifizierungs-Policy-Änderungen, Token-Erstellung und -Änderung, kritische App-Zugriffsumstellungen, neue externe Benutzer sowie ungewöhnliche Aktionen durch privilegierte Identitäten. **Genaue `Action`-Werte erst aus tatsächlichen Events ermitteln**; keine Detection ohne Baseline, Entity Mapping und False-Positive-Tuning als produktionsreif deklarieren.

**Duplikate erkennen:** `EventId` ist laut Schema die Event-ID für Korrelation und Deduplizierung; identische IDs über Zeitfenster prüfen.

```kusto
AtlassianAuditEvents_CL
| where TimeGenerated >= ago(7d)
| where isnotempty(EventId)
| summarize Copies=count() by EventId
| where Copies > 1
| order by Copies desc
```

## 6. Alternativen: Defender for Cloud Apps und Webhooks

### 6.1 Microsoft Defender for Cloud Apps (MDCA)

```text
Atlassian Organization Audit API
    → Microsoft Defender for Cloud Apps App Connector
    → Defender XDR (Cloud-App-Aktivitäten)
    → Sentinel, sofern Rohdatenintegration aktiviert (z. B. CloudAppEvents)
```

Vorteil: zusätzliche **Cloud-App-Aktivitätsrichtlinien**, Anomalieerkennung und Defendertools. Einschränkungen laut Microsoft:

- Atlassian-Connector verlangt derzeit **Organisations-API-Key ohne Scopes** (im Unterschied zum scoped Read-only-Key des direkten Sentinel-CCF-Connectors) — Sicherheits-/Berechtigungsrisiko abwägen und dedizierten Key verwenden.
- Domänenverifizierung ist für Benutzersichtbarkeit relevant.
- Cloud Apps stellt **nur Aktivitäten ab dem Anbindungszeitpunkt** bereit; kein automatischer historischer Backfill.
- Die Microsoft-Dokumentation verwendet teilweise noch die ältere Bezeichnung **„Atlassian Access“**.
- Defender-Alerts und Rohereignisse sind **unterschiedliche Datenflüsse**. Die Ingestion von `CloudAppEvents` in Sentinel muss separat geprüft und ggf. aktiviert werden. [MDCA: Atlassian anbinden][ms-mdca], [Sentinel Billing][ms-billing]

**Praxisentscheidung:** Für reine SIEM-Audit-Ingestion ist der direkte CCF-Connector wegen des **scoped API-Keys** oft die passendere erste Wahl. MDCA ergänzen, wenn die zusätzlichen Erkennungs- und Governance-Funktionen gewünscht sind.

### 6.2 Atlassian Audit-Log-Webhooks (Push)

Atlassian bietet Organisations-Audit-Log-Webhooks für **Guard Premium ODER einen Enterprise-Plan für Jira, Confluence oder Jira Service Management**. Also **kein verpflichtendes Guard Premium zusätzlich zu einem solchen Enterprise-Plan**. [Webhook-Details][atl-webhooks]

```text
Atlassian Audit-Log-Webhook (JSON)
   → eigener abgesicherter HTTPS-Receiver, z. B. Azure Function / Logic App
   → Log Ingestion API / DCR
   → Sentinel
```

Beachten:

- Maximal **3 Webhooks pro Organisation**.
- **Keine garantierte Reihenfolge**, potenzielle **doppelte Lieferung**, Deduplizierung per Ereignis-ID erforderlich.
- Fehlerhafte Zustellung wird **bis zu dreimal** erneut versucht; **keine öffentlichen Delivery-SLOs**.
- Receiver muss Authentifizierung, Rate-Limits, Fehlerbehandlung, Replay-Schutz und sichere Speicherung vorsehen.

**Bewertung:** Sinnvoll für eigene Push-Architekturen und geringe gewünschte Latenz. Technisch aufwendiger als der Microsoft-CCF-Polling-Connector; Webhook-Realtime ist keine garantierte verlustfreie Lieferung.

## 7. Betriebsrisiken, Retention und Kosten

### 7.1 Backlog / API-Rate-Limits

Der publizierte Microsoft-Organization-CCF-Poller nutzt in der eingesehenen Konfiguration u. a. `sortOrder=asc`, `limit=200` und einen persistenten Cursor. In großen Umgebungen kann ein neuer Connector einen historischen Backlog durchlaufen; API-Rate-Limits (HTTP **429**) und dadurch verzögert eintreffende aktuelle Events sind möglich. [Microsoft-Poller-Config][ms-poller]

Am **16.10.2026** ist [PR #15234][ms-pr-15234] im offiziellen Microsoft-Repository **noch offen**. Er schlägt u. a. einen initialen Zeitfilter, größere Pages (500) und explizites Pagination-Throttling vor. **Nicht als bereits produktiv ausgerollten Fix behandeln.** Bei Änderungen am veröffentlichten Paket/Setup Release Notes und tatsächliche Versionsnummer prüfen. Auch nach einem Fix bleibt Deduplizierung ein eigener Qualitätsaspekt.

### 7.2 Zwei unabhängige Retention-Ebenen

- **Atlassian-Quelle:** Nach aktueller Atlassian-Herstellerdokumentation seit Oktober 2026 bis zu **365 Tage mit Guard**, sonst 180 Tage (soweit überhaupt Audit-Events vorhanden sind). Upgrade stellt vergangene, vorher nicht erfasste Ereignisse nicht wieder her.
- **Sentinel / Log Analytics:** Das aktuell eingesehene Microsoft-Tabellen-Template setzt `retentionInDays: 180` für `AtlassianAuditEvents_CL`. **Das ist unabhängig von der Atlassian-Quellen-Historie**. Für längere Aufbewahrung tatsächliche Table-/Workspace-Settings, Tier und Kosten prüfen. [Tabellen-Template][ms-table-schema], [Sentinel Pricing][ms-billing]

### 7.3 Kostenarten

1. **Atlassian-Lizenzierung:** Guard Standard, Guard Premium oder produktbezogenes Enterprise – abhängig von Anforderungen und Benutzerzahl.
2. **Sentinel-/Log-Analytics-Ingestion:** Custom Audit-Logs sind nicht pauschal eine kostenlose Microsoft-Datenquelle; Menge, Abrechnungsmodell und ggf. Transformationsmöglichkeiten berücksichtigen.
3. **Retention / Analyse-Tier:** Je nach Table-Plan und benötigter Aufbewahrung.
4. **Optional:** MDCA-Lizenzierung, Azure Functions/Logic Apps, Key Vault, zusätzliche Betriebs-/Monitoringkosten.

Microsoft nennt bestimmte Security-Alerts als kostenlos, **nicht aber automatisch deren sämtliche Rohlogs**. [Microsoft Sentinel Billing][ms-billing]

### 7.4 Betriebs- und Security-Kontrollen

- Least Privilege: `read:events:admin` für den direkten Organizations-Connector; dedizierter Key, keine Wiederverwendung von Admin-/User-Tokens.
- API-Key-Rotation **vor Ablauf eines Jahres**, dokumentierter Owner und Notfallprozess.
- Events bei Quellsystem und Sentinel zählen/abgleichen; Missing Events, Backlog, HTTP 429 und Duplikate prüfen.
- Site-/Org-IDs, Berechtigungen, API-Änderungen und mögliche neue Atlassian-Produkte erfassen.
- PII in Logs (E-Mail/IP) gemäß Datenschutz und internen Policies behandeln.
- Keine Credentials, Tenant-/Org-IDs oder internen Ereignisbeispiele in diesem **öffentlichen** Repository speichern.

## 8. Empfehlung und Pilot-Checkliste

**Empfohlen:** **CCF Organization Audit Events als Basis → Ist-Event-Matrix → Jira-/Confluence-Connectoren nur bei nachgewiesenem Bedarf → Detektions- und Health-Regeln.** Ohne existierende Atlassian-Lizenzen zunächst **Guard Premium gegen Produkt-Enterprise** nach Funktionsumfang und Gesamtkosten vergleichen, statt Enterprise nur wegen Sentinel festzulegen.

- [ ] Benötigte Atlassian-Apps/Sites und konkrete Security-Use-Cases definiert
- [ ] Audit-Log-Events je Produkt und Plan gegen [Atlassian Eventdatenbank][atl-events-db] gemappt
- [ ] Lizenzpfade Guard Standard / Guard Premium / Enterprise (je Produkt) kaufmännisch bewertet
- [ ] POC mit scoped Organisations-API-Key und CCF-Connector eingerichtet
- [ ] KQL-Tabellennamen und `Action`-Werte in **eigenem** Workspace verifiziert
- [ ] Jira-/Confluence-API-Connectoren nur für relevante Lücken pilotiert
- [ ] Event-Vollständigkeit, Duplikate, Polling-Lag und 429-Fehler überprüft
- [ ] Aufbewahrungsanforderungen bei Atlassian **und** Sentinel getrennt geklärt
- [ ] Token-Rotation, Fehleralarmierung, Incident-Mapping und Kostenmonitoring umgesetzt
- [ ] PR-/Connector-Version für den Produktionseinsatz kontrolliert

## 9. Quellen und Herstellerdokumentation

**Microsoft / Azure**
- [Microsoft Sentinel: Offizielles Datenconnector-Verzeichnis][ms-connectors]
- [Microsoft Sentinel: Data Connectors einrichten][ms-setup]
- [Microsoft Defender for Cloud Apps: Atlassian-Anbindung][ms-mdca]
- [Microsoft Sentinel: Preise, Ingestion und freie Datenquellen][ms-billing]
- [Azure-Sentinel: Organization-Connector-Poller (Source)][ms-poller]
- [Azure-Sentinel: Table-Schema `AtlassianAuditEvents_CL` (Source)][ms-table-schema]
- [Azure-Sentinel PR #15234: Backlog-/429-Verbesserungen][ms-pr-15234]

**Atlassian**
- [Audit-Log-Abdeckung nach Cloud-Plan (Jira/Confluence/JSM u. a.)][atl-log-matrix]
- [Audit-Logs in Atlassian Administration ansehen und Lizenzvoraussetzungen][atl-view]
- [Audit-Log-Ereignisdatenbank][atl-events-db]
- [Organizations REST API: Events und `events-stream`][atl-events-api]
- [Organisations-API-Keys, Scopes und maximale Gültigkeit][atl-admin-api]
- [Atlassian Cloud Enterprise: Guard Standard enthalten][atl-enterprise-faq]
- [Enterprise-Plan, Bedingungen und Mindest-User-Tiers][atl-enterprise]
- [Audit-Log-Webhooks (inkl. Enterprise-Berechtigung und Delivery-Limits)][atl-webhooks]
- [Confluence: Produktinternes Audit-Log und Einschränkungen][confluence-audit]

[ms-connectors]: https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference
[ms-setup]: https://learn.microsoft.com/en-us/azure/sentinel/configure-data-connector
[ms-mdca]: https://learn.microsoft.com/en-us/defender-cloud-apps/protect-atlassian
[ms-billing]: https://learn.microsoft.com/en-us/azure/sentinel/billing
[ms-poller]: https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/AtlassianOrganizationAudit/Data%20Connectors/AtlassianOrganizationAuditConnector_CCF/AtlassianOrganizationAudit_PollerConfig.json
[ms-table-schema]: https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/AtlassianOrganizationAudit/Data%20Connectors/AtlassianOrganizationAuditConnector_CCF/table_AtlassianAuditEvents.json
[ms-pr-15234]: https://github.com/Azure/Azure-Sentinel/pull/15234
[atl-log-matrix]: https://support.atlassian.com/security-and-access-policies/docs/accessing-audit-log-activities/
[atl-view]: https://support.atlassian.com/security-and-access-policies/docs/view-audit-log-activities/
[atl-events-db]: https://support.atlassian.com/security-and-access-policies/docs/audit-log-activities-database/
[atl-events-api]: https://developer.atlassian.com/cloud/admin/organization/rest/api-group-events/#api-v1-orgs-orgid-events-stream-get
[atl-admin-api]: https://support.atlassian.com/organization-administration/docs/manage-an-organization-with-the-admin-apis/
[atl-enterprise-faq]: https://www.atlassian.com/licensing/enterprise-faq
[atl-enterprise]: https://support.atlassian.com/organization-administration/docs/what-is-an-enterprise-plan/
[atl-webhooks]: https://support.atlassian.com/security-and-access-policies/docs/learn-more-about-audit-log-webhooks/
[confluence-audit]: https://support.atlassian.com/confluence-cloud/docs/view-the-audit-log/

---

*Öffentliche technische Dokumentation, nur aus Herstellermaterial und öffentlichem Open-Source-Connector-Code abgeleitet. Keine produktiven Tenant-Daten, Credentials oder Konfigurationsgeheimnisse enthalten. Produkt-, Lizenz- und Connector-Verhalten kann sich ändern; vor Go-live im eigenen Tenant validieren.*
