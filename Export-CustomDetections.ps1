<#
  Exportiert alle Defender-XDR-Custom-Detections per Graph API und erzeugt:

  1) CustomDetectionRules.csv  -> Sentinel-Watchlist "CustomDetectionRules"
     (SearchKey: RuleId). Enthaelt Query (QueryGz) und alle Einstellungen
     (SettingsGz) gzip+Base64-kodiert fuer die Detailansicht im Workbook.

  2) .\AnalyticsRuleTemplates\<Regelname>.json
     Je Custom Detection ein fertiges ARM-Template fuer eine Analytics Rule
     mit uebernommenen Einstellungen (Name, Query, Severity, Taktiken,
     MITRE-Techniken, Intervall, Entity Mapping, Beschreibung).
     Import: Sentinel > Analytics > Import, oder per Pipeline deployen.
     Die Regeln werden DEAKTIVIERT angelegt (ausser mit -EnableRules).

  Voraussetzung: Install-Module Microsoft.Graph.Authentication
  Recht:         CustomDetection.Read.All (delegiert)

  Die Spalten AnalyticsRuleName, ManualStatus und Notes pflegst du in der CSV.
  Bei erneutem Export bleiben sie erhalten (Abgleich ueber RuleId).

  -InputJson <Datei>: liest die Regeln aus einer gespeicherten Graph-Antwort
  statt live aus der API (zum Testen/offline).
#>
param(
    [string]$Path = ".\CustomDetectionRules.csv",
    [string]$TemplateFolder = ".\AnalyticsRuleTemplates",
    [switch]$EnableRules,
    [string]$InputJson
)

$SentinelTactics = @('Reconnaissance','ResourceDevelopment','InitialAccess','Execution','Persistence',
    'PrivilegeEscalation','DefenseEvasion','CredentialAccess','Discovery','LateralMovement','Collection',
    'Exfiltration','CommandAndControl','Impact','PreAttack','ImpairProcessControl','InhibitResponseFunction')

# ---------- Hilfsfunktionen ----------

# gzip + Base64: bleibt einzeilig und passt ins Watchlist-Limit von 10.240
# Zeichen pro CSV-Zeile. Das Workbook entpackt mit gzip_decompress_from_base64_string().
function Compress-Text([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Close()
    return [Convert]::ToBase64String($ms.ToArray())
}

function ConvertTo-IsoDuration([TimeSpan]$Span) {
    return [System.Xml.XmlConvert]::ToString($Span)
}

function Format-Span([TimeSpan]$Span) {
    if ($Span.TotalDays -ge 1 -and ($Span.TotalDays % 1) -eq 0) { return "$([int]$Span.TotalDays) d" }
    if ($Span.TotalHours -ge 1 -and ($Span.TotalHours % 1) -eq 0) { return "$([int]$Span.TotalHours) h" }
    return "$([int]$Span.TotalMinutes) min"
}

# Deterministische GUID aus der Custom-Detection-ID: erneuter Import
# aktualisiert dieselbe Analytics Rule, statt ein Duplikat anzulegen.
function Get-StableGuid([string]$Seed) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("cd2ar:$Seed"))
    return ([guid]::new($hash)).ToString()
}

# Vereinheitlicht eine Regel aus der Graph-Antwort. Unterstuetzt das bisherige
# Beta-Schema (isEnabled, schedule.period, mitreTechniques, impactedAssets,
# responseActions) und das neuere (status, schedule.frequency, tactics[],
# entityMappings, automatedActions).
function ConvertTo-NormalizedRule($r) {
    $tpl = $r.detectionAction.alertTemplate

    $enabled = if ($null -ne $r.isEnabled) { [bool]$r.isEnabled } else { "$($r.status)" -eq 'enabled' }

    $periodRaw = "$($r.schedule.period)"
    if ([string]::IsNullOrEmpty($periodRaw)) { $periodRaw = "$($r.schedule.frequency)" }

    $tactics = @(); $techniques = @()
    if ($tpl.tactics) {
        foreach ($t in @($tpl.tactics)) {
            if ($t.tactic) { $tactics += "$($t.tactic)" }
            foreach ($q in @($t.techniques)) { if ($q.technique) { $techniques += "$($q.technique)" } }
        }
    }
    if ($tpl.category) { $tactics += "$($tpl.category)" }
    if ($tpl.mitreTechniques) { $techniques += @($tpl.mitreTechniques | ForEach-Object { "$_" }) }

    # Entitaeten: Liste von Gruppen @{ Kind; Fields = @(@{ Field; Column }) }
    $entities = @()
    foreach ($a in @($tpl.impactedAssets)) {
        if (-not $a -or -not $a.identifier) { continue }
        $kind = ("$($a.'@odata.type')" -replace '.*\.impacted', '' -replace 'Asset$', '').ToLower()
        $id = "$($a.identifier)"
        $col = $id.Substring(0, 1).ToUpper() + $id.Substring(1)
        $entities += , @{ Kind = $kind; Fields = @(@{ Field = $id; Column = $col }) }
    }
    if ($tpl.entityMappings) {
        foreach ($p in $tpl.entityMappings.PSObject.Properties) {
            foreach ($m in @($p.Value)) {
                if (-not $m) { continue }
                $fields = @()
                foreach ($f in $m.PSObject.Properties) {
                    if ($f.Value -is [string] -and $f.Value) {
                        $fields += @{ Field = ($f.Name -replace 'Column$', ''); Column = $f.Value }
                    }
                }
                if ($fields.Count) { $entities += , @{ Kind = $p.Name.ToLower(); Fields = $fields } }
            }
        }
    }

    $actions = @()
    foreach ($ra in @($r.detectionAction.responseActions)) {
        if (-not $ra) { continue }
        $n = "$($ra.'@odata.type')" -replace '#microsoft\.graph\.security\.', '' -replace 'ResponseAction$', ''
        if ($ra.identifier) { $n += " ($($ra.identifier))" }
        $actions += $n
    }
    if ($r.detectionAction.automatedActions) {
        foreach ($p in $r.detectionAction.automatedActions.PSObject.Properties) {
            if (@($p.Value).Count -gt 0 -and $p.Value) { $actions += $p.Name }
        }
    }

    $description = "$($tpl.description)"
    if ([string]::IsNullOrEmpty($description)) { $description = "$($r.description)" }

    return @{
        Id            = "$($r.id)"
        Name          = "$($r.displayName)"
        Enabled       = $enabled
        Query         = "$($r.queryCondition.queryText)"
        PeriodRaw     = $periodRaw
        Title         = "$($tpl.title)"
        Description   = $description
        Severity      = "$($tpl.severity)"
        Tactics       = @($tactics | Where-Object { $_ } | Select-Object -Unique)
        Techniques    = @($techniques | Where-Object { $_ } | Select-Object -Unique)
        Entities      = $entities
        Actions       = $actions
        Recommended   = "$($tpl.recommendedActions)"
        Scope         = if ($r.detectionAction.organizationalScope) { ($r.detectionAction.organizationalScope | ConvertTo-Json -Compress -Depth 5) } else { '' }
        CreatedBy     = "$($r.createdBy)"
        Created       = "$($r.createdDateTime)"
        ModifiedBy    = "$($r.lastModifiedBy)"
        Modified      = "$($r.lastModifiedDateTime)"
        LastRunStatus = "$($r.lastRunDetails.status)"
        LastRun       = "$($r.lastRunDetails.lastRunDateTime)"
    }
}

# Intervall der Custom Detection -> Typ, Frequenz und Zeitraum der Analytics Rule
function Get-ArSchedule($n, [System.Collections.Generic.List[string]]$hints) {
    $raw = $n.PeriodRaw.Trim()
    $result = @{ Kind = 'Scheduled'; Frequency = $null; Period = $null; CdText = $raw; CdLookback = '' }

    if ($raw -in @('0', 'PT0S', 'PT0M', 'PT0H')) {
        $result.Kind = 'NRT'
        $result.CdText = 'Continuous (NRT)'
        $result.CdLookback = 'Events bei Eingang'
        $hints.Add('Als NRT-Regel angelegt. NRT-Regeln sind in Sentinel pro Workspace limitiert; ggf. auf Scheduled mit 5 Minuten umstellen.')
        return $result
    }

    $freq = $null
    if ($raw -match '^(\d+)H$') { $freq = [TimeSpan]::FromHours([int]$Matches[1]) }
    elseif ($raw -match '^P') { try { $freq = [System.Xml.XmlConvert]::ToTimeSpan($raw) } catch { } }
    if (-not $freq -or $freq.TotalMinutes -lt 5) {
        $freq = [TimeSpan]::FromHours(1)
        $hints.Add("Intervall '$raw' nicht erkannt, 1 Stunde angenommen.")
    }
    $result.CdText = "alle $(Format-Span $freq)"

    # Lookback der Custom Detection: 4x Frequenz bzw. 30 Tage bei 24 h
    $cdLookback = if ($freq.TotalHours -ge 24) { [TimeSpan]::FromDays(30) } else { [TimeSpan]::FromTicks($freq.Ticks * 4) }
    $result.CdLookback = Format-Span $cdLookback

    # Zeitraum der Analytics Rule = Frequenz (sonst wertet Sentinel dieselben
    # Events mehrfach aus und alarmiert doppelt), erweitert auf das groesste
    # ago() in der Query, maximal 14 Tage.
    $period = $freq
    $maxAgo = [TimeSpan]::Zero
    foreach ($m in [regex]::Matches($n.Query, 'ago\(\s*(\d+)\s*(d|h|min|m|s)\s*\)')) {
        $v = [int]$m.Groups[1].Value
        $span = switch ($m.Groups[2].Value) {
            'd'   { [TimeSpan]::FromDays($v) }
            'h'   { [TimeSpan]::FromHours($v) }
            's'   { [TimeSpan]::FromSeconds($v) }
            default { [TimeSpan]::FromMinutes($v) }
        }
        if ($span -gt $maxAgo) { $maxAgo = $span }
    }
    if ($maxAgo -gt $period) {
        $period = $maxAgo
        $hints.Add("Zeitraum wegen ago($(Format-Span $maxAgo)) in der Query auf $(Format-Span $maxAgo) gesetzt. Zeitraum > Frequenz kann doppelte Alerts erzeugen.")
    }
    $max = [TimeSpan]::FromDays(14)
    if ($period -gt $max) {
        $period = $max
        $hints.Add('Zeitraum auf das Sentinel-Maximum von 14 Tagen gekuerzt.')
    }
    if ($cdLookback -gt $period) {
        $hints.Add("Die Custom Detection pruefte $(Format-Span $cdLookback) rueckwirkend (mit eingebauter Deduplizierung), die Analytics Rule nur $(Format-Span $period). Bei Schwellwert- oder Aggregationslogik den Zeitraum pruefen.")
    }

    $result.Frequency = ConvertTo-IsoDuration $freq
    $result.Period = ConvertTo-IsoDuration $period
    $result.ArText = "alle $(Format-Span $freq), Zeitraum $(Format-Span $period)"
    return $result
}

# Entitaeten der Custom Detection -> entityMappings der Analytics Rule
function Get-ArEntityMappings($n, [System.Collections.Generic.List[string]]$hints) {
    $mappings = @()
    foreach ($e in $n.Entities) {
        $kind = $e.Kind
        $type = $null
        $fieldMappings = @()
        foreach ($f in $e.Fields) {
            $field = "$($f.Field)".ToLower()
            $identifier = $null
            if ($kind -match 'device|host|machine') {
                $type = 'Host'
                if ($field -match 'name') { $identifier = 'FullName' }
                elseif ($n.Query -match '\bDeviceName\b') {
                    $fieldMappings += [ordered]@{ identifier = 'FullName'; columnName = 'DeviceName' }
                    $hints.Add("Entity: '$($f.Column)' hat keinen Host-Identifier in Sentinel, stattdessen DeviceName gemappt. Pruefen, ob die Query DeviceName ausgibt.")
                    continue
                }
                else {
                    $hints.Add("Entity: '$($f.Column)' laesst sich nicht auf Host mappen. DeviceName in der Query ausgeben und als Host/FullName mappen.")
                    continue
                }
            }
            elseif ($kind -match 'mail') {
                $type = 'Mailbox'
                $identifier = if ($field -match 'display') { 'DisplayName' } else { 'MailboxPrimaryAddress' }
            }
            elseif ($kind -match 'user|account') {
                $type = 'Account'
                if ($field -match 'sid') { $identifier = 'Sid' }
                elseif ($field -match 'objectid|aad') { $identifier = 'AadUserId' }
                elseif ($field -match 'upn|principal|mail|address') { $identifier = 'FullName' }
                elseif ($field -match 'name') { $identifier = 'Name' }
            }
            if ($identifier) {
                $fieldMappings += [ordered]@{ identifier = $identifier; columnName = "$($f.Column)" }
            }
            elseif ($type) {
                $hints.Add("Entity: Feld '$($f.Field)' ($($f.Column)) nicht automatisch zuordenbar, manuell mappen.")
            }
        }
        if (-not $type) {
            $hints.Add("Entity-Typ '$kind' nicht automatisch zuordenbar, manuell mappen.")
            continue
        }
        if ($fieldMappings.Count -gt 0) {
            $mappings += , ([ordered]@{ entityType = $type; fieldMappings = @($fieldMappings | Select-Object -First 3) })
        }
    }
    if ($mappings.Count -gt 10) {
        $hints.Add('Mehr als 10 Entity Mappings, auf 10 gekuerzt.')
        $mappings = @($mappings | Select-Object -First 10)
    }
    return , $mappings
}

function New-ArTemplate($n, $schedule, $entityMappings, [System.Collections.Generic.List[string]]$hints) {
    # Taktiken: nur Werte, die Sentinel kennt
    $tactics = @()
    foreach ($t in $n.Tactics) {
        $clean = $t -replace '[\s\-_]', ''
        $hit = $SentinelTactics | Where-Object { $_ -ieq $clean } | Select-Object -First 1
        if ($hit) { $tactics += $hit }
        else { $hints.Add("Kategorie '$t' ist keine Sentinel-Taktik und wurde nicht uebernommen.") }
    }
    $tactics = @($tactics | Select-Object -Unique)

    # Sentinel erwartet in "techniques" nur T#### ; Sub-Techniken separat
    $valid = @($n.Techniques | Where-Object { $_ -match '^T\d{4}(\.\d{3})?$' })
    $techniques = @($valid | ForEach-Object { $_.Substring(0, 5) } | Select-Object -Unique)
    $subTechniques = @($valid | Where-Object { $_ -match '\.' } | Select-Object -Unique)

    $severity = switch ("$($n.Severity)".ToLower()) {
        'high' { 'High' } 'medium' { 'Medium' } 'low' { 'Low' } default { 'Informational' }
    }

    $description = $n.Description
    if ($n.Recommended) { $description = ($description + "`n`nEmpfohlene Aktionen: " + $n.Recommended).Trim() }
    if ($description.Length -gt 5000) {
        $description = $description.Substring(0, 5000)
        $hints.Add('Beschreibung auf 5000 Zeichen gekuerzt.')
    }

    $override = $null
    if ($n.Title -and ($n.Title -ne $n.Name -or $n.Title -match '\{\{')) {
        $override = [ordered]@{ alertDisplayNameFormat = $n.Title }
        if ($n.Description -match '\{\{') { $override.alertDescriptionFormat = $n.Description }
        $hints.Add("Alert-Titel weicht vom Regelnamen ab und wurde als Alert-Namensformat uebernommen: '$($n.Title)'.")
    }

    $props = [ordered]@{
        displayName = $n.Name
        description = $description
        severity    = $severity
        enabled     = [bool]$EnableRules
        query       = $n.Query
    }
    if ($schedule.Kind -eq 'Scheduled') {
        $props.queryFrequency   = $schedule.Frequency
        $props.queryPeriod      = $schedule.Period
        $props.triggerOperator  = 'GreaterThan'
        $props.triggerThreshold = 0
    }
    $props.suppressionDuration   = 'PT5H'
    $props.suppressionEnabled    = $false
    $props.tactics               = $tactics
    $props.techniques            = $techniques
    $props.subTechniques         = $subTechniques
    $props.incidentConfiguration = [ordered]@{
        createIncident        = $true
        groupingConfiguration = [ordered]@{
            enabled               = $false
            reopenClosedIncident  = $false
            lookbackDuration      = 'PT5H'
            matchingMethod        = 'AllEntities'
            groupByEntities       = @()
            groupByAlertDetails   = @()
            groupByCustomDetails  = @()
        }
    }
    $props.eventGroupingSettings = [ordered]@{ aggregationKind = 'AlertPerResult' }
    $props.alertDetailsOverride  = $override
    $props.customDetails         = $null
    $props.entityMappings        = $null
    if ($entityMappings.Count -gt 0) { $props.entityMappings = @($entityMappings) }

    $guid = Get-StableGuid $n.Id
    return [ordered]@{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        parameters     = [ordered]@{ workspace = [ordered]@{ type = 'String' } }
        resources      = @(
            [ordered]@{
                id         = "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/$guid')]"
                name       = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/$guid')]"
                type       = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
                kind       = $schedule.Kind
                apiVersion = '2023-12-01-preview'
                properties = $props
            }
        )
    }
}

# ---------- Regeln laden ----------

if ($InputJson) {
    $data = Get-Content -Raw -Path $InputJson | ConvertFrom-Json
    $rules = if ($data.value) { @($data.value) } else { @($data) }
}
else {
    Connect-MgGraph -Scopes "CustomDetection.Read.All" -NoWelcome
    $rules = @()
    $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules"
    while ($uri) {
        $resp  = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        $rules += $resp.value
        $uri   = $resp.'@odata.nextLink'
    }
}

# Manuell gepflegte Spalten aus vorhandener CSV uebernehmen
$manual = @{}
if (Test-Path $Path) {
    Import-Csv $Path | ForEach-Object { $manual[$_.RuleId] = $_ }
}

$TemplateFolder = (New-Item -ItemType Directory -Force -Path $TemplateFolder).FullName
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$usedNames = @{}

# ---------- Verarbeiten ----------

$rows = foreach ($r in $rules) {
    $n = ConvertTo-NormalizedRule $r
    $hints = New-Object 'System.Collections.Generic.List[string]'

    $schedule = Get-ArSchedule $n $hints
    $entityMappings = Get-ArEntityMappings $n $hints
    $template = New-ArTemplate $n $schedule $entityMappings $hints

    if ($n.Actions.Count -gt 0) {
        $hints.Add("Response Actions ($($n.Actions -join ', ')) gibt es bei Analytics Rules nicht. Ueber Automation Rule und Playbook nachbauen.")
    }
    if ($n.Scope) {
        $hints.Add('Die Custom Detection ist auf Geraetegruppen eingeschraenkt. Analytics Rules kennen keinen Scope, Einschraenkung in die Query uebernehmen.')
    }

    # ARM-Template schreiben
    $fileBase = ($n.Name -replace '[^\w\-\. ]', '_').Trim()
    if ($fileBase.Length -gt 100) { $fileBase = $fileBase.Substring(0, 100) }
    if (-not $fileBase) { $fileBase = "rule_$($n.Id)" }
    if ($usedNames.ContainsKey($fileBase.ToLower())) { $fileBase = "${fileBase}_$($n.Id)" }
    $usedNames[$fileBase.ToLower()] = $true
    $templateFile = Join-Path $TemplateFolder "$fileBase.json"
    [System.IO.File]::WriteAllText($templateFile, ($template | ConvertTo-Json -Depth 20), $utf8NoBom)

    # Verwendete Tabellen grob aus der Query ziehen
    $tables = [regex]::Matches($n.Query, '(?m)^\s*(?:let\s+\w+\s*=\s*)?([A-Z][A-Za-z]+(?:Events|Info|Logs|Evidence|_CL)?)\b(?=\s*(\||$))') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    $entityText = ($n.Entities | ForEach-Object {
        $e = $_; ($e.Fields | ForEach-Object { "$($e.Kind): $($_.Column)" }) -join ', '
    }) -join '; '
    $arEntityText = ($entityMappings | ForEach-Object {
        $m = $_; "$($m.entityType) (" + (($m.fieldMappings | ForEach-Object { "$($_.identifier) = $($_.columnName)" }) -join ', ') + ")"
    }) -join '; '
    $p = $template.resources[0].properties

    # Einstellungen fuer die Detailansicht im Workbook (Reihenfolge = Anzeige)
    $settings = @(
        @{ k = 'Name';                         v = $n.Name }
        @{ k = 'Alert-Titel';                  v = $n.Title }
        @{ k = 'Beschreibung';                 v = $n.Description }
        @{ k = 'Empfohlene Aktionen';         v = $n.Recommended }
        @{ k = 'Severity';                     v = $n.Severity }
        @{ k = 'Kategorie / Taktiken';         v = ($n.Tactics -join ', ') }
        @{ k = 'MITRE-Techniken';              v = ($n.Techniques -join ', ') }
        @{ k = 'Intervall';                    v = $schedule.CdText }
        @{ k = 'Lookback';                     v = $schedule.CdLookback }
        @{ k = 'Betroffene Entities';         v = $entityText }
        @{ k = 'Response Actions';             v = ($n.Actions -join ', ') }
        @{ k = 'Device-Scope';                 v = $n.Scope }
        @{ k = 'Aktiv';                        v = "$($n.Enabled)" }
        @{ k = 'Erstellt';                     v = "$($n.CreatedBy) $($n.Created)".Trim() }
        @{ k = 'Zuletzt bearbeitet';             v = "$($n.ModifiedBy) $($n.Modified)".Trim() }
        @{ k = 'Regel-ID';                     v = $n.Id }
        @{ k = '-> Analytics Rule: Typ';        v = $schedule.Kind }
        @{ k = '-> Analytics Rule: Zeitplan';   v = "$($schedule.ArText)" }
        @{ k = '-> Analytics Rule: Taktiken';   v = ($p.tactics -join ', ') }
        @{ k = '-> Analytics Rule: Techniken';  v = (@($p.techniques) + @($p.subTechniques) -join ', ') }
        @{ k = '-> Analytics Rule: Entities';   v = $arEntityText }
        @{ k = '-> Analytics Rule: Template';   v = "$fileBase.json" }
        @{ k = 'Hinweise zur Migration';       v = ($hints -join "`n") }
    ) | Where-Object { $_.v }
    $settingsJson = ConvertTo-Json -InputObject @($settings | ForEach-Object { [ordered]@{ k = $_.k; v = "$($_.v)" } }) -Compress -Depth 3

    $queryGz = Compress-Text $n.Query
    $settingsGz = Compress-Text $settingsJson
    if (($queryGz.Length + $settingsGz.Length) -gt 9000) {
        Write-Warning "'$($n.Name)': Einstellungen zu lang fuer die Watchlist-Zeile, werden im Workbook ausgelassen (Template ist vollstaendig)."
        $settingsGz = ''
    }
    if ($queryGz.Length -gt 9000) {
        Write-Warning "'$($n.Name)': Query zu lang fuer die Watchlist-Zeile, wird im Workbook ausgelassen (Template ist vollstaendig)."
        $queryGz = ''
    }

    $old = $manual[$n.Id]
    [pscustomobject]@{
        RuleId            = $n.Id
        DisplayName       = $n.Name
        AlertTitle        = $n.Title
        IsEnabled         = $n.Enabled
        Period            = $schedule.CdText
        Severity          = $n.Severity
        Category          = ($n.Tactics -join ';')
        MitreTechniques   = ($n.Techniques -join ';')
        Tables            = ($tables -join ';')
        ResponseActions   = ($n.Actions -join ';')
        LastRunStatus     = $n.LastRunStatus
        LastRunDateTime   = $n.LastRun
        CreatedBy         = $n.CreatedBy
        LastModified      = $n.Modified
        MigrationHints    = $hints.Count
        AnalyticsRuleName = if ($old) { $old.AnalyticsRuleName } else { '' }
        ManualStatus      = if ($old) { $old.ManualStatus } else { '' }
        Notes             = if ($old) { $old.Notes } else { '' }
        QueryGz           = $queryGz
        SettingsGz        = $settingsGz
    }
}

$rows | Sort-Object DisplayName | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
Write-Host "$(@($rows).Count) Custom Detections nach $Path exportiert."
Write-Host "Analytics-Rule-Templates: $TemplateFolder"
