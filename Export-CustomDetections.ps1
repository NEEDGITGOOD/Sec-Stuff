<#
  Exportiert alle Defender-XDR-Custom-Detections per Graph API in eine CSV
  für die Sentinel-Watchlist "CustomDetectionRules" (SearchKey: RuleId).

  Voraussetzung: Install-Module Microsoft.Graph.Authentication
  Recht:         CustomDetection.Read.All (delegiert)

  Die Spalte QueryGz enthält die KQL-Query (gzip + Base64) für die
  Detailansicht im Workbook.

  Die Spalten AnalyticsRuleName, ManualStatus und Notes pflegst du in der CSV.
  Bei erneutem Export bleiben sie erhalten (Abgleich über RuleId).
#>
param(
    [string]$Path = ".\CustomDetectionRules.csv"
)

Connect-MgGraph -Scopes "CustomDetection.Read.All" -NoWelcome

# Manuell gepflegte Spalten aus vorhandener CSV übernehmen
$manual = @{}
if (Test-Path $Path) {
    Import-Csv $Path | ForEach-Object { $manual[$_.RuleId] = $_ }
}

$rules = @()
$uri = "https://graph.microsoft.com/beta/security/rules/detectionRules"
while ($uri) {
    $resp  = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    $rules += $resp.value
    $uri   = $resp.'@odata.nextLink'
}

# Query gzip-komprimiert + Base64 ablegen: bleibt einzeilig und passt ins
# Watchlist-Limit von 10.240 Zeichen pro CSV-Zeile. Das Workbook entpackt sie
# mit gzip_decompress_from_base64_string().
function Compress-Text([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Close()
    return [Convert]::ToBase64String($ms.ToArray())
}

$rows = foreach ($r in $rules) {
    $tpl   = $r.detectionAction.alertTemplate
    $query = [string]$r.queryCondition.queryText
    # Verwendete Tabellen grob aus der Query ziehen (Zeilenanfang, union, join)
    $tables = [regex]::Matches($query, '(?m)^\s*(?:let\s+\w+\s*=\s*)?([A-Z][A-Za-z]+(?:Events|Info|Logs|Evidence|_CL)?)\b(?=\s*(\||$))') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    $old = $manual["$($r.id)"]
    $queryGz = Compress-Text $query
    if ($queryGz.Length -gt 9000) {
        Write-Warning "Query von '$($r.displayName)' ist zu lang für die Watchlist und wird ausgelassen."
        $queryGz = ''
    }

    [pscustomobject]@{
        RuleId            = "$($r.id)"
        DisplayName       = $r.displayName
        AlertTitle        = $tpl.title
        IsEnabled         = [bool]$r.isEnabled
        Period            = $r.schedule.period
        Severity          = $tpl.severity
        Category          = $tpl.category
        MitreTechniques   = ($tpl.mitreTechniques -join ';')
        Tables            = ($tables -join ';')
        ResponseActions   = (($r.detectionAction.responseActions | ForEach-Object { $_.'@odata.type' -replace '#microsoft.graph.security.', '' }) -join ';')
        LastRunStatus     = $r.lastRunDetails.status
        LastRunDateTime   = $r.lastRunDetails.lastRunDateTime
        CreatedBy         = $r.createdBy
        LastModified      = $r.lastModifiedDateTime
        AnalyticsRuleName = if ($old) { $old.AnalyticsRuleName } else { '' }
        ManualStatus      = if ($old) { $old.ManualStatus } else { '' }
        Notes             = if ($old) { $old.Notes } else { '' }
        QueryGz           = $queryGz
    }
}

$rows | Sort-Object DisplayName | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
Write-Host "$($rows.Count) Custom Detections nach $Path exportiert."
