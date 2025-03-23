# ================================================
# 🛡️ NEXUS SENTINEL: AI-POWERED SECURITY TOOLKIT 2024
# ================================================
# Features:
# - Live AI-Powered Security Analysis and Remediation
# - Multi-terminal Real-time Monitoring (Process, Network, File)
# - Comprehensive System Security Assessment
# - AI-Generated Remediation with Auto-healing Capabilities
# - Advanced Threat Hunting and Neutralization
# ================================================

# ===== GLOBAL CONFIGURATION =====
$global:NexusConfig = @{
    # Core settings
    Version = "1.0.0"
    Title = "NEXUS SENTINEL: AI-POWERED SECURITY TOOLKIT"
    
    # File paths
    WorkingDir = "$env:USERPROFILE\NexusSentinel"
    LogDir = "$env:USERPROFILE\NexusSentinel\Logs"
    ReportDir = "$env:USERPROFILE\NexusSentinel\Reports"
    RemediationDir = "$env:USERPROFILE\NexusSentinel\Remediation"
    
    # DeepSeek API settings
    APIKey = ""  # User will be prompted to enter this
    DeepSeekAPI = "https://api.deepseek.com/v1/chat/completions"
    AIModel = "deepseek-chat"
    
    # Operation settings
    MaxScanResults = 100
    MaxRealtimeItems = 50
    ScanDepth = "Full"  # Options: Quick, Standard, Full
    
    # Terminal colors
    Colors = @{
        Title = "Cyan"
        Success = "Green"
        Warning = "Yellow"
        Error = "Red"
        Info = "Blue"
        Debug = "Gray"
        Alert = "Magenta"
    }
}

# Initialize variables
$global:ActiveMonitors = @()
$global:MonitorJobs = @{}
$global:ScanResults = @{}

# Create necessary directories
function Initialize-NexusEnvironment {
    $Dirs = @(
        $global:NexusConfig.WorkingDir,
        $global:NexusConfig.LogDir,
        $global:NexusConfig.ReportDir,
        $global:NexusConfig.RemediationDir
    )
    
    foreach ($Dir in $Dirs) {
        if (!(Test-Path -Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
            Write-NexusLog "Created directory: $Dir"
        }
    }
    
    # Initialize main log file
    $global:MainLogFile = Join-Path $global:NexusConfig.LogDir "NexusSentinel_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Nexus Sentinel initialized" | Out-File -FilePath $global:MainLogFile
    
    # Check for Administrator privileges
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $global:IsAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $global:IsAdmin) {
        Write-NexusLog "WARNING: Not running with Administrator privileges. Some features may not work properly." -Level "WARNING"
    }
}

# Enhanced logging function
function Write-NexusLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG", "ALERT")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole,
        
        [Parameter(Mandatory=$false)]
        [string]$LogFile = $global:MainLogFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    
    # Write to console with appropriate color unless suppressed
    if (-not $NoConsole) {
        $color = switch ($Level) {
            "INFO" { $global:NexusConfig.Colors.Info }
            "WARNING" { $global:NexusConfig.Colors.Warning }
            "ERROR" { $global:NexusConfig.Colors.Error }
            "SUCCESS" { $global:NexusConfig.Colors.Success }
            "DEBUG" { $global:NexusConfig.Colors.Debug }
            "ALERT" { $global:NexusConfig.Colors.Alert }
            default { "White" }
        }
        
        Write-Host $logEntry -ForegroundColor $color
    }
}

# Function to get API key from user
function Get-DeepSeekAPIKey {
    if ([string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        Write-Host "Enter your DeepSeek API Key (or press Enter to skip AI features): " -ForegroundColor Cyan -NoNewline
        $apiKey = Read-Host
        $global:NexusConfig.APIKey = $apiKey
    }
    
    if ([string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        Write-NexusLog "No API key provided. AI-powered features will be disabled." -Level "WARNING"
        return $false
    }
    return $true
}

# Function to call DeepSeek API with streaming support
function Invoke-DeepSeekAI {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Prompt,
        
        [Parameter(Mandatory=$false)]
        [string]$SystemPrompt = "You are an advanced cybersecurity AI assistant. Provide detailed, actionable security insights.",
        
        [Parameter(Mandatory=$false)]
        [switch]$Stream,
        
        [Parameter(Mandatory=$false)]
        [double]$Temperature = 0.3,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxTokens = 2000
    )
    
    if ([string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        Write-NexusLog "No API key configured. Cannot perform AI analysis." -Level "ERROR"
        return $null
    }
    
    try {
        $messages = @(
            @{ role = "system"; content = $SystemPrompt },
            @{ role = "user"; content = $Prompt }
        )
        
        $requestBody = @{
            model = $global:NexusConfig.AIModel
            messages = $messages
            temperature = $Temperature
            max_tokens = $MaxTokens
            stream = $Stream.IsPresent
        } | ConvertTo-Json -Depth 4
        
        if ($Stream) {
            # Streaming implementation
            $response = Invoke-WebRequest -Uri $global:NexusConfig.DeepSeekAPI -Method Post -Headers @{
                "Authorization" = "Bearer $($global:NexusConfig.APIKey)"
                "Content-Type" = "application/json"
            } -Body $requestBody -ResponseHeadersVariable responseHeaders -TimeoutSec 60 -UseBasicParsing
            
            $reader = [System.IO.StreamReader]::new($response.RawContentStream)
            $aiResponse = ""
            
            while (($line = $reader.ReadLine()) -ne $null) {
                if ($line.StartsWith("data: ")) {
                    $data = $line.Substring(6)
                    if ($data -ne "[DONE]") {
                        try {
                            $jsonData = $data | ConvertFrom-Json
                            $content = $jsonData.choices[0].delta.content
                            if ($content) {
                                Write-Host $content -NoNewline
                                $aiResponse += $content
                            }
                        } catch {
                            # Ignore parsing errors for incomplete JSON
                        }
                    }
                }
            }
            
            Write-Host "`n"
            return $aiResponse
        } else {
            # Non-streaming implementation
            $response = Invoke-RestMethod -Uri $global:NexusConfig.DeepSeekAPI -Method Post -Headers @{
                "Authorization" = "Bearer $($global:NexusConfig.APIKey)"
                "Content-Type" = "application/json"
            } -Body $requestBody
            
            return $response.choices[0].message.content
        }
    } catch {
        Write-NexusLog "Error calling DeepSeek API: $_" -Level "ERROR"
        return "Error: Unable to complete AI analysis. Please check your API key and connection."
    }
}

# ASCII Art Banner
function Show-NexusBanner {
    $bannerColor = $global:NexusConfig.Colors.Title
    $banner = @"
    
 ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
 ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
 ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
 ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
 ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                                                                                  
                         🛡️  AI-POWERED SECURITY TOOLKIT v$($global:NexusConfig.Version)  🛡️
"@
    
    Clear-Host
    Write-Host $banner -ForegroundColor $bannerColor
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    
    # Show admin status
    if ($global:IsAdmin) {
        Write-Host " [ADMIN] " -ForegroundColor Green -NoNewline
    } else {
        Write-Host " [USER] " -ForegroundColor Yellow -NoNewline
    }
    
    # Show hostname and user
    Write-Host "$env:COMPUTERNAME :: $env:USERNAME" -ForegroundColor Cyan
    
    # Show current date and time
    Write-Host " 🕒 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
}

# Main scanning function that performs comprehensive system security analysis
function Start-NexusSystemScan {
    param (
        [Parameter(Mandatory=$false)]
        [ValidateSet("Quick", "Standard", "Full")]
        [string]$ScanDepth = $global:NexusConfig.ScanDepth,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseAI
    )
    
    $scanId = "SystemScan_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $scanLogFile = Join-Path $global:NexusConfig.LogDir "$scanId.log"
    $reportFile = Join-Path $global:NexusConfig.ReportDir "$scanId.html"
    
    Write-NexusLog "Starting $ScanDepth system scan (ID: $scanId)" -LogFile $scanLogFile
    
    # Create results hashtable
    $global:ScanResults[$scanId] = @{
        StartTime = Get-Date
        EndTime = $null
        ScanDepth = $ScanDepth
        Results = @{
            SystemInfo = @{}
            InstalledPrograms = @()
            Services = @()
            Processes = @()
            NetworkConnections = @()
            UserAccounts = @()
            SecurityEvents = @()
            MalwareResults = @()
            VulnerabilityResults = @()
        }
        LogFile = $scanLogFile
        ReportFile = $reportFile
        UseAI = $UseAI.IsPresent
        AIAnalysis = @{}
    }
    
    # Create progress bar function for this scan
    function Update-ScanProgress {
        param (
            [int]$PercentComplete,
            [string]$Status
        )
        
        Write-Progress -Activity "System Security Scan" -Status $Status -PercentComplete $PercentComplete
        Write-NexusLog "[$PercentComplete%] $Status" -LogFile $scanLogFile -NoConsole
    }
    
    # 1. System Information
    Update-ScanProgress -PercentComplete 5 -Status "Collecting basic system information..."
    try {
        $systemInfo = Get-ComputerInfo | Select-Object CsName, CsDomain, CsManufacturer, CsModel, OsName, OsVersion, OsBuildNumber
        $global:ScanResults[$scanId].Results.SystemInfo = $systemInfo
        Write-NexusLog "System information collected successfully" -LogFile $scanLogFile
    } catch {
        Write-NexusLog "Error collecting system information: $_" -Level "ERROR" -LogFile $scanLogFile
    }
    
    # 2. Installed Programs
    Update-ScanProgress -PercentComplete 10 -Status "Scanning installed programs..."
    try {
        $installedPrograms = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate
        $global:ScanResults[$scanId].Results.InstalledPrograms = $installedPrograms
        Write-NexusLog "Collected information on $($installedPrograms.Count) installed programs" -LogFile $scanLogFile
    } catch {
        Write-NexusLog "Error collecting installed programs via WMI: $_" -Level "WARNING" -LogFile $scanLogFile
        try {
            $installedPrograms = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
                Where-Object { $_.DisplayName -ne $null }
            $global:ScanResults[$scanId].Results.InstalledPrograms = $installedPrograms
            Write-NexusLog "Collected information on $($installedPrograms.Count) installed programs (alternative method)" -LogFile $scanLogFile
        } catch {
            Write-NexusLog "Error collecting installed programs via registry: $_" -Level "ERROR" -LogFile $scanLogFile
        }
    }
    
    # 3. Services
    Update-ScanProgress -PercentComplete 20 -Status "Analyzing system services..."
    try {
        $services = Get-Service | Select-Object Name, DisplayName, Status, StartType
        $global:ScanResults[$scanId].Results.Services = $services
        Write-NexusLog "Collected information on $($services.Count) system services" -LogFile $scanLogFile
    } catch {
        Write-NexusLog "Error collecting service information: $_" -Level "ERROR" -LogFile $scanLogFile
    }
    
    # 4. Processes
    Update-ScanProgress -PercentComplete 30 -Status "Analyzing running processes..."
    try {
        $processes = Get-Process | Select-Object ProcessName, Id, Path, Company, Product, StartTime, 
            @{Name="CPU"; Expression={$_.CPU}}, 
            @{Name="Memory(MB)"; Expression={[Math]::Round($_.WorkingSet64 / 1MB, 2)}}
        $global:ScanResults[$scanId].Results.Processes = $processes
        Write-NexusLog "Collected information on $($processes.Count) running processes" -LogFile $scanLogFile
    } catch {
        Write-NexusLog "Error collecting process information: $_" -Level "ERROR" -LogFile $scanLogFile
    }
    
    # 5. Network Connections
    Update-ScanProgress -PercentComplete 40 -Status "Analyzing network connections..."
    try {
        $networkConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        $global:ScanResults[$scanId].Results.NetworkConnections = $networkConnections
        Write-NexusLog "Collected information on $($networkConnections.Count) network connections" -LogFile $scanLogFile
    } catch {
        Write-NexusLog "Error collecting network connection information: $_" -Level "WARNING" -LogFile $scanLogFile
        try {
            $netstat = netstat -ano
            $global:ScanResults[$scanId].Results.NetworkConnections = $netstat
            Write-NexusLog "Collected network connections using netstat (alternative method)" -LogFile $scanLogFile
        } catch {
            Write-NexusLog "Error collecting network connection information via netstat: $_" -Level "ERROR" -LogFile $scanLogFile
        }
    }
    
    # 6. User Accounts
    Update-ScanProgress -PercentComplete 50 -Status "Analyzing user accounts and permissions..."
    try {
        $userAccounts = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
        $global:ScanResults[$scanId].Results.UserAccounts = $userAccounts
        Write-NexusLog "Collected information on $($userAccounts.Count) user accounts" -LogFile $scanLogFile
    } catch {
        Write-NexusLog "Error collecting user account information: $_" -Level "ERROR" -LogFile $scanLogFile
    }
    
    # 7. Event Logs (Security)
    Update-ScanProgress -PercentComplete 60 -Status "Analyzing security event logs..."
    try {
        $securityEvents = Get-EventLog -LogName Security -EntryType Error, Warning, FailureAudit -Newest 500 | 
            Select-Object TimeGenerated, EntryType, Source, EventID, Message
        $global:ScanResults[$scanId].Results.SecurityEvents = $securityEvents
        Write-NexusLog "Collected $($securityEvents.Count) security event logs" -LogFile $scanLogFile
    } catch {
        Write-NexusLog "Error collecting security event logs: $_" -Level "WARNING" -LogFile $scanLogFile
    }
    
    # 8. Windows Defender Scan (if Full scan is selected)
    if ($ScanDepth -eq "Full" -or $ScanDepth -eq "Standard") {
        Update-ScanProgress -PercentComplete 70 -Status "Running malware scan..."
        try {
            Write-NexusLog "Starting Windows Defender quick scan..." -LogFile $scanLogFile
            Start-Process "MpCmdRun.exe" -ArgumentList "-Scan -ScanType 1" -Wait -NoNewWindow
            
            # Try to get scan results
            $defenderLogs = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows Defender\Support\MPLog*"
            if ($defenderLogs) {
                $malwareScanResults = Get-Content $defenderLogs[-1].FullName
                $global:ScanResults[$scanId].Results.MalwareResults = $malwareScanResults
                Write-NexusLog "Windows Defender scan completed" -LogFile $scanLogFile
            } else {
                Write-NexusLog "No Windows Defender logs found" -Level "WARNING" -LogFile $scanLogFile
            }
        } catch {
            Write-NexusLog "Error running Windows Defender scan: $_" -Level "ERROR" -LogFile $scanLogFile
        }
    }
    
    # 9. Vulnerability Scan (Full scan only)
    if ($ScanDepth -eq "Full") {
        Update-ScanProgress -PercentComplete 80 -Status "Checking for common vulnerabilities..."
        try {
            # Check for missing Windows updates
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
            
            $missingUpdates = @()
            if ($searchResult.Updates.Count -gt 0) {
                for ($i = 0; $i -lt $searchResult.Updates.Count; $i++) {
                    $update = $searchResult.Updates.Item($i)
                    $missingUpdates += [PSCustomObject]@{
                        Title = $update.Title
                        Severity = $update.MsrcSeverity
                        KB = ($update.KBArticleIDs | ForEach-Object { "KB$_" }) -join ", "
                    }
                }
            }
            
            $global:ScanResults[$scanId].Results.VulnerabilityResults = @{
                MissingUpdates = $missingUpdates
                UnsecuredServices = (Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -eq "Stopped" })
                SMBv1Enabled = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -eq "Enabled"
                PowerShellv2Enabled = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -eq "Enabled"
            }
            
            Write-NexusLog "Vulnerability scan completed. Found $($missingUpdates.Count) missing updates." -LogFile $scanLogFile
        } catch {
            Write-NexusLog "Error during vulnerability scan: $_" -Level "ERROR" -LogFile $scanLogFile
        }
    }
    
    # 10. AI Analysis (if enabled and API key provided)
    if ($UseAI -and -not [string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        Update-ScanProgress -PercentComplete 90 -Status "Performing AI-powered security analysis..."
        
        # Prepare data for AI analysis (in chunks to prevent overwhelming the API)
        $aiAnalysisData = @"
# System Information
$($global:ScanResults[$scanId].Results.SystemInfo | ConvertTo-Json -Depth 1)

# Top 10 Processes by Memory Usage
$($global:ScanResults[$scanId].Results.Processes | Sort-Object "Memory(MB)" -Descending | Select-Object -First 10 | ConvertTo-Json -Depth 1)

# Network Connections with Remote Endpoints (Non-local)
$($global:ScanResults[$scanId].Results.NetworkConnections | Where-Object { $_.RemoteAddress -notmatch "127.0.0.1|::1|0.0.0.0" } | Select-Object -First 20 | ConvertTo-Json -Depth 1)

# Security Events (Last 10)
$($global:ScanResults[$scanId].Results.SecurityEvents | Select-Object -First 10 | ConvertTo-Json -Depth 1)
"@
        
        try {
            Write-NexusLog "Submitting scan data to DeepSeek AI for analysis..." -LogFile $scanLogFile
            
            $aiPrompt = @"
You are an expert cybersecurity analyst. I'm providing you with the results of a security scan on a Windows system.
Please analyze this data and provide:
1. A security risk assessment (Low, Medium, High) with explanation
2. Identification of any suspicious processes, connections, or events
3. Specific, actionable recommendations to improve security
4. Any immediate threats that should be addressed

The scan data is provided below:

$aiAnalysisData
"@
            
            $aiResponse = Invoke-DeepSeekAI -Prompt $aiPrompt -SystemPrompt "You are an expert cybersecurity analyst analyzing Windows security scan results. Provide clear, concise, actionable insights." -Temperature 0.2 -MaxTokens 2000
            
            $global:ScanResults[$scanId].AIAnalysis.ScanAnalysis = $aiResponse
            Write-NexusLog "AI analysis completed" -LogFile $scanLogFile
            
            # Generate remediation recommendations
            $remediationPrompt = @"
Based on the security scan analysis below, generate PowerShell remediation scripts to address the identified issues. Each script should:
1. Be well-commented and safe to execute
2. Include error handling and logging
3. Get user confirmation before making changes
4. Be realistic and focus on addressing the specific issues identified
5. Use best security practices

Security Analysis:
$aiResponse
"@
            
            $remediationResponse = Invoke-DeepSeekAI -Prompt $remediationPrompt -SystemPrompt "You are a Windows security expert generating remediation PowerShell scripts. Focus on practical, specific fixes for the identified issues." -Temperature 0.2 -MaxTokens 3000
            
            $global:ScanResults[$scanId].AIAnalysis.RemediationScripts = $remediationResponse
            Write-NexusLog "AI remediation scripts generated" -LogFile $scanLogFile
        } catch {
            Write-NexusLog "Error performing AI analysis: $_" -Level "ERROR" -LogFile $scanLogFile
        }
    }
    
    # Complete the scan
    Update-ScanProgress -PercentComplete 100 -Status "Scan complete. Generating report..."
    
    # Record end time
    $global:ScanResults[$scanId].EndTime = Get-Date
    $scanDuration = $global:ScanResults[$scanId].EndTime - $global:ScanResults[$scanId].StartTime
    Write-NexusLog "Scan completed in $($scanDuration.TotalMinutes.ToString('0.00')) minutes" -LogFile $scanLogFile
    
    # Generate HTML report
    Generate-ScanReport -ScanId $scanId
    
    # Return scan ID
    return $scanId
}

# HTML Report Generation Function
function Generate-ScanReport {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScanId
    )
    
    if (-not $global:ScanResults.ContainsKey($ScanId)) {
        Write-NexusLog "Scan ID not found: $ScanId" -Level "ERROR"
        return
    }
    
    $scan = $global:ScanResults[$ScanId]
    $reportFile = $scan.ReportFile
    
    # Generate HTML report header
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Sentinel Security Report - $ScanId</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1, h2, h3, h4 {
            color: #0078d4;
        }
        .header {
            background-color: #0078d4;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .scan-info {
            background-color: #e6f3ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .section {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f9f9f9;
        }
        .risk-high {
            background-color: #ffebee;
            color: #c62828;
            padding: 2px 8px;
            border-radius: 3px;
        }
        .risk-medium {
            background-color: #fff8e1;
            color: #ff8f00;
            padding: 2px 8px;
            border-radius: 3px;
        }
        .risk-low {
            background-color: #e8f5e9;
            color: #2e7d32;
            padding: 2px 8px;
            border-radius: 3px;
        }
        .alert {
            background-color: #fff8e1;
            border-left: 4px solid #ff8f00;
            padding: 10px;
            margin-bottom: 15px;
        }
        .code-block {
            background-color: #f5f5f5;
            border-left: 4px solid #0078d4;
            padding: 15px;
            font-family: Consolas, monospace;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        .footer {
            text-align: center;
            color: #666;
            font-size: 14px;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Nexus Sentinel Security Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="scan-info">
        <h2>Scan Information</h2>
        <table>
            <tr>
                <td><strong>Scan ID:</strong></td>
                <td>$ScanId</td>
            </tr>
            <tr>
                <td><strong>Scan Depth:</strong></td>
                <td>$($scan.ScanDepth)</td>
            </tr>
            <tr>
                <td><strong>Start Time:</strong></td>
                <td>$($scan.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</td>
            </tr>
            <tr>
                <td><strong>End Time:</strong></td>
                <td>$($scan.EndTime.ToString('yyyy-MM-dd HH:mm:ss'))</td>
            </tr>
            <tr>
                <td><strong>Duration:</strong></td>
                <td>$(($scan.EndTime - $scan.StartTime).TotalMinutes.ToString('0.00')) minutes</td>
            </tr>
            <tr>
                <td><strong>Computer Name:</strong></td>
                <td>$($scan.Results.SystemInfo.CsName)</td>
            </tr>
            <tr>
                <td><strong>Operating System:</strong></td>
                <td>$($scan.Results.SystemInfo.OsName) ($($scan.Results.SystemInfo.OsVersion))</td>
            </tr>
        </table>
    </div>
"@
    
    # System Information Section
    $html += @"
    <div class="section">
        <h2>System Information</h2>
        <table>
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
"@

    $systemInfoObj = $scan.Results.SystemInfo
    $systemInfoProps = $systemInfoObj | Get-Member -MemberType Property | Select-Object -ExpandProperty Name
    
    foreach ($prop in $systemInfoProps) {
        $html += @"
            <tr>
                <td><strong>$prop</strong></td>
                <td>$($systemInfoObj.$prop)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
"@
    
    # Process Information
    $html += @"
    <div class="section">
        <h2>Running Processes</h2>
        <p>Top 20 processes by memory usage:</p>
        <table>
            <tr>
                <th>Name</th>
                <th>PID</th>
                <th>Memory (MB)</th>
                <th>CPU</th>
                <th>Start Time</th>
                <th>Company</th>
            </tr>
"@
    
    $topProcesses = $scan.Results.Processes | Sort-Object "Memory(MB)" -Descending | Select-Object -First 20
    
    foreach ($process in $topProcesses) {
        $html += @"
            <tr>
                <td>$($process.ProcessName)</td>
                <td>$($process.Id)</td>
                <td>$($process."Memory(MB)")</td>
                <td>$($process.CPU)</td>
                <td>$($process.StartTime)</td>
                <td>$($process.Company)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
"@
    
    # Network Connections
    $html += @"
    <div class="section">
        <h2>Network Connections</h2>
        <p>Active network connections (non-local):</p>
        <table>
            <tr>
                <th>Local Address</th>
                <th>Local Port</th>
                <th>Remote Address</th>
                <th>Remote Port</th>
                <th>State</th>
                <th>Process ID</th>
            </tr>
"@
    
    $externalConnections = $scan.Results.NetworkConnections | Where-Object { $_.RemoteAddress -notmatch "127.0.0.1|::1|0.0.0.0" } | Select-Object -First 30
    
    foreach ($conn in $externalConnections) {
        $html += @"
            <tr>
                <td>$($conn.LocalAddress)</td>
                <td>$($conn.LocalPort)</td>
                <td>$($conn.RemoteAddress)</td>
                <td>$($conn.RemotePort)</td>
                <td>$($conn.State)</td>
                <td>$($conn.OwningProcess)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
    </div>
"@
    
    # AI Analysis (if available)
    if ($scan.UseAI -and $scan.AIAnalysis.ScanAnalysis) {
        $html += @"
    <div class="section">
        <h2>AI Security Analysis</h2>
        <div class="code-block">
            $($scan.AIAnalysis.ScanAnalysis -replace "`n", "<br>")
        </div>
    </div>
"@
        
        if ($scan.AIAnalysis.RemediationScripts) {
            $html += @"
    <div class="section">
        <h2>AI-Generated Remediation Scripts</h2>
        <div class="alert">
            <strong>CAUTION:</strong> Review all remediation scripts carefully before executing them. Always backup your system before making security changes.
        </div>
        <div class="code-block">
            $($scan.AIAnalysis.RemediationScripts -replace "`n", "<br>")
        </div>
    </div>
"@
        }
    }
    
    # Footer
    $html += @"
    <div class="footer">
        <p>Generated by Nexus Sentinel v$($global:NexusConfig.Version) | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>This report is for informational purposes only and should be reviewed by a security professional.</p>
    </div>
</body>
</html>
"@
    
    # Save the HTML report
    $html | Out-File -FilePath $reportFile -Encoding utf8
    Write-NexusLog "HTML security report generated: $reportFile"
    
    return $reportFile
}

# Process monitoring function
function Start-ProcessMonitoring {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$UseAI,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = $global:NexusConfig.LogDir
    )
    
    $monitorId = "ProcessMonitor_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $monitorLogFile = Join-Path $OutputDirectory "$monitorId.log"
    
    Write-NexusLog "Starting process monitoring (ID: $monitorId)" -LogFile $monitorLogFile
    
    # Create new PowerShell window for monitoring
    $scriptBlock = {
        param($monitorId, $monitorLogFile, $apiKey, $deepSeekApi, $aiModel, $useAI)
        
        # Initialize
        $ErrorActionPreference = "Continue"
        Add-Content -Path $monitorLogFile -Value "[$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] Process monitoring started"
        
        # Function to log
        function Write-MonitorLog {
            param (
                [string]$Message,
                [string]$Level = "INFO"
            )
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logMessage = "[$timestamp] [$Level] $Message"
            Add-Content -Path $monitorLogFile -Value $logMessage
            Write-Host $logMessage
        }
        
        # Function to analyze process with AI
        function Analyze-ProcessWithAI {
            param (
                [string]$ProcessName,
                [int]$ProcessId,
                [string]$Path,
                [DateTime]$StartTime
            )
            
            if (-not $useAI -or [string]::IsNullOrWhiteSpace($apiKey)) {
                return "AI analysis disabled or no API key provided"
            }
            
            $processInfo = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue | 
                Select-Object Name, Id, Path, Company, Product, Description, 
                @{Name="CPU"; Expression={$_.CPU}}, 
                @{Name="Memory(MB)"; Expression={[Math]::Round($_.WorkingSet64 / 1MB, 2)}}
            
            $modules = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue | 
                ForEach-Object { $_.Modules } | 
                Select-Object -First 10 -Property FileName, ModuleName
            
            $netConnections = Get-NetTCPConnection -OwningProcess $ProcessId -ErrorAction SilentlyContinue | 
                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
            
            $prompt = @"
Analyze this newly launched Windows process for security risks:

Process Details:
- Name: $ProcessName
- PID: $ProcessId
- Path: $Path
- Started: $StartTime

Full Process Info:
$($processInfo | ConvertTo-Json -Depth 1)

Network Connections:
$($netConnections | ConvertTo-Json -Depth 1)

Top Modules:
$($modules | ConvertTo-Json -Depth 1)

Is this process suspicious? Why or why not? If suspicious, what actions should be taken?
Provide a brief analysis (100 words or less).
"@
            
            try {
                $messages = @(
                    @{ role = "system"; content = "You are a cybersecurity expert analyzing new processes. Provide brief, focused security assessments." },
                    @{ role = "user"; content = $prompt }
                )
                
                $requestBody = @{
                    model = $aiModel
                    messages = $messages
                    temperature = 0.2
                    max_tokens = 500
                } | ConvertTo-Json -Depth 3
                
                $response = Invoke-RestMethod -Uri $deepSeekApi -Method Post -Headers @{
                    "Authorization" = "Bearer $apiKey"
                    "Content-Type" = "application/json"
                } -Body $requestBody
                
                return $response.choices[0].message.content
            } catch {
                return "Error analyzing process: $_"
            }
        }
        
        # Set up process monitoring
        Write-MonitorLog "Setting up WMI event listener for new processes..."
        
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
        
        # Register permanent event consumer
        $processStartAction = {
            $process = $Event.SourceEventArgs.NewEvent.TargetInstance
            $processId = $process.ProcessId
            $processName = $process.Name
            $processPath = $process.ExecutablePath
            $processStartTime = [Management.ManagementDateTimeConverter]::ToDateTime($process.CreationDate)
            $processUser = $process.GetOwner().User
            
            $logMessage = "New process started - Name: $processName, PID: $processId, Path: $processPath, User: $processUser"
            Write-Host "ALERT: $logMessage" -ForegroundColor Yellow
            Write-MonitorLog $logMessage -Level "ALERT"
            
            # Do AI analysis if enabled
            if ($useAI -and -not [string]::IsNullOrWhiteSpace($apiKey)) {
                $analysis = Analyze-ProcessWithAI -ProcessName $processName -ProcessId $processId -Path $processPath -StartTime $processStartTime
                Write-MonitorLog "AI Analysis: $analysis" -Level "AI"
            }
        }
        
        # Start permanent event subscription
        Register-WmiEvent -Query $query -SourceIdentifier "ProcessMonitor" -Action $processStartAction
        
        # Display active process information
        Write-MonitorLog "Process monitoring active. Current processes:"
        
        Get-Process | Select-Object Name, Id, Path | Format-Table -AutoSize | Out-String | ForEach-Object {
            Write-MonitorLog $_
        }
        
        Write-Host "`n`n[INFO] Process monitoring active. Press Ctrl+C to stop.`n" -ForegroundColor Green
        
        try {
            # Keep the script running
            while ($true) {
                Start-Sleep -Seconds 1
            }
        } finally {
            # Clean up event subscription
            Unregister-Event -SourceIdentifier "ProcessMonitor" -ErrorAction SilentlyContinue
            Write-MonitorLog "Process monitoring stopped" -Level "INFO"
        }
    }
    
    # Launch the monitoring in a new window
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock.ToString()))
    
    $arguments = "-NoExit -ExecutionPolicy Bypass -EncodedCommand $encoded -Args '$monitorId', '$monitorLogFile', '$($global:NexusConfig.APIKey)', '$($global:NexusConfig.DeepSeekAPI)', '$($global:NexusConfig.AIModel)', '$(if ($UseAI) { $true } else { $false })'"
    
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -PassThru
    
    # Add to active monitors
    $global:ActiveMonitors += $monitorId
    $global:MonitorJobs[$monitorId] = @{
        Type = "Process"
        Process = $process
        StartTime = Get-Date
        LogFile = $monitorLogFile
        UseAI = $UseAI.IsPresent
    }
    
    Write-NexusLog "Process monitoring started in new window. Monitor ID: $monitorId"
    return $monitorId
}

# Network monitoring function
function Start-NetworkMonitoring {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$UseAI,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = $global:NexusConfig.LogDir
    )
    
    $monitorId = "NetworkMonitor_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $monitorLogFile = Join-Path $OutputDirectory "$monitorId.log"
    
    Write-NexusLog "Starting network monitoring (ID: $monitorId)" -LogFile $monitorLogFile
    
    # Create new PowerShell window for monitoring
    $scriptBlock = {
        param($monitorId, $monitorLogFile, $apiKey, $deepSeekApi, $aiModel, $useAI)
        
        # Initialize
        $ErrorActionPreference = "Continue"
        Add-Content -Path $monitorLogFile -Value "[$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] Network monitoring started"
        
        # Define known ports for reference
        $knownPorts = @{
            20 = "FTP Data"
            21 = "FTP Control"
            22 = "SSH"
            23 = "Telnet"
            25 = "SMTP"
            53 = "DNS"
            80 = "HTTP"
            110 = "POP3"
            143 = "IMAP"
            443 = "HTTPS"
            445 = "SMB"
            3389 = "RDP"
            5900 = "VNC"
        }
        
        # Function to log
        function Write-MonitorLog {
            param (
                [string]$Message,
                [string]$Level = "INFO"
            )
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logMessage = "[$timestamp] [$Level] $Message"
            Add-Content -Path $monitorLogFile -Value $logMessage
            Write-Host $logMessage
        }
        
        # Function to analyze connection with AI
        function Analyze-ConnectionWithAI {
            param (
                [string]$LocalAddress,
                [int]$LocalPort,
                [string]$RemoteAddress,
                [int]$RemotePort,
                [string]$State,
                [int]$OwningProcess
            )
            
            if (-not $useAI -or [string]::IsNullOrWhiteSpace($apiKey)) {
                return "AI analysis disabled or no API key provided"
            }
            
            $processInfo = Get-Process -Id $OwningProcess -ErrorAction SilentlyContinue | 
                Select-Object Name, Id, Path, Company, Product, Description
            
            $prompt = @"
Analyze this network connection for security risks:

Connection Details:
- Local: $LocalAddress`:$LocalPort
- Remote: $RemoteAddress`:$RemotePort
- State: $State
- Process ID: $OwningProcess

Process Info:
$($processInfo | ConvertTo-Json -Depth 1)

Is this connection suspicious? Why or why not? Is this a potential data exfiltration or C2 connection?
Provide a brief analysis (100 words or less).
"@
            
            try {
                $messages = @(
                    @{ role = "system"; content = "You are a cybersecurity expert analyzing network connections. Provide brief, focused security assessments." },
                    @{ role = "user"; content = $prompt }
                )
                
                $requestBody = @{
                    model = $aiModel
                    messages = $messages
                    temperature = 0.2
                    max_tokens = 500
                } | ConvertTo-Json -Depth 3
                
                $response = Invoke-RestMethod -Uri $deepSeekApi -Method Post -Headers @{
                    "Authorization" = "Bearer $apiKey"
                    "Content-Type" = "application/json"
                } -Body $requestBody
                
                return $response.choices[0].message.content
            } catch {
                return "Error analyzing connection: $_"
            }
        }
        
        # Function to resolve hostname from IP
        function Resolve-HostName {
            param ([string]$IPAddress)
            
            try {
                if ($IPAddress -eq "127.0.0.1" -or $IPAddress -eq "::1" -or $IPAddress -eq "0.0.0.0" -or $IPAddress -eq "::") {
                    return "localhost"
                }
                
                $hostEntry = [System.Net.Dns]::GetHostEntry($IPAddress)
                return $hostEntry.HostName
            } catch {
                return $IPAddress
            }
        }
        
        # Function to get port description
        function Get-PortDescription {
            param ([int]$Port)
            
            if ($knownPorts.ContainsKey($Port)) {
                return $knownPorts[$Port]
            } else {
                return "Unknown"
            }
        }
        
        # Store previous connections for comparison
        $previousConnections = @{}
        
        # Display current network status
        $currentConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        Write-MonitorLog "Network monitoring active. Current established connections:"
        
        foreach ($conn in $currentConnections) {
            $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
            if (!$processName) { $processName = "Unknown" }
            
            $key = "{0}:{1}-{2}:{3}" -f $conn.LocalAddress, $conn.LocalPort, $conn.RemoteAddress, $conn.RemotePort
            $previousConnections[$key] = $true
            
            $portDesc = Get-PortDescription -Port $conn.RemotePort
            $remoteHost = Resolve-HostName -IPAddress $conn.RemoteAddress
            
            $logMessage = "$processName (PID: $($conn.OwningProcess)) - $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) ($portDesc) [$remoteHost]"
            Write-MonitorLog $logMessage
        }
        
        Write-Host "`n`n[INFO] Network monitoring active. Press Ctrl+C to stop.`n" -ForegroundColor Green
        
        try {
            # Monitoring loop
            while ($true) {
                $currentConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
                $currentConnectionsMap = @{}
                
                foreach ($conn in $currentConnections) {
                    $key = "{0}:{1}-{2}:{3}" -f $conn.LocalAddress, $conn.LocalPort, $conn.RemoteAddress, $conn.RemotePort
                    $currentConnectionsMap[$key] = $conn
                    
                    # If this is a new connection
                    if (-not $previousConnections.ContainsKey($key)) {
                        $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
                        if (!$processName) { $processName = "Unknown" }
                        
                        $portDesc = Get-PortDescription -Port $conn.RemotePort
                        $remoteHost = Resolve-HostName -IPAddress $conn.RemoteAddress
                        
                        $logMessage = "NEW CONNECTION: $processName (PID: $($conn.OwningProcess)) - $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) ($portDesc) [$remoteHost]"
                        Write-Host $logMessage -ForegroundColor Yellow
                        Write-MonitorLog $logMessage -Level "ALERT"
                        
                        # Do AI analysis if enabled
                        if ($useAI -and -not [string]::IsNullOrWhiteSpace($apiKey)) {
                            $analysis = Analyze-ConnectionWithAI -LocalAddress $conn.LocalAddress -LocalPort $conn.LocalPort `
                                -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort `
                                -State $conn.State -OwningProcess $conn.OwningProcess
                            
                            Write-MonitorLog "AI Analysis: $analysis" -Level "AI"
                        }
                    }
                }
                
                # Check for closed connections
                foreach ($key in $previousConnections.Keys) {
                    if (-not $currentConnectionsMap.ContainsKey($key)) {
                        $logMessage = "CLOSED CONNECTION: $key"
                        Write-Host $logMessage -ForegroundColor Gray
                        Write-MonitorLog $logMessage
                    }
                }
                
                # Update previous connections
                $previousConnections = $currentConnectionsMap
                
                # Wait before next check
                Start-Sleep -Seconds 2
            }
        } finally {
            Write-MonitorLog "Network monitoring stopped" -Level "INFO"
        }
    }
    
    # Launch the monitoring in a new window
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock.ToString()))
    
    $arguments = "-NoExit -ExecutionPolicy Bypass -EncodedCommand $encoded -Args '$monitorId', '$monitorLogFile', '$($global:NexusConfig.APIKey)', '$($global:NexusConfig.DeepSeekAPI)', '$($global:NexusConfig.AIModel)', '$(if ($UseAI) { $true } else { $false })'"
    
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -PassThru
    
    # Add to active monitors
    $global:ActiveMonitors += $monitorId
    $global:MonitorJobs[$monitorId] = @{
        Type = "Network"
        Process = $process
        StartTime = Get-Date
        LogFile = $monitorLogFile
        UseAI = $UseAI.IsPresent
    }
    
    Write-NexusLog "Network monitoring started in new window. Monitor ID: $monitorId"
    return $monitorId
}

# File system monitoring function
function Start-FileSystemMonitoring {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Path = "C:\",
        
        [Parameter(Mandatory=$false)]
        [switch]$UseAI,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = $global:NexusConfig.LogDir
    )
    
    $monitorId = "FileMonitor_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $monitorLogFile = Join-Path $OutputDirectory "$monitorId.log"
    
    Write-NexusLog "Starting file system monitoring on $Path (ID: $monitorId)" -LogFile $monitorLogFile
    
    # Create new PowerShell window for monitoring
    $scriptBlock = {
        param($monitorId, $monitorLogFile, $pathToMonitor, $apiKey, $deepSeekApi, $aiModel, $useAI)
        
        # Initialize
        $ErrorActionPreference = "Continue"
        Add-Content -Path $monitorLogFile -Value "[$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] File system monitoring started for: $pathToMonitor"
        
        # Function to log
        function Write-MonitorLog {
            param (
                [string]$Message,
                [string]$Level = "INFO"
            )
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logMessage = "[$timestamp] [$Level] $Message"
            Add-Content -Path $monitorLogFile -Value $logMessage
            Write-Host $logMessage
        }
        
        # Function to analyze file with AI
        function Analyze-FileWithAI {
            param (
                [string]$FilePath,
                [string]$ChangeType
            )
            
            if (-not $useAI -or [string]::IsNullOrWhiteSpace($apiKey)) {
                return "AI analysis disabled or no API key provided"
            }
            
            # Get basic file information
            try {
                $fileInfo = Get-Item -Path $FilePath -ErrorAction Stop
                $fileExtension = $fileInfo.Extension
                $fileSize = $fileInfo.Length
                $fileSizeMB = [Math]::Round($fileSize / 1MB, 2)
                $fileCreationTime = $fileInfo.CreationTime
                $fileLastWriteTime = $fileInfo.LastWriteTime
                $fileOwner = (Get-Acl -Path $FilePath -ErrorAction SilentlyContinue).Owner
                
                # Get file signature if available
                $signature = "N/A"
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
                    if ($sig.Status -eq "Valid") {
                        $signature = "Signed: $($sig.SignerCertificate.Subject)"
                    } else {
                        $signature = "Not signed or invalid signature"
                    }
                } catch {
                    $signature = "Unable to verify signature"
                }
                
                # Get hash
                $fileHash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if (!$fileHash) { $fileHash = "N/A" }
                
                $prompt = @"
Analyze this file system event for security risks:

File Event Details:
- Path: $FilePath
- Event Type: $ChangeType
- File Extension: $fileExtension
- Size: $fileSizeMB MB
- Created: $fileCreationTime
- Modified: $fileLastWriteTime
- Owner: $fileOwner
- Signature: $signature
- SHA256: $fileHash

Could this file event represent a security threat? Why or why not?
Is this potentially malware, ransomware, or data exfiltration activity?
Provide a brief analysis (100 words or less).
"@
                
                try {
                    $messages = @(
                        @{ role = "system"; content = "You are a cybersecurity expert analyzing file system events. Provide brief, focused security assessments." },
                        @{ role = "user"; content = $prompt }
                    )
                    
                    $requestBody = @{
                        model = $aiModel
                        messages = $messages
                        temperature = 0.2
                        max_tokens = 500
                    } | ConvertTo-Json -Depth 3
                    
                    $response = Invoke-RestMethod -Uri $deepSeekApi -Method Post -Headers @{
                        "Authorization" = "Bearer $apiKey"
                        "Content-Type" = "application/json"
                    } -Body $requestBody
                    
                    return $response.choices[0].message.content
                } catch {
                    return "Error analyzing file: $_"
                }
            } catch {
                return "Error getting file information: $_"
            }
        }
        
        # Set up FileSystemWatcher
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $pathToMonitor
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        
        # Define event handlers
        $onCreated = Register-ObjectEvent -InputObject $watcher -EventName Created -Action {
            $path = $Event.SourceEventArgs.FullPath
            $name = $Event.SourceEventArgs.Name
            $changeType = $Event.SourceEventArgs.ChangeType
            
            $logMessage = "FILE CREATED: $path"
            Write-Host $logMessage -ForegroundColor Green
            Write-MonitorLog $logMessage -Level "ALERT"
            
            # Do AI analysis if enabled
            if ($useAI -and -not [string]::IsNullOrWhiteSpace($apiKey)) {
                $analysis = Analyze-FileWithAI -FilePath $path -ChangeType $changeType
                Write-MonitorLog "AI Analysis: $analysis" -Level "AI"
            }
        }
        
        $onChanged = Register-ObjectEvent -InputObject $watcher -EventName Changed -Action {
            $path = $Event.SourceEventArgs.FullPath
            $name = $Event.SourceEventArgs.Name
            $changeType = $Event.SourceEventArgs.ChangeType
            
            $logMessage = "FILE CHANGED: $path"
            Write-Host $logMessage -ForegroundColor Yellow
            Write-MonitorLog $logMessage
        }
        
        $onDeleted = Register-ObjectEvent -InputObject $watcher -EventName Deleted -Action {
            $path = $Event.SourceEventArgs.FullPath
            $name = $Event.SourceEventArgs.Name
            $changeType = $Event.SourceEventArgs.ChangeType
            
            $logMessage = "FILE DELETED: $path"
            Write-Host $logMessage -ForegroundColor Red
            Write-MonitorLog $logMessage -Level "ALERT"
        }
        
        $onRenamed = Register-ObjectEvent -InputObject $watcher -EventName Renamed -Action {
            $oldPath = $Event.SourceEventArgs.OldFullPath
            $newPath = $Event.SourceEventArgs.FullPath
            $changeType = $Event.SourceEventArgs.ChangeType
            
            $logMessage = "FILE RENAMED: $oldPath -> $newPath"
            Write-Host $logMessage -ForegroundColor Cyan
            Write-MonitorLog $logMessage
            
            # Do AI analysis if enabled and it's a high-risk extension change
            $oldExt = [System.IO.Path]::GetExtension($oldPath)
            $newExt = [System.IO.Path]::GetExtension($newPath)
            
            if ($oldExt -ne $newExt -and $useAI -and -not [string]::IsNullOrWhiteSpace($apiKey)) {
                $analysis = Analyze-FileWithAI -FilePath $newPath -ChangeType "Renamed (Extension Change: $oldExt -> $newExt)"
                Write-MonitorLog "AI Analysis: $analysis" -Level "AI"
            }
        }
        
        Write-Host "`n`n[INFO] File system monitoring active for $pathToMonitor. Press Ctrl+C to stop.`n" -ForegroundColor Green
        
        try {
            # Keep the script running
            while ($true) {
                Start-Sleep -Seconds 1
            }
        } finally {
            # Clean up event subscriptions
            Unregister-Event -SourceIdentifier $onCreated.Name -ErrorAction SilentlyContinue
            Unregister-Event -SourceIdentifier $onChanged.Name -ErrorAction SilentlyContinue
            Unregister-Event -SourceIdentifier $onDeleted.Name -ErrorAction SilentlyContinue
            Unregister-Event -SourceIdentifier $onRenamed.Name -ErrorAction SilentlyContinue
            Write-MonitorLog "File system monitoring stopped" -Level "INFO"
        }
    }
    
    # Launch the monitoring in a new window
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock.ToString()))
    
    $arguments = "-NoExit -ExecutionPolicy Bypass -EncodedCommand $encoded -Args '$monitorId', '$monitorLogFile', '$Path', '$($global:NexusConfig.APIKey)', '$($global:NexusConfig.DeepSeekAPI)', '$($global:NexusConfig.AIModel)', '$(if ($UseAI) { $true } else { $false })'"
    
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -PassThru
    
    # Add to active monitors
    $global:ActiveMonitors += $monitorId
    $global:MonitorJobs[$monitorId] = @{
        Type = "FileSystem"
        Path = $Path
        Process = $process
        StartTime = Get-Date
        LogFile = $monitorLogFile
        UseAI = $UseAI.IsPresent
    }
    
    Write-NexusLog "File system monitoring started in new window. Monitor ID: $monitorId"
    return $monitorId
}

# Threat hunting and remediation function
function Invoke-ThreatHunting {
    param (
        [Parameter(Mandatory=$false)]
        [ValidateSet("Quick", "Standard", "Deep")]
        [string]$HuntDepth = "Standard",
        
        [Parameter(Mandatory=$false)]
        [switch]$AutoRemediate,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseAI
    )
    
    $huntId = "ThreatHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $huntLogFile = Join-Path $global:NexusConfig.LogDir "$huntId.log"
    $remediationDir = Join-Path $global:NexusConfig.RemediationDir $huntId
    
    # Create remediation directory
    if (!(Test-Path $remediationDir)) {
        New-Item -ItemType Directory -Path $remediationDir -Force | Out-Null
    }
    
    Write-NexusLog "Starting $HuntDepth threat hunting (ID: $huntId)" -LogFile $huntLogFile
    
    # Create progress bar function for this hunt
    function Update-HuntProgress {
        param (
            [int]$PercentComplete,
            [string]$Status
        )
        
        Write-Progress -Activity "Threat Hunting" -Status $Status -PercentComplete $PercentComplete
        Write-NexusLog "[$PercentComplete%] $Status" -LogFile $huntLogFile -NoConsole
    }
    
    # Initialize results
    $huntResults = @{
        StartTime = Get-Date
        EndTime = $null
        HuntDepth = $HuntDepth
        SuspiciousItems = @{
            Processes = @()
            Services = @()
            NetworkConnections = @()
            Files = @()
            Registry = @()
            ScheduledTasks = @()
            WmiObjects = @()
        }
        RemediationDir = $remediationDir
        RemediationScripts = @()
        Remediated = @()
        AIAnalysis = $null
    }
    
    # 1. Hunt for suspicious processes
    Update-HuntProgress -PercentComplete 5 -Status "Hunting for suspicious processes..."
    
    # Define suspicious process characteristics
    $suspiciousProcessPatterns = @(
        @{Name="powershell.exe"; CommandLinePattern="-[eE][nN][cC]|hidden|bypass|downloadstring|webclient|iex|invoke-expression"; Reason="PowerShell with suspicious parameters"},
        @{Name="cmd.exe"; CommandLinePattern="/c\s+.*http|echo\s+.*\|\s*cmd|>.*\.exe"; Reason="Command shell with suspicious parameters"},
        @{Name="regsvr32.exe"; CommandLinePattern="/s.*\.dll|/i:http"; Reason="Regsvr32 with suspicious parameters"},
        @{Name="rundll32.exe"; CommandLinePattern="javascript:|shell32.dll,.*Control_RunDLL"; Reason="Rundll32 with suspicious parameters"},
        @{Name="svchost.exe"; ParentProcessNotName="services.exe"; Reason="Svchost running outside services.exe parent"},
        @{Name="lsass.exe"; ParentProcessNotName="wininit.exe"; Reason="LSASS running outside wininit.exe parent"},
        @{Name=""; PathPattern="\\temp\\|\\tmp\\|%temp%|AppData\\Local\\Temp"; Reason="Process running from temp directory"},
        @{Name=""; PathPattern="^[a-zA-Z0-9]{8,}\.exe$"; Reason="Process with random name pattern"}
    )
    
    $processes = Get-WmiObject Win32_Process | ForEach-Object {
        try {
            $parent = $null
            if ($_.ParentProcessId) {
                $parent = Get-WmiObject Win32_Process -Filter "ProcessId = '$($_.ParentProcessId)'"
            }
            
            $owner = $_.GetOwner()
            $ownerUser = if ($owner.User) { $owner.Domain + "\" + $owner.User } else { "SYSTEM" }
            
            [PSCustomObject]@{
                Name = $_.Name
                ProcessId = $_.ProcessId
                ParentProcessId = $_.ParentProcessId
                ParentProcessName = if ($parent) { $parent.Name } else { "None" }
                CommandLine = $_.CommandLine
                ExecutablePath = $_.ExecutablePath
                CreationDate = $_.CreationDate
                Owner = $ownerUser
            }
        } catch {
            Write-NexusLog "Error processing process $($_.ProcessId): $_" -Level "ERROR" -LogFile $huntLogFile
            # Return a minimal object so collection continues
            [PSCustomObject]@{
                Name = $_.Name
                ProcessId = $_.ProcessId
                ParentProcessId = $_.ParentProcessId
                ParentProcessName = "Error"
                CommandLine = "Error retrieving command line"
                ExecutablePath = "Error retrieving path"
                CreationDate = $_.CreationDate
                Owner = "Error"
            }
        }
    }
    
    # Find suspicious processes
    foreach ($process in $processes) {
        $isSuspicious = $false
        $suspiciousReason = ""
        
        foreach ($pattern in $suspiciousProcessPatterns) {
            # If a name pattern is specified and matches
            if ($pattern.Name -and $process.Name -like $pattern.Name) {
                # Check command line pattern if specified
                if ($pattern.CommandLinePattern -and $process.CommandLine -match $pattern.CommandLinePattern) {
                    $isSuspicious = $true
                    $suspiciousReason = $pattern.Reason
                    break
                }
                
                # Check parent process condition if specified
                if ($pattern.ParentProcessNotName -and $process.ParentProcessName -notlike $pattern.ParentProcessNotName) {
                    $isSuspicious = $true
                    $suspiciousReason = $pattern.Reason
                    break
                }
            }
            
            # Check path pattern if specified
            if ($pattern.PathPattern -and $process.ExecutablePath -match $pattern.PathPattern) {
                $isSuspicious = $true
                $suspiciousReason = $pattern.Reason
                break
            }
        }
        
        # Check for processes with network connections but shouldn't have them
        if (-not $isSuspicious) {
            $nonNetworkApps = @("calc.exe", "notepad.exe", "mspaint.exe", "wordpad.exe")
            if ($nonNetworkApps -contains $process.Name) {
                $hasNetworkConnection = Get-NetTCPConnection -OwningProcess $process.ProcessId -ErrorAction SilentlyContinue | 
                    Where-Object { $_.RemoteAddress -notmatch "127.0.0.1|::1|0.0.0.0" }
                
                if ($hasNetworkConnection) {
                    $isSuspicious = $true
                    $suspiciousReason = "Unexpected network connection from non-networking process"
                }
            }
        }
        
        # Check creation time if it's suspiciously recent (last 30 minutes)
        if (-not $isSuspicious -and $process.CreationDate) {
            $creationTime = [Management.ManagementDateTimeConverter]::ToDateTime($process.CreationDate)
            if ((Get-Date) - $creationTime -lt [TimeSpan]::FromMinutes(30)) {
                # Only flag system processes or those in system directories that were recently created
                if ($process.ExecutablePath -like "C:\Windows\*" -or $process.ExecutablePath -like "C:\Program Files\*") {
                    $isSuspicious = $true
                    $suspiciousReason = "Recently created system process (last 30 minutes)"
                }
            }
        }
        
        # Add to results if suspicious
        if ($isSuspicious) {
            $huntResults.SuspiciousItems.Processes += [PSCustomObject]@{
                Name = $process.Name
                ProcessId = $process.ProcessId
                Path = $process.ExecutablePath
                CommandLine = $process.CommandLine
                Parent = "$($process.ParentProcessName) (PID: $($process.ParentProcessId))"
                Owner = $process.Owner
                Reason = $suspiciousReason
            }
            
            Write-NexusLog "Found suspicious process: $($process.Name) (PID: $($process.ProcessId)) - $suspiciousReason" -LogFile $huntLogFile -Level "ALERT"
        }
    }
    
    Write-NexusLog "Found $($huntResults.SuspiciousItems.Processes.Count) suspicious processes" -LogFile $huntLogFile
    
    # 2. Hunt for suspicious services
    Update-HuntProgress -PercentComplete 15 -Status "Hunting for suspicious services..."
    
    # Define suspicious service characteristics
    $suspiciousServicePatterns = @(
        @{PathPattern="\\temp\\|\\tmp\\|%temp%|AppData\\Local\\Temp"; Reason="Service running from temp directory"},
        @{PathPattern=".*(powershell|cmd).*(-enc|-w hidden|iex|downloadstring)"; Reason="Service using obfuscated PowerShell/CMD"},
        @{DisplayNamePattern="^[a-zA-Z0-9]{8,}$"; Reason="Service with random name pattern"},
        @{State="Running"; StartMode="Auto"; PathPattern="^[a-zA-Z0-9]{8,}\.exe$"; Reason="Service with random executable name"}
    )
    
    $services = Get-WmiObject Win32_Service | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            State = $_.State
            StartMode = $_.StartMode
            PathName = $_.PathName
            StartName = $_.StartName
            Description = $_.Description
        }
    }
    
    # Find suspicious services
    foreach ($service in $services) {
        $isSuspicious = $false
        $suspiciousReason = ""
        
        foreach ($pattern in $suspiciousServicePatterns) {
            # Check path pattern if specified
            if ($pattern.PathPattern -and $service.PathName -match $pattern.PathPattern) {
                $isSuspicious = $true
                $suspiciousReason = $pattern.Reason
                break
            }
            
            # Check display name pattern if specified
            if ($pattern.DisplayNamePattern -and $service.DisplayName -match $pattern.DisplayNamePattern) {
                $isSuspicious = $true
                $suspiciousReason = $pattern.Reason
                break
            }
            
            # Check state and start mode if specified
            if ($pattern.State -and $pattern.StartMode -and 
                $service.State -eq $pattern.State -and $service.StartMode -eq $pattern.StartMode) {
                # Also check path pattern if specified
                if ($pattern.PathPattern -and $service.PathName -match $pattern.PathPattern) {
                    $isSuspicious = $true
                    $suspiciousReason = $pattern.Reason
                    break
                }
            }
        }
        
        # Check for services with blank descriptions (legitimate services typically have descriptions)
        if (-not $isSuspicious -and [string]::IsNullOrWhiteSpace($service.Description)) {
            # Only if it's not a known service with empty description
            $knownEmptyDescServices = @("Apple Mobile Device Service", "VMware Tools")
            $isKnownEmpty = $false
            
            foreach ($knownService in $knownEmptyDescServices) {
                if ($service.DisplayName -like "*$knownService*") {
                    $isKnownEmpty = $true
                    break
                }
            }
            
            if (-not $isKnownEmpty) {
                $isSuspicious = $true
                $suspiciousReason = "Service with blank description"
            }
        }
        
        # Add to results if suspicious
        if ($isSuspicious) {
            $huntResults.SuspiciousItems.Services += [PSCustomObject]@{
                Name = $service.Name
                DisplayName = $service.DisplayName
                State = $service.State
                StartMode = $service.StartMode
                Path = $service.PathName
                Account = $service.StartName
                Description = $service.Description
                Reason = $suspiciousReason
            }
            
            Write-NexusLog "Found suspicious service: $($service.Name) ($($service.DisplayName)) - $suspiciousReason" -LogFile $huntLogFile -Level "ALERT"
        }
    }
    
    Write-NexusLog "Found $($huntResults.SuspiciousItems.Services.Count) suspicious services" -LogFile $huntLogFile
    
    # 3. Hunt for suspicious network connections
    Update-HuntProgress -PercentComplete 30 -Status "Hunting for suspicious network connections..."
    
    # Define suspicious network connection characteristics
    $suspiciousPortsOutbound = @(4444, 8080, 8443, 1337, 31337, 666, 6666)
    $suspiciousPortsInbound = @(22, 23, 3389, 5900)
    
    $networkConnections = Get-NetTCPConnection | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
            OwningProcess = $_.OwningProcess
            ProcessName = if ($process) { $process.Name } else { "Unknown" }
        }
    }
    
    # Find suspicious network connections
    foreach ($conn in $networkConnections) {
        $isSuspicious = $false
        $suspiciousReason = ""
        
        # Check for connections to suspicious outbound ports
        if ($conn.State -eq "Established" -and $suspiciousPortsOutbound -contains $conn.RemotePort) {
            $isSuspicious = $true
            $suspiciousReason = "Connection to known suspicious port $($conn.RemotePort)"
        }
        
        # Check for listening on suspicious inbound ports
        if (-not $isSuspicious -and $conn.State -eq "Listen" -and $suspiciousPortsInbound -contains $conn.LocalPort) {
            # Only if it's not a known service
            $isKnownService = $false
            $services = Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq $conn.OwningProcess }
            
            if ($services) {
                $isKnownService = $true
            }
            
            if (-not $isKnownService) {
                $isSuspicious = $true
                $suspiciousReason = "Listening on sensitive port $($conn.LocalPort) without associated service"
            }
        }
        
        # Check for connections to suspicious domains/IPs (example)
        if (-not $isSuspicious -and $conn.RemoteAddress -match "185\.((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)") {
            $isSuspicious = $true
            $suspiciousReason = "Connection to suspicious IP range (185.x.x.x)"
        }
        
        # Check for processes that shouldn't have network connections
        if (-not $isSuspicious) {
            $nonNetworkApps = @("calc.exe", "notepad.exe", "mspaint.exe", "wordpad.exe")
            if ($nonNetworkApps -contains $conn.ProcessName) {
                $isSuspicious = $true
                $suspiciousReason = "Unexpected network connection from non-networking process"
            }
        }
        
        # Add to results if suspicious
        if ($isSuspicious) {
            $huntResults.SuspiciousItems.NetworkConnections += [PSCustomObject]@{
                LocalEndpoint = "$($conn.LocalAddress):$($conn.LocalPort)"
                RemoteEndpoint = "$($conn.RemoteAddress):$($conn.RemotePort)"
                State = $conn.State
                Process = "$($conn.ProcessName) (PID: $($conn.OwningProcess))"
                Reason = $suspiciousReason
            }
            
            Write-NexusLog "Found suspicious network connection: $($conn.ProcessName) (PID: $($conn.OwningProcess)) - $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) - $suspiciousReason" -LogFile $huntLogFile -Level "ALERT"
        }
    }
    
    Write-NexusLog "Found $($huntResults.SuspiciousItems.NetworkConnections.Count) suspicious network connections" -LogFile $huntLogFile
    
    # 4. Hunt for suspicious scheduled tasks
    Update-HuntProgress -PercentComplete 45 -Status "Hunting for suspicious scheduled tasks..."
    
    try {
        $scheduledTasks = Get-ScheduledTask | ForEach-Object {
            $taskInfo = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            $taskActions = $_.Actions
            
            [PSCustomObject]@{
                TaskName = $_.TaskName
                TaskPath = $_.TaskPath
                State = $_.State
                Author = $_.Author
                Description = $_.Description
                LastRunTime = $taskInfo.LastRunTime
                NextRunTime = $taskInfo.NextRunTime
                LastTaskResult = $taskInfo.LastTaskResult
                Actions = $taskActions
            }
        }
        
        # Define suspicious scheduled task characteristics
        $suspiciousTaskPatterns = @(
            @{ActionPattern="powershell.*-[eE][nN][cC]|powershell.*-w\s+hidden|powershell.*downloadstring"; Reason="PowerShell with suspicious parameters"},
            @{ActionPattern="cmd.*\/c\s+.*http|cmd.*>\s*.*\.exe"; Reason="Command shell with suspicious parameters"},
            @{ActionPattern=".*regsvr32.*\/s|.*regsvr32.*\/i:http"; Reason="Regsvr32 with suspicious parameters"},
            @{ActionPattern=".*\\temp\\|.*\\tmp\\|.*%temp%"; Reason="Task running from temp directory"},
            @{ActionPattern=".*msupdate|.*windowsupdate"; TaskNamePattern="^[a-zA-Z0-9]{8,}$"; Reason="Suspicious update task with random name"}
        )
        
        # Find suspicious scheduled tasks
        foreach ($task in $scheduledTasks) {
            $isSuspicious = $false
            $suspiciousReason = ""
            
            foreach ($pattern in $suspiciousTaskPatterns) {
                # Check action pattern if specified
                if ($pattern.ActionPattern) {
                    foreach ($action in $task.Actions) {
                        $actionString = "$($action.Execute) $($action.Arguments)"
                        if ($actionString -match $pattern.ActionPattern) {
                            $isSuspicious = $true
                            $suspiciousReason = $pattern.Reason
                            break
                        }
                    }
                }
                
                # Check task name pattern if specified
                if (-not $isSuspicious -and $pattern.TaskNamePattern -and $task.TaskName -match $pattern.TaskNamePattern) {
                    $isSuspicious = $true
                    $suspiciousReason = $pattern.Reason
                    break
                }
            }
            
            # Check for tasks with blank description but not in Microsoft paths
            if (-not $isSuspicious -and [string]::IsNullOrWhiteSpace($task.Description) -and 
                -not ($task.TaskPath -like "\Microsoft\*") -and $task.State -eq "Ready") {
                $isSuspicious = $true
                $suspiciousReason = "Non-Microsoft task with blank description"
            }
            
            # Add to results if suspicious
            if ($isSuspicious) {
                $actionDetails = @()
                foreach ($action in $task.Actions) {
                    $actionDetails += "$($action.Execute) $($action.Arguments)"
                }
                
                $huntResults.SuspiciousItems.ScheduledTasks += [PSCustomObject]@{
                    Name = $task.TaskName
                    Path = $task.TaskPath
                    State = $task.State
                    Actions = $actionDetails -join "; "
                    LastRun = $task.LastRunTime
                    NextRun = $task.NextRunTime
                    Author = $task.Author
                    Reason = $suspiciousReason
                }
                
                Write-NexusLog "Found suspicious scheduled task: $($task.TaskPath)$($task.TaskName) - $suspiciousReason" -LogFile $huntLogFile -Level "ALERT"
            }
        }
        
        Write-NexusLog "Found $($huntResults.SuspiciousItems.ScheduledTasks.Count) suspicious scheduled tasks" -LogFile $huntLogFile
    } catch {
        Write-NexusLog "Error hunting for suspicious scheduled tasks: $_" -Level "ERROR" -LogFile $huntLogFile
    }
    
    # 5. Hunt for suspicious WMI persistence
    if ($HuntDepth -eq "Standard" -or $HuntDepth -eq "Deep") {
        Update-HuntProgress -PercentComplete 60 -Status "Hunting for WMI persistence..."
        
        try {
            $wmiFilters = Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction Stop
            $wmiConsumers = Get-WmiObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction Stop
            $wmiBindings = Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding -ErrorAction Stop
            
            # Check for suspicious WMI event consumers
            foreach ($consumer in $wmiConsumers) {
                $isSuspicious = $false
                $suspiciousReason = ""
                
                # Check for CommandLineEventConsumer with suspicious commands
                if ($consumer.__CLASS -eq "CommandLineEventConsumer") {
                    if ($consumer.CommandLineTemplate -match "powershell|cmd|regsvr32|rundll32|wscript|cscript|mshta") {
                        $isSuspicious = $true
                        $suspiciousReason = "WMI CommandLineEventConsumer using suspicious command"
                    }
                }
                
                # Check for ActiveScriptEventConsumer with suspicious script
                if ($consumer.__CLASS -eq "ActiveScriptEventConsumer") {
                    if ($consumer.ScriptText -match "ActiveXObject|WScript.Shell|Shell.Application|CreateObject|RegWrite|powershell|downloadstring") {
                        $isSuspicious = $true
                        $suspiciousReason = "WMI ActiveScriptEventConsumer using suspicious script"
                    }
                }
                
                # Add to results if suspicious
                if ($isSuspicious) {
                    $huntResults.SuspiciousItems.WmiObjects += [PSCustomObject]@{
                        Type = "EventConsumer"
                        Name = $consumer.Name
                        Class = $consumer.__CLASS
                        Details = if ($consumer.__CLASS -eq "CommandLineEventConsumer") { $consumer.CommandLineTemplate } else { $consumer.ScriptText }
                        Reason = $suspiciousReason
                    }
                    
                    Write-NexusLog "Found suspicious WMI event consumer: $($consumer.Name) - $suspiciousReason" -LogFile $huntLogFile -Level "ALERT"
                }
            }
            
            # Check for suspicious event filters
            foreach ($filter in $wmiFilters) {
                $isSuspicious = $false
                $suspiciousReason = ""
                
                # Check for filters with suspicious queries
                if ($filter.Query -match "Win32_ProcessStartTrace|__InstanceCreationEvent|LogonUser|RegistryValueChange") {
                    # Look for corresponding bindings
                    $relatedBindings = $wmiBindings | Where-Object { $_.Filter -like "*$($filter.__RELPATH)*" }
                    
                    if ($relatedBindings) {
                        $isSuspicious = $true
                        $suspiciousReason = "WMI EventFilter monitoring sensitive system events"
                    }
                }
                
                # Add to results if suspicious
                if ($isSuspicious) {
                    $huntResults.SuspiciousItems.WmiObjects += [PSCustomObject]@{
                        Type = "EventFilter"
                        Name = $filter.Name
                        Query = $filter.Query
                        Reason = $suspiciousReason
                    }
                    
                    Write-NexusLog "Found suspicious WMI event filter: $($filter.Name) - $suspiciousReason" -LogFile $huntLogFile -Level "ALERT"
                }
            }
            
            Write-NexusLog "Found $($huntResults.SuspiciousItems.WmiObjects.Count) suspicious WMI objects" -LogFile $huntLogFile
        } catch {
            Write-NexusLog "Error hunting for WMI persistence: $_" -Level "ERROR" -LogFile $huntLogFile
        }
    }
    
    # 6. Deep file system hunt (only in Deep mode)
    if ($HuntDepth -eq "Deep") {
        Update-HuntProgress -PercentComplete 75 -Status "Performing deep file system hunt (this may take a while)..."
        
        # Define suspicious file patterns
        $suspiciousFilePatterns = @(
            @{PathPattern="C:\\Windows\\Temp\\.*\.(exe|dll|ps1|vbs|js)$"; Reason="Executable in Windows temp directory"},
            @{PathPattern="C:\\Windows\\.*\\runonce.*\.(exe|dll)$"; Reason="Suspicious runonce executable"},
            @{PathPattern="C:\\ProgramData\\.*\.(ps1|vbs|js|hta)$"; Reason="Script file in ProgramData directory"},
            @{PathPattern="C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.*\.(exe|vbs|js|ps1)$"; Reason="Startup folder executable"},
            @{PathPattern="C:\\Windows\\System32\\drivers\\etc\\hosts$"; FileChangedRecently=$true; Reason="Recently modified hosts file"}
        )
        
        # Get recent files
        $recentFiles = @()
        
        # Check Windows directory
        Write-NexusLog "Scanning Windows directory for suspicious files..." -LogFile $huntLogFile
        $recentFiles += Get-ChildItem -Path "C:\Windows" -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Extension -match "\.(exe|dll|ps1|vbs|js|hta)$" }
        
        # Check ProgramData directory
        Write-NexusLog "Scanning ProgramData directory for suspicious files..." -LogFile $huntLogFile
        $recentFiles += Get-ChildItem -Path "C:\ProgramData" -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.Extension -match "\.(exe|dll|ps1|vbs|js|hta)$" }
        
        # Check startup folders
        Write-NexusLog "Scanning startup folders for suspicious files..." -LogFile $huntLogFile
        $startupFolders = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        foreach ($folder in $startupFolders) {
            $recentFiles += Get-ChildItem -Path $folder -Force -ErrorAction SilentlyContinue
        }
        
        # Check for suspicious files
        foreach ($file in $recentFiles) {
            $isSuspicious = $false
            $suspiciousReason = ""
            
            foreach ($pattern in $suspiciousFilePatterns) {
                # Check path pattern
                if ($pattern.PathPattern -and $file.FullName -match $pattern.PathPattern) {
                    # Check if we need to verify it was changed recently
                    if ($pattern.FileChangedRecently) {
                        if ($file.LastWriteTime -gt (Get-Date).AddDays(-7)) {
                            $isSuspicious = $true
                            $suspiciousReason = $pattern.Reason
                            break
                        }
                    } else {
                        $isSuspicious = $true
                        $suspiciousReason = $pattern.Reason
                        break
                    }
                }
            }
            
            # Check executable signature for any EXE/DLL files
            if (-not $isSuspicious -and $file.Extension -match "\.(exe|dll)$") {
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop
                    if ($signature.Status -ne "Valid") {
                        # For system directories, unsigned executables are suspicious
                        if ($file.FullName -like "C:\Windows\*" -or $file.FullName -like "C:\Program Files\*") {
                            $isSuspicious = $true
                            $suspiciousReason = "Unsigned executable in system directory"
                        }
                    }
                } catch {
                    Write-NexusLog "Error checking signature for $($file.FullName): $_" -Level "WARNING" -LogFile $huntLogFile -NoConsole
                }
            }
            
            # Add to results if suspicious
            if ($isSuspicious) {
                $huntResults.SuspiciousItems.Files += [PSCustomObject]@{
                    Path = $file.FullName
                    Type = $file.Extension
                    Size = [Math]::Round($file.Length / 1KB, 2)
                    Created = $file.CreationTime
                    Modified = $file.LastWriteTime
                    Reason = $suspiciousReason
                }
                
                Write-NexusLog "Found suspicious file: $($file.FullName) - $suspiciousReason" -LogFile $huntLogFile -Level "ALERT"
            }
        }
        
        Write-NexusLog "Found $($huntResults.SuspiciousItems.Files.Count) suspicious files" -LogFile $huntLogFile
    }
    
    # 7. AI Analysis (if enabled)
    if ($UseAI -and -not [string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        Update-HuntProgress -PercentComplete 90 -Status "Performing AI threat analysis..."
        
        # Prepare data for AI analysis
        $aiHuntData = @"
# Threat Hunting Results

## Suspicious Processes
$($huntResults.SuspiciousItems.Processes | ConvertTo-Json -Depth 3)

## Suspicious Services
$($huntResults.SuspiciousItems.Services | ConvertTo-Json -Depth 3)

## Suspicious Network Connections
$($huntResults.SuspiciousItems.NetworkConnections | ConvertTo-Json -Depth 3)

## Suspicious Scheduled Tasks
$($huntResults.SuspiciousItems.ScheduledTasks | ConvertTo-Json -Depth 3)

## Suspicious WMI Objects
$($huntResults.SuspiciousItems.WmiObjects | ConvertTo-Json -Depth 3)

## Suspicious Files
$($huntResults.SuspiciousItems.Files | ConvertTo-Json -Depth 3)
"@
        
        try {
            Write-NexusLog "Submitting threat hunting data to DeepSeek AI for analysis..." -LogFile $huntLogFile
            
            $aiPrompt = @"
You are an expert malware analyst and threat hunter. I'm providing you with the results of a threat hunt on a Windows system.
Please analyze this data and provide:
1. An assessment of potential threats found (type of malware/attack, severity, etc.)
2. Behavioral analysis of any suspicious activity
3. Specific, actionable remediation steps for each threat category
4. Optional: MITRE ATT&CK tactics and techniques that align with these findings

The threat hunting data is provided below:

$aiHuntData
"@
            
            $aiResponse = Invoke-DeepSeekAI -Prompt $aiPrompt -SystemPrompt "You are an expert malware analyst and threat hunter analyzing Windows threat hunting results. Provide detailed, actionable analysis and specific remediation steps." -Temperature 0.2 -MaxTokens 3000
            
            $huntResults.AIAnalysis = $aiResponse
            Write-NexusLog "AI threat analysis completed" -LogFile $huntLogFile
        } catch {
            Write-NexusLog "Error performing AI threat analysis: $_" -Level "ERROR" -LogFile $huntLogFile
        }
    }
    
    # 8. Generate remediation scripts
    Update-HuntProgress -PercentComplete 95 -Status "Generating remediation scripts..."
    
    # Create a generic script header with logging and safety functions
    $remediationScriptHeader = @"
# ==============================================
# Nexus Sentinel Remediation Script
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# ==============================================

# Setup log file
`$logFile = "`$env:TEMP\NexusSentinel_Remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to log messages
function Write-RemediationLog {
    param (
        [Parameter(Mandatory=`$true)]
        [string]`$Message,
        
        [Parameter(Mandatory=`$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]`$Level = "INFO"
    )
    
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$logEntry = "[`$timestamp] [`$Level] `$Message"
    
    # Write to log file
    Add-Content -Path `$logFile -Value `$logEntry -ErrorAction SilentlyContinue
    
    # Write to console with appropriate color
    `$color = switch (`$Level) {
        "INFO" { "White" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    Write-Host `$logEntry -ForegroundColor `$color
}

# Check for Administrator rights
`$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
`$principal = New-Object System.Security.Principal.WindowsPrincipal(`$identity)
`$isAdmin = `$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not `$isAdmin) {
    Write-RemediationLog "This script requires Administrator privileges. Please run as Administrator." -Level "ERROR"
    Write-Host "Press any key to exit..."
    `$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

Write-RemediationLog "Starting remediation script" -Level "INFO"
Write-RemediationLog "Log file: `$logFile" -Level "INFO"

"@
    
    # Create remediation scripts based on findings
    
    # 1. Process remediation script
    if ($huntResults.SuspiciousItems.Processes.Count -gt 0) {
        $processScriptPath = Join-Path -Path $remediationDir -ChildPath "Remediate_Processes.ps1"
        $processScript = $remediationScriptHeader
        
        $processScript += @"

# ==============================================
# PROCESS REMEDIATION
# ==============================================

Write-RemediationLog "Starting suspicious process remediation" -Level "INFO"

# List of suspicious processes to terminate
`$suspiciousProcesses = @(

"@
        
        foreach ($process in $huntResults.SuspiciousItems.Processes) {
            $processScript += @"
    [PSCustomObject]@{
        ProcessId = $($process.ProcessId)
        Name = "$($process.Name)"
        Path = "$($process.Path)"
        Reason = "$($process.Reason)"
    },

"@
        }
        
        $processScript += @"
)

# Show suspicious processes and ask for confirmation
Write-Host "`nSuspicious Processes Found:" -ForegroundColor Red
`$i = 1
foreach (`$process in `$suspiciousProcesses) {
    Write-Host "[`$i] PID: `$(`$process.ProcessId) | Name: `$(`$process.Name)" -ForegroundColor Yellow
    Write-Host "    Path: `$(`$process.Path)" -ForegroundColor Gray
    Write-Host "    Reason: `$(`$process.Reason)" -ForegroundColor Gray
    `$i++
}

Write-Host "`nDo you want to terminate these processes? (Y/N/S - where S is selective): " -ForegroundColor Cyan -NoNewline
`$confirmation = Read-Host

if (`$confirmation -eq "Y" -or `$confirmation -eq "y") {
    # Terminate all processes
    foreach (`$process in `$suspiciousProcesses) {
        try {
            `$p = Get-Process -Id `$process.ProcessId -ErrorAction SilentlyContinue
            if (`$p) {
                Stop-Process -Id `$process.ProcessId -Force -ErrorAction Stop
                Write-RemediationLog "Terminated process: `$(`$process.Name) (PID: `$(`$process.ProcessId))" -Level "SUCCESS"
            } else {
                Write-RemediationLog "Process already terminated or not found: `$(`$process.Name) (PID: `$(`$process.ProcessId))" -Level "WARNING"
            }
        } catch {
            Write-RemediationLog "Error terminating process `$(`$process.Name) (PID: `$(`$process.ProcessId)): `$_" -Level "ERROR"
        }
    }
} elseif (`$confirmation -eq "S" -or `$confirmation -eq "s") {
    # Selective termination
    for (`$i = 0; `$i -lt `$suspiciousProcesses.Count; `$i++) {
        `$process = `$suspiciousProcesses[`$i]
        Write-Host "Terminate `$(`$process.Name) (PID: `$(`$process.ProcessId))? (Y/N): " -ForegroundColor Yellow -NoNewline
        `$processConfirmation = Read-Host
        
        if (`$processConfirmation -eq "Y" -or `$processConfirmation -eq "y") {
            try {
                `$p = Get-Process -Id `$process.ProcessId -ErrorAction SilentlyContinue
                if (`$p) {
                    Stop-Process -Id `$process.ProcessId -Force -ErrorAction Stop
                    Write-RemediationLog "Terminated process: `$(`$process.Name) (PID: `$(`$process.ProcessId))" -Level "SUCCESS"
                } else {
                    Write-RemediationLog "Process already terminated or not found: `$(`$process.Name) (PID: `$(`$process.ProcessId))" -Level "WARNING"
                }
            } catch {
                Write-RemediationLog "Error terminating process `$(`$process.Name) (PID: `$(`$process.ProcessId)): `$_" -Level "ERROR"
            }
        } else {
            Write-RemediationLog "Skipped termination of process: `$(`$process.Name) (PID: `$(`$process.ProcessId))" -Level "INFO"
        }
    }
} else {
    Write-RemediationLog "Process termination cancelled by user" -Level "INFO"
}

Write-RemediationLog "Process remediation completed" -Level "INFO"
Write-Host "`nProcess remediation completed. See log for details: `$logFile" -ForegroundColor Green
Write-Host "Press any key to exit..."
`$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
"@
        
        # Save the script
        $processScript | Out-File -FilePath $processScriptPath -Encoding utf8
        $huntResults.RemediationScripts += $processScriptPath
        Write-NexusLog "Created process remediation script: $processScriptPath" -LogFile $huntLogFile
    }
    
    # 2. Service remediation script
    if ($huntResults.SuspiciousItems.Services.Count -gt 0) {
        $serviceScriptPath = Join-Path -Path $remediationDir -ChildPath "Remediate_Services.ps1"
        $serviceScript = $remediationScriptHeader
        
        $serviceScript += @"

# ==============================================
# SERVICE REMEDIATION
# ==============================================

Write-RemediationLog "Starting suspicious service remediation" -Level "INFO"

# List of suspicious services to disable
`$suspiciousServices = @(

"@
        
        foreach ($service in $huntResults.SuspiciousItems.Services) {
            $serviceScript += @"
    [PSCustomObject]@{
        Name = "$($service.Name)"
        DisplayName = "$($service.DisplayName)"
        State = "$($service.State)"
        Path = "$($service.Path)"
        Reason = "$($service.Reason)"
    },

"@
        }
        
        $serviceScript += @"
)

# Show suspicious services and ask for confirmation
Write-Host "`nSuspicious Services Found:" -ForegroundColor Red
`$i = 1
foreach (`$service in `$suspiciousServices) {
    Write-Host "[`$i] Name: `$(`$service.Name) | Display Name: `$(`$service.DisplayName)" -ForegroundColor Yellow
    Write-Host "    Path: `$(`$service.Path)" -ForegroundColor Gray
    Write-Host "    State: `$(`$service.State)" -ForegroundColor Gray
    Write-Host "    Reason: `$(`$service.Reason)" -ForegroundColor Gray
    `$i++
}

Write-Host "`nDo you want to disable these services? (Y/N/S - where S is selective): " -ForegroundColor Cyan -NoNewline
`$confirmation = Read-Host

if (`$confirmation -eq "Y" -or `$confirmation -eq "y") {
    # Disable all services
    foreach (`$service in `$suspiciousServices) {
        try {
            `$svc = Get-Service -Name `$service.Name -ErrorAction SilentlyContinue
            if (`$svc) {
                if (`$svc.Status -eq "Running") {
                    Stop-Service -Name `$service.Name -Force -ErrorAction Stop
                    Write-RemediationLog "Stopped service: `$(`$service.Name)" -Level "SUCCESS"
                }
                
                Set-Service -Name `$service.Name -StartupType Disabled -ErrorAction Stop
                Write-RemediationLog "Disabled service: `$(`$service.Name)" -Level "SUCCESS"
            } else {
                Write-RemediationLog "Service not found: `$(`$service.Name)" -Level "WARNING"
            }
        } catch {
            Write-RemediationLog "Error disabling service `$(`$service.Name): `$_" -Level "ERROR"
        }
    }
} elseif (`$confirmation -eq "S" -or `$confirmation -eq "s") {
    # Selective disabling
    for (`$i = 0; `$i -lt `$suspiciousServices.Count; `$i++) {
        `$service = `$suspiciousServices[`$i]
        Write-Host "Disable `$(`$service.Name) (`$(`$service.DisplayName))? (Y/N): " -ForegroundColor Yellow -NoNewline
        `$serviceConfirmation = Read-Host
        
        if (`$serviceConfirmation -eq "Y" -or `$serviceConfirmation -eq "y") {
            try {
                `$svc = Get-Service -Name `$service.Name -ErrorAction SilentlyContinue
                if (`$svc) {
                    if (`$svc.Status -eq "Running") {
                        Stop-Service -Name `$service.Name -Force -ErrorAction Stop
                        Write-RemediationLog "Stopped service: `$(`$service.Name)" -Level "SUCCESS"
                    }
                    
                    Set-Service -Name `$service.Name -StartupType Disabled -ErrorAction Stop
                    Write-RemediationLog "Disabled service: `$(`$service.Name)" -Level "SUCCESS"
                } else {
                    Write-RemediationLog "Service not found: `$(`$service.Name)" -Level "WARNING"
                }
            } catch {
                Write-RemediationLog "Error disabling service `$(`$service.Name): `$_" -Level "ERROR"
            }
        } else {
            Write-RemediationLog "Skipped disabling of service: `$(`$service.Name)" -Level "INFO"
        }
    }
} else {
    Write-RemediationLog "Service remediation cancelled by user" -Level "INFO"
}

Write-RemediationLog "Service remediation completed" -Level "INFO"
Write-Host "`nService remediation completed. See log for details: `$logFile" -ForegroundColor Green
Write-Host "Press any key to exit..."
`$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
"@
        
        # Save the script
        $serviceScript | Out-File -FilePath $serviceScriptPath -Encoding utf8
        $huntResults.RemediationScripts += $serviceScriptPath
        Write-NexusLog "Created service remediation script: $serviceScriptPath" -LogFile $huntLogFile
    }
    
    # 3. Network remediation script (Firewall Rules)
    if ($huntResults.SuspiciousItems.NetworkConnections.Count -gt 0) {
        $networkScriptPath = Join-Path -Path $remediationDir -ChildPath "Remediate_Network.ps1"
        $networkScript = $remediationScriptHeader
        
        $networkScript += @"

# ==============================================
# NETWORK REMEDIATION
# ==============================================

Write-RemediationLog "Starting suspicious network connection remediation" -Level "INFO"

# List of suspicious network connections to block
`$suspiciousConnections = @(

"@
        
        foreach ($conn in $huntResults.SuspiciousItems.NetworkConnections) {
            # Extract process ID from process field
            $pidMatch = [regex]::Match($conn.Process, "PID: (\d+)")
            $pid = if ($pidMatch.Success) { $pidMatch.Groups[1].Value } else { "Unknown" }
            
            # Extract remote address and port
            $remoteMatch = [regex]::Match($conn.RemoteEndpoint, "(\d+\.\d+\.\d+\.\d+):(\d+)")
            if ($remoteMatch.Success) {
                $remoteAddress = $remoteMatch.Groups[1].Value
                $remotePort = $remoteMatch.Groups[2].Value
                
                $networkScript += @"
    [PSCustomObject]@{
        ProcessId = "$pid"
        Process = "$($conn.Process)"
        RemoteAddress = "$remoteAddress"
        RemotePort = "$remotePort"
        Reason = "$($conn.Reason)"
    },

"@
            }
        }
        
        $networkScript += @"
)

# Show suspicious connections and ask for confirmation
Write-Host "`nSuspicious Network Connections Found:" -ForegroundColor Red
`$i = 1
foreach (`$conn in `$suspiciousConnections) {
    Write-Host "[`$i] Process: `$(`$conn.Process)" -ForegroundColor Yellow
    Write-Host "    Remote: `$(`$conn.RemoteAddress):`$(`$conn.RemotePort)" -ForegroundColor Gray
    Write-Host "    Reason: `$(`$conn.Reason)" -ForegroundColor Gray
    `$i++
}

# Create a timestamp for rule naming
`$timestamp = Get-Date -Format "yyyyMMddHHmmss"

Write-Host "`nWhat action do you want to take?" -ForegroundColor Cyan
Write-Host "1. Create firewall rules to block connections" -ForegroundColor Cyan
Write-Host "2. Terminate processes" -ForegroundColor Cyan
Write-Host "3. Both (block + terminate)" -ForegroundColor Cyan
Write-Host "4. Cancel" -ForegroundColor Cyan
Write-Host "Enter choice (1-4): " -ForegroundColor Cyan -NoNewline
`$action = Read-Host

if (`$action -eq "1" -or `$action -eq "3") {
    # Create firewall rules
    Write-RemediationLog "Creating firewall rules to block suspicious connections" -Level "INFO"
    
    `$uniqueRemoteAddresses = `$suspiciousConnections | Select-Object -Property RemoteAddress -Unique
    
    foreach (`$remoteAddr in `$uniqueRemoteAddresses) {
        try {
            `$ruleName = "NexusSentinel_Block_`$(`$remoteAddr.RemoteAddress)_`$timestamp"
            New-NetFirewallRule -DisplayName `$ruleName -Direction Outbound -Action Block -RemoteAddress `$remoteAddr.RemoteAddress -Enabled True -ErrorAction Stop
            Write-RemediationLog "Created firewall rule to block outbound traffic to `$(`$remoteAddr.RemoteAddress)" -Level "SUCCESS"
        } catch {
            Write-RemediationLog "Error creating firewall rule for `$(`$remoteAddr.RemoteAddress): `$_" -Level "ERROR"
        }
    }
}

if (`$action -eq "2" -or `$action -eq "3") {
    # Terminate processes
    Write-RemediationLog "Terminating processes with suspicious connections" -Level "INFO"
    
    `$uniqueProcessIds = `$suspiciousConnections | Where-Object { `$_.ProcessId -ne "Unknown" } | Select-Object -Property ProcessId -Unique
    
    foreach (`$procId in `$uniqueProcessIds) {
        try {
            `$p = Get-Process -Id `$procId.ProcessId -ErrorAction SilentlyContinue
            if (`$p) {
                Stop-Process -Id `$procId.ProcessId -Force -ErrorAction Stop
                Write-RemediationLog "Terminated process with PID: `$(`$procId.ProcessId)" -Level "SUCCESS"
            } else {
                Write-RemediationLog "Process already terminated or not found with PID: `$(`$procId.ProcessId)" -Level "WARNING"
            }
        } catch {
            Write-RemediationLog "Error terminating process with PID `$(`$procId.ProcessId): `$_" -Level "ERROR"
        }
    }
}

if (`$action -eq "4") {
    Write-RemediationLog "Network remediation cancelled by user" -Level "INFO"
}

Write-RemediationLog "Network remediation completed" -Level "INFO"
Write-Host "`nNetwork remediation completed. See log for details: `$logFile" -ForegroundColor Green
Write-Host "Press any key to exit..."
`$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
"@
        
        # Save the script
        $networkScript | Out-File -FilePath $networkScriptPath -Encoding utf8
        $huntResults.RemediationScripts += $networkScriptPath
        Write-NexusLog "Created network remediation script: $networkScriptPath" -LogFile $huntLogFile
    }
    
    # 4. Scheduled Task remediation script
    if ($huntResults.SuspiciousItems.ScheduledTasks.Count -gt 0) {
        $taskScriptPath = Join-Path -Path $remediationDir -ChildPath "Remediate_ScheduledTasks.ps1"
        $taskScript = $remediationScriptHeader
        
        $taskScript += @"

# ==============================================
# SCHEDULED TASK REMEDIATION
# ==============================================

Write-RemediationLog "Starting suspicious scheduled task remediation" -Level "INFO"

# List of suspicious scheduled tasks to disable
`$suspiciousTasks = @(

"@
        
        foreach ($task in $huntResults.SuspiciousItems.ScheduledTasks) {
            $taskScript += @"
    [PSCustomObject]@{
        Name = "$($task.Name)"
        Path = "$($task.Path)"
        Actions = "$($task.Actions)"
        Reason = "$($task.Reason)"
    },

"@
        }
        
        $taskScript += @"
)

# Show suspicious tasks and ask for confirmation
Write-Host "`nSuspicious Scheduled Tasks Found:" -ForegroundColor Red
`$i = 1
foreach (`$task in `$suspiciousTasks) {
    Write-Host "[`$i] Name: `$(`$task.Name)" -ForegroundColor Yellow
    Write-Host "    Path: `$(`$task.Path)" -ForegroundColor Gray
    Write-Host "    Actions: `$(`$task.Actions)" -ForegroundColor Gray
    Write-Host "    Reason: `$(`$task.Reason)" -ForegroundColor Gray
    `$i++
}

Write-Host "`nDo you want to disable these scheduled tasks? (Y/N/S - where S is selective): " -ForegroundColor Cyan -NoNewline
`$confirmation = Read-Host

if (`$confirmation -eq "Y" -or `$confirmation -eq "y") {
    # Disable all tasks
    foreach (`$task in `$suspiciousTasks) {
        try {
            `$fullTaskPath = "`$(`$task.Path)`$(`$task.Name)"
            `$t = Get-ScheduledTask -TaskPath `$task.Path -TaskName `$task.Name -ErrorAction SilentlyContinue
            
            if (`$t) {
                Disable-ScheduledTask -TaskPath `$task.Path -TaskName `$task.Name -ErrorAction Stop
                Write-RemediationLog "Disabled scheduled task: `$fullTaskPath" -Level "SUCCESS"
            } else {
                Write-RemediationLog "Scheduled task not found: `$fullTaskPath" -Level "WARNING"
            }
        } catch {
            Write-RemediationLog "Error disabling scheduled task `$fullTaskPath: `$_" -Level "ERROR"
        }
    }
} elseif (`$confirmation -eq "S" -or `$confirmation -eq "s") {
    # Selective disabling
    for (`$i = 0; `$i -lt `$suspiciousTasks.Count; `$i++) {
        `$task = `$suspiciousTasks[`$i]
        `$fullTaskPath = "`$(`$task.Path)`$(`$task.Name)"
        
        Write-Host "Disable scheduled task `$fullTaskPath? (Y/N): " -ForegroundColor Yellow -NoNewline
        `$taskConfirmation = Read-Host
        
        if (`$taskConfirmation -eq "Y" -or `$taskConfirmation -eq "y") {
            try {
                `$t = Get-ScheduledTask -TaskPath `$task.Path -TaskName `$task.Name -ErrorAction SilentlyContinue
                
                if (`$t) {
                    Disable-ScheduledTask -TaskPath `$task.Path -TaskName `$task.Name -ErrorAction Stop
                    Write-RemediationLog "Disabled scheduled task: `$fullTaskPath" -Level "SUCCESS"
                } else {
                    Write-RemediationLog "Scheduled task not found: `$fullTaskPath" -Level "WARNING"
                }
            } catch {
                Write-RemediationLog "Error disabling scheduled task `$fullTaskPath: `$_" -Level "ERROR"
            }
        } else {
            Write-RemediationLog "Skipped disabling of scheduled task: `$fullTaskPath" -Level "INFO"
        }
    }
} else {
    Write-RemediationLog "Scheduled task remediation cancelled by user" -Level "INFO"
}

Write-RemediationLog "Scheduled task remediation completed" -Level "INFO"
Write-Host "`nScheduled task remediation completed. See log for details: `$logFile" -ForegroundColor Green
Write-Host "Press any key to exit..."
`$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
"@
        
        # Save the script
        $taskScript | Out-File -FilePath $taskScriptPath -Encoding utf8
        $huntResults.RemediationScripts += $taskScriptPath
        Write-NexusLog "Created scheduled task remediation script: $taskScriptPath" -LogFile $huntLogFile
    }
    
    # 5. AI-Generated Remediation Script (if AI analysis is available)
    if ($UseAI -and $huntResults.AIAnalysis) {
        $aiScriptPath = Join-Path -Path $remediationDir -ChildPath "AI_Remediation.ps1"
        
        # Generate AI remediation script request
        $aiRemediationPrompt = @"
Based on the threat hunting results and your analysis below, generate a comprehensive PowerShell remediation script to address all the identified threats.

The script should:
1. Include proper error handling and logging
2. Ask for user confirmation before taking actions
3. Be capable of remediating all the suspicious items found
4. Use best security practices
5. Document all actions taken for audit purposes

Your earlier analysis:
$($huntResults.AIAnalysis)
"@
        
        try {
            $aiScript = Invoke-DeepSeekAI -Prompt $aiRemediationPrompt -SystemPrompt "You are an expert Windows security engineer creating a PowerShell remediation script. The script must be complete, properly formatted, and follow best practices for security remediation." -Temperature 0.2 -MaxTokens 4000
            
            # Save the AI-generated script
            $aiScript | Out-File -FilePath $aiScriptPath -Encoding utf8
            $huntResults.RemediationScripts += $aiScriptPath
            Write-NexusLog "Created AI-generated remediation script: $aiScriptPath" -LogFile $huntLogFile
        } catch {
            Write-NexusLog "Error generating AI remediation script: $_" -Level "ERROR" -LogFile $huntLogFile
        }
    }
    
    # 9. Auto-remediation (if enabled)
    if ($AutoRemediate -and $huntResults.RemediationScripts.Count -gt 0) {
        Update-HuntProgress -PercentComplete 98 -Status "Executing auto-remediation..."
        
        Write-NexusLog "Auto-remediation mode enabled. Will execute scripts without user intervention." -LogFile $huntLogFile
        
        foreach ($script in $huntResults.RemediationScripts) {
            $scriptName = Split-Path -Path $script -Leaf
            
            try {
                Write-NexusLog "Executing remediation script: $scriptName" -LogFile $huntLogFile
                
                # Execute the script in a new PowerShell process
                $process = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$script`"" -PassThru -Wait
                
                if ($process.ExitCode -eq 0) {
                    Write-NexusLog "Remediation script executed successfully: $scriptName" -LogFile $huntLogFile -Level "SUCCESS"
                    $huntResults.Remediated += $scriptName
                } else {
                    Write-NexusLog "Remediation script execution failed with exit code $($process.ExitCode): $scriptName" -LogFile $huntLogFile -Level "ERROR"
                }
            } catch {
                Write-NexusLog "Error executing remediation script ${scriptName}: $_" -LogFile $huntLogFile -Level "ERROR"
            }
        }
    }
    
    # Complete the hunt
    Update-HuntProgress -PercentComplete 100 -Status "Threat hunting complete."
    
    # Record end time
    $huntResults.EndTime = Get-Date
    $huntDuration = $huntResults.EndTime - $huntResults.StartTime
    Write-NexusLog "Threat hunting completed in $($huntDuration.TotalMinutes.ToString('0.00')) minutes" -LogFile $huntLogFile
    
    # Generate summary
    $huntSummary = @"
===============================================================================
                        NEXUS SENTINEL THREAT HUNTING SUMMARY
===============================================================================
Hunt ID: $huntId
Date: $($huntResults.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
Duration: $($huntDuration.TotalMinutes.ToString('0.00')) minutes
Hunt Depth: $($huntResults.HuntDepth)

FINDINGS SUMMARY:
- Suspicious Processes: $($huntResults.SuspiciousItems.Processes.Count)
- Suspicious Services: $($huntResults.SuspiciousItems.Services.Count)
- Suspicious Network Connections: $($huntResults.SuspiciousItems.NetworkConnections.Count)
- Suspicious Scheduled Tasks: $($huntResults.SuspiciousItems.ScheduledTasks.Count)
- Suspicious WMI Objects: $($huntResults.SuspiciousItems.WmiObjects.Count)
- Suspicious Files: $($huntResults.SuspiciousItems.Files.Count)

REMEDIATION SCRIPTS:
$($huntResults.RemediationScripts | ForEach-Object { "- $(Split-Path -Path $_ -Leaf)" })

$( if ($AutoRemediate) {
"AUTO-REMEDIATION EXECUTED:
$($huntResults.Remediated | ForEach-Object { "- $_" })"
})

Remediation Scripts Location:
$remediationDir

Log File:
$huntLogFile
===============================================================================
"@
    
    Write-NexusLog $huntSummary -LogFile $huntLogFile
    Write-Host $huntSummary -ForegroundColor Cyan
    
    # Return hunt ID
    return $huntId
}

# Main menu system
function Show-MainMenu {
    param (
        [switch]$Refresh
    )
    
    if ($Refresh) {
        Show-NexusBanner
    }
    
    Write-Host "`n[MAIN MENU]`n" -ForegroundColor Cyan
    
    # Display menu options
    $menuOptions = @(
        @{ Number = "1"; Name = "System Security Scan"; Description = "Perform comprehensive system security assessment" }
        @{ Number = "2"; Name = "Real-time Monitoring"; Description = "Start process, network, or file system monitoring" }
        @{ Number = "3"; Name = "Threat Hunting"; Description = "Active hunt for threats and suspicious activities" }
        @{ Number = "4"; Name = "View Previous Results"; Description = "View reports from previous scans and hunts" }
        @{ Number = "5"; Name = "Settings"; Description = "Configure Nexus Sentinel settings" }
        @{ Number = "6"; Name = "Exit"; Description = "Exit Nexus Sentinel" }
    )
    
    foreach ($option in $menuOptions) {
        Write-Host "[$($option.Number)] $($option.Name)" -ForegroundColor Green
        Write-Host "    $($option.Description)" -ForegroundColor Gray
    }
    
    Write-Host "`nEnter your choice (1-6): " -ForegroundColor Cyan -NoNewline
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Show-ScanMenu }
        "2" { Show-MonitoringMenu }
        "3" { Show-ThreatHuntingMenu }
        "4" { Show-ResultsMenu }
        "5" { Show-SettingsMenu }
        "6" { Exit-NexusSentinel }
        default { 
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
            Show-MainMenu -Refresh
        }
    }
}

function Show-ScanMenu {
    Show-NexusBanner
    
    Write-Host "`n[SYSTEM SECURITY SCAN]`n" -ForegroundColor Cyan
    
    Write-Host "Select scan type:" -ForegroundColor Green
    Write-Host "[1] Quick Scan" -ForegroundColor White
    Write-Host "    Fast overview of system security (5-10 minutes)" -ForegroundColor Gray
    Write-Host "[2] Standard Scan" -ForegroundColor White
    Write-Host "    Comprehensive security assessment (10-20 minutes)" -ForegroundColor Gray
    Write-Host "[3] Full Scan" -ForegroundColor White
    Write-Host "    In-depth security analysis with vulnerability assessment (20-40 minutes)" -ForegroundColor Gray
    Write-Host "[4] Return to Main Menu" -ForegroundColor White
    
    Write-Host "`nEnter your choice (1-4): " -ForegroundColor Cyan -NoNewline
    $scanChoice = Read-Host
    
    if ($scanChoice -eq "4") {
        Show-MainMenu -Refresh
        return
    }
    
    if ($scanChoice -lt "1" -or $scanChoice -gt "3") {
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        Start-Sleep -Seconds 1
        Show-ScanMenu
        return
    }
    
    $scanDepth = switch ($scanChoice) {
        "1" { "Quick" }
        "2" { "Standard" }
        "3" { "Full" }
    }
    
    Write-Host "`nUse AI-powered analysis? (Y/N): " -ForegroundColor Cyan -NoNewline
    $useAI = (Read-Host) -eq "Y" -or (Read-Host) -eq "y"
    
    if ($useAI -and [string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        $hasApiKey = Get-DeepSeekAPIKey
        if (-not $hasApiKey) {
            $useAI = $false
        }
    }
    
    # Start the scan
    Write-Host "`nStarting $scanDepth scan..." -ForegroundColor Yellow
    $scanId = Start-NexusSystemScan -ScanDepth $scanDepth -UseAI:$useAI
    
    # Show scan results
    $reportFile = $global:ScanResults[$scanId].ReportFile
    
    Write-Host "`nScan completed! Report saved to: $reportFile" -ForegroundColor Green
    Write-Host "`nDo you want to open the report now? (Y/N): " -ForegroundColor Cyan -NoNewline
    $openReport = (Read-Host) -eq "Y" -or (Read-Host) -eq "y"
    
    if ($openReport) {
        Start-Process $reportFile
    }
    
    Write-Host "`nPress any key to return to the main menu..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-MainMenu -Refresh
}

function Show-MonitoringMenu {
    Show-NexusBanner
    
    Write-Host "`n[REAL-TIME MONITORING]`n" -ForegroundColor Cyan
    
    # Show active monitors if any
    if ($global:ActiveMonitors.Count -gt 0) {
        Write-Host "Active Monitors:" -ForegroundColor Green
        $i = 1
        foreach ($monitorId in $global:ActiveMonitors) {
            $monitor = $global:MonitorJobs[$monitorId]
            $monitorType = $monitor.Type
            $runTime = (Get-Date) - $monitor.StartTime
            $runTimeStr = "{0:D2}:{1:D2}:{2:D2}" -f $runTime.Hours, $runTime.Minutes, $runTime.Seconds
            
            $status = if ($monitor.Process.HasExited) { "Stopped" } else { "Running" }
            $statusColor = if ($status -eq "Running") { "Green" } else { "Red" }
            
            Write-Host "[$i] $monitorId" -ForegroundColor White
            Write-Host "    Type: $monitorType | Status: " -ForegroundColor Gray -NoNewline
            Write-Host "$status" -ForegroundColor $statusColor -NoNewline
            Write-Host " | Runtime: $runTimeStr" -ForegroundColor Gray
            $i++
        }
        Write-Host ""
    }
    
    Write-Host "Select monitoring option:" -ForegroundColor Green
    Write-Host "[1] Process Monitoring" -ForegroundColor White
    Write-Host "    Monitor new processes and analyze for suspicious activity" -ForegroundColor Gray
    Write-Host "[2] Network Monitoring" -ForegroundColor White
    Write-Host "    Monitor network connections for suspicious activity" -ForegroundColor Gray
    Write-Host "[3] File System Monitoring" -ForegroundColor White
    Write-Host "    Monitor file system changes for suspicious activity" -ForegroundColor Gray
    Write-Host "[4] Stop Monitor" -ForegroundColor White
    Write-Host "    Stop an active monitoring session" -ForegroundColor Gray
    Write-Host "[5] Return to Main Menu" -ForegroundColor White
    
    Write-Host "`nEnter your choice (1-5): " -ForegroundColor Cyan -NoNewline
    $monitorChoice = Read-Host
    
    if ($monitorChoice -eq "5") {
        Show-MainMenu -Refresh
        return
    }
    
    if ($monitorChoice -lt "1" -or $monitorChoice -gt "5") {
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        Start-Sleep -Seconds 1
        Show-MonitoringMenu
        return
    }
    
    if ($monitorChoice -eq "4") {
        if ($global:ActiveMonitors.Count -eq 0) {
            Write-Host "No active monitors to stop." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            Show-MonitoringMenu
            return
        }
        
        Write-Host "`nEnter the number of the monitor to stop: " -ForegroundColor Cyan -NoNewline
        $monitorNum = [int](Read-Host)
        
        if ($monitorNum -lt 1 -or $monitorNum -gt $global:ActiveMonitors.Count) {
            Write-Host "Invalid monitor number." -ForegroundColor Red
            Start-Sleep -Seconds 1
            Show-MonitoringMenu
            return
        }
        
        $monitorId = $global:ActiveMonitors[$monitorNum - 1]
        $monitor = $global:MonitorJobs[$monitorId]
        
        if (-not $monitor.Process.HasExited) {
            $monitor.Process.Kill()
            Write-NexusLog "Stopped monitor: $monitorId"
        } else {
            Write-NexusLog "Monitor already stopped: $monitorId"
        }
        
        # Remove from active monitors
        $global:ActiveMonitors = $global:ActiveMonitors | Where-Object { $_ -ne $monitorId }
        
        Write-Host "Monitor stopped: $monitorId" -ForegroundColor Green
        Start-Sleep -Seconds 2
        Show-MonitoringMenu
        return
    }
    
    Write-Host "`nUse AI-powered analysis? (Y/N): " -ForegroundColor Cyan -NoNewline
    $useAI = (Read-Host) -eq "Y" -or (Read-Host) -eq "y"
    
    if ($useAI -and [string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        $hasApiKey = Get-DeepSeekAPIKey
        if (-not $hasApiKey) {
            $useAI = $false
        }
    }
    
    switch ($monitorChoice) {
        "1" {
            # Start process monitoring
            $monitorId = Start-ProcessMonitoring -UseAI:$useAI
            Write-Host "`nProcess monitoring started in a new window (ID: $monitorId)" -ForegroundColor Green
        }
        "2" {
            # Start network monitoring
            $monitorId = Start-NetworkMonitoring -UseAI:$useAI
            Write-Host "`nNetwork monitoring started in a new window (ID: $monitorId)" -ForegroundColor Green
        }
        "3" {
            # Start file system monitoring
            Write-Host "`nEnter the path to monitor (default: C:\): " -ForegroundColor Cyan -NoNewline
            $path = Read-Host
            
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = "C:\"
            }
            
            if (-not (Test-Path -Path $path)) {
                Write-Host "Invalid path. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 1
                Show-MonitoringMenu
                return
            }
            
            $monitorId = Start-FileSystemMonitoring -Path $path -UseAI:$useAI
            Write-Host "`nFile system monitoring started in a new window (ID: $monitorId)" -ForegroundColor Green
        }
    }
    
    Write-Host "`nPress any key to return to the monitoring menu..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-MonitoringMenu
}

function Show-ThreatHuntingMenu {
    Show-NexusBanner
    
    Write-Host "`n[THREAT HUNTING]`n" -ForegroundColor Cyan
    
    Write-Host "Select threat hunting option:" -ForegroundColor Green
    Write-Host "[1] Quick Hunt" -ForegroundColor White
    Write-Host "    Rapid threat hunt focusing on common IOCs (5-10 minutes)" -ForegroundColor Gray
    Write-Host "[2] Standard Hunt" -ForegroundColor White
    Write-Host "    Comprehensive threat hunt with behavioral analysis (10-20 minutes)" -ForegroundColor Gray
    Write-Host "[3] Deep Hunt" -ForegroundColor White
    Write-Host "    In-depth hunt including file system analysis (20-40 minutes)" -ForegroundColor Gray
    Write-Host "[4] Return to Main Menu" -ForegroundColor White
    
    Write-Host "`nEnter your choice (1-4): " -ForegroundColor Cyan -NoNewline
    $huntChoice = Read-Host
    
    if ($huntChoice -eq "4") {
        Show-MainMenu -Refresh
        return
    }
    
    if ($huntChoice -lt "1" -or $huntChoice -gt "3") {
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        Start-Sleep -Seconds 1
        Show-ThreatHuntingMenu
        return
    }
    
    $huntDepth = switch ($huntChoice) {
        "1" { "Quick" }
        "2" { "Standard" }
        "3" { "Deep" }
    }
    
    Write-Host "`nUse AI-powered analysis? (Y/N): " -ForegroundColor Cyan -NoNewline
    $useAI = (Read-Host) -eq "Y" -or (Read-Host) -eq "y"
    
    if ($useAI -and [string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        $hasApiKey = Get-DeepSeekAPIKey
        if (-not $hasApiKey) {
            $useAI = $false
        }
    }
    
    Write-Host "`nEnable auto-remediation? (Y/N): " -ForegroundColor Cyan -NoNewline
    $autoRemediate = (Read-Host) -eq "Y" -or (Read-Host) -eq "y"
    
    # Start the hunt
    Write-Host "`nStarting $huntDepth threat hunt..." -ForegroundColor Yellow
    $huntId = Invoke-ThreatHunting -HuntDepth $huntDepth -UseAI:$useAI -AutoRemediate:$autoRemediate
    
    Write-Host "`nPress any key to return to the main menu..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Show-MainMenu -Refresh
}

function Show-ResultsMenu {
    Show-NexusBanner
    
    Write-Host "`n[VIEW PREVIOUS RESULTS]`n" -ForegroundColor Cyan
    
    # List scan results
    $scanReports = Get-ChildItem -Path $global:NexusConfig.ReportDir -Filter "*.html" -ErrorAction SilentlyContinue
    
    if ($scanReports -and $scanReports.Count -gt 0) {
        Write-Host "Available Security Scan Reports:" -ForegroundColor Green
        $i = 1
        foreach ($report in $scanReports) {
            $reportDate = $report.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "[$i] $($report.Name) - $reportDate" -ForegroundColor White
            $i++
        }
    } else {
        Write-Host "No scan reports found." -ForegroundColor Yellow
    }
    
    Write-Host "`nOptions:" -ForegroundColor Green
    Write-Host "[#] Enter report number to view" -ForegroundColor White
    Write-Host "[B] Return to Main Menu" -ForegroundColor White
    
    Write-Host "`nEnter your choice: " -ForegroundColor Cyan -NoNewline
    $choice = Read-Host
    
    if ($choice -eq "B" -or $choice -eq "b") {
        Show-MainMenu -Refresh
        return
    }
    
    if ([int]::TryParse($choice, [ref]$null)) {
        $reportNum = [int]$choice
        
        if ($reportNum -lt 1 -or $reportNum -gt $scanReports.Count) {
            Write-Host "Invalid report number." -ForegroundColor Red
            Start-Sleep -Seconds 1
            Show-ResultsMenu
            return
        }
        
        $selectedReport = $scanReports[$reportNum - 1]
        Write-Host "Opening report: $($selectedReport.Name)" -ForegroundColor Green
        Start-Process $selectedReport.FullName
    } else {
        Write-Host "Invalid selection." -ForegroundColor Red
        Start-Sleep -Seconds 1
    }
    
    Show-ResultsMenu
}

function Show-SettingsMenu {
    Show-NexusBanner
    
    Write-Host "`n[SETTINGS]`n" -ForegroundColor Cyan
    
    Write-Host "Settings Options:" -ForegroundColor Green
    Write-Host "[1] Configure DeepSeek API Key" -ForegroundColor White
    Write-Host "    Current: " -ForegroundColor Gray -NoNewline
    
    if ([string]::IsNullOrEmpty($global:NexusConfig.APIKey)) {
        Write-Host "Not configured" -ForegroundColor Red
    } else {
        $maskedKey = $global:NexusConfig.APIKey.Substring(0, 3) + "..." + $global:NexusConfig.APIKey.Substring($global:NexusConfig.APIKey.Length - 3)
        Write-Host "$maskedKey" -ForegroundColor Green
    }
    
    Write-Host "[2] Set Default Scan Depth" -ForegroundColor White
    Write-Host "    Current: $($global:NexusConfig.ScanDepth)" -ForegroundColor Gray
    
    Write-Host "[3] Clean Up Old Reports" -ForegroundColor White
    Write-Host "    Remove reports older than 30 days" -ForegroundColor Gray
    
    Write-Host "[4] Return to Main Menu" -ForegroundColor White
    
    Write-Host "`nEnter your choice (1-4): " -ForegroundColor Cyan -NoNewline
    $settingChoice = Read-Host
    
    switch ($settingChoice) {
        "1" {
            Write-Host "`nEnter your DeepSeek API Key (leave blank to skip): " -ForegroundColor Cyan -NoNewline
            $apiKey = Read-Host
            
            if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
                $global:NexusConfig.APIKey = $apiKey
                Write-NexusLog "DeepSeek API Key configured"
                Write-Host "DeepSeek API Key saved successfully!" -ForegroundColor Green
            } else {
                Write-Host "API Key not changed." -ForegroundColor Yellow
            }
        }
        "2" {
            Write-Host "`nSelect default scan depth:" -ForegroundColor Cyan
            Write-Host "[1] Quick" -ForegroundColor White
            Write-Host "[2] Standard" -ForegroundColor White
            Write-Host "[3] Full" -ForegroundColor White
            
            Write-Host "`nEnter your choice (1-3): " -ForegroundColor Cyan -NoNewline
            $depthChoice = Read-Host
            
            $newDepth = switch ($depthChoice) {
                "1" { "Quick" }
                "2" { "Standard" }
                "3" { "Full" }
                default { $global:NexusConfig.ScanDepth }
            }
            
            if ($newDepth -ne $global:NexusConfig.ScanDepth) {
                $global:NexusConfig.ScanDepth = $newDepth
                Write-NexusLog "Default scan depth changed to $newDepth"
                Write-Host "Default scan depth updated to $newDepth" -ForegroundColor Green
            } else {
                Write-Host "Scan depth not changed." -ForegroundColor Yellow
            }
        }
        "3" {
            Write-Host "`nCleaning up old reports..." -ForegroundColor Yellow
            
            $oldReports = Get-ChildItem -Path $global:NexusConfig.ReportDir -Filter "*.html" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
            
            if ($oldReports -and $oldReports.Count -gt 0) {
                Write-Host "Found $($oldReports.Count) reports older than 30 days." -ForegroundColor Cyan
                Write-Host "Do you want to delete these reports? (Y/N): " -ForegroundColor Cyan -NoNewline
                $confirm = Read-Host
                
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    $oldReports | Remove-Item -Force
                    Write-NexusLog "Removed $($oldReports.Count) old reports"
                    Write-Host "Old reports removed successfully!" -ForegroundColor Green
                } else {
                    Write-Host "Cleanup cancelled." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No old reports found to clean up." -ForegroundColor Green
            }
        }
        "4" {
            Show-MainMenu -Refresh
            return
        }
        default {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        }
    }
    
    Start-Sleep -Seconds 1
    Show-SettingsMenu
}

function Exit-NexusSentinel {
    Show-NexusBanner
    
    Write-Host "`nExiting Nexus Sentinel..." -ForegroundColor Yellow
    
    # Check for active monitors
    if ($global:ActiveMonitors.Count -gt 0) {
        Write-Host "`nWARNING: There are still $($global:ActiveMonitors.Count) active monitors running." -ForegroundColor Red
        Write-Host "Do you want to stop all active monitors before exiting? (Y/N): " -ForegroundColor Cyan -NoNewline
        $stopMonitors = (Read-Host) -eq "Y" -or (Read-Host) -eq "y"
        
        if ($stopMonitors) {
            foreach ($monitorId in $global:ActiveMonitors) {
                $monitor = $global:MonitorJobs[$monitorId]
                
                if (-not $monitor.Process.HasExited) {
                    $monitor.Process.Kill()
                    Write-NexusLog "Stopped monitor on exit: $monitorId"
                }
            }
            
            Write-Host "All monitors stopped." -ForegroundColor Green
        } else {
            Write-Host "Monitors will continue running in their own windows." -ForegroundColor Yellow
        }
    }
    
    Write-NexusLog "Nexus Sentinel exited"
    Write-Host "`nThank you for using Nexus Sentinel. Goodbye!" -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    exit
}

# Main execution script
try {
    # Initialize environment
    Initialize-NexusEnvironment
    
    # Show banner and get API key if not configured
    Show-NexusBanner
    Get-DeepSeekAPIKey
    
    # Show main menu
    Show-MainMenu
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Host "Critical error: $_" -ForegroundColor Red -ErrorAction 
    if ($global:MainLogFile) {
        Write-NexusLog "Critical error: $_" -Level "ERROR"
    }
    
    Write-Host "`nPress Enter to exit..." -ForegroundColor Yellow
    Read-Host | Out-Null
    exit 1
}
