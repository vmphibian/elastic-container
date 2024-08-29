# Kibana requires a pre-emptive auth when accessing, so with Invoke-RestMethod use `-Authentication Basic` with -Credential to force it in the header
# Set strict mode
Set-StrictMode -Version Latest

$ipvar = "0.0.0.0"

# Test value for Verbose
$Verbose = $true

# These should be set in the .env file
$LinuxDR = $null
$WindowsDR = $null
$MacOSDR = $null

$COMPOSE = $null

# Load .env file and set environment variables
Get-Content .env | ForEach-Object {
    if ($_ -match "^(.*?)=(.*)$") {
        $name = $matches[1]
        $value = $matches[2]
        Set-Item -Path "env:\$name" -Value $value
    }
}

$HEADERS = @{
    "kbn-version" = $env:STACK_VERSION
    "kbn-xsrf" = "kibana"
    "Content-Type" = "application/json"
}

function passphrase_reset {
    if (Select-String -Path .env -Pattern "changeme") {
        Write-Host "Sorry, looks like you haven't updated the passphrase from the default"
        Write-Host "Please update the changeme passphrases in the .env file."
        exit 1
    } else {
        Write-Host "Passphrase has been reset. Proceeding."
    }
}

function usage {
    @"
usage: .\elastic-container.ps1 [-Verbose] (stage|start|stop|restart|status|help)
actions:
  stage     downloads all necessary images to local storage
  start     creates a container network and starts containers
  stop      stops running containers without removing them
  destroy   stops and removes the containers, the network, and volumes created
  restart   restarts all the stack containers
  status    check the status of the stack containers
  clear     clear all documents in logs and metrics indexes
  help      print this message
flags:
  -Verbose  enable verbose output
"@
}

function configure_kbn {
    [CmdletBinding()]
    param(
        [int]$MaxTries = 15,
        [int]$RetryInterval = 20
    )

    $headers = @{
        "kbn-version" = $env:STACK_VERSION
        "kbn-xsrf" = "kibana"
        "Content-Type" = "application/json"
    }
    $cred = New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))

    for ($i = 1; $i -le $MaxTries; $i++) {
        Write-Host "Attempt $i of $MaxTries Checking Kibana status..."
        try {
            $status = (Invoke-WebRequest -SkipCertificateCheck -Uri $env:LOCAL_KBN_URL -Method Head -UseBasicParsing).StatusCode
            if ($status -in 200, 302) {
                Write-Host "Kibana is up. Proceeding with configuration."
                break
            }
        }
        catch {
            Write-Host "Failed to connect to Kibana. Retrying in $RetryInterval seconds."
        }
        
        if ($i -eq $MaxTries) {
            Write-Host "Exceeded maximum tries ($MaxTries) to setup detection engine."
            return $false
        }
        
        Start-Sleep -Seconds $RetryInterval
    }

    # Enable Detection Engine
    try {
        $output = Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/detection_engine/index" -Method Post -Headers $headers -Authentication Basic -Credential $cred
        if (-not $output.acknowledged) {
            throw "Detection Engine setup failed."
        }
        Write-Host "Detection engine enabled. Installing prepackaged rules."
    }
    catch {
        Write-Host "Error enabling Detection Engine: $_"
        return $false
    }

    # Install prepackaged rules
    try {
        Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/prepackaged" -Method Put -Headers $headers -Authentication Basic -Credential $cred
        Write-Host "Prepackaged rules installed successfully."
    }
    catch {
        Write-Host "Error installing prepackaged rules: $_"
        return $false
    }

    # Enable specific detection rules based on environment variables
    $osTypes = @{
        "LinuxDR" = @("Linux", "OS: Linux")
        "WindowsDR" = @("Windows", "OS: Windows")
        "MacOSDR" = @("macOS", "OS: macOS")
    }

    foreach ($os in $osTypes.Keys) {
        $envValue = [Environment]::GetEnvironmentVariable($os)
        if ($envValue -eq "1") {
            $tags = $osTypes[$os] -join '" OR "'
            try {
                Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/_bulk_action" -Method Post -Headers $headers -Authentication Basic -Credential $cred -Body (ConvertTo-Json @{
                    query = "alert.attributes.tags: (`"$tags`")"
                    action = "enable"
                })
                Write-Host "Successfully enabled $os detection rules."
            }
            catch {
                Write-Host "Error enabling $os detection rules: $_"
            }
        }
    }

    if (-not ([Environment]::GetEnvironmentVariable("LinuxDR") -eq "1" -or 
              [Environment]::GetEnvironmentVariable("WindowsDR") -eq "1" -or 
              [Environment]::GetEnvironmentVariable("MacOSDR") -eq "1")) {
        Write-Host "No detection rules enabled in the .env file, skipping detection rules enablement."
    }

    return $true
}

function get_host_ip {
            $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
            if ($os -match "Linux") {
                $ipvar = (hostname -I).Split(" ")[0]
            } elseif ($os -match "Darwin") {
                $ipvar = (ifconfig en0 | Select-String -Pattern "inet " | ForEach-Object { $_.Line.Split(" ")[1] })
            } elseif ($os -match "Windows") {
                $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Where-Object { $_.NextHop -ne "0.0.0.0" }
                if ($defaultRoute) {
                    $interfaceIndex = $defaultRoute.InterfaceIndex
                    $ipvar = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $interfaceIndex }).IPAddress
                } else {
                    Write-Host "No default route found."
                    $ipvar = "0.0.0.0"
                }
            }
            return $ipvar
}

function set_fleet_values {
    [CmdletBinding()]
    param()

    $headers = @{ "kbn-version" = $env:STACK_VERSION
                  "kbn-xsrf" = "kibana"
                  "Content-Type" = "application/json"
                }
    $cred = New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))

    # Get the current Fleet settings
    $currentSettings = Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/fleet/agents/setup" -Method Get -Headers $headers -Authentication Basic -Credential $cred

    if ($currentSettings.isReady) {
        Write-Host "Fleet settings are already configured."
        return
    }

    Write-Host "Fleet is not initialized, setting up Fleet..."
    
    $fingerprint = & $COMPOSE exec -w /usr/share/elasticsearch/config/certs/ca elasticsearch cat ca.crt | 
                   openssl x509 -noout -fingerprint -sha256 | 
                   ForEach-Object { ($_ -split "=")[1] -replace ":", "" }

    $fleetServerHosts = @("https://${ipvar}:$env:FLEET_PORT")
    $elasticsearchHosts = @("https://${ipvar}:9200")

    # Set Fleet Server hosts
    Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/fleet/settings" -Method Put -Headers $headers -Authentication Basic -Credential $cred -Body (ConvertTo-Json @{
        fleet_server_hosts = $fleetServerHosts
    } -Compress)

    # Set Elasticsearch hosts and SSL settings
    $outputSettings = @{
        hosts = $elasticsearchHosts
        ca_trusted_fingerprint = $fingerprint
        config_yaml = "ssl.verification_mode: certificate"
    }

    foreach ($setting in $outputSettings.GetEnumerator()) {
        Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/fleet/outputs/fleet-default-output" -Method Put -Headers $headers -Authentication Basic -Credential $cred -Body (ConvertTo-Json @{
            $setting.Key = $setting.Value
        } -Compress)
    }

    # Create Endpoint Policy
    $policyParams = @{
        name = "Endpoint Policy"
        description = ""
        namespace = "default"
        monitoring_enabled = @("logs", "metrics")
        inactivity_timeout = 1209600
    }
    $policyResponse = Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/fleet/agent_policies?sys_monitoring=true" -Method Post -Headers $headers -Authentication Basic -Credential $cred -Body ($policyParams | ConvertTo-Json)
    $policyId = $policyResponse.item.id

    # Get Endpoint package version
    $packageResponse = Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/fleet/epm/packages/endpoint" -Method Get -Headers $headers -Authentication Basic -Credential $cred
    $packageVersion = $packageResponse.item.version

    # Set up Elastic Defend package policy
    $packagePolicyParams = @{
        name = "Elastic Defend"
        description = ""
        namespace = "default"
        policy_id = $policyId
        enabled = $true
        inputs = @(
            @{
                enabled = $true
                streams = @()
                type = "ENDPOINT_INTEGRATION_CONFIG"
                config = @{
                    _config = @{
                        value = @{
                            type = "endpoint"
                            endpointConfig = @{
                                preset = "EDRComplete"
                            }
                        }
                    }
                }
            }
        )
        package = @{
            name = "endpoint"
            title = "Elastic Defend"
            version = $packageVersion
        }
    }

    Invoke-RestMethod -SkipCertificateCheck -Uri "$env:LOCAL_KBN_URL/api/fleet/package_policies" -Method Post -Headers $headers -Authentication Basic -Credential $cred -Body ($packagePolicyParams | ConvertTo-Json -Depth 10)
}
function clear_documents {
    if ((Invoke-RestMethod -SkipCertificateCheck -Uri "https://$ipvar:9200/_data_stream/logs-*" -Method Delete -Headers $HEADERS -Authentication Basic -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) | Select-String -Pattern "true").Count -gt 0) {
        Write-Host "Successfully cleared logs data stream"
    } else {
        Write-Host "Failed to clear logs data stream"
    }
    Write-Host
    if ((Invoke-RestMethod -SkipCertificateCheck -Uri "https://$ipvar:9200/_data_stream/metrics-*" -Method Delete -Headers $HEADERS -Authentication Basic -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) | Select-String -Pattern "true").Count -gt 0) {
        Write-Host "Successfully cleared metrics data stream"
    } else {
        Write-Host "Failed to clear metrics data stream"
    }
    Write-Host
}

# Main script logic
#param (
#    [switch]$Verbose
#)

$ACTION = $args[0]

if ($Verbose) {
    $VerbosePreference = "Continue"
} else {
    $VerbosePreference = "SilentlyContinue"
}

if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    $COMPOSE = "docker-compose"
} elseif (Get-Command docker -ErrorAction SilentlyContinue) {
    $COMPOSE = "docker compose"
} else {
    Write-Host "elastic-container requires docker compose!"
    exit 2
}

switch ($ACTION) {
    "stage" {
        # Collect the Elastic, Kibana, and Elastic-Agent Docker images
        docker pull "docker.elastic.co/elasticsearch/elasticsearch:$env:STACK_VERSION"
        docker pull "docker.elastic.co/kibana/kibana:$env:STACK_VERSION"
        docker pull "docker.elastic.co/beats/elastic-agent:$env:STACK_VERSION"
    }
    "start" {
        passphrase_reset

        get_host_ip

        Write-Host "Starting Elastic Stack network and containers."

        & $COMPOSE up -d --no-deps 

        configure_kbn

        Write-Host "Waiting 40 seconds for Fleet Server setup."
        Write-Host

        Start-Sleep -Seconds 40

        Write-Host "Populating Fleet Settings."
        set_fleet_values
        Write-Host

        Write-Host "READY SET GO!"
        Write-Host
        Write-Host "Browse to https://localhost:$env:KIBANA_PORT"
        Write-Host "Username: $env:ELASTIC_USERNAME"
        Write-Host "Passphrase: $env:ELASTIC_PASSWORD"
        Write-Host
    }
    "stop" {
        Write-Host "Stopping running containers."

        & $COMPOSE stop 
    }
    "destroy" {
        Write-Host "#####"
        Write-Host "Stopping and removing the containers, network, and volumes created."
        Write-Host "#####"
        & $COMPOSE down -v
    }
    "restart" {
        Write-Host "#####"
        Write-Host "Restarting all Elastic Stack components."
        Write-Host "#####"
        & $COMPOSE restart elasticsearch kibana fleet-server
    }
    "status" {
        & $COMPOSE ps | Select-String -Pattern "setup" -NotMatch
    }
    "clear" {
        clear_documents
    }
    "help" {
        usage
    }
    default {
        Write-Host "Proper syntax not used. See the usage"
        usage
    }
}