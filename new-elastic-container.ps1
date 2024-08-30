# Elastic Container PowerShell Script

# These should be set in the .env file
$env:LinuxDR = $null
$env:WindowsDR = $null
$env:MacOSDR = $null

$COMPOSE = $null

# Load environment variables from .env file
Get-Content .env | ForEach-Object {
    if ($_ -match '^(.+)=(.+)$') {
        Set-Item -Path "Env:$($Matches[1])" -Value $($Matches[2])
    }
}

$HEADERS = @(
    @{
        "kbn-version" = $env:STACK_VERSION
        "kbn-xsrf" = "kibana"
        "Content-Type" = "application/json"
    }
)

function Passphrase-Reset {
    if (Select-String -Path ".env" -Pattern "changeme" -Quiet) {
        Write-Host "Sorry, looks like you haven't updated the passphrase from the default"
        Write-Host "Please update the changeme passphrases in the .env file."
        exit 1
    } else {
        Write-Host "Passphrase has been reset. Proceeding."
    }
}

function Show-Usage {
    $usage = @"
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
    Write-Host $usage
}

function Configure-Kbn {
    $MAXTRIES = 15
    $i = $MAXTRIES

    while ($i -gt 0) {
        $STATUS = (Invoke-WebRequest -Uri $env:LOCAL_KBN_URL -Method Head -SkipCertificateCheck).StatusCode
        Write-Host ""
        Write-Host "Attempting to enable the Detection Engine and install prebuilt Detection Rules."

        if ($STATUS -eq 302 -or $STATUS -eq 200) {
            Write-Host ""
            Write-Host "Kibana is up. Proceeding."
            Write-Host ""
            $output = Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/index" -Method Post -Headers $HEADERS -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
            if (-not $output.acknowledged) {
                Write-Host ""
                Write-Host "Detection Engine setup failed :-("
                exit 1
            }

            Write-Host "Detection engine enabled. Installing prepackaged rules."
            Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/prepackaged" -Method Put -Headers $HEADERS -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck

            Write-Host ""
            Write-Host "Prepackaged rules installed!"
            Write-Host ""
            if ([int]$env:LinuxDR -eq 0 -and [int]$env:WindowsDR -eq 0 -and [int]$env:MacOSDR -eq 0) {
                Write-Host "No detection rules enabled in the .env file, skipping detection rules enablement."
                Write-Host ""
                break
            } else {
                Write-Host "Enabling detection rules"
                if ([int]$env:LinuxDR -eq 1) {
                    $body = @{
                        query = 'alert.attributes.tags: ("Linux" OR "OS: Linux")'
                        action = "enable"
                    } | ConvertTo-Json

                    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/_bulk_action" -Method Post -Headers $HEADERS -Body $body -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
                    Write-Host ""
                    Write-Host "Successfully enabled Linux detection rules"
                }
                if ([int]$env:WindowsDR -eq 1) {
                    $body = @{
                        query = 'alert.attributes.tags: ("Windows" OR "OS: Windows")'
                        action = "enable"
                    } | ConvertTo-Json

                    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/_bulk_action" -Method Post -Headers $HEADERS -Body $body -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
                    Write-Host ""
                    Write-Host "Successfully enabled Windows detection rules"
                }
                if ([int]$env:MacOSDR -eq 1) {
                    $body = @{
                        query = 'alert.attributes.tags: ("macOS" OR "OS: macOS")'
                        action = "enable"
                    } | ConvertTo-Json

                    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/_bulk_action" -Method Post -Headers $HEADERS -Body $body -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
                    Write-Host ""
                    Write-Host "Successfully enabled MacOS detection rules"
                }
            }
            Write-Host ""
            break
        } else {
            Write-Host ""
            Write-Host "Kibana still loading. Trying again in 40 seconds"
        }

        Start-Sleep -Seconds 40
        $i--
    }
    if ($i -eq 0) {
        Write-Host "Exceeded MAXTRIES ($MAXTRIES) to setup detection engine."
        exit 1
    }
    return $true
}

function Get-HostIP {
    $ipvar = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress
    return $ipvar
}

function Set-FleetValues {
    $CURRENT_SETTINGS = Invoke-RestMethod -Uri "$env:KIBANA_HOST/api/fleet/agents/setup" -Method Get -Headers $HEADERS -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck

    if ($CURRENT_SETTINGS.isInitialized) {
        Write-Host "Fleet settings are already configured."
        return
    }

    Write-Host "Fleet is not initialized, setting up Fleet..."

    $fingerprint = (docker compose exec -w /usr/share/elasticsearch/config/certs/ca elasticsearch cat ca.crt | openssl x509 -noout -fingerprint -sha256).Split("=")[1].Replace(":", "")
    
    $fleetServerHosts = @{ fleet_server_hosts = @("https://${ipvar}:$env:FLEET_PORT") } | ConvertTo-Json
    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/settings" -Method Put -Headers $HEADERS -Body $fleetServerHosts -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck

    $hosts = @{ hosts = @("https://${ipvar}:9200") } | ConvertTo-Json
    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/outputs/fleet-default-output" -Method Put -Headers $HEADERS -Body $hosts -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck

    $caFingerprint = @{ ca_trusted_fingerprint = $fingerprint } | ConvertTo-Json
    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/outputs/fleet-default-output" -Method Put -Headers $HEADERS -Body $caFingerprint -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck

    $configYaml = @{ config_yaml = "ssl.verification_mode: certificate" } | ConvertTo-Json
    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/outputs/fleet-default-output" -Method Put -Headers $HEADERS -Body $configYaml -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck

    $policyBody = @{
        name = "Endpoint Policy"
        description = ""
        namespace = "default"
        monitoring_enabled = @("logs", "metrics")
        inactivity_timeout = 1209600
    } | ConvertTo-Json

    $policy = Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/agent_policies?sys_monitoring=true" -Method Post -Headers $HEADERS -Body $policyBody -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
    $policy_id = $policy.item.id

    $pkgVersion = (Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/epm/packages/endpoint" -Method Get -Headers $HEADERS -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck).item.version

    $packagePolicyBody = @{
        name = "Elastic Defend"
        description = ""
        namespace = "default"
        policy_id = $policy_id
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
            version = $pkgVersion
        }
    } | ConvertTo-Json -Depth 10

    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/package_policies" -Method Post -Headers $HEADERS -Body $packagePolicyBody -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
}

function Clear-Documents {
    $logsResult = Invoke-RestMethod -Uri "https://${ipvar}:9200/_data_stream/logs-*" -Method Delete -Headers $HEADERS -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
    if ($logsResult.acknowledged) {
        Write-Host "Successfully cleared logs data stream"
    } else {
        Write-Host "Failed to clear logs data stream"
    }

    $metricsResult = Invoke-RestMethod -Uri "https://${ipvar}:9200/_data_stream/metrics-*" -Method Delete -Headers $HEADERS -Credential (New-Object PSCredential ($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -SkipCertificateCheck
    if ($metricsResult.acknowledged) {
        Write-Host "Successfully cleared metrics data stream"
    } else {
        Write-Host "Failed to clear metrics data stream"
    }
}

# Main script logic
$ACTION = $args[0]

if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
    $COMPOSE = "docker-compose"
} elseif (Get-Command "docker" -ErrorAction SilentlyContinue) {
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
        Passphrase-Reset
        $ipvar = Get-HostIP
        Write-Host "Starting Elastic Stack network and containers."
        Invoke-Expression "$COMPOSE up -d --no-deps"
        Configure-Kbn
        Write-Host "Waiting 40 seconds for Fleet Server setup."
        Write-Host ""
        Start-Sleep -Seconds 40
        Write-Host "Populating Fleet Settings."
        Set-FleetValues
        Write-Host ""
        Write-Host "READY SET GO!"
        Write-Host ""
        Write-Host "Browse to https://localhost:$env:KIBANA_PORT"
        Write-Host "Username: $env:ELASTIC_USERNAME"
        Write-Host "Passphrase: $env:ELASTIC_PASSWORD"
        Write-Host ""
    }
    "stop" {
        Write-Host "Stopping running containers."
        Invoke-Expression "$COMPOSE stop"
    }
    "destroy" {
        Write-Host "#####"
        Write-Host "Stopping and removing the containers, network, and volumes created."
        Write-Host "#####"
        Invoke-Expression "$COMPOSE down -v"
    }
    "restart" {
        Write-Host "#####"
        Write-Host "Restarting all Elastic Stack components."
        Write-Host "#####"
        Invoke-Expression "$COMPOSE restart elasticsearch kibana fleet-server"
    }
    "status" {
        Invoke-Expression "$COMPOSE ps" | Where-Object { $_ -notmatch 'setup' }
    }
    "clear" {
        Clear-Documents
    }
    "help" {
        Show-Usage
    }
    default {
        Write-Host "Proper syntax not used. See the usage`n"