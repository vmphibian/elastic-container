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

$HEADERS = @(
    @{ Name = "kbn-version"; Value = $env:STACK_VERSION }
    @{ Name = "kbn-xsrf"; Value = "kibana" }
    @{ Name = "Content-Type"; Value = "application/json" }
)

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
    $MAXTRIES = 15
    $i = $MAXTRIES

    while ($i -gt 0) {
        $STATUS = (Invoke-WebRequest -Uri $env:LOCAL_KBN_URL -Method Head -UseBasicParsing).StatusCode
        Write-Host
        Write-Host "Attempting to enable the Detection Engine and install prebuilt Detection Rules."

        if ($STATUS -eq 302) {
            Write-Host
            Write-Host "Kibana is up. Proceeding."
            Write-Host
            $output = Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/index" -Method Post -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))
            if ($output.acknowledged -ne $true) {
                Write-Host
                Write-Host "Detection Engine setup failed :-("
                exit 1
            }

            Write-Host "Detection engine enabled. Installing prepackaged rules."
            Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/prepackaged" -Method Put -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))

            Write-Host
            Write-Host "Prepackaged rules installed!"
            Write-Host
            if ($LinuxDR -eq 0 -and $WindowsDR -eq 0 -and $MacOSDR -eq 0) {
                Write-Host "No detection rules enabled in the .env file, skipping detection rules enablement."
                Write-Host
                break
            } else {
                Write-Host "Enabling detection rules"
                if ($LinuxDR -eq 1) {
                    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/_bulk_action" -Method Post -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -Body @{
                        query = "alert.attributes.tags: (""Linux"" OR ""OS: Linux"")"
                        action = "enable"
                    }
                    Write-Host
                    Write-Host "Successfully enabled Linux detection rules"
                }
                if ($WindowsDR -eq 1) {
                    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/_bulk_action" -Method Post -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -Body @{
                        query = "alert.attributes.tags: (""Windows"" OR ""OS: Windows"")"
                        action = "enable"
                    }
                    Write-Host
                    Write-Host "Successfully enabled Windows detection rules"
                }
                if ($MacOSDR -eq 1) {
                    Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/detection_engine/rules/_bulk_action" -Method Post -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) -Body @{
                        query = "alert.attributes.tags: (""macOS"" OR ""OS: macOS"")"
                        action = "enable"
                    }
                    Write-Host
                    Write-Host "Successfully enabled MacOS detection rules"
                }
            }
            Write-Host
            break
        } else {
            Write-Host
            Write-Host "Kibana still loading. Trying again in 40 seconds"
        }

        Start-Sleep -Seconds 40
        $i--
    }
    if ($i -eq 0) {
        Write-Host "Exceeded MAXTRIES ($MAXTRIES) to setup detection engine."
        exit 1
    }
    return 0
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
    # Get the current Fleet settings
    $CURRENT_SETTINGS = Invoke-RestMethod -Uri "$env:KIBANA_HOST/api/fleet/agents/setup" -Method Get -Headers @{ "Content-Type" = "application/json" } -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))

    # Check if Fleet is already set up
    if ($CURRENT_SETTINGS.isInitialized -eq $true) {
        Write-Host "Fleet settings are already configured."
        return
    }

    Write-Host "Fleet is not initialized, setting up Fleet..."
    
    $fingerprint = & $COMPOSE exec -w /usr/share/elasticsearch/config/certs/ca elasticsearch cat ca.crt | openssl x509 -noout -fingerprint -sha256 | cut -d "=" -f 2 | tr -d ":"
    $body = @{
        fleet_server_hosts = @("https://$($ipvar):$($env:FLEET_PORT)")
    }
    $body | ConvertTo-Json | Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/settings" -Method Put -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))
    $body = @{
        hosts = @("https://$ipvar:9200")
    }
    $body | ConvertTo-Json | Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/outputs/fleet-default-output" -Method Put -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))
    $body = @{
        ca_trusted_fingerprint = $fingerprint
    }
    $body | ConvertTo-Json | Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/outputs/fleet-default-output" -Method Put -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))
    $body = @{
        config_yaml = "ssl.verification_mode: certificate"
    }
    $body | ConvertTo-Json | Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/outputs/fleet-default-output" -Method Put -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))
    $policy_id = @{
        name = "Endpoint Policy"
        description = ""
        namespace = "default"
        monitoring_enabled = @("logs", "metrics")
        inactivity_timeout = 1209600
    } | ConvertTo-Json | Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/agent_policies?sys_monitoring=true" -Method Post -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) | Select-Object -ExpandProperty item | Select-Object -ExpandProperty id
    $pkg_version = Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/epm/packages/endpoint" -Method Get -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) | Select-Object -ExpandProperty item | Select-Object -ExpandProperty version
    $body = @{
        name = "Elastic Defend"
        description = ""
        namespace = "default"
        policy_id = $policy_id
        enabled = $true
        inputs = @(@{
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
        })
        package = @{
            name = "endpoint"
            title = "Elastic Defend"
            version = $pkg_version
        }
    }
    $body | ConvertTo-Json | Invoke-RestMethod -Uri "$env:LOCAL_KBN_URL/api/fleet/package_policies" -Method Post -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force)))
}

function clear_documents {
    if ((Invoke-RestMethod -Uri "https://$ipvar:9200/_data_stream/logs-*" -Method Delete -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) | Select-String -Pattern "true").Count -gt 0) {
        Write-Host "Successfully cleared logs data stream"
    } else {
        Write-Host "Failed to clear logs data stream"
    }
    Write-Host
    if ((Invoke-RestMethod -Uri "https://$ipvar:9200/_data_stream/metrics-*" -Method Delete -Headers $HEADERS -Credential (New-Object PSCredential($env:ELASTIC_USERNAME, (ConvertTo-SecureString $env:ELASTIC_PASSWORD -AsPlainText -Force))) | Select-String -Pattern "true").Count -gt 0) {
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