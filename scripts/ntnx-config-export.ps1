<#
    .SYNOPSIS
        Nutanix Cluster configuration export script to JSON via REST API  

    .DESCRIPTION
        The purpose of this script is to collect all Nutanix configuration elements and export them in a JSON file.
        The script can be run either against Prism Central or Prism Element. There will be one JSON file created per cluster.
        Prism Credentials need to be provided when prompted, this is used to connect to REST API.
        The Output Report will be saved in same Directory from where you run the script. 
        Things the script is currently not doing:
        - Syslog

    .PARAMETER 
        None  
    
    .INPUTS
        None

    .OUTPUTS
        None

    .NOTES
        Version:        0.3
        Author:         David Zoerb, Staff Consulting Architect <dz@nutanix.com>
        Organization:   Nutanix
        Creation Date:  May 12th 2020
        Purpose/Change: Added Networks section, Metro, Protection Domains, AD, SSL Cert

    .EXAMPLE
        Self explanatory, just run the script, specify PC IP or FQDN and enter your credentials.
#>

# Verbose Output
$debug = "true"

##############################################
# Nothing to configure below this line - Starting the main function of the script
################################################

# Global Error Handling
if ($debug -ne "true") { $ErrorActionPreference = 'SilentlyContinue' }

# Checking OS and add SkipCertificateCheck if required
$myvarOS=$PSVersionTable.Platform
if($myvarOS -eq "Unix" -and $($PSDefaultParameterValues.'Invoke-RestMethod:SkipCertificateCheck') -ne "true") {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)
    $PSDefaultParameterValues.Add("Invoke-WebRequest:SkipCertificateCheck",$true) 
}

# Print our awesome header :-)
Write-Host "__    _____    ___________  ______  __    _________ " -ForegroundColor Blue -NoNewline; Write-Host "__    __" -ForegroundColor DarkGreen
Write-Host "XX\   XX\XX\   XX\XXXXXXXX\ XXXXXX\ XX\   XX\XXXXXX\" -ForegroundColor Blue -NoNewline; Write-Host "XX\   XX\" -ForegroundColor DarkGreen
Write-Host "XXX\  XX XX |  XX \__XX  __XX  __XX\XXX\  XX \_XX  _" -ForegroundColor Blue -NoNewline; Write-Host "XX |  XX |" -ForegroundColor DarkGreen
Write-Host "XXXX\ XX XX |  XX |  XX |  XX /  XX XXXX\ XX | XX | " -ForegroundColor Blue -NoNewline; Write-Host "\XX\ XX  |" -ForegroundColor DarkGreen
Write-Host "XX XX\XX XX |  XX |  XX |  XXXXXXXX XX XX\XX | XX |  " -ForegroundColor Blue -NoNewline; Write-Host "\XXXX  /" -ForegroundColor DarkGreen
Write-Host "XX \XXXX XX |  XX |  XX |  XX  __XX XX \XXXX | XX |  " -ForegroundColor Blue -NoNewline; Write-Host "XX  XX<" -ForegroundColor DarkGreen
Write-Host "XX |\XXX XX |  XX |  XX |  XX |  XX XX |\XXX | XX | " -ForegroundColor Blue -NoNewline; Write-Host "XX  /\XX\" -ForegroundColor DarkGreen
Write-Host "XX | \XX \XXXXXX  |  XX |  XX |  XX XX | \XX XXXXXX\" -ForegroundColor Blue -NoNewline; Write-Host "XX /  XX |" -ForegroundColor DarkGreen
Write-Host "\__|  \__|\______/   \__|  \__|  \__\__|  \__\______\" -ForegroundColor Blue -NoNewline; Write-Host "__|  \__|" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "Nutanix Cluster Audit REST API script via Prism Central" -ForegroundColor DarkGray; Write-Host ""
if ($myvarCluster -AND $myvarHeader) {
    Write-Host "We found an active connection with authentication header to cluster $myvarCluster - reusing it..." -ForegroundColor Cyan; Write-Host ""
} else {
    $myvarCluster = Read-Host "Please specify the Prism Central IP address or FQDN"  ; Write-Host;  
}

# User Input for credentials
if(!$myvarCredentials) { $myvarCredentials = $host.ui.PromptForCredential("Need credentials", "Please specify your Prism login credentials", "", "") }

# Adding certificate exception to prevent API errors
if($myvarOS -ne "Unix") {
    try {
    Write-Host "$(get-date) [INFO] Adding certificate exception to prevent API connectivity issues..." -ForegroundColor DarkGray;
    add-type @"
    	using System.Net;
    	using System.Security.Cryptography.X509Certificates;
    	public class TrustAllCertsPolicy : ICertificatePolicy {
    		public bool CheckValidationResult(
    			ServicePoint srvPoint, X509Certificate certificate,
    			WebRequest request, int certificateProblem) {
    			return true;
    		}
    	}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch { }
}

################################################
# Building Nutanix API Auth Header
################################################
if(!$myvarPassword) { $myvarPassword = $((New-Object PSCredential "$($myvarCredentials.username)",$($myvarCredentials.Password)).GetNetworkCredential().Password) }
if(!$myvarHeader) { $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($myvarCredentials.Username)"+":"+$($myvarPassword)))} }
if(!$myvarType) { $myvarType = "application/json" }

################################################
# Setting API URIs
################################################
$myvarPCURLv1 = "https://" + $myvarCluster + ":9440/PrismGateway/services/rest/v1"
$myvarPCURLv2 = "https://" + $myvarCluster + ":9440/PrismGateway/services/rest/v2.0"
$myvarPCURLv3 = "https://" + $myvarCluster + ":9440/api/nutanix/v3"

################################################
# Connect to PC and get all  clusters
################################################
try {
    Write-Host "$(get-date) [ACTION] Connecting to Prism Central $($myvarCluster) and getting all connected PE clusters..." -ForegroundColor Green
    $myvarBody = '{"kind":"cluster"}'
    $myvarResult = Invoke-RestMethod -Method POST -Uri $($myvarPCURLv3+"/clusters/list") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType -Body $myvarBody
    Write-Host "$(get-date) [ACTION] Removing Prism Central from the array of found clusters..." -ForegroundColor Green
    $myvarResult = $myvarResult.entities | Where-Object { $_.spec.name -ne "Unnamed" } | Sort-Object -Property { $_.spec.name }
    Write-Host "$(get-date) [INFO] Found a total of $($myvarResult.Count) connected clusters: $($($myvarResult.spec.name) -join ", ")" -ForegroundColor DarkGray
} catch { $myvarErrorMessage = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvarErrorMessage" -ForegroundColor Red; Return; }

foreach ($myvarItem in $myvarResult) {
    $myvarUUID = $myvarItem.metadata.uuid
    $myvarName = $myvarItem.spec.name
    $myvarGenesisBody = '{"value":"{\".oid\":\"LifeCycleManager\",\".method\":\"lcm_framework_rpc\",\".kwargs\":{\"method_class\":\"LcmFramework\",\"method\":\"get_config\"}}"}'

    Write-Host "$(get-date) [ACTION] Processing cluster $($myvarName)..." -ForegroundColor Cyan 
    Write-Host "$(get-date) [INFO] Getting General Cluster Details..." -ForegroundColor DarkGray
    $myvarClusterDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/clusters/$myvarUUID") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType  
    Write-Host "$(get-date) [INFO] Getting LCM Configuration..." -ForegroundColor DarkGray
    $myvarGenesisDetails = Invoke-RestMethod -Method POST -Uri $($myvarPCURLv1+"/genesis?proxyClusterUuid=$myvarUUID") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType -Body $myvarGenesisBody 
    Write-Host "$(get-date) [INFO] Getting SNMP Configuration..." -ForegroundColor DarkGray
    $myvarSNMPDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/snmp?proxyClusterUuid=$myvarUUID") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType    
    Write-Host "$(get-date) [INFO] Getting SMTP Configuration..." -ForegroundColor DarkGray
    $myvarSMTPDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/cluster/smtp?proxyClusterUuid=$myvarUUID") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType    
    Write-Host "$(get-date) [INFO] Getting Alert Configuration..." -ForegroundColor DarkGray
    $myvarAlertConfigDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/alerts/configuration?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType 
    Write-Host "$(get-date) [INFO] Getting Pulse Configuration..." -ForegroundColor DarkGray
    $myvarPulseDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/pulse?proxyClusterUuid=$myvarUUID") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType  
    Write-Host "$(get-date) [INFO] Getting Remote Support Configuration..." -ForegroundColor DarkGray
    $myvarRemoteSupportDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/cluster/remote_support?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType 
    Write-Host "$(get-date) [INFO] Getting Storage Pool Configuration..." -ForegroundColor DarkGray
    $myvarStoragePoolDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/storage_pools?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType    
    Write-Host "$(get-date) [INFO] Getting Storage Container Details..." -ForegroundColor DarkGray
    $myvarStorageContainerDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/containers?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType  
    Write-Host "$(get-date) [INFO] Getting Prism Central Registration Status..." -ForegroundColor DarkGray
    $myvarPrismCentralDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/multicluster/cluster_external_state?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType 
    Write-Host "$(get-date) [INFO] Getting Hypervisor Host Details..." -ForegroundColor DarkGray
    $myvarHostDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/hosts?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType   
    Write-Host "$(get-date) [INFO] Getting Directory Configuration Information..." -ForegroundColor DarkGray
    $myvarDirectoryDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/authconfig?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType 
    if ($($myvarDirectoryDetails.directoryList.name)) {
        Write-Host "$(get-date) [INFO] Getting Directory Role Mapping Configuration Information..." -ForegroundColor DarkGray
        $myvarAuthConfigRoleMappingDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/authconfig/directories/"+$( $myvarDirectoryDetails.directoryList.name)+"/role_mappings?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType
    } else {
        Write-Host "$(get-date) [WARN] Unable to read Directory Information, skipping Role Mapping Configuration Information..." -ForegroundColor Yellow
    }   
    if ($($myvarClusterDetails.hypervisorTypes -eq "kKvm")) { 
        Write-Host "$(get-date) [INFO] Getting Network Configuration Information..." -ForegroundColor DarkGray
        $myvarNetworkDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv2+"/networks?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType
        Write-Host "$(get-date) [INFO] Getting Network Switch Configuration Information..." -ForegroundColor DarkGray
        $myvarNetworkSwitchDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/switches?configOnly=true&proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType
    }   
    Write-Host "$(get-date) [INFO] Getting Remote Site Configuration..." -ForegroundColor DarkGray
    $myvarRemoteSiteDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/remote_sites?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType  
    Write-Host "$(get-date) [INFO] Getting Protection Domain Configuration..." -ForegroundColor DarkGray
    $myvarPDDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/protection_domains?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType    
    Write-Host "$(get-date) [INFO] Getting Nutanix Licensing information via Portal API connectivity..." -ForegroundColor DarkGray
    $myvarPortalDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/portal/config?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType 
    Write-Host "$(get-date) [INFO] Getting HTTP Proxy Configuration..." -ForegroundColor DarkGray
    $myvarHTTPProxyDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/http_proxies?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType   
    Write-Host "$(get-date) [INFO] Getting HTTP Proxy Whitelist Configuration..." -ForegroundColor DarkGray
    $myvarHTTPProxyWhitelistDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/http_proxies/whitelist?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType    
    Write-Host "$(get-date) [INFO] Getting Nutanix Files (AFS) Configuration..." -ForegroundColor DarkGray
    $myvarAFSDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/vfilers?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType  
    Write-Host "$(get-date) [INFO] Getting Nutanix Volume Group Configuration..." -ForegroundColor DarkGray
    $myvarVolumeGroupDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv2+"/volume_groups?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType    
    Write-Host "$(get-date) [INFO] Getting Local User Configuration..." -ForegroundColor DarkGray
    $myvarLocalUserDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/users?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType
    #Write-Host "$(get-date) [INFO] Getting any cutom UI settings..." -ForegroundColor DarkGray
    #$myvarCustomUIDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/application/system_data?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType    
    Write-Host "$(get-date) [INFO] Getting cluster SSL certificate configuration..." -ForegroundColor DarkGray
    $myvarSSLCertDetails = Invoke-RestMethod -Method GET -Uri $($myvarPCURLv1+"/keys/pem?proxyClusterUuid=$myvarUUID") -TimeoutSec 30 -Headers $myvarHeader -ContentType $myvarType 
    
    # Check if we were able to get the LCM URL
    if($myvarGenesisDetails) { $myvarLCMDetails = ConvertFrom-Json $myvarGenesisDetails.value }

    # Remove Storage Containers "SelfServiceContainer" and "NutanixManagementShare"
    $myvarStorageContainerDetail = $myvarStorageContainerDetails.entities | Where-Object { $_.name -ne "SelfServiceContainer" -AND $_.name -ne "NutanixManagementShare" } | Sort-Object -Property { $_.name }   
    
    # Start putting the configuration together and prepare for JSON export
    $myvarObj = [PSCustomObject]@{
        "clusterName" = $($myvarClusterDetails.name)
        "clusterUUID" = $($myvarClusterDetails.uuid)
        "hypervisorType" = $($myvarClusterDetails.hypervisorTypes)
        "clusterExternalIPAddress" = $($myvarClusterDetails.clusterExternalIPAddress)
        "clusterExternalDataServicesIPAddress" = $($myvarClusterDetails.clusterExternalDataServicesIPAddress)
        "managementServerIpAddress" = $(if($($myvarClusterDetails.hypervisorTypes -eq "kVMware")) { $($myvarClusterDetails.managementServers.ipAddress) } else {"not required on AHV"})
        "clusterRedundancyFactor" = $($myvarClusterDetails.clusterRedundancyState.desiredRedundancyFactor)
        "faultToleranceDomainType" = $($myvarClusterDetails.faultToleranceDomainType)
        "numNodes" = $($myvarClusterDetails.numNodes)
        "timezone" = $($myvarClusterDetails.timezone)
        "nameServers" = $($($myvarClusterDetails.nameServers) -join ", ")
        "ntpServers" = $($($myvarClusterDetails.ntpServers) -join ", ")
        "lcmRepository" = $($myvarLCMDetails.'.return'.url)
        "lcmAutoUpdate" = $($myvarLCMDetails.'.return'.auto_update_enabled)
        "prismCentralIpAddress" = $($myvarPrismCentralDetails.clusterDetails.ipAddresses)
        "prismCentralConnected" = $($myvarPrismCentralDetails.remoteConnectionExists)
        "pulseEnabled" = $($myvarPulseDetails.enable)
        "remoteSupportEnabled" = $($myvarRemoteSupportDetails.enable.enabled)
        "portalConnection" = $($myvarPortalDetails.status)
        "portalApiKey" = $($myvarPortalDetails.portalApiKey)
        "storagePoolName" = $($myvarStoragePoolDetails.entities.name)
        "globalFilesystemWhitelist" = $($($myvarClusterDetails.globalNfsWhiteList) -join ", ")
        hostDetails = @(
            foreach($myvarHost in $($myvarHostDetails.entities)) {
                [PSCustomObject]@{
                    "name" = $($myvarHost.name)
                    "blockModelName" = $($myvarHost.blockModelName)
                    "blockSerial" = $($myvarHost.blockSerial)
                    "nodeSerial" = $($myvarHost.serial)
                    "position" = $($myvarHost.position.ordinal)
                    "serviceVMExternalIP" = $($myvarHost.serviceVMExternalIP)
                    "hypervisorAddress" = $($myvarHost.hypervisorAddress)
                    "controllerVmBackplaneIp" = $($myvarHost.controllerVmBackplaneIp)
                    "managementServerName" = $($myvarHost.managementServerName)
                    "ipmiAddress" = $($myvarHost.ipmiAddress)
                }
            }
        )
        storageContainer = @(
            foreach($myvarStorageContainer in ($myvarStorageContainerDetail)) {
                [PSCustomObject]@{
                    "name" = $($myvarStorageContainer.name)
                    "nfsWhiteList" = $($($myvarStorageContainer.nfsWhitelist) -join ", ")
                    "replicationFactor" = $($myvarStorageContainer.replicationFactor)
                    "compressionEnabled" = $($myvarStorageContainer.compressionEnabled)
                    "compressionDelayInSecs" = $($myvarStorageContainer.compressionDelayInSecs)
                    "fingerPrintOnWrite" = $($myvarStorageContainer.fingerPrintOnWrite)
                    "onDiskDedup" = $($myvarStorageContainer.onDiskDedup)
                    "erasureCode" = $($myvarStorageContainer.erasureCode)
                }
            }
        )
        volumeGroup = @($(if($($myvarVolumeGroupDetails)) { 
            foreach($myvarVolumeGroup in $($myvarVolumeGroupDetails.entities)) {
                [PSCustomObject]@{
                    "name" = $($myvarVolumeGroup.name)
                    "uuid" = $($myvarVolumeGroup.uuid)
                    "description" = $($myvarVolumeGroup.description)
                    "disk_list" = $($myvarVolumeGroup.disk_list)
                    "iscsi_target" = $($myvarVolumeGroup.iscsi_target)
                    "attachment_list" = $($myvarVolumeGroup.attachment_list)
                    "flash_mode_enabled" = $($myvarVolumeGroup.flash_mode_enabled)
                    "enabled_authentications" = $($myvarVolumeGroup.name)
                    "is_shared" = $($myvarVolumeGroup.uuid)
                }
            }
        }))
        securityComplianceConfig = @(
            [PSCustomObject]@{
                "schedule" = $($myvarClusterDetails.securityComplianceConfig.schedule)
                "enableAide" = $($myvarClusterDetails.securityComplianceConfig.enableAide)
                "enableCore" = $($myvarClusterDetails.securityComplianceConfig.enableCore)
                "enableHighStrengthPassword" = $($myvarClusterDetails.securityComplianceConfig.enableHighStrengthPassword)
                "enableBanner" = $($myvarClusterDetails.securityComplianceConfig.enableBanner)
                "enableSNMPv3Only" = $($myvarClusterDetails.securityComplianceConfig.enableSNMPv3Only)
            }
        )
        hypervisorSecurityComplianceConfig = @(
            [PSCustomObject]@{
                "schedule" = $($myvarClusterDetails.hypervisorSecurityComplianceConfig.schedule)
                "enableAide" = $($myvarClusterDetails.hypervisorSecurityComplianceConfig.enableAide)
                "enableCore" = $($myvarClusterDetails.hypervisorSecurityComplianceConfig.enableCore)
                "enableHighStrengthPassword" = $($myvarClusterDetails.hypervisorSecurityComplianceConfig.enableHighStrengthPassword)
                "enableBanner" = $($myvarClusterDetails.hypervisorSecurityComplianceConfig.enableBanner)
            }
        )
        alerting = @(
            [PSCustomObject]@{
                "enabled" = $($myvarAlertConfigDetails.enable)
                "smtpServerAddress" = $($myvarSMTPDetails.address)
                "smtpServerPort" = $($myvarSMTPDetails.port)
                "smtpStatus" = $($myvarSMTPDetails.emailStatus.status)
                "enableEmailDigest" = $($myvarAlertConfigDetails.enableEmailDigest)
                "emailContactList" = ($($myvarAlertConfigDetails.emailContactList) -join ", ")
                "emailConfigRules" = $($myvarAlertConfigDetails.emailConfigRules)
                "defaultNutanixEmail" = $($myvarAlertConfigDetails.defaultNutanixEmail)
            }
        )
        snmp = @(
            [PSCustomObject]@{
                "enabled" = $($myvarSNMPDetails.enabled)
                snmpUsers = @($(if($($myvarSNMPDetails.snmpUsers)) { 
                    [PSCustomObject]@{
                        "username" = $($myvarSNMPDetails.snmpUsers.username)
                        "authType" = $($myvarSNMPDetails.snmpUsers.authType)
                        "authKey" = $($myvarSNMPDetails.snmpUsers.authKey)
                        "privType" = $($myvarSNMPDetails.snmpUsers.privType)
                        "privKey" = $($myvarSNMPDetails.snmpUsers.privKey)
                    }
                }))
                snmpTraps = @($(if($($myvarSNMPDetails.snmpTraps)) { 
                    [PSCustomObject]@{
                        "trapAddress" = $($myvarSNMPDetails.snmpTraps.trapAddress)
                        "trapUsername" = $($myvarSNMPDetails.snmpTraps.trapUsername)
                        "transportProtocol" = $($myvarSNMPDetails.snmpTraps.transportProtocol)
                        "port" = $($myvarSNMPDetails.snmpTraps.port)
                        "inform" = $($myvarSNMPDetails.snmpTraps.inform)
                        "engineID" = $($myvarSNMPDetails.snmpTraps.engineID)
                        "version" = $($myvarSNMPDetails.snmpTraps.version)
                        "communityString" = $($myvarSNMPDetails.snmpTraps.communityString)
                        "receiverName" = $($myvarSNMPDetails.snmpTraps.receiverName)
                    }
                }))
            }
        )
        authentication = @($(if($($myvarDirectoryDetails.directoryList)) { 
            [PSCustomObject]@{
                "name" = $($myvarDirectoryDetails.directoryList.name)
                "directoryType" = $($myvarDirectoryDetails.directoryList.directoryType)
                "connectionType" = $($myvarDirectoryDetails.directoryList.connectionType)
                "domain" = $($myvarDirectoryDetails.directoryList.domain)
                "url" = $($myvarDirectoryDetails.directoryList.url)
                "groupSearchType" = $($myvarDirectoryDetails.directoryList.groupSearchType)
                "serviceAccountUsername" = $($myvarDirectoryDetails.directoryList.serviceAccountUsername)
                roleMapping = @(
                    foreach ($myvarRoleMapping in $myvarAuthConfigRoleMappingDetails) {
                        [PSCustomObject]@{
                            "role" = "$($myvarRoleMapping.role)"
                            "entityType" = "$($myvarRoleMapping.entityType)"
                            "entityValues" = "$($myvarRoleMapping.entityValues)"
                        }
                    }
                )
            }
        }))
        localUsers = @($(if($($myvarLocalUserDetails)) { 
            foreach ($myvarLocalUser in $myvarLocalUserDetails) {
                [PSCustomObject]@{
                    "username" = $($myvarLocalUser.profile.username)
                    "firstName" = $($myvarLocalUser.profile.firstName)
                    "middleInitial" = $($myvarLocalUser.profile.middleInitial)
                    "lastName" = $($myvarLocalUser.profile.lastName)
                    "emailId" = $($myvarLocalUser.profile.emailId)
                    "roles" = $($myvarLocalUser.roles)
                    "enabled" = $($myvarLocalUser.enabled)
                }
            }
        }))
        networks = @( $(if($($myvarClusterDetails.hypervisorTypes -eq "kKvm")) { 
            foreach ($myvarNet in $myvarNetworkDetails.entities) {
                [PSCustomObject]@{
                    "networkName" = $($myvarNet.name)
                    "vlanID" = $($myvarNet.vlan_id)
                    "ipConfig_networkAddress" = $($myvarNet.ip_config.network_address)
                    "ipConfig_prefixLength" = $($myvarNet.ip_config.prefix_length)
                    "ipConfig_defaultGateway" = $($myvarNet.ip_config.default_gateway)
                    "ipConfig_dhcpServerAddress" = $($myvarNet.ip_config.dhcp_server_address)
                    "ipConfig_dhcpOptions_domainName" = $($myvarNet.ip_config.dhcp_options.domain_name)
                    "ipConfig_dhcpOptions_domainNameServer" = $($myvarNet.ip_config.dhcp_options.domain_name_server)
                    "ipConfig_dhcpOptions_domainSearch" = $($myvarNet.ip_config.dhcp_options.domain_search)
                    "ipConfig_dhcpOptions_tftpServerName" = $($myvarNet.ip_config.dhcp_options.tftp_server_name)
                    "ipConfig_dhcpOptions_bootFileName" = $($myvarNet.ip_config.dhcp_options.boot_file_name)
                    "ipConfig_pool_range" = $($myvarNet.ip_config.pool.range)
                }
            }
        }))
        networkSwitch = @( $(if($($myvarClusterDetails.hypervisorTypes -eq "kKvm")) { 
            foreach ($myvarNetworkSwitch in $myvarNetworkSwitchDetails) {
                [PSCustomObject]@{

                    "version" = $($myvarNetworkSwitch.version)
                    "community" = $($myvarNetworkSwitch.community)
                    "securityLevel" = $($myvarNetworkSwitch.securityLevel)
                    "username" = $($myvarNetworkSwitch.username)
                    "authType" = $($myvarNetworkSwitch.authType)
                    "authKey" = $($myvarNetworkSwitch.authKey)
                    "privType" = $($myvarNetworkSwitch.privType)
                    "privKey" = $($myvarNetworkSwitch.privKey)
                    "id" = $($myvarNetworkSwitch.id)
                    "uuid" = $($myvarNetworkSwitch.uuid)
                    "address" = $($myvarNetworkSwitch.address)
                    "snmpProfileNameToApply" = $($myvarNetworkSwitch.snmpProfileNameToApply)
                    "hostAddresses" = $($myvarNetworkSwitch.hostAddresses)
                    "name" = $($myvarNetworkSwitch.name)
                    "managementAddresses" = $($myvarNetworkSwitch.managementAddresses)
                    "description" = $($myvarNetworkSwitch.description)
                    "objectId" = $($myvarNetworkSwitch.objectId)
                    "contactInfo" = $($myvarNetworkSwitch.contactInfo)
                    "locationInfo" = $($myvarNetworkSwitch.locationInfo)
                    "vendorName" = $($myvarNetworkSwitch.vendorName)
                    "services" = $($myvarNetworkSwitch.services)
                    "interfaceIds" = $($myvarNetworkSwitch.interfaceIds)
                    "interfaceUuids" = $($myvarNetworkSwitch.interfaceUuids)
                }
            }
        }))
        httpProxy = @($(if($($myvarHTTPProxyDetails)) { 
            [PSCustomObject]@{
                "address" = $($myvarHTTPProxyDetails[0].address) 
                "port" = $($myvarHTTPProxyDetails[0].port)
                whitelist = @(
                    foreach ($myvarProxyWhitelist in $($myvarHTTPProxyWhitelistDetails.whitelist)) {
                        [PSCustomObject]@{
                            "whitelistTargetType" = $($myvarProxyWhitelist.targetType)
                            "whitelistTarget" = $($myvarProxyWhitelist.target)
                        }
                    }
                ) 
            }
        }))
        sslCert = @(
            [PSCustomObject]@{
                "countryCode" = $($myvarSSLCertDetails.countryCode) 
                "state" = $($myvarSSLCertDetails.state) 
                "city" = $($myvarSSLCertDetails.city) 
                "organizationName" = $($myvarSSLCertDetails.organizationName) 
                "commonName" = $($myvarSSLCertDetails.commonName) 
                "organizationalUnitList" = $($myvarSSLCertDetails.organizationalUnitList) 
                "keyType" = $($myvarSSLCertDetails.keyType) 
                "expiryDate" = $($myvarSSLCertDetails.expiryDate) 
                "signAlgoName" = $($myvarSSLCertDetails.signAlgoName) 
            }
        )
        dataProtectionRemoteSite = @(
            foreach($myvarRemoteSite in ($myvarRemoteSiteDetails)) {
                [PSCustomObject]@{
                    "name" = $($myvarRemoteSite.name) 
                    "uuid" = $($myvarRemoteSite.uuid) 
                    "remoteIpPorts" = $($myvarRemoteSite.remoteIpPort) 
                    "cloudType" = $($myvarRemoteSite.cloudType) 
                    "proxyEnabled" = $($myvarRemoteSite.proxyEnabled) 
                    "compressionEnabled" = $($myvarRemoteSite.compressionEnabled) 
                    "sshEnabled" = $($myvarRemoteSite.sshEnabled) 
                    "vStoreNameMap" = $($myvarRemoteSite.vStoreNameMap) 
                    "networkMapping" = $($myvarRemoteSite.networkMapping) 
                    "capabilities" = $($myvarRemoteSite.capabilities) 
                }
            }
        )
        dataProtectionProtectionDomains = @(
            foreach($myvarPD in ($myvarPDDetails)) {
                [PSCustomObject]@{
                    "name" = $($myvarPD.name) 
                    "vms" = $($myvarPD.vms) 
                    "nfsFiles" = $($myvarPD.nfsFiles) 
                    "volumeGroups" = $($myvarPD.volumeGroups) 
                    "active" = $($myvarPD.active) 
                    "cronSchedules" = $($myvarPD.cronSchedules) 
                    "minSnapshotToRetain" = $($myvarPD.minSnapshotToRetain) 
                    "metroAvailStatus" = $($myvarPD.metroAvail.status) 
                    "metroAvailRole" = $($myvarPD.metroAvail.role)
                    "metroAvailTimeout" = $($myvarPD.metroAvail.timeout)
                    "metroAvailContainer" = $($myvarPD.metroAvail.contaienr)
                    "metroAvailRemoteSite" = $($myvarPD.metroAvail.remoteSite)
                    "metroAvailFailureHandling" = $($myvarPD.metroAvail.failureHandling)
                }
            }
        )
        fileServer = @($(if($($myvarAFSDetails)) { 
            foreach ($myvarAFS in $myvarAFSDetails.entities) {
                [PSCustomObject]@{
                    "name" = $($myvarAFS.name)
                    "uuid" = $($myvarAFS.uuid)
                    "externalIpAddress" = $($myvarAFS.externalIpAddress)
                    "dnsDomainName" = $($myvarAFS.dnsDomainName)
                    "dnsServerIpAddresses" = $($myvarAFS.dnsServerIpAddresses)
                    "ntpServers" = $($myvarAFS.ntpServers)
                    "numShares" = $($myvarAFS.numShares)
                    "numHomeShares" = $($myvarAFS.numHomeShares)
                    "numNestedShares" = $($myvarAFS.numNestedShares)
                    "version" = $($myvarAFS.version)
                    "protectionDomainState" = $($myvarAFS.protectionDomainState)
                    "pdStatus" = $($myvarAFS.pdStatus)
                    "protectionDomainName" = $($myvarAFS.protectionDomainName)
                    "fileServerState" = $($myvarAFS.fileServerState)
                    internalNetwork = @(
                        [PSCustomObject]@{
                            "uuid" = $($myvarAFS.internalNetwork.uuid)
                            "pool" = $($myvarAFS.internalNetwork.pool)
                            "subnetMask" = $($myvarAFS.internalNetwork.subnetMask)
                            "defaultGateway" = $($myvarAFS.internalNetwork.defaultGateway)
                        }
                    )
                    externalNetwork = @(
                        [PSCustomObject]@{
                            "uuid" = $($myvarAFS.externalNetworks.uuid)
                            "pool" = $($myvarAFS.externalNetworks.pool)
                            "subnetMask" = $($myvarAFS.externalNetworks.subnetMask)
                            "defaultGateway" = $($myvarAFS.externalNetworks.defaultGateway)
                        }
                    )
                    domainDirectoryDTO = @(
                        [PSCustomObject]@{
                            "windowsAdDomainName" = $($myvarAFS.domainDirectoryDTO.windowsAdDomainName)
                            "windowsAdUsername" = $($myvarAFS.domainDirectoryDTO.windowsAdUsername)
                            "organizationalUnit" = $($myvarAFS.domainDirectoryDTO.organizationalUnit)
                            "overwriteUserAccount" = $($myvarAFS.domainDirectoryDTO.overwriteUserAccount)
                            "spnDnsOnly" = $($myvarAFS.domainDirectoryDTO.spnDnsOnly)
                            "nvmOnly" = $($myvarAFS.domainDirectoryDTO.nvmOnly)
                            "validateAdCredential" = $($myvarAFS.domainDirectoryDTO.validateAdCredential)
                            "preferredDomainController" = $($myvarAFS.domainDirectoryDTO.preferredDomainController)
                            "addUserAsFsAdmin" = $($myvarAFS.domainDirectoryDTO.addUserAsFsAdmin)
                            "protocolType" = $($myvarAFS.domainDirectoryDTO.protocolType)
                            "rfc2307Enabled" = $($myvarAFS.domainDirectoryDTO.rfc2307Enabled)
                            "useSameCredentialsForDns" = $($myvarAFS.domainDirectoryDTO.useSameCredentialsForDns)

                        }
                    )
                    dnsEntries = @(
                        foreach ($myvarAFSDNS in $myvarAFS.dnsEntries) {
                            [PSCustomObject]@{
                                "dnsName" = $($myvarAFSDNS.dnsName)
                                "dnsIpAddress" = $($myvarAFSDNS.dnsIpAddress)
                                "action" = $($myvarAFSDNS.action)
                                "verified" = $($myvarAFSDNS.verified)
                            }
                        }
                    )
                }
            }
        }))
    }
    # Export to JSON
    Write-Host "$(get-date) [INFO] Writing output to $($myvarName).json..." -ForegroundColor Cyan    
    $myvarObj | ConvertTo-Json -Depth 10 | Out-File $myvarName".json"
}

# Clean up our variables
Write-Host "$(get-date) [INFO] Cleaning up..." -ForegroundColor Cyan
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Write-Host "$(get-date) [INFO] Done!" -ForegroundColor Green
