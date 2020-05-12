<#
  .SYNOPSIS
    Nutanix CALM objects export via REST API
  
  .DESCRIPTION
    The purpose of this script is to collect and export Calm objects and configurations.
    The following items are exported: blueprints, applications, marketplace items, 
    library tasks, library variables, providers, projects.
	
  .PARAMETER myvarUsername
    PC/PE username

  .PARAMETER myvarPassword
    PC/PE username's password

  .PARAMETER myvarCluster
    PC/PE IP
  
  .INPUTS
    None
    
  .OUTPUTS
    None
  
  .NOTES
    Version: 0.1
    Author:	 Igor Zecevic, Senior Consultant <izecevic@nutanix.com>
    Organization:		Nutanix
    Creation Date:	May 12th 2020
  
  .EXAMPLE
    Self explanatory, just run the script, specify PC IP or FQDN and enter your credentials.
#>

#region parameters  
Param
(
    [parameter(mandatory = $false)] $myvarUsername,
    [parameter(mandatory = $false)] $myvarPassword,
    [parameter(mandatory = $true)] $myvarCluster
)
# endregion

# Verbose Output
$debug = "true"

##############################################
# Nothing to configure below this line - Starting the main function of the script
################################################

# Global Error Handling
if ($debug -ne "true") { $ErrorActionPreference = 'SilentlyContinue' }

# Import ntnx-global-functions module
Remove-Module ntnx-global-functions -ErrorAction SilentlyContinue
Import-Module $PSScriptRoot/ntnx-global-functions.psm1 -ErrorAction Stop

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

# Adding certificate exception to prevent API errors
if ($PSVersionTable.PSVersion.Major -lt '6'){
    try {
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
    }
    catch {}
}

################################################
# Building Nutanix API Auth Header
################################################
# User Input for credentials
if (!$myvarUsername) { $myvarUsername = Read-Host "Enter the Prism username"} 
if (!$myvarPassword) { $Securepassword = Read-Host "Enter the Prism user $myvarUsername password" -AsSecureString
} else { $SecurePassword = ConvertTo-SecureString $myvarPassword –asplaintext –force; Remove-Variable myvarPassword}
$myvarCredentials = New-Object PSCredential $username, $SecurePassword

if(!$myvarPassword) { $myvarPassword = $((New-Object PSCredential "$($myvarCredentials.username)",$($myvarCredentials.Password)).GetNetworkCredential().Password) }
if(!$myvarHeader) { $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($myvarCredentials.Username)"+":"+$($myvarPassword)))} }
if(!$myvarType) { $myvarType = "application/json" }

################################################
# Setting API URIs
################################################
$myvarPCURLv1 = "https://" + $myvarCluster + ":9440/PrismGateway/services/rest/v1"
$myvarPCURLv2 = "https://" + $myvarCluster + ":9440/PrismGateway/services/rest/v2.0"
$myvarPCURLv3 = "https://" + $myvarCluster + ":9440/api/nutanix/v3"


####################################################
#* Create Export Directory
####################################################  
# create export directory
$myvarExportPath = "$(Get-Location)/calm_config_export"
Write-Info "Creating Calm Export Config Folder $myvarCluster" -CATEGORY TASKINFO

Write-Info "creating blueprints folder"
If(!(test-path "$myvarExportPath/blueprints")) {
  New-Item -ItemType Directory -Force -Path "$myvarExportPath/blueprints" | Out-Null
}
Write-Info "creating applications folder"
If(!(test-path "$myvarExportPath/applications")) {
  New-Item -ItemType Directory -Force -Path "$myvarExportPath/applications" | Out-Null
}
Write-Info "creating marketplace folder"
If(!(test-path "$myvarExportPath/marketplace")) {
  New-Item -ItemType Directory -Force -Path "$myvarExportPath/marketplace" | Out-Null
}
Write-Info "creating library_taks folder"
If(!(test-path "$myvarExportPath/library_tasks")) {
  New-Item -ItemType Directory -Force -Path "$myvarExportPath/library_tasks" | Out-Null
}
Write-Info "creating library_variables folder"
If(!(test-path "$myvarExportPath/library_variables")) {
  New-Item -ItemType Directory -Force -Path "$myvarExportPath/library_variables" | Out-Null
}
Write-Info "creating providers folder"
If(!(test-path "$myvarExportPath/providers")) {
  New-Item -ItemType Directory -Force -Path "$myvarExportPath/providers" | Out-Null
}
Write-Info "creating projects folder"
If(!(test-path "$myvarExportPath/projects")) {
  New-Item -ItemType Directory -Force -Path "$myvarExportPath/projects" | Out-Null
}

####################################################
#* Export Calm Blueprints
####################################################  
# retreive all blueprints
Write-Info "Exporting Calm Blueprints on PC $myvarCluster" -CATEGORY TASKINFO
$myvarPayload = @{
  kind="blueprint"
  offset=0
  length=250
}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarBpList =  Invoke-PrismAPICall -Method POST -url $($myvarPCURLv3+"/blueprints/list") -credential $myvarCredentials -body $myvarBody

# export all blueprints
foreach ($myvarBp in $myvarBpList.entities.metadata){
  $myvarBpSpec =  Invoke-PrismAPICall -Method GET -url $($myvarPCURLv3+"/blueprints/"+$($myvarBp.uuid)+"/export_json") -credential $myvarCredentials
  ConvertTo-JSON $myvarBpSpec -Depth 10 | Out-File "$myvarExportPath/blueprints/$($myvarBp.name).json"
}

####################################################
#* Export Calm Applications
####################################################    
# retreive all apps
Write-Info "Exporting Calm Applications on PC $myvarCluster" -CATEGORY TASKINFO
$myvarPayload = @{
  kind="app"
  offset=0
  length=250
}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarAppList=  Invoke-PrismAPICall -Method POST -url $($myvarPCURLv3+"/apps/list") -credential $myvarCredentials -body $myvarBody

# export applications
foreach($myvarApp in $myvarAppList.entities) {
  ConvertTo-JSON $($myvarApp.status) -Depth 10 | Out-File "$myvarExportPath/applications/$($myvarApp.status.name).json"
}

####################################################
#* Export Calm MarketPlace Items
####################################################    
# retreive all marketplace items
Write-Info "Exporting Calm Marketplace Items on PC $myvarCluster" -CATEGORY TASKINFO
$myvarPayload = @{
  kind="marketplace_item"
  offset=0
  length=250
}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarMarketplaceList =  Invoke-PrismAPICall -Method POST -url $($myvarPCURLv3+"/calm_marketplace_items/list") -credential $myvarCredentials -body $myvarBody

# export marketplace items
foreach($myvarMarketItem in $myvarMarketplaceList.entities) {
  ConvertTo-JSON $($myvarMarketItem.status) -Depth 10 | Out-File "$myvarExportPath/marketplace/$($myvarMarketItem.status.name).json"
}

####################################################
#* Export Calm Library Tasks
####################################################    
# retreive all library tasks
Write-Info "Exporting Calm Library Tasks on PC $myvarCluster" -CATEGORY TASKINFO
$myvarPayload = @{
  kind="app_task"
  offset=0
  length=250
}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarLibraryTasksList =  Invoke-PrismAPICall -Method POST -url $($myvarPCURLv3+"/app_tasks/list") -credential $myvarCredentials -body $myvarBody

# export library tasks
foreach($myvarLibraryTask in $myvarLibraryTasksList.entities) {
  $myvarLibraryTaskSpec =  Invoke-PrismAPICall -Method GET -url $($myvarPCURLv3+"/app_tasks/"+$($myvarLibraryTask.metadata.uuid)) -credential $myvarCredentials
  ConvertTo-JSON $myvarLibraryTaskSpec -Depth 10 | Out-File "$myvarExportPath/library_tasks/$($myvarLibraryTaskSpec.spec.name).json"
}

####################################################
#* Export Calm Library Variables
####################################################    
# retreive all library variables
Write-Info "Exporting Calm Library Variables Types on PC $myvarCluster" -CATEGORY TASKINFO
$myvarPayload = @{
  kind="app_variable"
  offset=0
  length=250
}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarLibraryVarList =  Invoke-PrismAPICall -Method POST -url $($myvarPCURLv3+"/app_variables/list") -credential $myvarCredentials -body $myvarBody

# export library variable types
foreach($myvarLibraryVar in $myvarLibraryVarList.entities) {
  ConvertTo-JSON $($myvarLibraryVar.status.resources) -Depth 10 | Out-File "$myvarExportPath/library_variables/$($myvarLibraryVar.status.name).json"
}

####################################################
#* Export Calm Providers
####################################################    
# retreive all calm providers
Write-Info "Exporting Calm Providers on PC $myvarCluster" -CATEGORY TASKINFO
$myvarPayload = @{
  kind="account"
  offset=0
  length=250
}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarProvidersList =  Invoke-PrismAPICall -Method POST -url $($myvarPCURLv3+"/accounts/list") -credential $myvarCredentials -body $myvarBody

# export each provider settings
foreach($myvarProvider in $myvarProvidersList.entities) {
  ConvertTo-JSON $($myvarProvider.status.resources) -Depth 10 | Out-File "$myvarExportPath/providers/$($myvarProvider.status.name).json"
}

####################################################
#* Export Calm Projects
####################################################    
# retreive all calm projects
Write-Info "Exporting Calm Projects on PC $myvarCluster" -CATEGORY TASKINFO
$myvarPayload = @{
  kind="project"
  offset=0
  length=250
}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarProjectsList =  Invoke-PrismAPICall -Method POST -url $($myvarPCURLv3+"/projects/list") -credential $myvarCredentials -body $myvarBody

# export each provider settings
foreach($myvarProject in $myvarProjectsList.entities) {
  ConvertTo-JSON $($myvarProject.status.resources) -Depth 10 | Out-File "$myvarExportPath/projects/$($myvarProject.status.name).json"
}

####################################################
#* Clean UP
#################################################### 
# Clean up our variables
Write-Info " Cleaning up..." -CATEGORY TASKINFO
Write-Host "$(get-date) [INFO] Cleaning up..." -ForegroundColor Cyan
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Write-Host "$(get-date) [INFO] Done!" -ForegroundColor Green