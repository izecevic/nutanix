<#
    .SYNOPSIS
    The purpose of this script is to retreive Projects details on PC (vCPU, memory, storage utilization/limit) and export them
    in an Excel file. Additionnaly, the script will calculate Total of resources used accross all projects.

    .DESCRIPTION
    The assumption is that nodes are imaged and passed in array as paramater. All paramaters should be gathered (from JSON file) outside of this function.
    PowerShell 6 version and above, is required.

    .NOTES
    Version:        0.1
    Author:         Igor Zecevic, Senior Staff Consulting Architect <izecevic@nutanix.com>
    Organization:   Nutanix
    Creation Date:  28 June 2021
                    13 October 2021 (fixed annual/monthly affectation and utilisation values)
                    20 July 2022 (fixed utilisation data retreival using v3/groups PC API)
    Purpose/Change: 

    .EXAMPLE
    .\ntnx-getPCmyvarProjectsReport.ps1 -myvar_pc_ip "myvar_pc_ip" -myvar_pc_user "myvar_pc_user" -myvar_pc_pwd "myvar_pc_pwd" -myvar_rapport_file "myvar_rapport_file"
    Get Prism Central Project details and export them in an Excel File
#>

#region parameters
Param
(
    [parameter(mandatory = $false)] [string]$debugme = $false,
    [parameter(mandatory = $true)]  [string]$myvar_pc_user = "iz@emeagso.lab",
    [parameter(mandatory = $true)]  [string]$myvar_pc_pwd= "nutanix/4u",
    [parameter(mandatory = $true)]  [string]$myvar_pc_ip = "10.68.97.150",
    [parameter(mandatory = $true)]  [string]$myvar_rapport_file = "pc-project-rapport",
    [parameter(mandatory = $false)] [string]$myvar_project_excluded = "NUTANIX|default",
    [parameter(mandatory = $false)] [switch]$myvar_html
)
#endregion parameters

#region prepwork
#region Installing Powershell Modules
Install-Module ImportExcel -ErrorAction Stop
if ($myvar_html) {
    #we need html output, so let's load the PSWriteHTML module
    Install-Module PSWriteHTML
}
#endregion Installing Powershell Modules

# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

#region Nutanix Logo
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
#endregion Nutanix Logo

#region SSL
# Checking OS and add SkipCertificateCheck if required (Mainly *nix and Windows on PowerShell Core >7)
$myvar_os=$PSVersionTable.Platform
if($($PSDefaultParameterValues.'Invoke-RestMethod:SkipCertificateCheck') -ne "true" -AND $myvar_os -eq "Unix" -AND $($PSVersionTable.PSVersion -join ".") -gt 7) {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)
    $PSDefaultParameterValues.Add("Invoke-WebRequest:SkipCertificateCheck",$true) 
}
# Adding certificate exception to prevent API errors for Windows and PowerShell less than Version 7
if($myvar_os -ne "Unix" -AND $($PSVersionTable.PSVersion -join ".") -lt 7) {
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
    } catch { $myvar_error_message = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvar_error_message" -ForegroundColor Red; Return; }
}
#endregion SSL

#region credentials
if (!$myvar_pc_user) { $myvar_pc_user = Read-Host "Enter the Prism username"} 
if (!$myvar_pc_pwd) { $myvar_pc_pwd_secure = Read-Host "Enter the Prism user $myvar_pc_user password" -AsSecureString }
else { $myvar_pc_pwd_secure = ConvertTo-SecureString $myvar_pc_pwd -Asplaintext -Force }
$myvar_creds = New-Object PSCredential $myvar_pc_user, $myvar_pc_pwd_secure
#endregion credentials

#region Headers
if(!$myvar_pc_pwd) { $myvar_pc_pwd= $((New-Object PSCredential "$($myvar_creds.username)",$($myvar_creds.Password)).GetNetworkCredential().Password) }
if(!$myvar_header) { $myvar_header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($myvar_creds.Username)"+":"+$($myvar_pc_pwd)))} }
if(!$myvar_type) { $myvar_type = "application/json" }
#endregion Headers

#region variables
$myvar_elasped_time = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
$myvar_year = (Get-Date).year
$myvar_month = (Get-Date).ToUniversalTime().Month | %{(Get-Culture).DateTimeFormat.GetMonthName($_)}
$myvar_pc_url = "https://" + $myvar_pc_ip + ":9440/api/nutanix/v3"
#endregion

#endregion prepwork

####################################################################################
# Nothing to configure below this line - Starting the main function of the script
####################################################################################

#* Processing starts here
#region processing
####################################################
#* PC Project Section
####################################################    
try {
    Write-Host "$(get-date) [ACTION] Getting PC Project Details on Nutanix PC $myvar_pc_ip" -ForegroundColor Green
    $myvar_payload = @{ kind = "project" }
    $myvar_body = ConvertTo-Json $myvar_payload
    $myvar_projects_details = Invoke-RestMethod -Method POST -Uri $($myvar_pc_url+"/projects/list") -TimeoutSec 60 -Headers $myvar_header -ContentType $myvar_type -Body $myvar_body
    $myvar_projects = $myvar_projects_details.entities | where {$_.status.name -notmatch $myvar_project_excluded}
} catch { $myvar_error_message = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvar_error_message" -ForegroundColor Red; Return; }

####################################################
#* Affectation (limit) Project Export
#################################################### 
Write-Host "$(get-date) [ACTION] Creating Affectation Project Report" -ForegroundColor Green
$myvar_affectation_project_table = @()
$myvar_affectation_total_table = @()

# Retrieving Total limits
$myvar_proc_total = ((($myvar_projects.status.resources.resource_domain.resources | Where {$_.resource_type -match "VCPUS"}).limit | Measure-Object -Sum).sum) | % {$_.ToString("#.##")}
$myvar_ram_total = [math]::Round((((($myvar_projects.status.resources.resource_domain.resources | Where {$_.resource_type -match "MEMORY"}).limit | Measure-Object -Sum).sum / 1GB) | % {$_.ToString("#.##")}))
$myvar_disque_total = [math]::Round((((($myvar_projects.status.resources.resource_domain.resources | Where {$_.resource_type -match "STORAGE"}).limit | Measure-Object -Sum).sum / 1GB) | % {$_.ToString("#.##")}))

# creating a total table
$myvar_affectation_total_table = [PSCustomObject]@{
    pools = "Total"
    proc_net = $myvar_proc_total
    ram_net = $myvar_ram_total
    disque_net = $myvar_disque_total
    proc_affectation = "100%"
    ram_affectation = "100%"
    disque_affectation = "100%"
    proc_variation_annuelle = ""
    ram_variation_annuelle = ""
    disque_variation_annuelle = ""
    proc_variation_mensuelle = ""
    ram_variation_mensuelle = ""
    disque_variation_mensuelle = ""
} 

# pushing to myvar_affectation_project_table
$myvar_affectation_project_table += $myvar_affectation_total_table

# Pushing all projects details into the myvar_affectation_project_table
ForEach ($myvar_project in $myvar_projects){
    $myvar_project_pool = $($myvar_project.status.name)
    $myvar_proc_project= ($myvar_project.status.resources.resource_domain.resources | Where {$_.resource_type -match "VCPUS"}).limit | % {$_.ToString("#.##")}
    $myvar_ram_project = [math]::Round((($myvar_project.status.resources.resource_domain.resources | Where {$_.resource_type -match "MEMORY"}).limit / 1GB))
    $myvar_disque_project = [math]::Round((($myvar_project.status.resources.resource_domain.resources | Where {$_.resource_type -match "STORAGE"}).limit /1GB))
    $myvar_proc_affectation_project = ($myvar_proc_project/ $myvar_proc_total).toString("P")
    $myvar_ram_affectation_project = ($myvar_ram_project / $myvar_ram_total).toString("P")
    $myvar_disque_affectation_project = ($myvar_disque_project / $myvar_disque_total).toString("P")

    # pushing to myvar_affectation_project_table
    $myvar_affectation_project_table += [PSCustomObject]@{
        pools = $myvar_project_pool
        proc_net = $myvar_proc_project
        proc_affectation =  $myvar_proc_affectation_project
        proc_variation_annuelle = ""
        proc_variation_mensuelle = ""
        ram_net = $myvar_ram_project
        ram_affectation = $myvar_ram_affectation_project 
        ram_variation_annuelle = ""
        ram_variation_mensuelle = ""
        disque_net = $myvar_disque_project
        disque_affectation = $myvar_disque_affectation_project
        disque_variation_annuelle = ""
        disque_variation_mensuelle = ""
    }
}

# pushing variation annuelle datas every month
if ($myvar_month -notmatch "January"){
    Write-Host "$(get-date) [ACTION] Adding Yearly/Monthly Affectation Variation to Project Report" -ForegroundColor Green
    # Importing January reference data
    if (Test-Path $myvar_rapport_file-$($myvar_year).json) {
        if ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON)."January") {
            $myvar_affectation_january = ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON)."January"."affectation")
            # Pushing all projects details into the myvar_affectation_project_table
            ForEach ($myvar_project in $myvar_affectation_project_table){
                # getting proc/ram/disque annuelle affectation values
                $myvar_project_affectation_january = ($myvar_affectation_january | Where {$_.pools -eq $myvar_project.pools})
                # calculating proc/ram/disque variation annuelle values
                $myvar_proc_variation_annuelle = (($myvar_project.proc_net - $myvar_project_affectation_january.proc_net) / $myvar_project_affectation_january.proc_net).toString("P")
                $myvar_ram_variation_annuelle = (($myvar_project.ram_net - $myvar_project_affectation_january.ram_net) / $myvar_project_affectation_january.ram_net).toString("P")
                $myvar_disque_variation_annuelle = (($myvar_project.disque_net - $myvar_project_affectation_january.disque_net) / $myvar_project_affectation_january.disque_net).toString("P")
             # pushing proc/ram/disque annuelle affectation values
                $myvar_project.proc_variation_annuelle = $myvar_proc_variation_annuelle
                $myvar_project.ram_variation_annuelle = $myvar_ram_variation_annuelle
                $myvar_project.disque_variation_annuelle = $myvar_disque_variation_annuelle
            }

            # updating Total proc/ram/disque variation annuelle values
            $myvar_affectation_january_total = $myvar_affectation_january | Where {$_.pools -eq "Total"}
            # calculating proc/ram/disque variation annuelle values
            $myvar_proc_variation_annuelle = (($myvar_affectation_total_table.proc_net - $myvar_affectation_january_total.proc_net) / $myvar_affectation_january_total.proc_net).toString("P")
            $myvar_ram_variation_annuelle = (($myvar_affectation_total_table.ram_net - $myvar_affectation_january_total.ram_net) / $myvar_affectation_january_total.ram_net).toString("P")
            $myvar_disque_variation_annuelle = (($myvar_affectation_total_table.disque_net - $myvar_affectation_january_total.disque_net) / $myvar_affectation_january_total.disque_net).toString("P")
            # pushing proc/ram/disque annuelle affectation values
            $myvar_affectation_total_table.proc_variation_annuelle = $myvar_proc_variation_annuelle
            $myvar_affectation_total_table.ram_variation_annuelle = $myvar_ram_variation_annuelle
            $myvar_affectation_total_table.disque_variation_annuelle = $myvar_disque_variation_annuelle
        } { Write-Host "$(get-date) [WARNING] January doesn't seem to exist on the $($myvar_rapport_file)-$($myvar_year).json file" -ForegroundColor Yellow }
    }  else { Write-Host "$(get-date) [WARNING] $($myvar_rapport_file)-$($myvar_year).json file not available" -ForegroundColor Yellow }

    # Importing previous month reference data
    if (Test-Path $myvar_rapport_file-$($myvar_year).json) {
        $myvar_previous_month = ((Get-Date).ToUniversalTime().Month -1 )| %{(Get-Culture).DateTimeFormat.GetMonthName($_)}
        if ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON).$myvar_previous_month) {
            $myvar_affectation_previous_month = ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON)."$($myvar_previous_month)".affectation)
            ForEach ($myvar_project in $myvar_affectation_project_table){
                # getting proc/ram/disque mensuelle affectation values
                $myvar_project_affectation_previous_month = ($myvar_affectation_previous_month | Where {$_.pools -eq $myvar_project.pools})
                 # calculating proc/ram/disque variation mensuelle values
                $myvar_proc_variation_mensuelle = (($myvar_project.proc_net - $myvar_project_affectation_previous_month.proc_net) / $myvar_project_affectation_previous_month.proc_net).toString("P")
                $myvar_ram_variation_mensuelle = (($myvar_project.ram_net - $myvar_project_affectation_previous_month.ram_net) / $myvar_project_affectation_previous_month.ram_net).toString("P")
                $myvar_disque_variation_mensuelle = (($myvar_project.disque_net - $myvar_project_affectation_previous_month.disque_net) / $myvar_project_affectation_previous_month.disque_net).toString("P")
                # pushing proc/ram/disque mensuelle affectation values
                $myvar_project.proc_variation_mensuelle = $myvar_proc_variation_mensuelle
                $myvar_project.ram_variation_mensuelle = $myvar_ram_variation_mensuelle
                $myvar_project.disque_variation_mensuelle = $myvar_disque_variation_mensuelle
            }

            # updating total proc/ram/disque variation mensuelle values
            $myvar_affectation_previous_month_total = $myvar_affectation_previous_month | Where {$_.pools -eq "Total"}
            # calculating proc/ram/disque varaition mensuelle values
            $myvar_proc_variation_mensuelle = (($myvar_affectation_total_table.proc_net - $myvar_affectation_previous_month_total.proc_net) / $myvar_affectation_previous_month_total.proc_net).toString("P")
            $myvar_ram_variation_mensuelle = (($myvar_affectation_total_table.ram_net - $myvar_affectation_previous_month_total.ram_net) / $myvar_affectation_previous_month_total.ram_net).toString("P")
            $myvar_disque_variation_mensuelle = (($myvar_affectation_total_table.disque_net - $myvar_affectation_previous_month_total.disque_net) / $myvar_affectation_previous_month_total.disque_net).toString("P")

            # updating total proc/ram/disque mensuelle affectation values
            $myvar_affectation_total_table.proc_variation_mensuelle = $myvar_proc_variation_mensuelle
            $myvar_affectation_total_table.ram_variation_mensuelle = $myvar_ram_variation_mensuelle
            $myvar_affectation_total_table.disque_variation_mensuelle = $myvar_disque_variation_mensuelle 
        } { Write-Host "$(get-date) [WARNING] Previous month data doesn't seem to exist on the $($myvar_rapport_file)-$($myvar_year).json file" -ForegroundColor Yellow }
    }  else {Write-Host "$(get-date) [WARNING] $($myvar_rapport_file)-$($myvar_year).json file not available" -ForegroundColor Yellow }
}

####################################################
#* Utilisation (Usage) Project Export
#################################################### 
Write-Host "$(get-date) [ACTION] Creating Utilisation Project Report" -ForegroundColor Green
$myvar_utilisation_project_table = @()
$myvar_utilisation_total_table = @()
$myvar_total_projects_utilisation_details = @()

# Getting PC project Details
try {
    Write-Host "$(get-date) [ACTION] Getting PC Project Details on Nutanix PC $myvar_pc_ip" -ForegroundColor Green
    $myvar_payload = @{ kind = "project" }
    $myvar_body = ConvertTo-Json $myvar_payload
    $myvar_projects_details = Invoke-RestMethod -Method POST -Uri $($myvar_pc_url+"/projects/list") -TimeoutSec 60 -Headers $myvar_header -ContentType $myvar_type -Body $myvar_body
    $myvar_projects = $myvar_projects_details.entities | where {$_.status.name -notmatch $myvar_project_excluded}
} catch { $myvar_error_message = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvar_error_message" -ForegroundColor Red; Return; }

# Getting PC Project cpu/memory/disk usage values
ForEach ($myvar_project in $myvar_projects){
    Write-Host "$(get-date) [ACTION] Getting PC Project $($myvar_project.status.name) Usage Values on Nutanix PC $myvar_pc_ip" -ForegroundColor Green
    $myvar_payload = @{    
        entity_type = "mh_vm"
        group_member_count = 500 
        query_name = "prism:BaseGroupModel"
        availability_zone_scope = "GLOBAL"
        filter_criteria = "project_reference=in=$($myvar_project.metadata.uuid)"
        group_member_attributes = @(@{attribute = "vm_name"}; @{attribute = "num_vcpus"}; @{attribute = "memory_size_bytes"}; @{attribute = "capacity_bytes"})
    }
    try {
        $myvar_body = ConvertTo-Json $myvar_payload
        $myvar_project_utilisation_details = Invoke-RestMethod -Method POST -Uri $($myvar_pc_url+"/groups") -TimeoutSec 60 -Headers $myvar_header -ContentType $myvar_type -Body $myvar_body
    } catch { $myvar_error_message = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvar_error_message" -ForegroundColor Red; Return; }
    
    #pushing usage data to the total table
    $myvar_total_projects_utilisation_details += [PSCustomObject]@{
        name = $($myvar_project.status.name)
        data = $myvar_project_utilisation_details
    }
}

# Retrieving Total cpu/memory/disk usage values
$myvar_proc_total = (($myvar_total_projects_utilisation_details.data.group_results.entity_results.data | Where-Object {$_.name -eq "num_vcpus"}).values.values | Measure-Object -Sum).sum
$myvar_ram_total = [math]::Round((((($myvar_total_projects_utilisation_details.data.group_results.entity_results.data | Where-Object {$_.name -eq "memory_size_bytes"}).values.values | Measure-Object -Sum).Sum) / 1GB))
$myvar_disque_total = [math]::Round((((($myvar_total_projects_utilisation_details.data.group_results.entity_results.data | Where-Object {$_.name -eq "capacity_bytes"}).values.values | Measure-Object -Sum).sum)/1GB))
$myvar_proc_utilisation_total = ($myvar_proc_total / $myvar_affectation_total_table.proc_net).toString("P")
$myvar_ram_utilisation_total = ($myvar_ram_total / $myvar_affectation_total_table.ram_net).toString("P")
$myvar_disque_utilisation_total = ($myvar_disque_total / $myvar_affectation_total_table.disque_net).toString("P")

# creating a utilisation total table
$myvar_utilisation_total_table = [PSCustomObject]@{
    pools = "Total"
    proc_net = $myvar_proc_total
    ram_net = $myvar_ram_total
    disque_net = $myvar_disque_total
    proc_affectation = "100.00%"
    ram_affectation = "100.00%"
    disque_affectation = "100.00%"
    proc_utilisation = $myvar_proc_utilisation_total
    ram_utilisation = $myvar_ram_utilisation_total
    disque_utilisation = $myvar_disque_utilisation_total
    proc_variation_annuelle = ""
    proc_variation_mensuelle = ""
    ram_variation_annuelle = ""
    ram_variation_mensuelle = ""
    disque_variation_annuelle = ""
    disque_variation_mensuelle = ""
} 

# pushing to myvar_utilisation_project_table
$myvar_utilisation_project_table += $myvar_utilisation_total_table

# Pushing all projects details into the myvarProjectTable
ForEach ($myvar_project in $myvar_projects){
    $myvar_project_pool = $($myvar_project.status.name)
    $myvar_proc_project = ((($myvar_total_projects_utilisation_details | Where {$_.name -eq $myvar_project_pool}).data.group_results.entity_results.data | Where-Object {$_.name -eq "num_vcpus"}).values.values | Measure-Object -Sum).Sum
    $myvar_ram_project = [math]::Round(((((($myvar_total_projects_utilisation_details | Where {$_.name -eq $myvar_project_pool}).data.group_results.entity_results.data | Where-Object {$_.name -eq "memory_size_bytes"}).values.values | Measure-Object -Sum).Sum)/1GB))
    $myvar_disque_project = [math]::Round(((((($myvar_total_projects_utilisation_details | Where {$_.name -eq $myvar_project_pool}).data.group_results.entity_results.data | Where-Object {$_.name -eq "capacity_bytes"}).values.values | Measure-Object -Sum).Sum)/1GB))
    $myvar_proc_affectation_project = ($myvar_proc_project/ $myvar_proc_total).toString("P")
    $myvar_ram_affectation_project = ($myvar_ram_project / $myvar_ram_total).toString("P")
    $myvar_disque_affectation_project = ($myvar_disque_project / $myvar_disque_total).toString("P")
    $myvar_proc_utilisation_project = ($myvar_proc_project/ (($myvar_affectation_project_table | Where-Object {$_.pools -eq $myvar_project_pool}).proc_net)).toString("P")
    $myvar_ram_utilisation_project = ($myvar_ram_project/ (($myvar_affectation_project_table | Where-Object {$_.pools -eq $myvar_project_pool}).ram_net)).toString("P")
    $myvar_disque_utilisation_project = ($myvar_disque_project / (($myvar_affectation_project_table | Where-Object {$_.pools -eq $myvar_project_pool}).disque_net)).toString("P")

    # pushing to myvar_utilisation_project_table
    $myvar_utilisation_project_table += [PSCustomObject]@{
        pools = $myvar_project_pool
        proc_net = $myvar_proc_project
        proc_utilisation = $myvar_proc_utilisation_project
        proc_affectation = $myvar_proc_affectation_project
        proc_variation_annuelle = ""
        proc_variation_mensuelle = ""
        ram_net = $myvar_ram_project
        ram_utilisation = $myvar_ram_utilisation_project
        ram_affectation = $myvar_ram_affectation_project 
        ram_variation_annuelle = ""
        ram_variation_mensuelle = ""
        disque_net = $myvar_disque_project
        disque_utilisation = $myvar_disque_utilisation_project
        disque_affectation =  $myvar_disque_affectation_project
        disque_variation_annuelle = ""
        disque_variation_mensuelle = ""
    }
}

# pushing variation annuelle datas
if ($myvar_month -notmatch "January"){
    Write-Host "$(get-date) [ACTION] Adding Yearly/Monthly Utilisation Variation to Project Report" -ForegroundColor Green
    # Importing January reference data
    if (Test-Path $myvar_rapport_file-$($myvar_year).json) {
        if ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON)."January") {
            $myvar_utilisation_january = ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON)."January"."utilisation")
            # Pushing all projects details into the myvar_utilisation_project_table
            ForEach ($myvar_project in $myvar_utilisation_project_table){
                # getting proc/ram/disque annuelle utilisation values
                $myvar_project_utilisation_january = ($myvar_utilisation_january | Where {$_.pools -eq $myvar_project.pools})
                # calculating proc/ram/disque variation annuelle values
                $myvar_proc_variation_annuelle = (($myvar_project.proc_net - $myvar_project_utilisation_january.proc_net) / $myvar_project_utilisation_january.proc_net).toString("P")
                $myvar_ram_variation_annuelle = (($myvar_project.ram_net - $myvar_project_utilisation_january.ram_net) / $myvar_project_utilisation_january.ram_net).toString("P")
                $myvar_disque_variation_annuelle = (($myvar_project.disque_net - $myvar_project_utilisation_january.disque_net) / $myvar_project_utilisation_january.disque_net).toString("P")
                # pushing proc/ram/disque annuelle utilisation values
                $myvar_project.proc_variation_annuelle = $myvar_proc_variation_annuelle
                $myvar_project.ram_variation_annuelle = $myvar_ram_variation_annuelle
                $myvar_project.disque_variation_annuelle = $myvar_disque_variation_annuelle
            }

            # updating Total proc/ram/disque variation annuelle values
            $myvar_utilisation_january_total = $myvar_utilisation_january | Where {$_.pools -eq "Total"}
            # calculating proc/ram/disque variation annuelle values
            $myvar_proc_variation_annuelle = (($myvar_utilisation_total_table.proc_net - $myvar_utilisation_january_total.proc_net) / $myvar_utilisation_january_total.proc_net).toString("P")
            $myvar_ram_variation_annuelle = (($myvar_utilisation_total_table.ram_net - $myvar_utilisation_january_total.ram_net) / $myvar_utilisation_january_total.ram_net).toString("P")
            $myvar_disque_variation_annuelle = (($myvar_utilisation_total_table.disque_net - $myvar_utilisation_january_total.disque_net) / $myvar_utilisation_january_total.disque_net).toString("P")
            # pushing proc/ram/disque annuelle utilisation values
            $myvar_utilisation_total_table.proc_variation_annuelle = $myvar_proc_variation_annuelle
            $myvar_utilisation_total_table.ram_variation_annuelle = $myvar_ram_variation_annuelle
            $myvar_utilisation_total_table.disque_variation_annuelle = $myvar_disque_variation_annuelle
        } { Write-Host "$(get-date) [WARNING] January doesn't seem to exist on the $($myvar_rapport_file)-$($myvar_year).json file" -ForegroundColor Yellow }
    } else { Write-Host "$(get-date) [WARNING] $($myvar_rapport_file)-$($myvar_year).json file not available" -ForegroundColor Yellow }

    # Importing previous month reference data
    if (Test-Path $myvar_rapport_file-$($myvar_year).json) {
        $myvar_previous_month = ((Get-Date).ToUniversalTime().Month -1 )| %{(Get-Culture).DateTimeFormat.GetMonthName($_)}
        if ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON).$myvar_previous_month) {
            $myvar_utilisation_previous_month = ((Get-Content $myvar_rapport_file-$($myvar_year).json | ConvertFrom-JSON)."$($myvar_previous_month)".utilisation)
            ForEach ($myvar_project in $myvar_utilisation_project_table){
                # getting proc/ram/disque mensuelle utilisation values
                $myvar_project_utilisation_previous_month = ($myvar_utilisation_previous_month | Where {$_.pools -eq $myvar_project.pools})
                 # calculating proc/ram/disque variation mensuelle values
                $myvar_proc_variation_mensuelle = (($myvar_project.proc_net - $myvar_project_utilisation_previous_month.proc_net) / $myvar_project_utilisation_previous_month.proc_net).toString("P")
                $myvar_ram_variation_mensuelle = (($myvar_project.ram_net - $myvar_project_utilisation_previous_month.ram_net) / $myvar_project_utilisation_previous_month.ram_net).toString("P")
                $myvar_disque_variation_mensuelle = (($myvar_project.disque_net - $myvar_project_utilisation_previous_month.disque_net) / $myvar_project_utilisation_previous_month.disque_net).toString("P")
                # pushing proc/ram/disque mensuelle utilisation values
                $myvar_project.proc_variation_mensuelle = $myvar_proc_variation_mensuelle
                $myvar_project.ram_variation_mensuelle = $myvar_ram_variation_mensuelle
                $myvar_project.disque_variation_mensuelle = $myvar_disque_variation_mensuelle
            }

            # updating total proc/ram/disque variation mensuelle values
            $myvar_utilisation_previous_month_total = $myvar_utilisation_previous_month | Where {$_.pools -eq "Total"}
            # calculating proc/ram/disque varaition mensuelle values
            $myvar_proc_variation_mensuelle = (($myvar_utilisation_total_table.proc_net - $myvar_utilisation_previous_month_total.proc_net) / $myvar_utilisation_previous_month_total.proc_net).toString("P")
            $myvar_ram_variation_mensuelle = (($myvar_utilisation_total_table.ram_net - $myvar_utilisation_previous_month_total.ram_net) / $myvar_utilisation_previous_month_total.ram_net).toString("P")
            $myvar_disque_variation_mensuelle = (($myvar_utilisation_total_table.disque_net - $myvar_utilisation_previous_month_total.disque_net) / $myvar_utilisation_previous_month_total.disque_net).toString("P")

            # updating total proc/ram/disque mensuelle affectation values
            $myvar_utilisation_total_table.proc_variation_mensuelle = $myvar_proc_variation_mensuelle
            $myvar_utilisation_total_table.ram_variation_mensuelle = $myvar_ram_variation_mensuelle
            $myvar_utilisation_total_table.disque_variation_mensuelle = $myvar_disque_variation_mensuelle 
        } { Write-Host "$(get-date) [WARNING] Previous Month data doesn't seem to exist on the $($myvar_rapport_file)-$($myvar_year).json file" -ForegroundColor Yellow }
    } else { Write-Host "$(get-date) [WARNING] $($myvar_rapport_file)-$($myvar_year).json file not available" -ForegroundColor Yellow }
}

####################################################
#* Exporting Table in JSON object
#################################################### 
Write-Host "$(get-date) [ACTION] Exporting Project Report in JSON file" -ForegroundColor Green
if (Test-Path $myvar_rapport_file-$($myvar_year).json){
    $myvar_rapport_json = @()
    $myvar_rapport_json += $(Get-Content "$myvar_rapport_file-$($myvar_year).json" | ConvertFrom-Json)
    $myvar_rapport_json += @{
        $myvar_month = @{
            "affectation" = $myvar_affectation_project_table
            "utilisation" = $myvar_utilisation_project_table
        }
    }
} else {
    $myvar_rapport_json = @{
        $myvar_month = @{
            "affectation" = $myvar_affectation_project_table
            "utilisation" = $myvar_utilisation_project_table
        }
    }
}

ConvertTo-Json $myvar_rapport_json -Depth 10 | Out-File "$myvar_rapport_file-$($myvar_year).json"

####################################################
#* Exporting Table in Excel File
#################################################### 
Write-Host "$(get-date) [ACTION] Exporting Project Report in Excel File" -ForegroundColor Green
$myvar_affectation_project_table | Export-Excel ./$myvar_rapport_file-$($myvar_year).xlsx -AutoSize -WorksheetName $($myvar_month + "_Affectation") -Table $($myvar_month + "_Affectation")
$myvar_utilisation_project_table | Export-Excel ./$myvar_rapport_file-$($myvar_year).xlsx -AutoSize -WorksheetName $($myvar_month + "_Utilisation") -Table $($myvar_month + "_Utilisation")

####################################################
#* Exporting Table in HTML file
#################################################### 
if ($myvar_html) {#we need html output
    Write-Host "$(get-date) [ACTION] Exporting Project Report in HTML File" -ForegroundColor Green

    #* html report creation/formatting starts here
    $myvar_html_report = New-Html -TitleText "Project Report" -Online {
        New-HTMLTableStyle -BackgroundColor Black -TextColor White -Type Button
        New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#d6d6d2" -TextColor Black -TextAlign center -Type Header
        New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#d6d6d2" -TextColor Black -TextAlign center -Type Footer
        New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor White -TextColor Black -TextAlign center -Type RowOdd
        New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor WhiteSmoke -TextColor Black -TextAlign center -Type RowEven
        New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#87aec9" -TextColor WhiteSmoke -TextAlign center -Type RowSelected
        New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#87aec9" -TextColor WhiteSmoke -TextAlign center -Type RowHoverSelected
        New-HTMLTableStyle -FontFamily 'system-ui' -FontSize 14 -BackgroundColor "#5c5c5a" -TextColor WhiteSmoke -TextAlign center -Type RowHover
        New-HTMLTableStyle -Type Header -BorderLeftStyle dashed -BorderLeftColor "#d6d6d2" -BorderLeftWidthSize 1px
        New-HTMLTableStyle -Type Footer -BorderLeftStyle dotted -BorderLeftColor "#d6d6d2" -BorderleftWidthSize 1px
        New-HTMLTableStyle -Type Footer -BorderTopStyle none -BorderTopColor Black -BorderTopWidthSize 5px -BorderBottomColor "#d6d6d2" -BorderBottomStyle solid

        #* this is the collapsed general info section at the top which contains configuration settings and cluster details
        New-HtmlSection -HeaderText "Project Details" -Wrap wrap -CanCollapse -Collapsed -HeaderBackGroundColor "#168CF5" -HeaderTextColor White -HeaderTextSize 18 -Direction Row {
            New-HtmlSection -HeaderText "Affecté"  -HeaderBackGroundColor "#7cab61" -HeaderTextColor White -HeaderTextSize 16 {                
                New-HtmlTable -DataTable ($myvar_affectation_project_table) -HideFooter {
                    New-HTMLTableHeader -Names 'proc_net', 'proc_affectation', 'proc_variation_annuelle', 'proc_mensuelle_annuelle' -Title 'Proc' -Color Black
                    New-HTMLTableHeader -Names 'ram_net', 'ram_affectation', 'ram_variation_annuelle', 'ram_mensuelle_annuelle' -Title 'Ram' -Color Black
                    New-HTMLTableHeader -Names 'disque_net', 'disque_affectation', 'disque_variation_annuelle', 'disque_mensuelle_annuelle' -Title 'Disque' -Color Black
                    New-HTMLTableCondition -Name 'Pools' -Type string -Operator eq -Value 'Total' -Row -Color Black -FontWeight Bold
                }
            }
            New-HtmlSection -HeaderText "Utilisé" -HeaderBackGroundColor "#7cab61" -HeaderTextColor White -HeaderTextSize 16 {
                New-HtmlTable -DataTable ($myvar_utilisation_project_table) -HideFooter {
                    New-HTMLTableHeader -Names 'proc_net', 'proc_utilisation', 'proc_affectation', 'proc_variation_annuelle', 'proc_mensuelle_annuelle' -Title 'Proc' -Color Black
                    New-HTMLTableHeader -Names 'ram_net', 'ram_utilisation', 'ram_affectation', 'proc_variation_annuelle', 'proc_mensuelle_annuelle' -Title 'Ram' -Color Black
                    New-HTMLTableHeader -Names 'disque_net', 'disque_utilisation', 'disque_affectation', 'proc_variation_annuelle', 'proc_mensuelle_annuelle' -Title 'Disque'  -Color Black
                    New-HTMLTableCondition -Name 'Pools' -Type string -Operator eq -Value 'Total' -Row -Color Black -FontWeight Bold
                }
            }
        }
    }
    $myvar_html_report_file = $($myvar_rapport_file)+"-"+$($myvar_year)+"-"+$($myvar_month)+".html"
    $myvar_html_report | Out-File -FilePath $myvar_html_report_file
}
#endregion
#endregion
#* Processing ends here

#region cleanup
#let's figure out how much time this all took
Write-Host "$(get-date) [SUM] total processing time: $($myvar_elasped_time.Elapsed.ToString())" -ForegroundColor Magenta

#cleanup after ourselves and delete all custom variables
Remove-Module ntnx-globalFunctions -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Remove-Variable debugme -ErrorAction SilentlyContinue
Remove-Variable myvar* -ErrorAction SilentlyContinue
#endregion