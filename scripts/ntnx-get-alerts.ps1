<#
	.SYNOPSIS
	  Nutanix Cluster reporting script via Prism Central REST API

	.DESCRIPTION
	  The script connects to Prism Central via REST API and detects all connected Prism Element clusters.
	  The purpose of this script is to collect ALL Alerts of the respective clusters even if >1000.
	  Prism Credentials need to be provided when prompted, this is used to connect to REST API.
	  The Output Report will be saved in same Directory from where you run the script.  
	
	.PARAMETER 
	  None

	.INPUTS
	  None
	
	.OUTPUTS
	  None
	
	.NOTES
	  Version:			1.1
	  Author:			David Zoerb, Staff Consulting Architect <dz@nutanix.com>
	  Organization:		Nutanix
	  Creation Date:	May 7th 2019
	  Purpose/Change:	Changed to make it work across platforms. Tested on W10, Server 2016 and macOS
	
	.EXAMPLE
	  Self explanatory, just run the script, specify PC IP or FQDN and enter your credentials.
#>

# Verbose Outputw
$myvarDebug = "true"

##############################################
# Nothing to configure below this line - Starting the main function of the script
################################################
# Ask for cluster name to be configured
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
$myvarCluster = Read-Host "Please specify the Prism Central IP address or FQDN"  ; Write-Host;  

# User Input for credentials
$myvarCredentials = $host.ui.PromptForCredential("Need credentials", "Please specify your Prism login credentials", "", "")

# Global Error Handling
if ($myvarDebug -ne "true") { $ErrorActionPreference = 'SilentlyContinue' }

# Adding certificate exception to prevent API errors
$myvarOS=$PSVersionTable.Platform
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
$myvarPassword = $((New-Object PSCredential "$($myvarCredentials.username)",$($myvarCredentials.Password)).GetNetworkCredential().Password)
$myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($myvarCredentials.Username)"+":"+$($myvarPassword)))}
$myvarType = "application/json"

$myvarPCURLv2 = "https://" + $myvarCluster + ":9440/PrismGateway/services/rest/v2.0"
$myvarPCURLv3 = "https://" + $myvarCluster + ":9440/api/nutanix/v3"

$myvarFilenameInfo = "Nutanix_Report-"+(Get-Date -Format yyyMMdd_hhmm)+"-$myvarCluster"
$myvarOutput = $myvarFilenameInfo+"-Alerts.csv"
if($myvarOS -eq "Unix") { $myvarTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Europe/Berlin") }
else { $myvarTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central European Standard Time") }
$myvarURI = "${myvarPCURLv2}/alerts/?page=1&count=1"
$myvarContext = $null 
if($myvarOS -eq "Unix") { $myvarResponse = Invoke-RestMethod -Method GET -Uri $myvarURI -Header $myvarHeader -ContentType $myvarType -SkipCertificateCheck }
else { $myvarResponse = Invoke-RestMethod -Method GET -Uri $myvarURI -Header $myvarHeader -ContentType $myvarType }

# Connect to PC and get all connected clusters including PC itself
try {
	Write-Host "$(get-date) [ACTION] Connecting to Prism Central $($myvarCluster) and getting all connected PE clusters..." -ForegroundColor Green
	$myvarBody = '{"kind":"cluster"}'
	if($myvarOS -eq "Unix") { $myvarResult = Invoke-RestMethod -Method POST -Uri $($myvarPCURLv3+"/clusters/list") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType -Body $myvarBody -SkipCertificateCheck } 
	else { $myvarResult = Invoke-RestMethod -Method POST -Uri $($myvarPCURLv3+"/clusters/list") -TimeoutSec 60 -Headers $myvarHeader -ContentType $myvarType -Body $myvarBody }
	$myvarResult = $myvarResult.entities
	Write-Host "$(get-date) [INFO] Found a total of $($myvarResult.Count) connected clusters: $($($myvarResult.spec.name) -join ", ")" -ForegroundColor DarkGray
} catch { $myvarErrorMessage = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvarErrorMessage" -ForegroundColor Red; Return; }

# Remember the Cluster Names and UUIDs so we can include the cluster name in the report later
try {
    $myvarObj = $null
    $myvarClusterInfo = @()
	foreach ($myvarItem in $myvarResult) {
		$myvarUUID = $myvarItem.metadata.uuid
	    $myvarName = $myvarItem.spec.name
        $myvarObj = New-Object -TypeName PSObject
        $myvarObj | Add-Member -MemberType NoteProperty -Name ClusterUUID -Value $myvarUUID
        $myvarObj | Add-Member -MemberType NoteProperty -Name ClusterName -Value $myvarName
        $myvarClusterInfo += $myvarObj
	}
} catch { $myvarErrorMessage = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvarErrorMessage" -ForegroundColor Red; Return; }

$myvarTotalPages = $null
Write-Host "$(get-date) [INFO] Found a total of $($myvarResponse.metadata.grand_total_entities) Alerts..." -ForegroundColor DarkGray
if($($myvarResponse.metadata.grand_total_entities) -gt 1000) { 
    $myvarTotalPages = [Math]::Round($($myvarResponse.metadata.grand_total_entities)/1000)+0.5
    for($myvarPageNum=1;$myvarPageNum -lt $myvarTotalPages;$myvarPageNum++) { 
        $myvarURI = "${myvarPCURLv2}/alerts/?page=$myvarPageNum&count=1000"
		if($myvarOS -eq "Unix") { $myvarResponse = Invoke-RestMethod -Method GET -Uri $myvarURI -Header $myvarHeader -ContentType $myvarType -SkipCertificateCheck }
		else { $myvarResponse = Invoke-RestMethod -Method GET -Uri $myvarURI -Header $myvarHeader -ContentType $myvarType }
        Write-Host "$(get-date) [ACTION] Processiong Alerts $($myvarResponse.metadata.start_index) to $($myvarResponse.metadata.end_index)..." -ForegroundColor Green
        Foreach($myvarAlarm in $myvarResponse.entities) {
	        #Create context hash for each alarm Binding ContextTypes with ContextValues
	        $myvarContext=@{}
	        $myvarI=0
	        foreach($myvarName in $myvarAlarm.Context_Types) {
		        #Watch out for empty entries ( no idea why there are null entries for Type that correspond to a value )
		        # CM:	i am troubled about adding keys that exist twice or more in ContextTypes, hence the test context[name]
	    	        if($myvarName) {
			        if( $myvarContext[$myvarName] ) { 
				        start-sleep 0
			        } else {
				        $myvarContext.Add($myvarName,$myvarAlarm.Context_Values[$myvarI]) 
			        }
    		        }
		        $myvarI++
	        }
	        #Swap the {var} with value from our $context hash
    	        Foreach ($myvarContextType in ([regex]::Matches($myvarAlarm.message,'{(.*?)}')).Value )
	        {
        	        $myvarContextTypeName=$myvarContextType.Substring(1,$myvarContextType.Length-2)
	                $myvarAlarm.message = $myvarAlarm.message -replace $myvarContextType,$myvarContext[$myvarContextTypeName]
	        }
	        $myvarMyCluster = ($myvarClusterInfo|Where-Object{$_.ClusterUUID -eq $myvarAlarm.cluster_Uuid}).ClusterName
	        $myvarMyTime = ([System.TimeZoneInfo]::ConvertTimeFromUtc((New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([math]::Floor($myvarAlarm.created_Time_Stamp_In_Usecs/1000000)),$myvarTimeZone)).ToString()
            $myvarAlarm | add-member -Type NoteProperty -Name "NTNX_Cluster" -Value $myvarMyCluster	
            $myvarAlarm | add-member -Type NoteProperty -Name "CreatedTime" -Value $myvarMyTime
	        $myvarAlarm | Select-Object NTNX_Cluster,Cluster_UUID,CreatedTime,severity,alert_Title,message,resolved,acknowledged | Sort-Object createdTime | Export-Csv $myvarOutput -NoTypeInformation -Encoding UTF8  -Append 
        }
    } 
} else {
        $myvarURI = "${myvarPCURLv2}/alerts/?page=1&count=1000"
		if($myvarOS -eq "Unix") { $myvarResponse = Invoke-RestMethod -Method GET -Uri $myvarURI -Header $myvarHeader -ContentType $myvarType -SkipCertificateCheck }
		else { $myvarResponse = Invoke-RestMethod -Method GET -Uri $myvarURI -Header $myvarHeader -ContentType $myvarType }
        Write-Host "$(get-date) [ACTION] Processiong Alerts $($myvarResponse.metadata.start_index) to $($myvarResponse.metadata.end_index)..." -ForegroundColor Green
        Foreach($myvarAlarm in $myvarResponse.entities) {
	        #Create context hash for each alarm Binding ContextTypes with ContextValues
	        $myvarContext=@{}
	        $myvarI=0
	        foreach($myvarName in $myvarAlarm.Context_Types) {
		        #Watch out for empty entries ( no idea why there are null entries for Type that correspond to a value )
		        # CM:	i am troubled about adding keys that exist twice or more in ContextTypes, hence the test context[name]
	    	        if($myvarName) {
			        if( $myvarContext[$myvarName] ) { 
				        start-sleep 0
			        } else {
				        $myvarContext.Add($myvarName,$myvarAlarm.Context_Values[$myvarI]) 
			        }
    		        }
		        $myvarI++
	        }
	        #Swap the {var} with value from our $context hash
    	        Foreach ($myvarContextType in ([regex]::Matches($myvarAlarm.message,'{(.*?)}')).Value )
	        {
        	        $myvarContextTypeName = $myvarContextType.Substring(1,$myvarContextType.Length-2)
	                $myvarAlarm.message = $myvarAlarm.message -replace $myvarContextType,$myvarContext[$myvarContextTypeName]
	        }
	        $myvarMyCluster = ($myvarClusterInfo|Where-Object{$_.ClusterUUID -eq $myvarAlarm.cluster_Uuid}).ClusterName
	        $myvarMyTime = ([System.TimeZoneInfo]::ConvertTimeFromUtc((New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds([math]::Floor($myvarAlarm.created_Time_Stamp_In_Usecs/1000000)),$myvarTimeZone)).ToString()
            $myvarAlarm | add-member -Type NoteProperty -Name "NTNX_Cluster" -Value $myvarMyCluster	
            $myvarAlarm | add-member -Type NoteProperty -Name "CreatedTime" -Value $myvarMyTime
	        $myvarAlarm | Select-Object NTNX_Cluster,Cluster_UUID,CreatedTime,severity,alert_Title,message,resolved,acknowledged | Sort-Object createdTime | Export-Csv $myvarOutput -NoTypeInformation -Encoding UTF8  -Append 
        }
}
# endforeach

# Clean up our variables
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
