<#
    .SYNOPSIS
    This script retrieves files and shares details on Prism Element. The script generates an excel report.

    .DESCRIPTION
    XXX

    .PARAMETER myvar_pe_ip
    Prism Element IP address

    .PARAMETER myvar_pe_user
    Prism Element user

    .PARAMETER myvar_pe_pwd
    Prism Element password

    .NOTES
    Version:        0.1
    Author:         Igor Zecevic, Senior Staff Consulting Architect <izecevic@nutanix.com>
    Organization:   Nutanix
    Creation Date:  04 January 2024
    Purpose/Change: 

    .EXAMPLE
    .\ntnx-files_report.ps1 -myvar_pe_ip "10.10.10.10" -myvar_pe_user "admin" -myvar_pe_pwd "nutanix/4u"
#>

#region parameters
Param (
    [parameter(mandatory = $true)] [string]$myvar_pe_ip,
    [parameter(mandatory = $true)] [string]$myvar_pe_user,
    [parameter(mandatory = $true)] [string]$myvar_pe_pwd,
    [parameter(mandatory = $false)] [string]$myvar_cost_per_tb = 6
)
#endregion

#region functions
# function Write-LogOutput
function Write-LogOutput {
    <#
    .SYNOPSIS
    Outputs color coded messages to the screen and/or log file based on the category.
    .DESCRIPTION
    This function is used to produce screen and log output which is categorized, time stamped and color coded.
    .PARAMETER Category
    This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".
    .PARAMETER Message
    This is the actual message you want to display.
    .PARAMETER LogFile
    If you want to log output to a file as well, use logfile to pass the log file full path name.
    .NOTES
    Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
    .EXAMPLE
    .\Write-LogOutput -category "ERROR" -message "You must be kidding!"
    Displays an error message.
    .LINK
    https://github.com/sbourdeaud
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		#[Parameter(Mandatory)]
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','TASKINFO')]
        [string]$Category="INFO",
        [Parameter(Position=10)][string]$Message,
        [string]$LogFile
	)

    process
    {
        $Date = get-date #getting the date so we can timestamp the output entry
        $FgColor = "Gray" #resetting the foreground/text color
        $taskInfoDash = "-"
        switch ($Category) #we'll change the text color depending on the selected category
	    {
		    "INFO" {$FgColor = "Green"}
		    "WARNING" {$FgColor = "Yellow"}
		    "ERROR" {$FgColor = "Red"}
            "SUM" {$FgColor = "Magenta"}
            "SUCCESS" {$FgColor = "Cyan"}
	    }

        if ($Category -eq "TASKINFO"){
            Write-Host ""
            Write-Host $Message
            Write-Host ($taskInfoDash * $message.Length)
            Start-sleep -s 2
        } else {
            Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen 
        }
        
        
        if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            #Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }
}
#end function Write-LogOutput

# function Invoke-PrismRESTCall
function Invoke-PrismRESTCall {
	#input: username, password, url, method, body
	#output: REST response
    <#
    .SYNOPSIS
    Connects to Nutanix Prism REST API.
    .DESCRIPTION
    This function is used to connect to Prism REST API.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER username
    Specifies the Prism username.
    .PARAMETER password
    Specifies the Prism password.
    .PARAMETER url
    Specifies the Prism url.
    .EXAMPLEfntn
    PS> PrismRESTCall -username admin -password admin -url https://10.10.10.10:9440/PrismGateway/services/rest/v1/ 
    #>
	param
	(
		[string] $username,
        [string] $password,
        [string] $url,
        [string] [ValidateSet('GET','PATCH','PUT','POST','DELETE')]$method,
        [string] $message,
        [string] $contenttype,
        $body
	)

    begin{

    	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process {
        if ($body) {
            if ($contenttype -eq "multipart/form-data") {
                $myvarHeader += @{"Content-Type"="multipart/form-data"}
            } else {
                $myvarHeader += @{"Accept"="application/json"}
                $myvarHeader += @{"Content-Type"="application/json"}
            }
            if ($IsLinux -or $IsMacOS) {
                try {
                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                        Write-LogOutput -category "INFO" -message $Message
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    } else {
                        Write-LogOutput -category "INFO" -message $Message
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop 
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    }
		        }
                catch {
                    try {
                        if ($PSVersionTable.PSVersion.Major -ge 6) {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                            Start-sleep -s 2
                            Write-LogOutput -category "SUCCESS" -message $Message
                        } else {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop 
                            Start-sleep -s 2
                            Write-LogOutput -category "SUCCESS" -message $Message
                        }
                    } catch {
                        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                        try {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        } catch {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                        }
                        #exit 1
                    }
		        }
            }
            else {
                try {
                    Write-LogOutput -category "INFO" -message $Message
                    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
                    Start-sleep -s 2
                    Write-LogOutput -category "SUCCESS" -message $Message
		        }
                catch {
                    try {
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    } catch {
                        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                        try {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        } catch {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                        }
                        #exit 1
                    }
		        }
            }
        } 
        else {
            if ($IsLinux -or $IsMacOS) {
                try {
                    Write-LogOutput -category "INFO" -message $Message
                    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -ErrorAction Stop
                    Start-sleep -s 2
                    Write-LogOutput -category "SUCCESS" -message $Message
		        } catch {
                    try {
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -ErrorAction Stop
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    } catch {
                        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                        try {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        } catch {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                        }
                        #exit 1
                    }
		        }
            }
            else {
                try {
                    Write-LogOutput -category "INFO" -message $Message
                    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
                    Start-sleep -s 2
                    Write-LogOutput -category "SUCCESS" -message $Message
		        } catch {
                    try {
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    } catch {
			            Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                        try {
                            $RESTError = Get-RESTError -ErrorAction Stop
                            $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                            if ($RESTErrorMessage) {
                                Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"
                            }
                        } catch {
                            Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                        }
                        #exit 1
                    }
		        }
            }
        }
    }
    end
    {
        return $myvarRESTOutput
    }
}
#end function nvoke-PrismRESTCall

# function Get-NtnxCertException
function Get-NtnxCertException {
# Adding certificate exception to prevent API errors
    try {
        Write-LogOutput "Adding certificate exception to prevent API connectivity issues..." -Category INFO
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
# end function Get-NtnxCertException
#endregion

################################################
# Configure the variables below for the Nutanix Cluster
################################################
#region prepwork

# Global Error Handling
if ($debug -ne "true") { $ErrorActionPreference = 'SilentlyContinue' }

# Start of the script
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()

#region variables
#$myvar_pe_ip = "10.68.97.150"
#$myvar_pe_user= "iz@emeagso.lab"
#$myvar_pe_pwd = "nutanix/4u"
$myvar_pe_url= ("https://" + $myvar_pe_ip + ":9440/api/nutanix/v1")
$myvar_pc_url_v3= ("https://" + $myvar_pc_ip + ":9440/api/nutanix/v3")
#myvar_pe_pwd = (New-Object PSCredential 0, $myvar_pe_secure_pwd).GetNetworkCredential().Password
$myvar_report_table = @()
exit 0
#endregion

#* Processing starts here
#region processing
################################################
#* Retrieving PE cluster details
################################################
Write-LogOutput "Retrieving PE cluster details" -Category TASKINFO
$myvar_message = "Retrieving PE cluster details on Prism Central $myvar_pe_url"
$myvar_payload = @{ kind = "cluster" }
$myvar_body = ConvertTo-Json $myvar_payload
$myvar_cluster_details = Invoke-PrismRESTCall -Method POST -Url $($myvar_pc_url_v3+"/clusters/list") -username $myvar_pe_user -password $myvar_pe_pwd -message $myvar_message -body $myvar_body

######
$myvar_cluster_details.entities.spec.name
$myvar_cluster_details.entities.metadata.uuid
https://10.68.97.150:9440/api/nutanix/v1/vfilers?proxyClusterUuid=000582c6-cf0d-e0a8-0000-000000016950
######

################################################
#* Retrieving Files details
################################################
Write-LogOutput "Retrieving Files details" -Category TASKINFO
$myvar_message = "Retrieving Files details on Prism Element $myvar_pe_url"
$myvar_files_details = Invoke-PrismRESTCall -Method GET -Url $($myvar_pe_url+"/vfilers") -username $myvar_pe_user -password $myvar_pe_pwd -message $myvar_message

foreach ($myvar_file in $myvar_files_details.entities){
    $myvar_file_name = $myvar_file.name
    $myvar_file_uuid = $myvar_file.uuid
    $myvar_file_size = $myvar_file.usageStats.fileserver_size_bytes
    $myvar_file_size
    $myvar_file_size_gib = $($myvar_file_size/1024/1024/1024)
    $myvar_file_size_gib
    Write-LogOutput "Retrieving Files $($myvar_file_name)shares details" -Category TASKINFO
    $myvar_shares_details = Invoke-PrismRESTCall -Method GET -Url $($myvar_pe_url+"/vfilers/"+$($myvar_file_uuid)+"/shares") -username $myvar_pe_user -password $myvar_pe_pwd -message $myvar_message
    foreach ($myvar_share in $myvar_shares_details.entities){
        Write-LogOutput "Retrieving $($myvar_share.name) share details"
        $myvar_share_name = $myvar_share.name
        $myvar_share_file_name = $myvar_share.fileServerName
        $myvar_share_max_size_gib = $myvar_share.maxSizeGiB
        $myvar_share_size_used_bytes = $myvar_share.usageStats.share_used_bytes
        $myvar_share_used_snapshots_bytes =$myvar_share.usageStats.share_usedbysnapshots_bytes
        $myvar_share_name
        $myvar_share_file_name
        $myvar_share_max_size_gib
        $myvar_share_size_used_gib = ($myvar_share_size_used_bytes/1024/1024/1024) | % { '{0:0.##}' -f $_ }
        $myvar_share_used_snapshots_gib = ($myvar_share_used_snapshots_bytes/1024/1024/1024) | % { '{0:0.##}' -f $_ }
        $myvar_share_size_used_gib
        if ($myvar_share_max_size_gib -eq 0){
            Write-LogOutput "share max size equal 0"
            $myvar_share_max_size_gib = $myvar_file_size_gib
            $myvar_share_max_size_gib
        }

        $myvar_report_table += [PSCustomObject]@{
            file_share = $myvar_share_name
            file_server = $myvar_share_file_name
            share_space_provisioned = $myvar_share_max_size_gib
            share_space_used = $myvar_share_size_used_gib
            share_snapshot_used = $myvar_share_used_snapshots_gib
            cost = ($myvar_share_max_size_gib * $myvar_cost_per_tb)

        }
    }
}


Write-Logoutput "Exporting File Report in an excel file" -Category TASKINFO
$myvar_affectation_project_table | Export-Excel $myvar_rapport_file-$($myvar_year).xlsx -AutoSize -WorksheetName $($myvar_month + "_Affectation") -Table $($myvar_month + "_Affectation")

#region cleanup
#let's figure out how much time this all took
Write-LogOutput "Total Script Processing "-Category TASKINFO
Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

#cleanup after ourselves and delete all custom variables
Remove-Module ntnx-globalFunctions -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Remove-Variable debug -ErrorAction SilentlyContinue
Remove-Variable myvar* -ErrorAction SilentlyContinue
#endregion