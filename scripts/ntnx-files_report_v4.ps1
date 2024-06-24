<#
    .SYNOPSIS
    This script retrieves Files servers and associated shares details on Prism Central. Upon retrieval, the script generates an Excel report.

    .DESCRIPTION
    XXX

    .PARAMETER myvar_pc_ip
    Prism Central IP address

    .PARAMETER myvar_pc_user
    Prism Central user

    .PARAMETER myvar_pc_pwd
    Prism Central password

    .NOTES
    Version:        0.1
    Author:         Igor Zecevic, Senior Staff Consulting Architect <izecevic@nutanix.com>
    Organization:   Nutanix
    Creation Date:  04 January 2024
<<<<<<< HEAD
    Purpose/Change: 

    .EXAMPLE
    .\ntnx-files_report.ps1 -myvar_pc_ip "10.10.10.10" -myvar_pc_user "admin" -myvar_pc_pwd "nutanix/4u"
=======
    Purpose/Change:

    .EXAMPLE
    .\ntnx-files_report.ps1 -myvar_pc_ip "10.10.10.10" -myvar_pc_user "admin" -myvar_pc_pwd "nutanix/4u" -myvar_file_server "file_server_name"
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
#>

#region parameters
Param (
    [parameter(mandatory = $true)] [string]$myvar_pc_ip,
    [parameter(mandatory = $true)] [string]$myvar_pc_user,
    [parameter(mandatory = $true)] [string]$myvar_pc_pwd,
<<<<<<< HEAD
=======
    [parameter(mandatory = $true)] [string]$myvar_file_server,
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
    [parameter(mandatory = $false)] [string]$myvar_cost_used_per_tb = 6,
    [parameter(mandatory = $false)] [string]$myvar_cost_tiered_per_tb = 3
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
<<<<<<< HEAD
    https://github.com/sbourdeaud
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		#[Parameter(Mandatory)]
=======
    https://github.com/sbourdeaud [github.com]
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

      param
      (
            #[Parameter(Mandatory)]
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
        [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','TASKINFO')]
        [string]$Category="INFO",
        [Parameter(Position=10)][string]$Message,
        [string]$LogFile
<<<<<<< HEAD
	)
=======
      )
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a

    process
    {
        $Date = get-date #getting the date so we can timestamp the output entry
        $FgColor = "Gray" #resetting the foreground/text color
        $taskInfoDash = "-"
        switch ($Category) #we'll change the text color depending on the selected category
<<<<<<< HEAD
	    {
		    "INFO" {$FgColor = "Green"}
		    "WARNING" {$FgColor = "Yellow"}
		    "ERROR" {$FgColor = "Red"}
            "SUM" {$FgColor = "Magenta"}
            "SUCCESS" {$FgColor = "Cyan"}
	    }
=======
          {
                "INFO" {$FgColor = "Green"}
                "WARNING" {$FgColor = "Yellow"}
                "ERROR" {$FgColor = "Red"}
            "SUM" {$FgColor = "Magenta"}
            "SUCCESS" {$FgColor = "Cyan"}
          }
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a

        if ($Category -eq "TASKINFO"){
            Write-Host ""
            Write-Host $Message
            Write-Host ($taskInfoDash * $message.Length)
            Start-sleep -s 2
        } else {
<<<<<<< HEAD
            Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen 
        }
        
        
=======
            Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
        }
       
       
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
	#input: username, password, url, method, body
	#output: REST response
=======
      #input: username, password, url, method, body
      #output: REST response
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
    PS> PrismRESTCall -username admin -password admin -url https://10.10.10.10:9440/PrismGateway/services/rest/v1/ 
    #>
	param
	(
		[string] $username,
=======
    PS> PrismRESTCall -username admin -password admin -url https://10.10.10.10:9440/PrismGateway/services/rest/v1/ [10.10.10.10]
    #>
      param
      (
            [string] $username,
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
        [string] $password,
        [string] $url,
        [string] [ValidateSet('GET','PATCH','PUT','POST','DELETE')]$method,
        [string] $message,
        [string] $contenttype,
        $body
<<<<<<< HEAD
	)

    begin{

    	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
=======
      )

    begin{

      #Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}  
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop 
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    }
		        }
=======
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    }
                    }
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
                catch {
                    try {
                        if ($PSVersionTable.PSVersion.Major -ge 6) {
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                            Start-sleep -s 2
                            Write-LogOutput -category "SUCCESS" -message $Message
                        } else {
<<<<<<< HEAD
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop 
=======
                            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
		        }
=======
                    }
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
            }
            else {
                try {
                    Write-LogOutput -category "INFO" -message $Message
                    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
                    Start-sleep -s 2
                    Write-LogOutput -category "SUCCESS" -message $Message
<<<<<<< HEAD
		        }
=======
                    }
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
		        }
            }
        } 
=======
                    }
            }
        }
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
        else {
            if ($IsLinux -or $IsMacOS) {
                try {
                    Write-LogOutput -category "INFO" -message $Message
                    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -ErrorAction Stop
                    Start-sleep -s 2
                    Write-LogOutput -category "SUCCESS" -message $Message
<<<<<<< HEAD
		        } catch {
=======
                    } catch {
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
		        }
=======
                    }
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
            }
            else {
                try {
                    Write-LogOutput -category "INFO" -message $Message
                    $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
                    Start-sleep -s 2
                    Write-LogOutput -category "SUCCESS" -message $Message
<<<<<<< HEAD
		        } catch {
=======
                    } catch {
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
                    try {
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
                        Start-sleep -s 2
                        Write-LogOutput -category "SUCCESS" -message $Message
                    } catch {
<<<<<<< HEAD
			            Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
=======
                              Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
		        }
=======
                    }
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
            }
        }
    }
    end
    {
        return $myvarRESTOutput
    }
}
<<<<<<< HEAD
#end function nvoke-PrismRESTCall

# function Get-NtnxCertException
function Get-NtnxCertException {
# Adding certificate exception to prevent API errors
    try {
=======
#end function Invoke-PrismRESTCall
#endregion

# Adding certificate exception to prevent API errors
try {
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
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
<<<<<<< HEAD
}
# end function Get-NtnxCertException
#endregion
=======

>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a

################################################
# Configure the variables below for the Nutanix Cluster
################################################
#region prepwork

<<<<<<< HEAD
=======
# Import Module
Import-module ImportExcel

>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
# Global Error Handling
if ($debug -ne "true") { $ErrorActionPreference = 'SilentlyContinue' }

# Start of the script
$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()

#region variables
<<<<<<< HEAD
$myvar_pc_url= ("https://" + $myvar_pc_ip + ":9440")
=======
$myvar_pc_url= ("https://" [%22] + $myvar_pc_ip + ":9440")
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
$myvar_report_table = @()
#endregion

#* Processing starts here
#region processing
################################################
#* Retrieving Files details
################################################
Write-LogOutput "Retrieving Files details" -Category TASKINFO
$myvar_message = "Retrieving Files details on Prism Central $myvar_pc_url"
$myvar_files_details = Invoke-PrismRESTCall -Method GET -Url $($myvar_pc_url+"/api/files/v4.0.a2/config/file-servers") -username $myvar_pc_user -password $myvar_pc_pwd -message $myvar_message
<<<<<<< HEAD
foreach ($myvar_file in $myvar_files_details.data){
    $myvar_file_name = $myvar_file.name
    $myvar_file_uuid = $myvar_file.extId
    $myvar_file_size_tb = ($myvar_file.sizeInGib)
    Write-LogOutput "Retrieving Files $($myvar_file_name) shares details" -Category TASKINFO
    $myvar_message = "Retrieving Files $($myvar_file_name) shares details"
    $myvar_shares_details = Invoke-PrismRESTCall -Method GET -Url $($myvar_pc_url+"/api/files/v4.0.a2/config/file-servers/"+$($myvar_file_uuid)+"/mount-targets") -username $myvar_pc_user -password $myvar_pc_pwd -message $myvar_message
    foreach ($myvar_share in $myvar_shares_details.data){
        Write-LogOutput "Retrieving $($myvar_share.name) share details"
        $myvar_share_name = $myvar_share.name
        $myvar_share_uuid = $myvar_share.extId
        $myvar_share_description = $myvar_share.description
        if ($myvar_share.secondaryProtocol){
            $myvar_share_protocol = ($myvar_share.protocol + "," + $myvar_share.secondaryProtocol)
        } else {
            $myvar_share_protocol = $myvar_share.protocol
        }
        $myvar_share_max_size_tb = ($myvar_share.maxSizeGiB) | % { '{0:0.##}' -f $_ }

        # retrieving file share date creation using PC v3 group API
        $myvar_message = "Retrieving shares $($myvar_share_name) creation date details"
        $myvar_payload = @{
            entity_type = "file_server_share"
            filter_criteria = "original_entity_id==$($myvar_share_uuid)"
        }
        $myvar_body = ConvertTo-JSON $myvar_payload 
        $myvar_share_groups_details = Invoke-PrismRESTCall -Method POST -Url $($myvar_pc_url+"/api/files/nutanix/v3/"+$($myvar_file_uuid)+"/groups") -username $myvar_pc_user -password $myvar_pc_pwd -message $myvar_message -body $myvar_body
        $myvar_share_date_created_timestamp = $myvar_share_groups_details.group_results.entity_results.data.values.time
        $myvar_share_date_created = Get-Date -f "dd/MM/yyyy" -UnixTime ($myvar_share_date_created_timestamp / 1000 / 1000)

        # retreiving file share stats (share_usedbysnapshots_bytes,share_used_bytes,on_prem_share_tiered_bytes)
        $myvar_message = "Retrieving shares $($myvar_share_name) stats details"
        $myvar_body = @{metrics = "share_usedbysnapshots_bytes,share_used_bytes,on_prem_share_tiered_bytes"}
        $myvar_share_stats_details = Invoke-PrismRESTCall -Method GET -Url $($myvar_pc_url+"/api/files/v4.0.a2/stats/file-servers/"+$($myvar_file_uuid)+"/mount-targets/$($myvar_share_uuid)") -username $myvar_pc_user -password $myvar_pc_pwd -message $myvar_message -body $myvar_body
        $myvar_share_used_snapshots_tb = ($myvar_share_stats_details.data[0].values.value / 1024/1024/1024) | % { '{0:0.#}' -f $_ }
        $myvar_share_used_tb = ($myvar_share_stats_details.data[1].values.value / 1024/1024/1024) | % { '{0:0.#}' -f $_ }
        $myvar_share_on_prem_tiered_tb  = ($myvar_share_stats_details.data[2].values.value / 1024/1024/1024) | % { '{0:0.#}' -f $_ }
        if ($myvar_share_max_size_tb -eq 0){
            $myvar_share_provisioned_tb = $myvar_file_size_tb
        } else {
            $myvar_share_provisioned_tb = $myvar_share_max_size_tb
        }
       
        # creating the export table       
        Write-LogOutput "Pushing shares details to the export report table" -Category INFO
        $myvar_report_table += [PSCustomObject]@{
            'Date Created' = $myvar_share_date_created
            'File Share Name' = $myvar_share_name
            'File Share Description' = $myvar_share_description
            'File Share Protocol' = $myvar_share_protocol
            'File Server Name' = $myvar_file_name
            'Share Space Provisioned' = $myvar_share_provisioned_tb
            'Share Space Used' = $myvar_share_used_tb
            #share_snapshot_used = $myvar_share_used_snapshots_gib
            'Cost Space Provisioned'= ([decimal]$myvar_share_provisioned_tb * ($myvar_cost_used_per_tb))
            'Share Space Tiered' =  $myvar_share_on_prem_tiered_tb
            'Cost Space Tiered'= ([decimal]$myvar_share_on_prem_tiered_tb.Replace(",", ".") * ($myvar_cost_tiered_per_tb))
        }
=======
#$myvar_files_details.data

foreach ($myvar_file in $myvar_files_details.data){
    if ($($myvar_file.name) -eq $myvar_file_server){
        $myvar_file_name = $myvar_file.name
        $myvar_file_uuid = $myvar_file.extId
        $myvar_file_size_tb = (($myvar_file.sizeInGib) / 1024)
        Write-LogOutput "Retrieving Files $($myvar_file_name) shares details" -Category TASKINFO
        $myvar_message = "Retrieving Files $($myvar_file_name) shares details"
        $myvar_shares_details = Invoke-PrismRESTCall -Method GET -Url $($myvar_pc_url+"/api/files/v4.0.a2/config/file-servers/"+$($myvar_file_uuid)+"/mount-targets") -username $myvar_pc_user -password $myvar_pc_pwd -message $myvar_message
        foreach ($myvar_share in $myvar_shares_details.data){
            Write-LogOutput "Retrieving $($myvar_share.name) share details"
            $myvar_share_name = $myvar_share.name
            $myvar_share_uuid = $myvar_share.extId
            $myvar_share_description = $myvar_share.description
            if ($myvar_share.secondaryProtocol){
                $myvar_share_protocol = ($myvar_share.protocol + "," + $myvar_share.secondaryProtocol)
            } else {
                $myvar_share_protocol = $myvar_share.protocol
            }
            $myvar_share_max_size_tb = (($myvar_share.maxSizeGiB) / 1024) | % { '{0:0.##}' -f $_ }

            # retrieving file share date creation using PC v3 group API
            $myvar_message = "Retrieving shares $($myvar_share_name) creation date details"
            $myvar_payload = @{
                entity_type = "file_server_share"
                filter_criteria = "original_entity_id==$($myvar_share_uuid)"
            }
            $myvar_body = ConvertTo-JSON $myvar_payload
            $myvar_share_groups_details = Invoke-PrismRESTCall -Method POST -Url $($myvar_pc_url+"/api/files/nutanix/v3/"+$($myvar_file_uuid)+"/groups") -username $myvar_pc_user -password $myvar_pc_pwd -message $myvar_message -body $myvar_body
            $myvar_share_date_created_timestamp = $myvar_share_groups_details.group_results.entity_results.data.values.time
            $myvar_share_date_created = Get-Date -f "dd/MM/yyyy" -UnixTime ($myvar_share_date_created_timestamp / 1000 / 1000)

            # retreiving file share stats (share_usedbysnapshots_bytes,share_used_bytes,on_prem_share_tiered_bytes)
            $myvar_message = "Retrieving shares $($myvar_share_name) stats details"
            $myvar_body = @{metrics = "share_usedbysnapshots_bytes,share_used_bytes,on_prem_share_tiered_bytes"}
            $myvar_share_stats_details = Invoke-PrismRESTCall -Method GET -Url $($myvar_pc_url+"/api/files/v4.0.a2/stats/file-servers/"+$($myvar_file_uuid)+"/mount-targets/$($myvar_share_uuid)") -username $myvar_pc_user -password $myvar_pc_pwd -message $myvar_message -body $myvar_body
            $myvar_share_used_snapshots_tb = ($myvar_share_stats_details.data[0].values.value / 1024/1024/1024/1024) | % { '{0:0.#}' -f $_ }
            $myvar_share_used_tb = ($myvar_share_stats_details.data[1].values.value / 1024/1024/1024/1024) | % { '{0:0.#}' -f $_ }
            $myvar_share_on_prem_tiered_tb  = ($myvar_share_stats_details.data[2].values.value / 1024/1024/1024/1024) | % { '{0:0.#}' -f $_ }
            if ($myvar_share_max_size_tb -eq 0){
                $myvar_share_provisioned_tb = $myvar_file_size_tb
            } else {
                $myvar_share_provisioned_tb = $myvar_share_max_size_tb
            }
       
            # creating the export table      
            Write-LogOutput "Pushing shares details to the export report table" -Category INFO
            $myvar_report_table += [PSCustomObject]@{
                'Date Created' = $myvar_share_date_created
                'File Share Name' = $myvar_share_name
                'File Share Description' = $myvar_share_description
                'File Share Protocol' = $myvar_share_protocol
                'File Server Name' = $myvar_file_name
                'Share Space Provisioned' = $myvar_share_provisioned_tb
                'Share Space Used' = $myvar_share_used_tb
                #share_snapshot_used = $myvar_share_used_snapshots_gib
                'Cost Space Provisioned £'= ([decimal]$myvar_share_provisioned_tb * ($myvar_cost_used_per_tb))
                'Share Space Tiered' =  $myvar_share_on_prem_tiered_tb
                'Cost Space Tiered £'= ([decimal]$myvar_share_on_prem_tiered_tb.Replace(",", ".") * ($myvar_cost_tiered_per_tb))
                'Total Cost £' = (([decimal]$myvar_share_provisioned_tb * ($myvar_cost_used_per_tb)) + ([decimal]$myvar_share_on_prem_tiered_tb.Replace(",", ".") * ($myvar_cost_tiered_per_tb)))
            }
        }
    } else {
        Write-Logoutput "skipping file server $($myvar_file.name)" -Category WARNING
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
    }
}

Write-Logoutput "Exporting File Report.." -Category TASKINFO
[Array]::Reverse($myvar_report_table) # reverse order date creation
$myvar_report_table | Export-Excel -TableStyle "Light1" -WorksheetName "Cost Recovery Report" -Title "Date Produced - $(Get-Date -Format "dd/MM/yy")" -TitleSize 12 -TitleBold -AutoSize -StartRow 3 -StartColumn 2 -Path ./"Cost Recovery Report-$(Get-Date -Format "MMMM-yy").xlsx"

#region cleanup
#let's figure out how much time this all took
Write-LogOutput "Total Script Processing "-Category TASKINFO
Write-Host "$(get-date) [SUM] total processing time: $($myvarElapsedTime.Elapsed.ToString())" -ForegroundColor Magenta

#cleanup after ourselves and delete all custom variables
Remove-Module ntnx-globalFunctions -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Remove-Variable debug -ErrorAction SilentlyContinue
Remove-Variable myvar* -ErrorAction SilentlyContinue
<<<<<<< HEAD
#endregion
=======
#endregion
>>>>>>> 7a69f968fc56ad0ebc227877b90704921b40cb8a
