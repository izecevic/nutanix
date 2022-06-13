<#
    .SYNOPSIS
      This script can be used to suspend or resume Nutanix asynchronous or near-sync protection domains.

    .DESCRIPTION
      This script can be used to suspend or resume Nutanix asynchronous or near-sync protection domains.
      This script has two main worflows: (1) suspend protection domain(s), (2) resume protection domain(s)

      (1) suspend protection domain(s): this workflow will suspend active protection domain schedules for a given Nutanix Cluster
      (2) resume protection domain(s): this workflow will resume active protection domain schedules for a given Nutanix Cluster

      Suspending or Resuming a protection domain doesn't delete entities or snapshots managed by the protection domain.

    .PARAMETER help
      Displays a help message.

    .PARAMETER debugme
      Turns off SilentlyContinue on unexpected error messages.

    .PARAMETER myvarPrismUser
      Nutanix cluster admin user.
        
    .PARAMETER myvarPrismPwd
      Nutanix cluster admin user password.
    
    .PARAMETER myvarPrismIp
      Nutanix cluster fully qualified domain name or IP address.
            
    .PARAMETER myvarPrismPd
      Lets you specify which protection domain(s) you want to suspend/resume. If left blank, all applicable (active) protection domains will be processed.
      You can specify a single protection domain: "pd_test"
      You can specifcy more than a single protection domain: "pd_test1,pd_test2"

    .PARAMETER myvarPrismPdAction
      Nutanix cluster protection Domain action: resume or suspend

    .EXAMPLE
      .\ntnx-PdSchedules.ps1 -myvarPrismUser <admin> -myvarPrismPwd <secret> -myvarPrismIp <cluster_ip> -myvarPrismPd <pd_test> -myvarPrismPdAction <resume>
      Resume the protection domain pd_test on the specified Nutanix cluter

    .EXAMPLE
      .\ntnx-PdSchedules.ps1 -myvarPrismUser <admin> -myvarPrismPwd <secret> -myvarPrismIp <cluster_ip> -myvarPrismPd <pd_test> -myvarPrismPdAction <suspend>
      Suspend the protection domain pd_test on the specified Nutanix cluter

    .EXAMPLE
      .\ntnx-PdSchedules.ps1 -myvarPrismUser <admin> -myvarPrismPwd <secret> -myvarPrismIp <cluster_ip> -myvarPrismPdAction <resume>
      Suspend all protection domains on the specified Nutanix cluter

    .NOTES
      Version:        1.0
      Author:         Igor Zecevic, Consulting Architect <igor.zecevic@nutanix.com>
      Organization:   Nutanix
      Creation Date:  January 19th 2020
      Purpose/Change: Suspend/Resume Nutanix Protection Domains

#>

#region parameters
Param
(
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [string]$debugme = $true,
    [parameter(mandatory = $true)]  [string]$myvarPrismUser = "USER_NUTANIX_CLUSTER",
    [parameter(mandatory = $true)]  [string]$myvarPrismPwd = "PASSWORD_NUTANIX_CLUSTER",
    [parameter(mandatory = $true)]  [string]$myvarPrismIp = "IP_NUTANIX_CLUSTER",
    [parameter(mandatory = $false)] $myvarPrismPd = "PROTECTION_DOMAIN_NUTANIX_CLUSTER", #don't specify type as this is sometimes a string, sometimes an array in the script
    [parameter(mandatory = $true)] [ValidateSet('resume','suspend')][string]$myvarPrismPdAction = "resume ou suspend"
)
#endregion parameters

#region custom variables
    $myvarPrismURLv1 = "https://" + $myvarPrismIp + ":9440/api/nutanix/v1"
    $myvarPrismURLv2 = "https://" + $myvarPrismIp + ":9440/api/nutanix/v2.0"
    $myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
    $myvarOutputLogFile += "$($myvarPrismPd)_$($myvarPrismPdAction)_OutputLog.log"
    $myvarPrismEmailRecipients = "igor.zecevic@nutanix.com"
    $myvarPrismEmailSubject = "Veeam Backup: Action on Protection Domain $($myvarPrismPd): $($myvarPrismPdAction) all active schedules"
    $myvarPrismEmailText = "Hi,`nLooks Like a Veeam Backup is running.`nFor more information, please check the $($myvarOutputLogFile) logfile."
#endregion custom variables

#region functions
# function Write-LogOutput
function Write-LogOutput {
    
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

    param
    (
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
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Write entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }
}
#end function Write-LogOutput

# function Invoke-PrismRESTCall
function Invoke-PrismRESTCall {
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
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process 
    {
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
                        exit 1
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
                        exit 1
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
                        exit 1
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
                        exit 1
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
#end function Get-PrismRESTCall

#function Get-RESTError
function Get-RESTError  {
    $global:helpme = $body
    $global:helpmoref = $moref
    $global:result = $_.Exception.Response.GetResponseStream()
    $global:reader = New-Object System.IO.StreamReader($global:result)
    $global:responseBody = $global:reader.ReadToEnd();

    return $global:responsebody

    break
}
#end function Get-RESTError

#endregion functions

#region prepare
####################################################################################
# Nothing to configure below this line - Starting the main function of the script
####################################################################################

# check if we need to display help
$myvarScriptName = ".\ntnx-PdSchedules.ps1"
if ($help) {
    get-help $myvarScriptName
    exit 0
}

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

#region variables
    $myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp

    # Global Error Handling
    if ($debugme -ne "true") { $ErrorActionPreference = 'SilentlyContinue' }

    #region SSL
        # Checking OS and add SkipCertificateCheck if required (Mainly *nix and Windows on PowerShell Core >7)
        $myvarOS=$PSVersionTable.Platform
        if($($PSDefaultParameterValues.'Invoke-RestMethod:SkipCertificateCheck') -ne "true" -AND $myvarOS -eq "Unix" -AND $($PSVersionTable.PSVersion -join ".") -gt 7) {
            $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)
            $PSDefaultParameterValues.Add("Invoke-WebRequest:SkipCertificateCheck",$true) 
        }

        # Adding certificate exception to prevent API errors for Windows and PowerShell less than Version 7
        if($myvarOS -ne "Unix" -AND $($PSVersionTable.PSVersion -join ".") -lt 7) {
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
            } catch { $myvarErrorMessage = $_.Exception.Message; Write-Host "$(get-date) [ERROR] $myvarErrorMessage" -ForegroundColor Red; Return; }
        }
    #endregion SSL
#endregion variables
#endregion prepare

#region processing
####################################################
# Connect and get Prism Element Details
####################################################
Write-LogOutput "Connecting to Nutanix REST API on $($myvarPrismIp)..." -Category "TASKINFO" -LogFile $myvarOutputLogFile
$myvarMessage = "Getting Nutanix Cluster Information"
$myvarPrismDetails = Invoke-PrismRESTCall -Method GET -url $($myvarPrismURLv2+"/cluster") -username $myvarPrismUser -password $myvarPrismPwd -message $myvarMessage
$myvarPrismName = $myvarPrismDetails.name

####################################################
#* Get Protection Domains
####################################################    
Write-LogOutput "Getting all Protection Domains on $($myvarPrismName)..." -Category "TASKINFO" -LogFile $myvarOutputLogFile
$myvarMessage = "Getting all Protection Domains"
$myvarPdDetails = Invoke-PrismRESTCall -Method GET -url $($myvarPrismURLv2+"/protection_domains") -username $myvarPrismUser -password $myvarPrismPwd -message $myvarMessage

# check if protection domain was provided as parameter, otherwise get all actives protection domains
if ($myvarPrismPd){
    $myvarPrismPd = $myvarPrismPd.split(",") #make sure we process protection_domains as an array
    $myvarPDs = $myvarPdDetails.entities | Where-Object {$_.active -eq $true} | Where-Object {$myvarPrismPd -contains $_.name}
    Write-LogOutput "A list of protection domains was specified to the script: $($myvarPDs.count) protection domains will be processed" -Category INFO
    Write-LogOutput "List of protection domains to processed: $($myvarPDs.name)" -Category "INFO" -LogFile $myvarOutputLogFile
    if (!$myvarPDs) {
        Write-LogOutput "There are no active protection domain named $($myvarPrismPd) on $($myvarPrismName) ..." -Category "ERROR" -LogFile $myvarOutputLogFile
        exit 1
    }
} else {
    $myvarPDs = $myvarPdDetails.entities | Where-Object {$_.active -eq $true} 
    Write-LogOutput "No protection domains was specified as parameter, all active protection domains will be processed ..." -Category "WARNING" -LogFile $myvarOutputLogFile
    Write-LogOutput "There are $($myvarPDs.count) active Protection Domains to processed on $($myvarPrismName)" -"Category INFO" -LogFile $myvarOutputLogFile
    Write-LogOutput "List of protection domains to processed: $($myvarPDs.name)" -Category "INFO" -LogFile $myvarOutputLogFile
}

####################################################
#* Suspend/Resume Protection Domains Schedules
####################################################
if ($myvarPrismPdAction -eq "suspend") {
    Write-LogOutput "Suspending Protection Domains on $($myvarPrismName)..." -Category "TASKINFO" -LogFile $myvarOutputLogFile
    Write-LogOutput "Suspending $($myvarPDs.count) Protection Domains on $($myvarPrismName)" -Category "INFO" -LogFile $myvarOutputLogFile
    forEach ($myvarPD in $myvarPDs){
        if ($myvarPD.cron_schedules.suspended -eq $false){
            Write-LogOutput "Suspending $($myvarPD.name) Protection Domain..." -Category "INFO" -LogFile $myvarOutputLogFile
            Write-LogOutput "VMs part of the $($myvarPD.name) protection domain: $($myvarPD.vms.vm_name)" -Category "INFO" -LogFile $myvarOutputLogFile
            $myvarMessage = "Suspending Protection Domain $($myvarPD.name)..."
            Invoke-PrismRESTCall -Method PUT -url $($myvarPrismURLv2+"/protection_domains/"+$($myvarPD.name)+"/schedules/suspend") -username $myvarPrismUser -password $myvarPrismPwd -message $myvarMessage | Out-Null
        } else {
            Write-LogOutput "Protection Domain $($myvarPD.name) already suspended..." -Category "WARNING" -LogFile $myvarOutputLogFile
        } 
    }
} elseif ($myvarPrismPdAction -eq "resume") {
    Write-LogOutput "Resuming Protection Domains Schedules on $($myvarPrismName)..." -Category "TASKINFO" -LogFile $myvarOutputLogFile
    Write-LogOutput "Resuming $($myvarPDs.count) Protection Domains on $($myvarPrismName)" -Category "INFO" -LogFile $myvarOutputLogFile
    forEach ($myvarPD in $myvarPDs){
        if ($myvarPD.cron_schedules.suspended -eq $true){
            Write-LogOutput "Resuming $($myvarPD.name) Protection Domain..." -Category "INFO" -LogFile $myvarOutputLogFile
            Write-LogOutput "VMs part of the $($myvarPD.name) protection domain: $($myvarPD.vms.vm_name)" -Category "INFO" -LogFile $myvarOutputLogFile
            $myvarMessage = "Resuming Protection Domain $($myvarPD.name)..."
            Invoke-PrismRESTCall -Method PUT -url $($myvarPrismURLv2+"/protection_domains/"+$($myvarPD.name)+"/schedules/resume") -username $myvarPrismUser -password $myvarPrismPwd -message $myvarMessage | Out-Null
        } else {
            Write-LogOutput "Protection Domain $($myvarPD.name) already resumed..." -Category "WARNING" -LogFile $myvarOutputLogFile
        } 
    }
}

####################################################
#* Send Email
####################################################
Write-LogOutput "Sending Email" -Category "TASKINFO" -LogFile $myvarOutputLogFile
$myvarMessage = "Sending Email"
$myvarPayload = @{
    recipients = @($myvarPrismEmailRecipients)
    subject = $myvarPrismEmailSubject
    text = $myvarPrismEmailText
}
$myvarBody = ConvertTo-Json $myvarPayload
Invoke-PrismRESTCall -Method POST $($myvarPrismURLv1+"/cluster/send_email") -username $myvarPrismUser -password $myvarPrismPwd -body $myvarBody  -message $myvarMessage | Out-Null


#endregion processing

#region Housekeeping
#let's figure out how much time this all took
Write-LogOutput "Total Script Processing "-Category "TASKINFO" -LogFile $myvarOutputLogFile
Write-LogOutput "Total processing time: $($myvarElapsedTime.Elapsed.ToString())" -Category "INFO" -LogFile $myvarOutputLogFile

# Clean up our variables
Write-LogOutput "Cleaning up..." -Category "INFO" -LogFile $myvarOutputLogFile
Remove-Variable myvar* -ErrorAction SilentlyContinue
Remove-Variable ErrorActionPreference -ErrorAction SilentlyContinue
Write-Host "$(get-date) [INFO] Done!" -ForegroundColor Green
#endregion Housekeeping