<#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER debugme
      Turns off SilentlyContinue on unexpected error messages.

    .PARAMETER myvarPCuser
      Nutanix PC admin user.
        
    .PARAMETER myvarPCpwd
      Nutanix PC admin user password.
    
    .PARAMETER myvarPCip
      Nutanix PC fully qualified domain name or IP address.
            
    .EXAMPLE
      .\ntnx-getProjectsConsumption.ps1 -myvarPCiser <pc_user> -myvarPCpwd <pc_secret> -myvarPCip <pc_ip> 
      Get consumption data of all calm projects

    .NOTES
      Version:        1.0
      Author:         Igor Zecevic, Senior Staff Consulting Architect <igor.zecevic@nutanix.com>
      Organization:   Nutanix
      Creation Date:  Monday 25th October 2022

#>

#region parameters
Param
(
    [parameter(mandatory = $false)] [string]$debugme = $true,
    [parameter(mandatory = $true)]  [string]$myvarPCuser = "iz@emeagso.lab",
    [parameter(mandatory = $true)]  [string]$myvarPCpwd = "XXX",
    [parameter(mandatory = $true)]  [string]$myvarPCip = "XXX"
)
#endregion parameters

#region module
    Install-Module ImportExcel -ErrorAction Stop
#end region

#region custom variables
    $myvarPCURLv3 = "https://" + $myvarPCip + ":9440/api/nutanix/v3"
    $myvarPrismEmailRecipients = "igor.zecevic@nutanix.com"
    $myvarPrismEmailSubject = "Test"
    $myvarPrismEmailText = "subject table"
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

#function Get-NtnxBanner
function Get-NtnxBanner {
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
}
#end function Get-NtnxBanner
#endregion functions

#region prepare
####################################################################################
# Nothing to configure below this line - Starting the main function of the script
####################################################################################

#region Nutanix Logo
Get-NtnxBanner
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
# Get Calm Projects Details
####################################################
Write-LogOutput "Getting Calm Projects Details on PC $($myvarPCiP)..." -Category "TASKINFO"
$myvarMessage = "Getting Calm Projects Details"
$myvarPayload = @{kind = "project"}
$myvarBody = ConvertTo-Json $myvarPayload
$myvarProjectsDetails = Invoke-PrismRESTCall -Method POST -url $($myvarPCURLv3+"/projects/list") -username $myvarPCuser -password $myvarPCpwd -body $myvarBody -message $myvarMessage

####################################################
#* Get Calm Projects Comsuption data
####################################################  
$myvarPcProjectTable = @()
Write-LogOutput "Getting Calm Projects Consumption data on PC $($myvarPCiP)..." -Category "TASKINFO"
ForEach ($myvarProject in $myvarProjectsDetails.entities.metadata){
    $myvarMessage = "Getting consumption data for Project $($myvarProject.name)"
    $myvarPayload = @{
        time_unit = "month"
        filters = @{
            entity_ids = @($myvarProject.uuid)
        }
        
    }
    $myvarBody = ConvertTo-Json $myvarPayload
    $myvarProjectConsumption = Invoke-PrismRESTCall -Method POST -url $($myvarPCURLv3+"/projects/consumption_list") -username $myvarPCuser -password $myvarPCpwd -body $myvarBody -message $myvarMessage
    
    # filling the myvarPcProjectTable
    $myvarPcProjectTable += [PSCustomObject]@{
        Project_Name = $($myvarProject.name)
        Project_Uuid =$($myvarProject.uuid)
        Project_USD = [math]::Round($myvarProjectConsumption.data.total_spend,2)
    }
}

####################################################
#* Exporting Table in Excel File
#################################################### 
Write-Host "$(get-date) [ACTION] Exporting PC Calm Project Consumption Table in Excel File" -ForegroundColor Green
$myvarPcProjectTable | Export-Excel ./myrapport.xlsx -AutoSize -WorksheetName "CalmPcExportTable"

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
#Invoke-PrismRESTCall -Method POST $($myvarPCURLv1+"/cluster/send_email") -username $myvarPCuser -password $myvarPCpwd -body $myvarBody  -message $myvarMessage | Out-Null


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