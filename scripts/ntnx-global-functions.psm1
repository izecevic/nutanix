# function Write-Info
function Write-Info
{
  param(
    [ValidateSet('INFO','WARNING','ERROR','SUM','SUCCESS','TASKINFO')]
    [string]$Category="INFO",
    [Parameter(Position=10)][string]$Message,
    [string]$LogFile
	)
  process {
    $Date = get-date #getting the date so we can timestamp the output entry
    $FgColor = "Gray" #resetting the foreground/text color
    $taskInfoDash = "-"
     #we'll change the text color depending on the selected category
    switch ($Category) {
      "INFO" {$FgColor = "Green"}
      "WARNING" {$FgColor = "Yellow"}
      "ERROR" {$FgColor = "Red"}
      "SUM" {$FgColor = "Magenta"}
      "SUCCESS" {$FgColor = "Cyan"}
  }
    if ($Category -eq "TASKINFO"){
        Write-Host ""
        Write-Host "[ACTION] $Message"
        Write-Host ($taskInfoDash * ($message.Length + 9))
    } else {
        Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen 
    }
  }
}
#end function Write-Info


# function Invoke-PrismAPICall
function Invoke-PrismAPICall
#this function is used to make a REST api call to Prism
{
param 
(
    [parameter(mandatory = $true)]  [ValidateSet("POST","GET","DELETE","PUT")][string]$method,
    [parameter(mandatory = $true)]  [string] $url,
    [parameter(mandatory = $false)] [string] $body,
    [parameter(mandatory = $true)]  [System.Management.Automation.PSCredential]$credential
)
process {
    Write-Host "$(Get-Date) [INFO] Making a $method call to $url" -ForegroundColor Green
    try {
        #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            $headers = @{
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            if ($body) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $body -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
            }
        } else {
            $username = $credential.UserName
            $password = $credential.Password
            $headers = @{
                "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                "Content-Type"="application/json";
                "Accept"="application/json"
            }
            if ($body) {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $body  -ErrorAction Stop
            } else {
                $resp = Invoke-RestMethod -Method $method -Uri $url -Headers $headers  -ErrorAction Stop
            }
        }
        Write-Host "$(get-date) [SUCCESS] Call $method to $url succeeded." -ForegroundColor Cyan
    }
    catch {
        $saved_error = $_.Exception.Message
        Write-Host "$(get-date) [ERROR] $saved_error" -ForegroundColor Red
        Write-Host "$(get-Date) [INFO] Payload: $body" -ForegroundColor Green
    }
}
end
{
return $resp
}    
}
#end function Invoke-PrismRESTCall


# region function Set-Creds
function Set-Creds {
    Param 
    (
        [parameter(mandatory = $false)] $myvarUsername,
        [parameter(mandatory = $false)] $myvarPassword
    )

    Write-Host "Please specify your login credentials"
    if (!$myvarUsername) { 
        $myvarUsername = Read-Host "Enter username"
    } 
    if (!$myvarPassword) { 
      $Securepassword = Read-Host "Enter the user $myvarUsername password" -AsSecureString
    } else { 
      $SecurePassword = ConvertTo-SecureString $myvarPassword –asplaintext –force
      Remove-Variable myvarPassword
    }

    # building the creds
    $myvarCredentials = New-Object PSCredential $username, $SecurePassword

    return $myvarCredentials
}
# end function Set-Creds