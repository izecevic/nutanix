# region headers
# task_name:    DomainUnjoin
# description:  tries to unjoin Active Directory domain. Does not return an error if it fails.
#               this is to prevent calm app delete task from failing at this step.
# output vars:  none
# dependencies: none
# endregion

#region capture Calm variables
$ad_username = "@@{ad_credentials.username}@@"
$ad_username_secret = "@@{ad_credentials.secret}@@"
$ad_domain = "@@{ad_domain}@@"
#endregion

#converting password to something we can use
$adminpassword = ConvertTo-SecureString -asPlainText -Force -String "ad_username_secret"
#creating the credentials object based on the Calm variables
$credential = New-Object System.Management.Automation.PSCredential($ad_username ,$adminpassword)
#unjoining the domain
write-host "$(get-date) [INFO] Unjoining Active Directory domain" -ForegroundColor Green
try 
{
    $result = remove-computer -UnjoinDomainCredential ($credential) -Force -PassThru -ErrorAction Stop -Verbose
}
catch 
{
    write-host "$(get-date) [ERROR] Could not unjoin Active Directory domain : $($_.Exception.Message)"
    $Error.Clear()
}
write-host "$(get-date) [SUCCESS] Successfully unjoined Active Directory domain" -ForegroundColor Green