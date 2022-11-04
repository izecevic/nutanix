
# WORK IN PROGRESS

$myvar_user = "iz@emeagso.lab"
$myvar_pwd = "nutanix/4u"
$myvar_ip = "10.68.97.100"
$myvar_url = "https://" + $myvar_ip + ":9440/api/nutanix/v1"
$myvar_header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($myvar_user)"+":"+$($myvar_pwd)))}
$myvar_type = "application/octet-stream;charset=UTF-8" 


$myvar_file_metadata = "/Users/igorzecevic/Downloads/generated-nutanix-ncc-el7.3-release-ncc-4.6.1-x86_64-latest.metadata.json"
$myvar_file_binary = "/Users/igorzecevic/Downloads/nutanix-ncc-el7.3-release-ncc-4.6.1-x86_64-latest.tar.gz"
$myvar_file_medatata_item = (Get-Item $myvar_file_metadata)
$myvar_file_binary_item = (Get-Item $myvar_file_binary)
$myvar_file_metadata_content = (Get-Content $myvar_file_metadata | ConvertFrom-Json)
$myvar_file_type = $($myvar_file_metadata_content.type)
$myvar_file_version_id = $($myvar_file_metadata_content.version_id)
$myvar_file_size = $($myvar_file_metadata_content.size)
$myvar_file_md5 = $($myvar_file_metadata_content.hex_md5)


# validate metadata
$myvar_validate_metadata = Invoke-RestMethod -Method POST $($myvar_url+"/upgrade/$($myvar_file_type)/softwares/validate_upload") -Headers $myvar_header -ContentType $myvar_type -Infile $myvar_file_medatata_item -TimeoutSec 30 -SessionVariable myvar_session -SkipCertificateCheck

# upload file
Invoke-RestMethod -Method POST $($myvar_url+"/upgrade/$($myvar_file_type)/softwares/$($myvar_file_version_id )/upload?fileSize=$($myvar_file_size)&md5Sum=$($myvar_file_md5 )&overwrite=falsefileName=$($myvar_file_version_id)&version=$($myvar_file_version_id)") -Headers $myvar_header -ContentType $myvar_type -Infile $myvar_file_binary_item -Websession $myvar_session -TimeoutSec 300 -SkipCertificateCheck