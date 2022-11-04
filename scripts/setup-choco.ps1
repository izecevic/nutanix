#choco-install
Set-ExecutionPolicy Unrestricted -Force -Confirm:$false
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

#system-tools
choco install -y powershell
choco install -y googlechrome
choco install -y firefox
choco install -y mobaxterm
choco install -y flashplayerplugin
choco install -y notepadplusplus
choco install -y 7zip
choco install -y jre8
choco install -y adobereader
choco install -y vmware-powercli-psmodule
choco install -y winscp
choco install -y putty
choco install -y vcscode
choco install -y postman
choco install -y vmrc