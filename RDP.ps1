#Written by Alex Richardson - Logic, Inc.  
# alex@logic-control.com
# 10/9/2024
# Install the RDP role.  Session Host and License Server.  
# Also does the normal group policy configurations for thin clients
# It will prompt a couple times to install powershell modules.  Say yes to all that.
# This has only been tested on Windows Server 2022
# This requires internet because it download modules for doing gpedit
# Before running this script do these two powershell commands to make sure powershell can do stuff

#set-executionpolicy RemoteSigned
#Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator."
    exit
}

#needed to properly install the session host and license server for RDP.  Otherwise, things get half installed.
Import-Module ServerManager

#Install RDP Role Session Host
Install-WindowsFeature -Name RDS-RD-Server -IncludeAllSubFeature -IncludeManagementTools -Restart:$false


#Install RDP Role License Server
Install-WindowsFeature -Name RDS-Licensing -IncludeAllSubFeature -IncludeManagementTools -Restart:$false


Install-Module -Name PolicyFileEditor

#An example of getting policies
#Get-PolicyFileEntry -Path "C:\Windows\System32\GroupPolicy\Machine\Registry.pol" -All #| Export-Clixml -Path C:\temp\UserPol.xml

#an example of using remove
#Remove-PolicyFileEntry -Key "C:\Windows\system32\GroupPolicy\Machine\registry.pol" -ValueName "LicenseServers" -Path "$env:windir\system32\GroupPolicy\Machine\registry.pol"

#set the license server to 127.0.0.1
Set-PolicyFileEntry -Path "$env:windir\system32\GroupPolicy\Machine\registry.pol" -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "LicenseServers" -Data "127.0.0.1"

#Set the licensing mode to per device
Set-PolicyFileEntry -Path "$env:windir\system32\GroupPolicy\Machine\registry.pol" -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "LicensingMode" -Data "2" -Type DWord

#Allow Remote Start of Unlisted programs
Set-PolicyFileEntry -Path "$env:windir\system32\GroupPolicy\Machine\registry.pol" -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fAllowUnlistedRemotePrograms" -Data "1" -Type DWord

#Disable Single Session
Set-PolicyFileEntry -Path "$env:windir\system32\GroupPolicy\Machine\registry.pol" -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fSingleSessionPerUser" -Data "0" -Type DWord

#Max Disconnect Time 1 Minute
Set-PolicyFileEntry -Path "$env:windir\system32\GroupPolicy\Machine\registry.pol" -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "MaxDisconnectionTime" -Data "60000" -Type DWord

#User Authentication
Set-PolicyFileEntry -Path "$env:windir\system32\GroupPolicy\Machine\registry.pol" -Key "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "UserAuthentication" -Data "0" -Type DWord

gpupdate /force  #this might not be necessary

Restart-Computer -Force


<#

#Below is some code for activating the license using scripting
# usually best to manually do it, but here it is for when it is helpful

$licenseKey = 'NJJ87BBC9DR2CD4RXW4MRC4PV' #no hyphens!!


#### Activate RDP License Server ###
$wmiClass = ([wmiclass]"\\localhost\root\cimv2:Win32_TSLicenseServer")

$wmiTSLicenseObject = Get-WMIObject Win32_TSLicenseServer -computername 'localhost'
$wmiTSLicenseObject.FirstName="Suzy"
$wmiTSLicenseObject.LastName="Sample"
$wmiTSLicenseObject.Company="Independent Consolidators"
$wmiTSLicenseObject.CountryRegion="United States"
$wmiTSLicenseObject.Put()

$wmiClass.ActivateServerAutomatic()


$InvokeSplat = @{
    MethodName = 'InstallRetailPurchaseLicenseKeyPack'
    ClassName  = 'Win32_TSLicenseKeyPack'
    Namespace  = 'root\cimv2'
    Arguments  = @{
        sLicenseCode    = $licenseKey  #no hyphens!!!!
    }
}

Invoke-CimMethod @InvokeSplat
#>
