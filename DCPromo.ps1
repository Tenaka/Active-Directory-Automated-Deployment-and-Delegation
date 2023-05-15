<#-----------------------------
Overview.
    Deploy multiple Domain Controllers and a new Forest from the JSON file input
    
Description.
    This is script 1 of 4

    They execute via scheduled tasks in the following order:

    1 - DCPromo.ps1
            Imports JSON config and either deploys new forest and DC or additional DC's to the forest
            Sets AutoLogon and Schedule Task for System Logon

    2 - schRebootDCInit.ps1
            System start up configures the next schedule and reboots
            This step is required as the DCPromo scheduled task wont create and resolve the administrator name without a fully functional DC
            
    3 - schAdminDeploy.ps1
            Resolves the Administrator account for the next scheduled task

    4 - CreateOU.ps1
            Deploys the Domain configutation eg Sites, DNS, OU Structure, enabled AD Recycle Bin


Version.
230510.1 - workable scripts 
230511.1 - Functions for delegation (CreateOU)
230512.1 - OU structure from JSON (CreateOU)
230513.1 - New OU added for basic structure

-----------------------------#>

#Confirm for elevated admin
if (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Host "An elevated administrator account is required to run this script." -ForegroundColor Red
    }
else
{
<#-----------------------------

Declare variable for Present Working Directory for either PS or ISE

-----------------------------#>

    if($psise -ne $null)
    {
        $ISEPath = $psise.CurrentFile.FullPath
        $ISEDisp = $psise.CurrentFile.DisplayName.Replace("*","")
        $Pwdir = $ISEPath.TrimEnd("$ISEDisp")

    }
    else
    {
        $Pwdir = split-path -parent $MyInvocation.MyCommand.Path
    }

<#-----------------------------

Start Some Basic Logging

-----------------------------#>

    Start-Transcript -Path "$($Pwdir)\1_DCPromo.log" -Append -Force

<#-----------------------------

Import json and subnet csv

-----------------------------#>

    #Import json and csv files.
    $dcPromoJson = "DCPromo.json"
    $dcPromoSubnet = "Subnet.csv"
   
    $gtDCPromoJ = Get-Content -raw -Path "$($Pwdir)\$($dcPromoJson)" | ConvertFrom-Json -ErrorAction Stop
    [array]$gtSubnet = Import-Csv -Path "$($Pwdir)\$($dcPromoSubnet)"

    #declare names of other scripts
    $dcSchInit = "schRebootDCInit.ps1"
    $dcSchAdmin = "schAdminDeploy.ps1"
    $ouDeployment = "CreateOU.ps1" 
    
    #paths to scripts referenced by the scheduled tasks
    $schInitial = "$($Pwdir)\$($dcSchInit)"
    $schInitial2 = "$($Pwdir)\$($dcSchAdmin)"
    $schOUDeploy = "$($Pwdir)\$($ouDeployment)"

<#-----------------------------

Install Windows Features and load AD Module

-------------------------------#>
    
    try 
    {
        Install-WindowsFeature -Name "AD-Domain-Services","DNS" -IncludeManagementTools
    }
    Catch
    {
        Write-Host "error installing features" -ForegroundColor Red
    }
    Import-Module "ADDSDeployment"

<#-----------------------------

Declare PDC and Domain vars 

-------------------------------#>

    #Declare varibles from JSON import for 1st Domain Controller and domain specific attibutes
    $PDC_Name = $gtDCPromoJ.FirstDC.PDCName
    $PDC_IP = $gtDCPromoJ.FirstDC.IPAddress
    $PDC_Subnet = $gtDCPromoJ.FirstDC.Subnet
    $PDC_Route = $gtDCPromoJ.FirstDC.DefaultGateway
    $PDC_DomainName = $gtDCPromoJ.FirstDC.DomainName
    $PDC_Netbios = $gtDCPromoJ.FirstDC.DomainNetbiosName
    $PDC_DomainMode = $gtDCPromoJ.FirstDC.DomainMode
    $PDC_ForestMode = $gtDCPromoJ.FirstDC.ForestMode
    $PDC_DBPath = $gtDCPromoJ.FirstDC.DatabasePath
    $PDC_LogPath = $gtDCPromoJ.FirstDC.LogPath
    $PDC_SysVolPath = $gtDCPromoJ.FirstDC.SysvolPath
    $PDC_CreateDNSDele = [system.convert]::ToBoolean($gtDCPromoJ.FirstDC.CreateDnsDelegation)
    $PDC_InstallDNS = [system.convert]::ToBoolean($gtDCPromoJ.FirstDC.InstallDns)
    $PDC_Reboot = [system.convert]::ToBoolean($gtDCPromoJ.FirstDC.NoRebootOnCompletion)
    $PDC_Force = [system.convert]::ToBoolean($gtDCPromoJ.FirstDC.Force)
    $PDC_DRSM = $gtDCPromoJ.FirstDC.DRSM
    $Dom_Admin = $gtDCPromoJ.FirstDC.DomAcct
    $Dom_Passwrd = $gtDCPromoJ.FirstDC.DomPwd
    $Dom_PromptPw = $gtDCPromoJ.FirstDC.PromptPw

    #Decalre additional varibles from JSON for additional Domain Controllers
    $DC_CriticalRep = [system.convert]::ToBoolean($gtDCPromoJ.SubDCs.CriticalReplicationOnly)    
    $DC_NoGC = [system.convert]::ToBoolean($gtDCPromoJ.SubDCs.NoGlobalCatalog)

<#-----------------------------

Ask some questions or comment them out to take default values from json
JSON config @ $Dom_PromptPw = $gtDCPromoJ.FirstDC.PromptPw will prompt for new passwords if set to TRUE, otherwise will use the password provided

-----------------------------#>  
 
    #First DC and PDC Emulator
    if ($PDC_Name -eq $env:computername)
    {
        if ($Dom_PromptPw -eq "true")
            {
            #Gives option to use the default DRSM password provided in clear text in the json file or prompt to use a different password
            $rdDrsm = Read-Host "Take default password for DRSM or update....Y update or another key to exit"
            if ($rdDrsm -eq "Y")
                {
                    $PDC_DRSM = Read-Host "Enter the new DRSM password"
                }
            #Hash the above DRSM lines so there is no prompt for password change and the clear text password is taken from the Json file
            }

        #convert the DRSM password to a secure string
        $drsmSecurePassword = ConvertTo-SecureString -AsPlainText $PDC_DRSM -Force

<#-----------------------------
  
Set Networking 

------------------------------#>

        #Get Network properties
        $gtNetAdpap = Get-NetAdapter | where {$_.Status -eq "up"}
        $intAlias = $gtNetAdpap.InterfaceAlias

        $gtNetIPConfig = Get-NetIPConfiguration -InterfaceAlias $gtNetAdpap.Name
        $IPAddress = $gtNetIPConfig.IPv4Address.ipaddress
        $DHCPRouter = $gtNetIPConfig.IPv4DefaultGateway.nexthop
        $dnsAddress = $gtNetIPConfig.dnsserver.serveraddresses

        #Test if current IP is the same JSON, if not remove all properties and reset
        if ($IPAddress -ne $PDC_IP -and $dnsAddress -ne $PDC_IP)
        {            
            #Remove current IP Address and router
            $gtNetIPConfig | Remove-NetIPAddress -Confirm:$false
            $gtNetIPConfig.IPv4DefaultGateway |Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
            Set-DnsClientServerAddress -InterfaceAlias $intAlias -ResetServerAddresses

            #Subnet to CIDR conversion table 
            foreach($lnSubnet in $gtSubnet)
            {
                if ($lnSubnet.mask -cmatch $PDC_Subnet)
                    {
                        $Prefix = $lnSubnet.cidr
                    }
            }

            #Set new IP Address specified from json file
            New-NetIPAddress -InterfaceAlias $gtNetAdpap.Name `
                     -IPAddress $PDC_IP                       `
                     -AddressFamily IPv4                      `
                     -PrefixLength $Prefix                    `
                     -DefaultGateway $PDC_Route
        
            #Set DNS Server                 
            Set-DnsClientServerAddress -ServerAddresses $PDC_IP -InterfaceAlias $intAlias
        }

<#-----------------------------

Set Autologon for the PDC - Risk password is writtent to Registry in the clear
Warning - setting Passwored for Autologon is a security risk and should not be used in production

-----------------------------#>

        #Autologon
        $adminGet = gwmi win32_useraccount | where {$_.name -eq "$Dom_Admin"}
        $sidGet = $adminGet.SID

        #Sets Autologon Reg keys and credentials
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1 -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "$($PDC_Netbios)\$($Dom_Admin)" -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value $Dom_Passwrd -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonSID -Value $sidGet -Force
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 0 -PropertyType string -Force

        $schTaskName = "DCInitialBoot"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $NTSystem = "NT Authority\System"
        $battery = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries 
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-executionPolicy bypass -file $schInitial"
        Register-ScheduledTask -TaskName $schTaskName -Trigger $trigger -Settings $battery -User $NTSystem -Action $action -RunLevel Highest -Force
  

<#-----------------------------

DCPROMO and create the first Domain Controller

-----------------------------#>

        #DCPromo the Server
        Install-ADDSForest                       `
        -CreateDnsDelegation:$PDC_CreateDNSDele  `
        -DatabasePath $PDC_DBPath                `
        -DomainMode $PDC_DomainMode              `
        -DomainName $PDC_DomainName              `
        -DomainNetbiosName $PDC_Netbios          `
        -ForestMode $PDC_ForestMode              `
        -InstallDns:$PDC_InstallDNS              `
        -LogPath $PDC_LogPath                    `
        -NoRebootOnCompletion:$PDC_Reboot        `
        -SysvolPath $PDC_SysVolPath              `
        -Force:$PDC_Force                        `
        -SafeModeAdministratorPassword $drsmSecurePassword

<#-----------------------------

Stop Logging

-----------------------------#>

        Stop-Transcript -Force

    }
    else
    {
<#-----------------------------

Additional Domain Controllers

-----------------------------#>

        $DC_Details = $gtDCPromoJ.SubDCs.Networking

        foreach($lnDC in $DC_Details)
            {
                if ($lnDC.DCName -cmatch $env:computername)
                    {
                        $DC_IP = $lnDC.IPAddress
                        $DC_Subnet = $lnDC.Subnet
                        $DC_Route = $lnDC.DefaultGateway
                        $AD_Site = $lnDC.SiteName
                        $DC_DRSM = $lnDC.DRSM
                    }
            }

<#-----------------------------

Set Networking and DNS Adapter Settings

-----------------------------#>

        #Set Network Properties
        $gtNetAdpap = Get-NetAdapter | where {$_.Status -eq "up"}
        $intAlias = $gtNetAdpap.InterfaceAlias

        $gtNetIPConfig = Get-NetIPConfiguration -InterfaceAlias $gtNetAdpap.Name
        $IPAddress = $gtNetIPConfig.IPv4Address.ipaddress
        $DHCPRouter = $gtNetIPConfig.IPv4DefaultGateway.nexthop
        $dnsAddress = $gtNetIPConfig.dnsserver.serveraddresses
        
        #Test if current IP is the same JSON, if not remove all properties and reset
        if ($IPAddress -ne $DC_IP -and $dnsAddress -ne $PDC_IP)
            {
                #Remove current IP Address and router
                $gtNetIPConfig | Remove-NetIPAddress -Confirm:$false 
                $gtNetIPConfig.IPv4DefaultGateway |Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                Set-DnsClientServerAddress -InterfaceAlias $intAlias -ResetServerAddresses

                #Subnet to CIDR conversion table 
                foreach($lnSubnet in $gtSubnet)
                {
                    if ($lnSubnet.mask -cmatch $DC_Subnet)
                        {
                            $prefix = $lnSubnet.cidr
                        }
                }
        
                #Set new IP Address specified from json file
                New-NetIPAddress -InterfaceAlias $gtNetAdpap.Name   `
                         -IPAddress $DC_IP                          `
                         -AddressFamily IPv4                        `
                         -PrefixLength $prefix                  `
                         -DefaultGateway $DC_Route
        
                #Set DNS Server                 
                Set-DnsClientServerAddress -ServerAddresses $PDC_IP -InterfaceAlias $intAlias
            }
 
<#-----------------------------

Ask some questions or comment them out to take default values from json
JSON config @ $Dom_PromptPw = $gtDCPromoJ.FirstDC.PromptPw will prompt for new passwords if set to TRUE, otherwise will use the password provided

-----------------------------#>   
  
        #Gives option to use the Domain Administrator and password provided in clear text in the json file or prompt to use a different password
        if ($Dom_PromptPw -eq "true")
            {
            $rdDomPwd = Read-Host "Use the supplied Domain Admin and Password or update....Y update or another key to exit"
            if ($rdDomPwd -eq "Y")
                {
                    $domcreds = Read-Host "Enter Domain Admin Credentials eg 'Administrator,Password'... with a comma separator"

                    $Dom_Admin = $domcreds.split(",")[0]
                    $Dom_Passwrd = $domcreds.split(",")[1] 
                }
            }

<#-----------------------------

Create Secure credentials to be used in DCPROM'ing subsequent DC's

-----------------------------#>  

        $secPasswd = ConvertTo-SecureString $Dom_Passwrd -AsPlainText -Force
        $domcred = New-Object System.Management.Automation.PSCredential ("$($PDC_Netbios)\$($Dom_Admin)", $secPasswd)    
    
        #Gives option to use the default DRSM password provided in clear text in the json file or prompt to use a different password
        if ($Dom_PromptPw -eq "true")
            {        
            $rdDrsm = Read-Host "Take default password for DRSM or update....Y update or another key to exit"
            if ($rdDrsm -eq "Y")
                {
                    $DC_DRSM = Read-Host "Enter the new DRSM password"
                }
            #Hash the above DRSM lines so there is no prompt for password change and the clear text password is taken from the Json file
            }
        #convert the DRSM password to a secure string
        $drsmSecurePassword = ConvertTo-SecureString -AsPlainText $DC_DRSM -Force

<#-----------------------------

DCPROMO of Addtional DC's

-----------------------------#>  

        Install-ADDSDomainController             `
        -NoGlobalCatalog:$DC_NoGC                `
        -CreateDnsDelegation:$PDC_CreateDNSDele  `
        -Credential (Get-Credential $domcred)    `
        -CriticalReplicationOnly:$DC_CriticalRep `
        -DatabasePath $PDC_DBPath                `
        -DomainName $PDC_DomainName              `
        -InstallDns:$PDC_InstallDNS              `
        -LogPath $PDC_LogPath                    `
        -NoRebootOnCompletion:$false             `
        -SiteName "Default-First-Site-Name"      `
        -SysvolPath $PDC_SysVolPath              `
        -Force:$PDC_Force                        `
        -SafeModeAdministratorPassword $drsmSecurePassword 

<#-----------------------------

Stop Logging

-----------------------------#>

        Stop-Transcript -Force
    
    }
}


