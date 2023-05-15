<#-----------------------------
Overview.
    Deploy multiple Domain Controllers and a new Forest from the JSON file input
    
Description.
    This is script 2 of 4


Version.
230510.1 - Created 

-----------------------------#>

<#-----------------------------

Declare Present Working Directory for either PS or ISE

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

    Start-Transcript -Path "$($Pwdir)\2_SchInitalLogon.log" -Append -Force

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

Declare PDC and Domain vars

-----------------------------#> 

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

Set Autologon for the PDC - Risk password is writtent to Registry in the clear

-----------------------------#>
 
        #Autologon
        $adminGet = gwmi win32_useraccount | where {$_.name -eq "$Dom_Admin"}
        $sidGet = $adminGet.SID

        #Creates Schedule that runs at logon and persists between reboots
        $Schedule = "SchAdminReboot"
        $allowBatt = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries 
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$($PDC_Netbios)\$($Dom_Admin)"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-executionPolicy bypass -file $schInitial2"
        $principal = New-ScheduledTaskPrincipal -LogonType Interactive -UserId "$($PDC_Netbios)\$($Dom_Admin)"  -RunLevel Highest 
        Register-ScheduledTask -TaskName $Schedule -Trigger $trigger -Settings $allowBatt -Action $action -Principal $principal 

        Disable-ScheduledTask -TaskName "DCInitialBoot"

        sleep 5

<#-----------------------------

Stop Logging

-----------------------------#>

        Stop-Transcript -Force

<#-----------------------------

Reboot

-----------------------------#>

        Restart-Computer -Force 