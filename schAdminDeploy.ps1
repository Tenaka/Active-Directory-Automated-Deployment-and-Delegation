<#-----------------------------
Overview.
    Deploy multiple Domain Controllers and a new Forest from the JSON file input
    
Description.
    This is script 3 of 4

    Executes via scheduled tasks in the following order:
    1 - DCPromo.ps1
            Imports JSON config and either deploys new forest and DC or additional DC's to the forest
            Sets AutoLogon and Schedule Task for System Logon

    2 - schRebootDCInit.ps1
            System start up configures the next schedule and reboots
            This step is required as the DCPromo scheduled task wont create and resolve the administrator name without a fully functional DC
            
    3 - schAdminDeploy.ps1
            Resolves the Administrator account for the next scheduled task

    4 - CreateOU.ps1
            OU Structure and delegation


Version.
230921.1 - workable scripts 

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

    Start-Transcript -Path "$($Pwdir)\3_SchAdminLogon.log" -Append -Force

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

        #Creates Schedule that runs at logon and persists between reboots
        $Schedule = "schCreateOU"
        $allowBatt = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries 
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$($PDC_Netbios)\$($Dom_Admin)"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-executionPolicy bypass -file $schOUDeploy"
        $principal = New-ScheduledTaskPrincipal -LogonType Interactive -UserId "$($PDC_Netbios)\$($Dom_Admin)"  -RunLevel Highest 
        Register-ScheduledTask -TaskName $Schedule -Trigger $trigger -Settings $allowBatt -Action $action -Principal $principal 

        sleep 5

        Disable-ScheduledTask -TaskName "schAdminReboot"
        #Disable Server Manager as logon
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Server Manager\ServerManager"

<#-----------------------------

Stop Logging

-----------------------------#>

        Stop-Transcript

<#-----------------------------

Reboot

-----------------------------#>

        Restart-Computer -Force