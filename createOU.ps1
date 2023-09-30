<#-----------------------------
Overview.
    Deploy multiple Domain Controllers and a new Forest from the JSON file input
    
Description.
    This is script 4 of 4

    The creation of OU's, GPO's and the importing of policies MUST be deployed from the PDC 
    
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
            OU Structure and delegation 

Version.
230921.1 - workable scripts 


ToDo.
Add further if statements to validate if an imported gpo is already linked to the target OU

-----------------------------#>

#Confirm for elevated admin
if (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Host "An elevated administrator account is required to run this script." -ForegroundColor Red
    }
else
{

Import-Module activedirectory    

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

Deploy from PDC Only Check - TO BE DONE

-----------------------------#>


$PDCEmulator = ((Get-ADDomain).PDCEmulator).split(".")[0]

if ($env:COMPUTERNAME -eq $PDCEmulator)
    {

    <#-----------------------------

    Import json and subnet csv

    -----------------------------#>

        #Import json and csv files.
        $dcPromoJson = "DCPromo.json"
        $dcPromoSubnet = "Subnet.csv"
    
        #declare names of other scripts
        $dcSchInit = "schRebootDCInit.ps1"
        $dcSchAdmin = "schAdminDeploy.ps1"
        $ouDeployment = "CreateOU.ps1" 

        #paths to scripts referenced by the scheduled tasks
        $schInitial = "$($Pwdir)\$($dcSchInit)"
        $tpschInitial = Test-Path $schInitial
        if ($tpschInitial -eq $true){Write-host "$schInitial is present"}else{write-host "$schInitial is missing" -ForegroundColor Red | write-host "blah" } #pause
        
        $schInitial2 = "$($Pwdir)\$($dcSchAdmin)"
        $tpschInitial2 = Test-Path $schInitial2
        if ($tpschInitial -eq $true){Write-host "$schInitial2 is present"}else{write-host "$schInitial2 is missing" -ForegroundColor Red | write-host "blah" } #pause
    
        $schOUDeploy = "$($Pwdir)\$($ouDeployment)"
        $tpschOUDeploy = Test-Path $schOUDeploy
        if ($tpschOUDeploy -eq $true){Write-host "$schOUDeploy is present"}else{write-host "$schOUDeploy is missing" -ForegroundColor Red | write-host "blah" } #pause

        $gtDCPromoJ = Get-Content -raw -Path "$($Pwdir)\$($dcPromoJson)" | ConvertFrom-Json -ErrorAction Stop
        [array]$gtSubnet = Import-Csv -Path "$($Pwdir)\$($dcPromoSubnet)"
    
    <#-----------------------------

    Start Some Basic Logging

    -----------------------------#>
    
        Start-Transcript -Path "$($Pwdir)\4_CreateOUs.log" -Force

    <#-----------------------------

    Write output to screen to assist with support

    -----------------------------#>

    function Funcwriteout
    {
        <#

        Funcwriteout($funcname,$funcDescription,$funcComment)

            [string]$funcName = "FuncName"
            $funcDescription = "sometexthere"
            $funcComment = "sometexthere"

        #>
        Write-Host " "
        Write-Host "<#-----------------------------" -ForegroundColor Green
        Write-Host "<#-----------------------------" -ForegroundColor Green
        Write-Host " "
        Write-Host "Name of function: " -ForegroundColor Green -NoNewline
        write-host " $funcName" -ForegroundColor Yellow
        Write-Host " "
        Write-Host "Description: " -ForegroundColor Green -NoNewline
        Write-Host "$funcDescription" -ForegroundColor Green 
        Write-Host "Comment: " -ForegroundColor Green -NoNewline
        Write-Host "$funcComment" -ForegroundColor Gray
        Write-Host " "
        if ($args -match "failed"){write-host $args -ForegroundColor RED}else{write-host $args -ForegroundColor green}
        Write-Host "-----------------------------#>" -ForegroundColor Green
        Write-Host "-----------------------------#>" -ForegroundColor Green
        Write-Host " "
    }

    <#-----------------------------

    Disable Scheduled Task and Reset Autologon Reg values

    -----------------------------#>
    $gtSchTaskCreateOU = Get-ScheduledTask -taskname "schCreateOU"
    Function AutoLogonRemoval
    {
            $funcname = "Disable Scheduled Task schCreateOU"
            $funcDescription = "The scheduled task that deploys OU's is disabled to prevent re-run"
            $funcComment = ""
            Funcwriteout($funcname,$funcDescription,$funcComment)
            try{Disable-ScheduledTask -TaskName "schCreateOU" -ErrorAction SilentlyContinue
            "schCreateOU schedule task does not exist" | Out-File "$($pwdir)\errorLog.log" -Append}catch{}
    
        <#-----------------------------

        Disable Autologon 

        -----------------------------#>
            $funcname = "Disable and Remove Auto Logon Credentials from Registry"
            $funcDescription = "Removes the setting that Auto logon the Administrator account"
            $funcComment = ""
            Funcwriteout($funcname,$funcDescription,$funcComment)
    
            $winLogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

            #AutoAdminLogin
            $getRegValue = "AutoAdminLogon "
            $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
            $stRegValue = "0"

            if ($gtRegAuto -ne $stRegValue)
                {
                    $funcComment = "Setting HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value $stRegValue" 
                    Funcwriteout($funcname,$funcDescription,$funcComment)

                    Set-ItemProperty -Path $winLogon -Name $getRegValue -Value $stRegValue -Force
                    $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
                    if ($gtRegAuto -ne $stRegValue){Write-host "Value failed to set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value $stRegValue" -ForegroundColor Red}
                }
            Else{
                $funcComment = "Value is already set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value $stRegValue"
                Funcwriteout($funcname,$funcDescription,$funcComment)
                }

            #DefaultUserName
            $getRegValue = "DefaultUserName"
            $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
            $stRegValue = "" #Null
            if ($gtRegAuto -ne "")
                {
                    $funcComment = "Setting HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null"
                    Funcwriteout($funcname,$funcDescription,$funcComment)

                    Set-ItemProperty -Path $winLogon -Name $getRegValue -Value $stRegValue -Force
                    $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
                    if ($gtRegAuto -ne $stRegValue){Write-host "Value failed to set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null" -ForegroundColor Red}
                }
            Else
                {
                    $funcComment = "Value is already set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null"
                    Funcwriteout($funcname,$funcDescription,$funcComment)
                }

            #DefaultPassword
            $getRegValue = "DefaultPassword"
            $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
            $stRegValue = "" #Null
            if ($gtRegAuto -ne "")
                {
                    $funcComment = "Setting HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null" 
                    Funcwriteout($funcname,$funcDescription,$funcComment)

                    Set-ItemProperty -Path $winLogon -Name $getRegValue -Value $stRegValue -Force
                    $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
                    if ($gtRegAuto -ne $stRegValue){Write-host "Value failed to set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null" -ForegroundColor Red}
                }
            Else
                {
                    $funcComment = "Value is already set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null" 
                    Funcwriteout($funcname,$funcDescription,$funcComment)
                }

            #AutoLogonSID
            $getRegValue = "AutoLogonSID"
            $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
            $stRegValue = "" #Null
            if ($gtRegAuto -ne "")
                {
                    $funcComment = "Setting HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null" 
                    Funcwriteout($funcname,$funcDescription,$funcComment)

                    Set-ItemProperty -Path $winLogon -Name $getRegValue -Value $stRegValue -Force
                    $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
                    if ($gtRegAuto -ne $stRegValue){Write-host "Value failed to set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null" -ForegroundColor Red}
                }
            Else
                {
                    $funcComment = "Value is already set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null"
                    Funcwriteout($funcname,$funcDescription,$funcComment)
                }

            #AutoAdminLogin
            $getRegValue = "AutoLogonCount"
            $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
            $stRegValue = "1"

            if ([string]::IsNullOrEmpty($gtRegAuto))
                {
                    $funcComment = "New Reg Key HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value $stRegValue" 
                    Funcwriteout($funcname,$funcDescription,$funcComment)
                    
                    New-ItemProperty -Path $winLogon -Name $getRegValue -Value $stRegValue -Force
                    $gtRegAuto = Get-ItemPropertyValue $winLogon -Name $getRegValue
                    if ($gtRegAuto -ne $stRegValue){Write-host "Value failed to set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value $stRegValue" -ForegroundColor Red}
                }
            Else
                {
                    $funcComment = "Value is already set HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -Name $getRegValue -Value Null"
                    Funcwriteout($funcname,$funcDescription,$funcComment)
                }
        
        }
    if ($gtSchTaskCreateOU.TaskName -eq "schCreateOU")
        {
            AutoLogonRemoval
        }
    <#-----------------------------

    FUNCTIONS - OU Delegation

    -----------------------------#>

    Function Delegate_User
    {
    <#-----------------------------

    Functions for delegating the creation of Users, Workstation or Groups etc

         All                             =  00000000-0000-0000-0000-000000000000 
         Computer                        =  bf967a86-0de6-11d0-a285-00aa003049e2 
         Contact                         =  5cb41ed0-0e4c-11d0-a286-00aa003049e2 
         gPLink                          =  f30e3bbe-9ff0-11d1-b603-0000f80367c1 
         Group                           =  bf967a9c-0de6-11d0-a285-00aa003049e2 
         GroupManagedServiceAccount      =  7b8b558a-93a5-4af7-adca-c017e67f1057 
         ManagedServiceAccount           =  ce206244-5827-4a86-ba1c-1c0c386c1b64 
         OrganizationalUnit              =  bf967aa5-0de6-11d0-a285-00aa003049e2 
         User                            =  bf967aba-0de6-11d0-a285-00aa003049e2 

        delOU_UsrOU = "OU=Resources,DC=tenaka,DC=loc"
        $delOU_UsrGrp = "TESTGP"
        Delegate_User(delOU_UsrOU,$delOU_UsrGrp)

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "Delegate_User"
        $funcDescription = "Function used for delegating rights for an OU to create\delete\update User objects"
        $funcComment = "$GroupName at $delOU_FullOU"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        Set-Location AD:

        try
            {
                $ouACL = (get-acl -path $delOU_FullOU).Access
                $ouPermsCheck = ForEach-Object {$ouACL.InheritedObjectType -match "bf967aba-0de6-11d0-a285-00aa003049e2" -and $ouACL.IdentityReference -match $GroupName}
            
                if ($ouPermsCheck -eq $false)
                    {
                        $ouACL = (get-acl -path $delOU_FullOU).Access
                        $getGp = Get-ADGroup -Identity $GroupName
                        $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
                        $ouACL = Get-Acl -Path $delOU_FullOU

                        $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                        $InheritedObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        Funcwriteout("Setting User Delegation $($delOU_FullOU) with $($GroupName)")
                    }Else{Funcwriteout("Previously set User Delegation $($delOU_FullOU) with $($GroupName)")}
            }
        catch
            {
                Funcwriteout("Failed setting User Delegation $($delOU_FullOU) with $($GroupName)")
            }
    }

    Function Delegate_Group 
    {
    <#-----------------------------

    delOU_GrpOU = "OU=Resources,DC=tenaka,DC=loc"
    $delOU_GrpGrp = "TESTGP"
    Delegate_Group(delOU_GrpOU,$delOU_GrpGrp)

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "Delegate_Group"
        $funcDescription = "Function used for delegating rights for an OU to create\delete\update Group objects"
        $funcComment = "$GroupName at $delOU_FullOU"
        Funcwriteout($funcname,$funcDescription,$funcComment)
    
        Set-Location AD:

        try
            {
                $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access 
                $ouPermsCheck = ForEach-Object {$ouACL.InheritedObjectType -match "bf967a9c-0de6-11d0-a285-00aa003049e2" -and $ouACL.IdentityReference -match $GroupName}
            
                if ($ouPermsCheck -eq $false)
                    {  
                        $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access
                        $getGp = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
                        $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
                        $ouACL = Get-Acl -Path $delOU_FullOU -ErrorAction SilentlyContinue

                        $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                        $InheritedObjectType = [guid] "bf967a9c-0de6-11d0-a285-00aa003049e2"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967a9c-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967a9c-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        Funcwriteout("Setting Group Delegation $($delOU_FullOU) with $($GroupName)")
                    }Else{Funcwriteout("Previously set Group Delegation $($delOU_FullOU) with $($GroupName)")}
            }
        catch
            {
                Funcwriteout("Failed setting Group Delegation $($delOU_FullOU) with $($GroupName)")
            }

    }

    Function Delegate_Computer
    {
    <#-----------------------------

    delOU_CompOU = "OU=Resources,DC=tenaka,DC=loc"
    $delOU_CompGrp = "TESTGP"
    Delegate_Computer(delOU_CompOU,$delOU_CompGrp)

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "Delegate_Computer"
        $funcDescription = "Function used for delegating rights for an OU to create\delete\update Computer objects"
        $funcComment = "$GroupName at $delOU_FullOU"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        Set-Location AD:

        try
            {
                $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access
                $ouPermsCheck = ForEach-Object {$ouACL.InheritedObjectType -match "bf967a86-0de6-11d0-a285-00aa003049e2" -and $ouACL.IdentityReference -match $GroupName}
            
                if ($ouPermsCheck -eq $false)
                    {
                        $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access
                        $getGp = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
                        $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
                        $ouACL = Get-Acl -Path $delOU_FullOU -ErrorAction SilentlyContinue

                        $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                        $InheritedObjectType = [guid] "bf967a86-0de6-11d0-a285-00aa003049e2"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967a86-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967a86-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                       Funcwriteout("Setting Computer Delegation $($delOU_FullOU) with $($GroupName)")
                    }Else{Funcwriteout("Previously set Computer Delegation $($delOU_FullOU) with $($GroupName)")}
            }
        catch
            {
                Funcwriteout("Failed setting Computer Delegation $($delOU_FullOU) with $($GroupName)")
            }
    }

    Function Delegation_SvcAccts
    {
    <#-----------------------------

    delOU_SvcAccOU = "OU=Resources,DC=tenaka,DC=loc"
    $delOU_SvcAccGrp = "TESTGP"
    Delegate_SvcAccts(delOU_SvcAccOU,$delOU_SvcAccGrp)

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "Delegate_SvcAccts"
        $funcDescription = "Function used for delegating rights for an OU to create\delete\update Service Account objects"
        $funcComment = "$GroupName at $delOU_FullOU"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        Set-Location AD:

            try
            {
                $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access
                $ouPermsCheck = ForEach-Object {$ouACL.InheritedObjectType -match "bf967aba-0de6-11d0-a285-00aa003049e2" -and $ouACL.IdentityReference -match $GroupName}
            
                if ($ouPermsCheck -eq $false)
                    {
                        $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access
                        $getGp = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
                        $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
                        $ouACL = Get-Acl -Path $delOU_FullOU -ErrorAction SilentlyContinue

                        #Users
                        $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                        $InheritedObjectType = [guid] "ce206244-5827-4a86-ba1c-1c0c386c1b64"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "ce206244-5827-4a86-ba1c-1c0c386c1b64"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "ce206244-5827-4a86-ba1c-1c0c386c1b64"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        #ManagedServiceAccount
                        #$gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                        $InheritedObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        #Group Managed Service Accounts
                        #$gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                        $InheritedObjectType = [guid] "7b8b558a-93a5-4af7-adca-c017e67f1057"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "7b8b558a-93a5-4af7-adca-c017e67f1057"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "7b8b558a-93a5-4af7-adca-c017e67f1057"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        Funcwriteout("Setting Service Account Delegation $($delOU_FullOU) with $($GroupName)")
                    }Else{Funcwriteout("Previously set Service Account Delegation $($delOU_FullOU) with $($GroupName)")}
            }
        catch
            {
                Funcwriteout("Failed setting Service Account Delegation $($delOU_FullOU) with $($GroupName)")
            }
    }

    Function Delegate_FullControl
    {
    <#-----------------------------

    delOU_FullOU = "OU=Resources,DC=tenaka,DC=loc"
    $delOU_FullGrp = "TESTGP"
    Delegate_FullControl(delOU_FullOU,$delOU_FullGrp)

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "Delegate_FullControl"
        $funcDescription = "Function used for delegating rights for an OU to Full Control all object types"
        $funcComment = "$GroupName at $delOU_FullOU"
        Funcwriteout($funcname,$funcDescription,$funcComment)
   
        Set-Location AD:

        try
            {
                $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access
                $ouPermsCheck = ForEach-Object {$ouACL.InheritedObjectType -match "00000000-0000-0000-0000-000000000000" -and $ouACL.IdentityReference -match $GroupName}
            
                if ($ouPermsCheck -eq $false)
                    {

                        $ouACL = (get-acl -path $delOU_FullOU -ErrorAction SilentlyContinue).Access
                        $getGp = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
                        $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
                        $ouACL = Get-Acl -Path $delOU_FullOU -ErrorAction SilentlyContinue

                        $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
                        $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                        $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
                        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

                        $ouACL.AddAccessRule($ACE)
                        Set-Acl -Path $delOU_FullOU -AclObject $ouACL

                        Funcwriteout("Setting User Delegation $($delOU_FullOU) with $($GroupName)")
                    }Else{Funcwriteout("Previously set User Delegation $($delOU_FullOU) with $($GroupName)")}
            }
        catch
            {
                Funcwriteout("Failed setting User Delegation $($delOU_FullOU) with $($GroupName)")
            }
    }

    <#-----------------------------

    FUNCTIONS - Create OUs 

    -----------------------------#>

    function CreateOU-OrgRoot
    {
    <#-----------------------------

    Create Organisation level OU

    OU=ORG2,DC=testdom,DC=loc

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "CreateOU-OrgRoot"
        $funcDescription = "Function to create Organisation or Top level OU"
        $funcComment = "$ouTierNameRootDN"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        if ($gtouOrgNameDN.DistinguishedName -ne $ouTierNameRootDN)
            {
                    #Create new Organisation OU 
                try {
                        New-ADOrganizationalUnit -Name $ouTierNameRoot -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-OrgRoot - $($ouTierNameRoot)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-OrgRoot - $($ouTierNameRoot)")
                    } 
            }
    }    

    function CreateOU-TopTier-Service-Admin
    {
    <#-----------------------------

    Creates OU for Service\Applications eg Exchange, Certs, SCOM, SCCM

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "CreateOU-TopTier-Service-Admin"
        $funcDescription = "Function to create Service\Application OU under Service Resouces"
        $funcComment = "$ouCompItem at $ouSvrResDN"
        Funcwriteout($funcname,$funcDescription,$funcComment)
   
        if ($gtouSvrResMgmtDN.DistinguishedName -ne $ouSvrCompDN)
        {
            try
                {
                    New-ADOrganizationalUnit -Name $ouCompItem -Path $ouTierNameRootDN -ProtectedFromAccidentalDeletion $ouProtect
                    Funcwriteout("New AD OU - CreateOU-TopTier-Service-Admin - $($ouCompItem)")
                }
            catch
                {
                     Funcwriteout("Failed to create new AD OU - CreateOU-TopTier-Service-Admin - $($ouCompItem)")
                }
        }
    }

    function CreateOU-AdminRes
    {
    <#-----------------------------

    Create Administrative Resources

    OU=Administrative Resouces,OU=Org2,DC=testdom,DC=loc

    -----------------------------#> 
        #Function to write out to screen
        [string]$funcName = "CreateOU-AdminRes"
        $funcDescription = "Function to create Administrative Resouces OU under that of the Organisation"
        $funcComment = "$ouTierNameRootDN"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        if ($gtouAdminResDN.DistinguishedName -ne $ouAdminResDN)
            {
                try {
                        New-ADOrganizationalUnit -Name $ouMgmdRes -Path $ouTierNameRootDN -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-AdminRes - $($ouMgmdRes)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-AdminRes - $($ouMgmdRes)")
                    }
                }
        }

    function CreateOU-AdminResSub
    {
    <#-----------------------------

    Create Administrative Resources
    CreateOU-AdminResSub($ouMgmdRes,$AdministrativeOU,$ouProtect)

    OU=Administrative Resouces,OU=Org2,DC=testdom,DC=loc

    -----------------------------#> 
        #Function to write out to screen
        [string]$funcName = "CreateOU-AdminResSub"
        $funcDescription = "Function to create Administrative Resouces OU under that of the Organisation"
        $funcComment = "$ouTierNameRootDN"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        #Creates Admin Resources for all delegation and admin functions
        $gtAdministrativeOU = try {Get-ADOrganizationalUnit "OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)" -ErrorAction SilentlyContinue}catch{}
        if ($gtAdministrativeOU -eq $null)
            {
                try
                    {        
                        New-ADOrganizationalUnit -Name "$($adminTaskOU) $($ouTierNameRoot)" -Path "$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-AdminResSub - $($AdministrativeOU)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-AdminResSub - OU=$($ouTierNameRoot) $($adminTaskOU),$($AdministrativeOU)")
                    }
            }

        #Creates Admin Resources for all delegation and admin functions
        $gtAdministrativeOU = try {Get-ADOrganizationalUnit "OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)" -ErrorAction SilentlyContinue}catch{}
        if ($gtAdministrativeOU -eq $null)
            {
                try
                    {        
                        New-ADOrganizationalUnit -Name "$($adminRoles) $($ouTierNameRoot)" -Path "$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-AdminResSub - $($AdministrativeOU)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-AdminResSub - OU=$($ouTierNameRoot) $($adminRoles),$($AdministrativeOU)")
                    }
            }


        #Creates Admin Management OU for the delegation groups for each service
        $gtadminMgmtOU = try {Get-ADOrganizationalUnit "OU=Admin Accounts $($ouTierNameRoot),$($AdministrativeOU)" -ErrorAction SilentlyContinue}catch{}
        if ($gtadminMgmtOU -eq $null)
            {
            try {
                    New-ADOrganizationalUnit -Name "Admin Accounts $($ouTierNameRoot)"-Path "$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                    Funcwriteout("New AD OU Admin Accounts at - CreateOU-AdminResSub - OU=Admin Accounts $($ouTierNameRoot),$($AdministrativeOU) has been created")

                    #New-ADOrganizationalUnit -Name "Admin Roles"-Path "$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                    #Funcwriteout("New AD OU Admin Roles at $($AdministrativeOU) has been created")
                }
            catch
                {
                    Funcwriteout("Failed to create new AD OU - CreateOU-AdminResSub - OU=Admin Accounts $($ouTierNameRoot),$($AdministrativeOU)")
                }    
            }
        }

    function CreateOU-AdminResService-AdminMgmt
    {
    <#-----------------------------

    Create Admin Tasks and Roles for each Organisation and service eg Member Server and Exhange
 
    OU=Administrative Resouces,OU=Org2,DC=testdom,DC=loc
    CreateOU-AdminResService($ouCompItem,$ouTierNameRoot,$AdministrativeOU,$ouProtect)

    -----------------------------#> 
        #Function to write out to screen
        [string]$funcName = "CreateOU-AdminResService-AdminMgmt"
        $funcDescription = "Function to create Administrative Resouces OU under that of the Organisation"
        $funcComment = "$ouTierNameRootDN"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        $gtAdminService = try {Get-ADOrganizationalUnit "OU=$($adminTaskOU) $($ouCompItem),OU=$($ouTierNameRoot),$($AdministrativeOU)" -ErrorAction SilentlyContinue}catch{}
        if ($gtAdminService -eq $null)
            {
                try
                    {        
                        New-ADOrganizationalUnit -Name $ouCompItem -Path "OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-AdminResService-AdminMgmt - OU=$($ouCompItem),OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-AdminResService-AdminMgmt - OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
            }
            
        $gtAdminMgmtService = try {Get-ADOrganizationalUnit "OU=$ouTierNameRoot,OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)" -ErrorAction SilentlyContinue}catch{}
        if ($gtAdminMgmtService -eq $null)
            {
                try
                    {        
                        New-ADOrganizationalUnit -Name $ouTierNameRoot -Path "OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-AdminResService-AdminMgmt - OU=$ouTierNameRoot,OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-AdminResService-AdminMgmt - OU=$ouTierNameRoot,OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
            }

        
        $gtAdminService = try {Get-ADOrganizationalUnit "OU=$($adminRoles) $($ouCompItem),OU=$($ouTierNameRoot),$($AdministrativeOU)" -ErrorAction SilentlyContinue}catch{}
        if ($gtAdminService -eq $null)
            {
                try
                    {        
                        New-ADOrganizationalUnit -Name $ouCompItem -Path "OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-AdminResService-AdminMgmt - OU=$($ouCompItem),OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-AdminResService-AdminMgmt - OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
            }
            
        $gtAdminMgmtService = try {Get-ADOrganizationalUnit "OU=$ouTierNameRoot,OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)" -ErrorAction SilentlyContinue}catch{}
        if ($gtAdminMgmtService -eq $null)
            {
                try
                    {        
                        New-ADOrganizationalUnit -Name $ouTierNameRoot -Path "OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)" -ProtectedFromAccidentalDeletion $ouProtect
                        Funcwriteout("New AD OU - CreateOU-AdminResService-AdminMgmt - OU=$ouTierNameRoot,OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
                catch
                    {
                        Funcwriteout("Failed to create new AD OU - CreateOU-AdminResService-AdminMgmt - OU=$ouTierNameRoot,OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)")
                    }
            }
        }                          

    function CreateOU-Services-Management
    {
    <#-----------------------------
    #Create Administrative sub-ou for each Service or Application

    $ouSrvResOU = OU to Create
    $ouSrvResCompDN = DN of parent OU
    $ouProtect = Is protected
    
    CreateOU-Services-Management($ouSrvResOU,$ouSrvResCompDN,$ouProtect)

    -----------------------------#>

        #Function to write out to screen
        [string]$funcName = "CreateOU-Services-Management"
        $funcDescription = "Function to create Service\Application sub-OU to manage Service Accounts, Server Objects"
        $funcComment = "$ouSrvResOU at $ouSrvResCompDN"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        if ($gtouSvrResMgmtDN.DistinguishedName -ne $ouSvrResMgmtDN)
                {
            try 
                {
                    New-ADOrganizationalUnit -Name $ouSrvResOU -Path $ouSrvResDN -ProtectedFromAccidentalDeletion $ouProtect
                    Funcwriteout("New AD OU - CreateOU-Services-Management - $($ouSrvResOU)")
                }
            catch
                {
                    Funcwriteout("Failed to create new AD OU - CreateOU-Services-Management - $($ouSrvResOU)")
                }
            }
    }

    <#-----------------------------

    FUNCTIONS - Create Security Groups and link to OUs and GPOs

    -----------------------------#>

    function ADGroup-TopTier-Delegation-GPO 
    {
    <#-----------------------------

    Created GPO and Groups for delegation of the Member Server and Client eg Tier top level OU

    #Top level delegation and gpo restricted group and URA - Member Servers and Clients
    ADGroup-TopTier-Delegation-GPO($ouTierNameRootDN,$ouTierNameRoot,$ouCompItem,$AdministrativeOU,$ouProtect)

    Create nested groups Domain Global into Domain Local and attach Domain Local to the object
    AL AG_Administrative Resources_OU_FullCtrl

    Creates Service or app level full control deletation groups
    Creates GPO modify 
    Creates Restricted and URA groups

    Creates GPO and updates restricted Groups and URA

    -----------------------------#>   
        #Function to write out to screen
        [string]$funcName = "ADGroup-TopTier-Delegation-GPO"
        $funcDescription = "Function to create AD Groups for Restricted Groups and URA for Administrative\Service Infrastructure OU"
        $funcComment = "No Comment"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        #$ouAdminResServiceRt = "OU=$ouTierNameRoot,$AdministrativeOU"
        $ouAdminResServiceRt = "OU=$($topTierOU),OU=$($adminTaskOU) $($topTierOU),$($AdministrativeOU)"
        $adminMgmtServiceOU = "OU=$($ouCompItem),ou=$($ouTierNameRoot),$($AdministrativeOU)"
        $adminMgmtServiceRole = "OU=$($topTierOU),OU=$($adminRoles) $($ouTierNameRoot),$($AdministrativeOU)"
       
        $ouServiceResDN = $ouTierNameRootDN

        #Group Acl and Description
        $del_OU_Full_Acl = "FullCtrl","Full Control of all OU objects"
        $del_OU_Computer_Acl = "CompMgmt","Manage Computer Objects"
        $del_OU_Group_Acl = "GroupMgmt","Manage Group objects"
        $del_OU_User_Acl = "UserMgmt","Manage User objects"
        $del_OU_Service_Acl = "SvcMgmt","Manage Service Accounts"
        $del_GPO_Edit_Acl = "GPOedit","Edit Group Policy Objects"
        $del_ResGrp_Admin = "ResGrpAdmin","Local Administrative access"
        $del_ResGrp_User = "ResGrpUser","Local User access"
        $del_GPO_Modify_ACL = "GPOModify","Edit and Modify GPO"

        $del_DL_SrvOUGroup=@()
        $del_DG_SrvOUGroup=@()
        $del_Description=@()
        $adTasksDestination=@()
        $SvcResTrun=@()

        #Group Descriptions
        $del_OU_Description = "Members of this group have $($del_OU_Full_Acl.split(",")[1])"
        $del_RG_Admin_Description = "Members of this group have $($del_ResGrp_Admin.split(",")[1])"
        $del_RG_User_Description = "Members of this group have $($del_ResGrp_User.split(",")[1])"
        $del_GP_SvcAtts_Description = "Members of this group have $($del_OU_Service_Acl.split(",")[1])"
        $del_GP_Compu_Description = "Members of this group have $($del_OU_Computer_Acl.split(",")[1])"
        $del_GP_Group_Description = "Members of this group have $($del_OU_Group_Acl.split(",")[1])"
        $del_GP_User_Description = "Members of this group have $($del_OU_User_Acl.split(",")[1])"
        $del_GPO_GPOEdit_Description = "Members of this group have $($del_GPO_Edit_Acl.split(",")[1])"
        $del_GPO_Modify_Description = "Members of this group have $($del_GPO_Modify_ACL.split(",")[1])"

        #Local and Global
        $del_DomainLocal = "AL_"
        $del_DomainGlobal = "AG_"
        $del_DomainLocalRole = "RL_"
        $del_DomainGlobalRole = "RG_"
        $del_Group = $del_DomainLocal,$del_DomainGlobal

        #$SvcResTrun = "SvcRes"
        #$AdminResTruc = "AdminRes"

        #Role up for Service
        $del_DL_SvcRoleGroup = "$($del_DomainLocalRole)OU_$($ouTierNameRoot)_AdminRole"
        $del_DG_SvcRoleGroup = "$($del_DomainGlobalRole)OU_$($ouTierNameRoot)_AdminRole"

        #OU Delegation Group - Group Delegation of OU
        $del_DL_AdminMgmtOUGroupName = "$($del_DomainLocal)OU_$($ouTierNameRoot)_$($del_OU_Group_Acl.split(",")[0])"
        $del_DG_AdminMgmtOUGroupName = "$($del_DomainGlobal)OU_$($ouTierNameRoot)_$($del_OU_Group_Acl.split(",")[0])"

        #OU Delegation Group - Full Control of OU
        $del_DL_OUGroupName = "$($del_DomainLocal)OU_$($ouTierNameRoot)_$($del_OU_Full_Acl.split(",")[0])"
        $del_DG_OUGroupName = "$($del_DomainGlobal)OU_$($ouTierNameRoot)_$($del_OU_Full_Acl.split(",")[0])"

        #Restriced Group 
        $del_DL_RGGroupNameAdmin = "$($del_DomainLocal)RG_$($ouTierNameRoot)_$($del_ResGrp_Admin.split(",")[0])"
        $del_DG_RGGroupNameAdmin = "$($del_DomainGlobal)RG_$($ouTierNameRoot)_$($del_ResGrp_Admin.split(",")[0])"

        #OU delegation for users
        $del_DL_RGGroupNameUser = "$($del_DomainLocal)RG_$($ouTierNameRoot)_$($del_ResGrp_User.split(",")[0])"
        $del_DG_RGGroupNameUser = "$($del_DomainGlobal)RG_$($ouTierNameRoot)_$($del_ResGrp_User.split(",")[0])"

        #GPO Modify
        $del_DL_GPOGroupModify = "$($del_DomainLocal)GPO_$($ouTierNameRoot)_$($del_GPO_Modify_ACL.split(",")[0])"
        $del_DG_GPOGroupModify = "$($del_DomainGlobal)GPO_$($ouTierNameRoot)_$($del_GPO_Modify_ACL.split(",")[0])"

        #Role up for Service
        $del_DL_SvcRoleGroup = "$($del_DomainLocalRole)OU_$($ouTierNameRoot)_AdminRole"
        $del_DG_SvcRoleGroup = "$($del_DomainGlobalRole)OU_$($ouTierNameRoot)_AdminRole"

        $del_GP_Role_Description = "Members of this group have delegated permissions to manage $($ouCompItem)"

        #AD Roles for top tier - member servers
        try
            {
                New-ADGroup $del_DL_SvcRoleGroup -groupscope DomainLocal -Path $adminMgmtServiceRole -Description $del_GP_Role_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_SvcRoleGroup)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_SvcRoleGroup)") 
           }
      
        try
            {
                New-ADGroup $del_DG_SvcRoleGroup -groupscope Global -Path $adminMgmtServiceRole -Description $del_GP_Role_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_SvcRoleGroup)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_SvcRoleGroup)")
            }
   
        Add-ADGroupMember $del_DL_SvcRoleGroup $del_DG_SvcRoleGroup



        #OU Delegation Group - Servcies full control
        try
            {
                New-ADGroup $del_DL_OUGroupName -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_OU_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_OUGroupName)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_OUGroupName)")
            }
    
        try
            {
                New-ADGroup $del_DG_OUGroupName -groupscope Global -Path $ouAdminResServiceRt -Description $del_OU_Description
                Funcwriteout("New AD Group $($del_DG_OUGroupName)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_OUGroupName)") 
            }  
    
        Add-ADGroupMember $del_DL_OUGroupName $del_DG_OUGroupName

        #OU Delegation Group - Admin Mgmt full control
        try
            {
                New-ADGroup $del_DL_AdminMgmtOUGroupName -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_OU_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_AdminMgmtOUGroupName)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_AdminMgmtOUGroupName)")
            }
    
        try
            {
                New-ADGroup $del_DG_AdminMgmtOUGroupName -groupscope Global -Path $ouAdminResServiceRt -Description $del_OU_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_AdminMgmtOUGroupName)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_AdminMgmtOUGroupName)") 
            }  
    
        Add-ADGroupMember $del_DL_AdminMgmtOUGroupName $del_DG_AdminMgmtOUGroupName


        #Restriced Group 
        try
            {
                New-ADGroup $del_DL_RGGroupNameAdmin -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_RG_Admin_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameAdmin)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameAdmin)") 
            }
      
        try
            {
                New-ADGroup $del_DG_RGGroupNameAdmin -groupscope Global -Path $ouAdminResServiceRt -Description $del_RG_Admin_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_RGGroupNameAdmin)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_RGGroupNameAdmin)") 
            }
    
        Add-ADGroupMember $del_DL_RGGroupNameAdmin $del_DG_RGGroupNameAdmin 
                
        try
            {
                New-ADGroup $del_DL_RGGroupNameUser -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_RG_User_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameUser)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameUser)")  
            } 
    
        try
            {
                New-ADGroup $del_DG_RGGroupNameUser -groupscope Global -Path $ouAdminResServiceRt -Description $del_RG_User_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_RGGroupNameUser)")  
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_RGGroupNameUser)")  
            }
     
        Add-ADGroupMember $del_DL_RGGroupNameUser $del_DG_RGGroupNameUser          
                
        #GPO Modify
        try
            {
                New-ADGroup $del_DL_GPOGroupModify -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_GPO_Modify_Description
                Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_GPOGroupModify)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group $($del_DL_GPOGroupModify)") 
            }
       
        try
        {
            New-ADGroup $del_DG_GPOGroupModify -groupscope Global -Path $ouAdminResServiceRt -Description $del_GPO_Modify_Description
            Funcwriteout("New AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_GPOGroupModify)")
        }
        catch
        {
            Funcwriteout("Failed to create new AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DG_GPOGroupModify)")
        }
     
        Add-ADGroupMember $del_DL_GPOGroupModify $del_DG_GPOGroupModify
        
        #Delegate Service Level OU full control
        $GroupName = $del_DL_OUGroupName 
        $delOU_FullOU = $ouServiceResDN
        #Function to delegate OU Full Control to a named group
        Delegate_FullControl($delOU_FullOU,$GroupName)  


        #delegate Admin Mgmt OU to 
        $GroupName = $del_DL_AdminMgmtOUGroupName 
        $delOU_FullOU = $adminMgmtServiceOU

        #Function to delegate OU Full Control to a named group
        Delegate_Group($GroupName,$delOU_FullOU) 
                              
        #Get New Group Name and SID
        $gt_del_RG_SvcRes_AdminSid=@()
        $del_RG_DL_SvcResUser=@()
        $gpoName = "GPO_$($ouTierNameRoot)_RestrictedGroups"
    
        try
            {
                $del_RG_DL_SvcResAdmin = Get-ADGroup $del_DL_RGGroupNameAdmin
                Funcwriteout("Get AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameAdmin)")
            }
        catch
            {
                Funcwriteout("Failed to get AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameAdmin)")
            }

        try
            {
                $del_RG_DL_SvcResUser = Get-ADGroup $del_DL_RGGroupNameUser
                Funcwriteout("Get AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameUser)")
            }
        catch
            {
                Funcwriteout("Failed to get AD Group - ADGroup-TopTier-Delegation-GPO - $($del_DL_RGGroupNameUser)")
            }
        #Create GPO at service level with restricted groups and URA - Delegate OU to be modified by GPOModify group
        $del_GPOGroupModify = $del_DL_GPOGroupModify     
        GPO-TopTier-RestrictedGroup($gpoName,$del_RG_DL_SvcResAdmin,$del_RG_DL_SvcResUser,$ouServiceResDN,$del_GPOGroupModify)
    }

    function ADGroup-Organisation-AdminManagement
    {
    <#-----------------------------

    Created GPO and Groups for delegation of the Member Server and Client eg Tier top level OU

    #Top level delegation and gpo restricted group and URA - Member Servers and Clients
                            ADGroup-Organisation-AdminManagement($topTierOU,$ouTierNameRoot,$AdministrativeOU,$ouTierNameRoot,$ouCompItem,$ouProtect)

    Create nested groups Domain Global into Domain Local and attach Domain Local to the object
    AL AG_Administrative Resources_OU_FullCtrl

    Creates Service or app level full control deletation groups
    Creates GPO modify 
    Creates Restricted and URA groups

    Creates GPO and updates restricted Groups and URA

    -----------------------------#>   
        #Function to write out to screen
        [string]$funcName = "ADGroup-Organisation-AdminManagement"
        $funcDescription = "Function to create AD Groups for Restricted Groups and URA for Administrative\Service Infrastructure OU"
        $funcComment = "No Comment"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        $ouAdminResServiceRt = "OU=$($ouTierNameRoot),OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)"
        $adminMgmtServiceOU = "OU=$($ouCompItem),OU=$($adminTaskOU), $($ouTierNameRoot),$($AdministrativeOU)"
        $ouServiceResDN = $ouTierNameRootDN

        #Group Acl and Description
        $del_OU_Full_Acl = "FullCtrl","Full Control of all OU objects"
        $del_OU_Computer_Acl = "CompMgmt","Manage Computer Objects"
        $del_OU_Group_Acl = "GroupMgmt","Manage Group objects"
        $del_OU_User_Acl = "UserMgmt","Manage User objects"
        $del_OU_Service_Acl = "SvcMgmt","Manage Service Accounts"
        $del_GPO_Edit_Acl = "GPOedit","Edit Group Policy Objects"
        $del_ResGrp_Admin = "ResGrpAdmin","Local Administrative access"
        $del_ResGrp_User = "ResGrpUser","Local User access"
        $del_GPO_Modify_ACL = "GPOModify","Edit and Modify GPO"

        $del_DL_SrvOUGroup=@()
        $del_DG_SrvOUGroup=@()
        $del_Description=@()
        $adTasksDestination=@()
        $SvcResTrun=@()

        #Group Descriptions
        $del_OU_Description = "Members of this group have $($del_OU_Full_Acl.split(",")[1])"
        $del_RG_Admin_Description = "Members of this group have $($del_ResGrp_Admin.split(",")[1])"
        $del_RG_User_Description = "Members of this group have $($del_ResGrp_User.split(",")[1])"
        $del_GP_SvcAtts_Description = "Members of this group have $($del_OU_Service_Acl.split(",")[1])"
        $del_GP_Compu_Description = "Members of this group have $($del_OU_Computer_Acl.split(",")[1])"
        $del_GP_Group_Description = "Members of this group have $($del_OU_Group_Acl.split(",")[1])"
        $del_GP_User_Description = "Members of this group have $($del_OU_User_Acl.split(",")[1])"
        $del_GPO_GPOEdit_Description = "Members of this group have $($del_GPO_Edit_Acl.split(",")[1])"
        $del_GPO_Modify_Description = "Members of this group have $($del_GPO_Modify_ACL.split(",")[1])"

        #Truncate Service Resouce - to limit character limit for groups
        $SvcResTrun = "SvcRes"

        #Local and Global
        $del_DomainLocal = "AL_"
        $del_DomainGlobal = "AG_"
        $del_Group = $del_DomainLocal,$del_DomainGlobal

        #$SvcResTrun = "SvcRes"
        #$AdminResTruc = "AdminRes"

        #OU Delegation Group - Group Delegation of OU
        $del_DL_AdminMgmtOUGroupName = "$($del_DomainLocal)OU_$($adminResourceName)_$($adminTaskOU) $($ouTierNameRoot)_$($ouCompItem)_$($del_OU_Group_Acl.split(",")[0])"
        $del_DG_AdminMgmtOUGroupName = "$($del_DomainGlobal)OU_$($adminResourceName)_$($adminTaskOU) $($ouTierNameRoot)_$($ouCompItem)_$($del_OU_Group_Acl.split(",")[0])"

        #OU Delegation Group - Admin Mgmt full control
        try
            {
                New-ADGroup $del_DL_AdminMgmtOUGroupName -groupscope DomainLocal -Path $adminMgmtServiceOU -Description $del_OU_Description
                Funcwriteout("New AD Group - ADGroup-Organisation-AdminManagement - $($del_DL_AdminMgmtOUGroupName)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD  - ADGroup-Organisation-AdminManagement - $($del_DL_AdminMgmtOUGroupName)")
            }
    
        try
            {
                New-ADGroup $del_DG_AdminMgmtOUGroupName -groupscope Global -Path $adminMgmtServiceOU -Description $del_OU_Description
                Funcwriteout("New AD Group  - ADGroup-Organisation-AdminManagement -$($del_DG_AdminMgmtOUGroupName)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-Organisation-AdminManagement - $($del_DG_AdminMgmtOUGroupName)") 
            }  
    
        Add-ADGroupMember $del_DL_AdminMgmtOUGroupName $del_DG_AdminMgmtOUGroupName
        
        #Delegate Service Level OU full control
        $GroupName = $del_DL_AdminMgmtOUGroupName 
        $delOU_FullOU = $adminMgmtServiceOU
        #Function to delegate OU Full Control to a named group
        Delegate_Group($delOU_FullOU,$GroupName)  
                 
    }

    function ADGroup-ServiceResources 
    {
    <#-----------------------------

    Create nested groups Domain Global into Domain Local and attach Domain Local to the object
    AL AG_Administrative Resources_OU_FullCtrl

    Creates Service or app level full control deletation groups
    Creates GPO modify 
    Creates Restricted and URA groups

    Creates GPO and updates restricted Groups and URA

    -----------------------------#>   
        #Function to write out to screen
        [string]$funcName = "ADGroup-ServiceResources"
        $funcDescription = "Function to create AD Groups for Restricted Groups and URA for Administrative\Service Infrastructure OU"
        $funcComment = "No Comment"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        $adminMgmtServiceOU = "OU=$($ouCompItem),OU=$($adminTaskOU) $($ouTierNameRoot),$($AdministrativeOU)"
        $ouServiceResDN = "OU=$($ouCompItem),$ouTierNameRootDN"

        #Group Acl and Description
        $del_OU_Full_Acl = "FullCtrl","Full Control of all OU objects"
        $del_OU_Computer_Acl = "CompMgmt","Manage Computer Objects"
        $del_OU_Group_Acl = "GroupMgmt","Manage Group objects"
        $del_OU_User_Acl = "UserMgmt","Manage User objects"
        $del_OU_Service_Acl = "SvcMgmt","Manage Service Accounts"
        $del_GPO_Edit_Acl = "GPOedit","Edit Group Policy Objects"
        $del_ResGrp_Admin = "ResGrpAdmin","Local Administrative access"
        $del_ResGrp_User = "ResGrpUser","Local User access"
        $del_GPO_Modify_ACL = "GPOModify","Edit and Modify GPO"

        $del_DL_SrvOUGroup=@()
        $del_DG_SrvOUGroup=@()
        $del_Description=@()
        $adTasksDestination=@()
        $SvcResTrun=@()

        #Group Descriptions
        $del_OU_Description = "Members of this group have $($del_OU_Full_Acl.split(",")[1])"
        $del_RG_Admin_Description = "Members of this group have $($del_ResGrp_Admin.split(",")[1])"
        $del_RG_User_Description = "Members of this group have $($del_ResGrp_User.split(",")[1])"
        $del_GP_SvcAtts_Description = "Members of this group have $($del_OU_Service_Acl.split(",")[1])"
        $del_GP_Compu_Description = "Members of this group have $($del_OU_Computer_Acl.split(",")[1])"
        $del_GP_Group_Description = "Members of this group have $($del_OU_Group_Acl.split(",")[1])"
        $del_GP_User_Description = "Members of this group have $($del_OU_User_Acl.split(",")[1])"
        $del_GPO_GPOEdit_Description = "Members of this group have $($del_GPO_Edit_Acl.split(",")[1])"
        $del_GPO_Modify_Description = "Members of this group have $($del_GPO_Modify_ACL.split(",")[1])"

        #Truncate Service Resouce - to limit character limit for groups
        $SvcResTrun = "SvcRes"

        $adTasksDestination = $ouAdminResServiceRt

        #Local and Global
        $del_DomainLocal = "AL_"
        $del_DomainGlobal = "AG_"

        $del_Group = $del_DomainLocal,$del_DomainGlobal

        #OU Delegation Group - Full Control of OU
        $del_DL_OUGroupName = "$($del_DomainLocal)OU_$($ouTierNameRoot)_$($ouCompItem)_$($del_OU_Full_Acl.split(",")[0])"
        $del_DG_OUGroupName = "$($del_DomainGlobal)OU_$($ouTierNameRoot)_$($ouCompItem)_$($del_OU_Full_Acl.split(",")[0])"

        try
            {
                New-ADGroup $del_DL_OUGroupName -groupscope DomainLocal -Path $adminMgmtServiceOU -Description $del_OU_Description
                Funcwriteout("New AD Group - ADGroup-ServiceResources -$($del_DL_OUGroupName)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-ServiceResources - $($del_DL_OUGroupName)")
            }
    
        try
            {
                New-ADGroup $del_DG_OUGroupName -groupscope Global -Path $adminMgmtServiceOU -Description $del_OU_Description
                Funcwriteout("New AD Group - ADGroup-ServiceResources - $($del_DG_OUGroupName)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-ServiceResources - $($del_DG_OUGroupName)") 
            }  
    
        Add-ADGroupMember $del_DL_OUGroupName $del_DG_OUGroupName

        #Delegate Service Level OU full control
        $GroupName = $del_DL_OUGroupName 
        $delOU_FullOU = $ouServiceResDN
        #Function to delegate OU Full Control to a named group
        Delegate_FullControl($delOU_FullOU,$GroupName)  
                
    }

    function ADGroup-Services-Management 
    {
    <#-----------------------------

    Server level gpo and restricted group assigned against the SERVER OU
                    
    Create nested groups Domain Global into Domain Local and attach Domain Local to the object
    AL AG_Administrative Resources_OU_FullCtrl

    ADGroup-Services-Management($AdministrativeOU,$ouSrvResDN,$ouSrvResOU,$ouSrvResObj,$ouCompItem,$ouTierNameRoot)

    -----------------------------#> 
    #>
        #Function to write out to screen
        [string]$funcName = "ADGroup-Services-Management"
        $funcDescription = "Function to create AD Groups for delegation of Service\Application sub-Ous, Service Accounts, Servers etc"
        $funcComment = "No Comment"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        $ouAdminResServiceRt = "OU=$ouCompItem,OU=$($adminTaskOU) $($ouTierNameRoot),$AdministrativeOU"
        $ouAdminResServiceRole = "OU=$ouCompItem,OU=$($adminRoles) $($ouTierNameRoot),$AdministrativeOU"

        #Group Acl and Description
        $del_OU_Full_Acl = "FullCtrl","Full Control of all OU objects"
        $del_OU_Computer_Acl = "CompMgmt","Manage Computer Objects"
        $del_OU_Group_Acl = "GroupMgmt","Manage Group objects"
        $del_OU_User_Acl = "UserMgmt","Manage User objects"
        $del_OU_Service_Acl = "SvcMgmt","Manage Service Accounts"
        $del_GPO_Edit_Acl = "GPOedit","Edit Group Policy Objects"
        $del_ResGrp_Admin = "ResGrpAdmin","Local Administrative access"
        $del_ResGrp_User = "ResGrpUser","Local User access"
        $del_GPO_Modify_ACL = "GPOModify","Edit and Modify GPO"
    
        #Role up of permissions for team who manage a service eg SCCM, Exhange, SCOM
        $del_Role_Service = "GroupMgmt","Manage Group objects"

        $del_DL_SrvOUGroup=@()
        $del_DG_SrvOUGroup=@()
        $del_Description=@()
        $adTasksDestination=@()
        $SvcResTrun=@()

        #Group Descriptions
        $del_OU_Description = "Members of this group have $($del_OU_Full_Acl.split(",")[1])"
        $del_RG_Admin_Description = "Members of this group have $($del_ResGrp_Admin.split(",")[1])"
        $del_RG_User_Description = "Members of this group have $($del_ResGrp_User.split(",")[1])"
        $del_GP_SvcAtts_Description = "Members of this group have $($del_OU_Service_Acl.split(",")[1])"
        $del_GP_Compu_Description = "Members of this group have $($del_OU_Computer_Acl.split(",")[1])"
        $del_GP_Group_Description = "Members of this group have $($del_OU_Group_Acl.split(",")[1])"
        $del_GP_User_Description = "Members of this group have $($del_OU_User_Acl.split(",")[1])"
        $del_GPO_GPOEdit_Description = "Members of this group have $($del_GPO_Edit_Acl.split(",")[1])"
        $del_GPO_Modify_Description = "Members of this group have $($del_GPO_Modify_ACL.split(",")[1])"

        if ($ouSrvResObj -eq "Group")
        {
            $groupSub = $del_OU_Group_Acl
            $del_Description = $del_GP_Group_Description
        }

        if ($ouSrvResObj -eq "User")
        {
            $groupSub = $del_OU_User_Acl
            $del_Description = $del_GP_User_Description
        }
    
        if ($ouSrvResObj -eq "Computer")
        {
            $groupSub = $del_OU_Computer_Acl
            $del_Description = $del_GP_Compu_Description
        }

        if ($ouSrvResObj -eq "SvcAccts")
        {
            $groupSub = $del_OU_Service_Acl
            $del_Description = $del_GP_SvcAtts_Description
        }    
        
        #Local and Global
        $del_DomainLocal = "AL_"
        $del_DomainGlobal = "AG_"
        $del_DomainLocalRole = "RL_"
        $del_DomainGlobalRole = "RG_"

        #Role up for Service
        $del_DL_SvcRoleGroup = "$($del_DomainLocalRole)OU_$($ouTierNameRoot)_$($ouCompItem)_AdminRole"
        $del_DG_SvcRoleGroup = "$($del_DomainGlobalRole)OU_$($ouTierNameRoot)_$($ouCompItem)_AdminRole"

        $del_GP_Role_Description = "Members of this group have delegated permissions to manage $($ouCompItem)"

        try
            {
                New-ADGroup $del_DL_SvcRoleGroup -groupscope DomainLocal -Path $ouAdminResServiceRole -Description $del_GP_Role_Description
                Funcwriteout("New AD Group - ADGroup-Services-Management - $($del_DL_SvcRoleGroup)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management -  $($del_DL_SvcRoleGroup)") 
           }
      
        try
            {
                New-ADGroup $del_DG_SvcRoleGroup -groupscope Global -Path $ouAdminResServiceRole -Description $del_GP_Role_Description
                Funcwriteout("New AD Group  - ADGroup-Services-Management - $($del_DG_SvcRoleGroup)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group  - ADGroup-Services-Management - $($del_DG_SvcRoleGroup)")
            }
   
        Add-ADGroupMember $del_DL_SvcRoleGroup $del_DG_SvcRoleGroup

        #OU Delegation Group
        $del_DL_SrvOUGroup = "$($del_DomainLocal)OU_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($groupSub.split(",")[0])"
        $del_DG_SrvOUGroup = "$($del_DomainGlobal)OU_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($groupSub.split(",")[0])"

        try
            {
                New-ADGroup $del_DL_SrvOUGroup -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_Description
                Funcwriteout("New AD Group - ADGroup-Services-Management -  $($del_DL_SrvOUGroup)") 
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DL_SrvOUGroup)") 
            }

        try
            {
                New-ADGroup $del_DG_SrvOUGroup -groupscope Global -Path $ouAdminResServiceRt -Description $del_Description
                Funcwriteout("New AD Group - ADGroup-Services-Management -  $($del_DG_SrvOUGroup)")
            }
        catch
            {
                Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DG_SrvOUGroup)")
            }     
     
        Add-ADGroupMember $del_DL_SrvOUGroup $del_DG_SrvOUGroup
        Add-ADGroupMember $del_DL_SrvOUGroup $del_DL_SvcRoleGroup
  
        #Create Delegation Groups
        $GroupName = $del_DL_SrvOUGroup 
        $delOU_FullOU = "OU=$ouSrvResOU,$ouSrvResDN"

        #Delegate group to OU with acls required
        if ($ouSrvResObj -eq "Group")
        {
            Delegate_Group($GroupName,$delOU_FullOU)   
        }
        elseif ($ouSrvResObj -eq "User")
        {
            Delegate_User($GroupName,$delOU_FullOU)   
        }
        elseif ($ouSrvResObj -eq "SvcAccts")
        {
            Delegation_SvcAccts($GroupName,$delOU_FullOU)   
        }
        elseif ($ouSrvResObj -eq "computer")
        {
            Delegate_Computer($GroupName,$delOU_FullOU)   
 
            #Restriced Group 
            $del_DL_RGGroupNameAdmin = "$($del_DomainLocal)RG_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_Admin.split(",")[0])"
            $del_DG_RGGroupNameAdmin = "$($del_DomainGlobal)RG_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_Admin.split(",")[0])"

            $del_DL_RGGroupNameUser = "$($del_DomainLocal)RG_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_User.split(",")[0])"
            $del_DG_RGGroupNameUser = "$($del_DomainGlobal)RG_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_User.split(",")[0])"

            #GPO Modify
            $del_DL_GPOGroupModify = "$($del_DomainLocal)GPO_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($del_GPO_Modify_ACL.split(",")[0])"
            $del_DG_GPOGroupModify = "$($del_DomainGlobal)GPO_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_$($del_GPO_Modify_ACL.split(",")[0])"
   
            #Restriced Group 
            try
                {
                    New-ADGroup $del_DL_RGGroupNameAdmin -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_RG_Admin_Description
                    Funcwriteout("New AD Group - ADGroup-Services-Management - $($del_DL_RGGroupNameAdmin)") 
                }
            catch
                {
                    Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DL_RGGroupNameAdmin)") 
                }          
              
            try
                {
                    New-ADGroup $del_DG_RGGroupNameAdmin -groupscope Global -Path $ouAdminResServiceRt -Description $del_RG_Admin_Description
                    Funcwriteout("New AD Group - ADGroup-Services-Management - $($del_DG_RGGroupNameAdmin)")
                }
            catch
                {
                    Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DG_RGGroupNameAdmin)")
                }
                      
            Add-ADGroupMember $del_DL_RGGroupNameAdmin $del_DG_RGGroupNameAdmin
            Add-ADGroupMember $del_DL_RGGroupNameAdmin $del_DL_SvcRoleGroup

            try
                {
                    New-ADGroup $del_DL_RGGroupNameUser -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_RG_User_Description
                    Funcwriteout("New AD Group - ADGroup-Services-Management - $($del_DL_RGGroupNameUser)")
                }
            catch
                {
                    Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DL_RGGroupNameUser)")
                }
                  
            try
                {
                    New-ADGroup $del_DG_RGGroupNameUser -groupscope Global -Path $ouAdminResServiceRt -Description $del_RG_User_Description
                    Funcwriteout("New AD Group - ADGroup-Services-Management - $($del_DG_RGGroupNameUser)") 
                }
            catch
                {
                    Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DG_RGGroupNameUser)") 
                }
       
            Add-ADGroupMember $del_DL_RGGroupNameUser $del_DG_RGGroupNameUser
            #Add-ADGroupMember $del_DL_SvcRoleGroup $del_DL_RGGroupNameUser
                
            #GPO Modify
            try
                {
                    New-ADGroup $del_DL_GPOGroupModify -groupscope DomainLocal -Path $ouAdminResServiceRt -Description $del_GPO_Modify_Description
                    Funcwriteout("New AD Group - ADGroup-Services-Management - $($del_DL_GPOGroupModify)") 
                }
            catch
                {
                    Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DL_GPOGroupModify)") 
                }
        
            try
                {
                    New-ADGroup $del_DG_GPOGroupModify -groupscope Global -Path $ouAdminResServiceRt -Description $del_GPO_Modify_Description
                    Funcwriteout("New AD Group - ADGroup-Services-Management - $($del_DG_GPOGroupModify)")  
                }
            catch
                {
                    Funcwriteout("Failed to create new AD Group - ADGroup-Services-Management - $($del_DG_GPOGroupModify)")  
                }
       
            Add-ADGroupMember $del_DL_GPOGroupModify $del_DG_GPOGroupModify
            Add-ADGroupMember $del_DL_GPOGroupModify $del_DL_SvcRoleGroup

            #$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)
            $gpoName = "GPO_$($ouTierNameRoot)_$($ouCompItem)_$($ouSrvResOU)_RestrictedGroup"


            $del_DL_RG_ServerResGp_Admin = Get-ADGroup $del_DL_RGGroupNameAdmin
            $del_DL_RG_ServerResGp_User = Get-ADGroup $del_DL_RGGroupNameUser

            GPO-ServiceRes-DelegationGrp($gpoName,$ouSrvResDN,$ouSrvResOU,$del_DL_RG_ServerResGp_Admin,$del_DL_RG_ServerResGp_User,$del_DL_GPOGroupModify)       
        }       
    }

    <#-----------------------------

    FUNCTIONS - Update User Rights Assignments and Restricted Groups

    -----------------------------#>

    Function GPO-TopTier-RestrictedGroup
    {
    <#-----------------------------

    OU=AD Tasks,OU=Service Infrastructure,OU=Org3,DC=testdom,DC=loc
    AL_OU_ORG1_SvcRes_SCCM_URA_GroupMgmt

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "GPO-ServiceResource-URA-ResGps"
        $funcDescription = "Function to create Service Resouce OU level GPO and set Restricted Groups and URA for Admin and User Access plus Logon via RDP"
        $funcComment = "No Comment"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        #Root of the domain
        $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

        #Path to Sysvol
        $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

        #Get New Group Name and SID
        Write-Host $del_RG_DL_SvcResUser -ForegroundColor Yellow
        write-host $del_RG_DL_SvcResAdmin -ForegroundColor Yellow
        $gt_del_RG_SvcRes_AdminSid = $del_RG_DL_SvcResAdmin.SID.Value
        $gt_del_RG_SvcRes_UserSid = $del_RG_DL_SvcResUser.SID.Value

        <#-----------------------------

        Create Member Server top level GPO and set Restricted Groups and URA

        -----------------------------#>
        $gtGPO=@()
        $gtGPO = Get-GPO -Name $GPOName
            if ($gtGPO -eq $null)
                {

                $getOUMS = try {Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue | where {$_.DistinguishedName -eq $ouServiceResDN} }catch{}
                #New GPO based on the service and linked to OU
        
                try
                    {
                        New-GPO -Name $GPOName -ErrorAction SilentlyContinue | New-GPLink -Target $getOUMS.DistinguishedName
                        (Get-GPO -Name $GPOName).GpoStatus="UserSettingsDisabled"
                        Funcwriteout("New GPO - GPO-TopTier-RestrictedGroup - $($GPOName)")

                        $getGpoId = (Get-GPO $GPOName -ErrorAction SilentlyContinue).id
                        $getGPOPath = (Get-GPO $GPOName -ErrorAction SilentlyContinue).path
                        $del_GPO_Edit_Acl
                        Set-GPPermission -Guid $getGpoId -PermissionLevel GpoEditDeleteModifySecurity -TargetType Group -TargetName $del_GPOGroupModify

                        $sysvol = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\Machine\Microsoft\Windows NT\SecEdit"
                        $gpt = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\GPT.ini"
                        Set-content $gpt -Value "[General]"
                        Add-Content $gpt -Value "Version=1" 

                        Funcwriteout("New GPO Guid is  - GPO-TopTier-RestrictedGroup - $($getGpoId)")

                        try {
                                New-Item -Path $sysvol -ItemType Directory -Force
                                New-Item -Path $sysvol -Name GptTmpl.inf -ItemType File -Force
                                Funcwriteout("New GPTmpl.inf created  at $($sysvol)")
                            }
                        catch
                            {
                                Funcwriteout("Failed to create new  - GPO-TopTier-RestrictedGroup - GPTmpl.inf created  at $($sysvol)")                
                            }

                        $gptFile = "$($sysvol)\GptTmpl.inf"

                        #S-1-5-32-544 = Administrator Group
                        #S-1-5-32-555 = Remote Desktop Group
                        #SeRemoteInteractiveLogonRight = Allow log on through Remote Desktop Services

                        #Admin Group Sids for Restricted Groups
                        $addConAdmin = "*S-1-5-32-544__Members = *$($gt_del_RG_SvcRes_AdminSid)"
                        #RDP Group Sids for Restricted Groups
                        $addConRDP = "*S-1-5-32-555__Members = *$($gt_del_RG_SvcRes_UserSid)" 

                        #User Rights Assignments
                        $addConURARemote = "SeRemoteInteractiveLogonRight = *$($gt_del_RG_SvcRes_AdminSid),*$($gt_del_RG_SvcRes_UserSid)" 

                        #Update GmpTmpl.inf with URA and Restricted Groups
                        Add-Content -Path $gptFile -Value '[Unicode]'
                        Add-Content -Path $gptFile -Value 'Unicode=yes'
                        Add-Content -Path $gptFile -Value '[Version]'
                        Add-Content -Path $gptFile -Value 'signature="$CHICAGO$"'
                        Add-Content -Path $gptFile -Value 'Revision=1'
                        Add-Content -Path $gptFile -Value '[Group Membership]'
                        Add-Content -Path $gptFile -Value '*S-1-5-32-544__Memberof ='
                        Add-Content -Path $gptFile -Value $addConAdmin 
                        Add-Content -Path $gptFile -Value '*S-1-5-32-555__Memberof ='
                        Add-Content -Path $gptFile -Value $addConRDP 
                        Add-Content -Path $gptFile -Value '[Privilege Rights]'
                        Add-Content -Path $gptFile -Value $addConURARemote    

                        #Set GPMC Machine Extensions so Manual Intervention is both displayed in GPO Administrative and applies to target 
                        Set-ADObject -Identity $getGPOPath -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"}
                        Set-ADObject -Identity $getGPOPath -Replace @{versionNumber="1"}
                           
                    }
                catch {Funcwriteout("Failed to create new GPO - GPO-TopTier-RestrictedGroup - $($GPOName)")}
                }
    }

    Function GPO-ServiceRes-DelegationGrp
    {
    <#-----------------------------

    OU=AD Tasks,OU=Service Infrastructure,OU=Org3,DC=testdom,DC=loc
    AL_OU_ORG1_SvcRes_SCCM_URA_GroupMgmt

    GPO-ServiceRes-DelegationGrp($gpoName,$ouSrvResServiceDN,$ouSrvResOU,$del_RG_DL_ServerAdmin, $del_RG_DL_ServerUser,$del_DL_GPOGroupModify) 

    $ouSrvResServiceDN,$ouSrvResOU

    -----------------------------#>
        #Function to write out to screen
        [string]$funcName = "GPO-ServiceResource-URA-ResGps"
        $funcDescription = "Function to create Service\Application OU level GPO and set Restricted Groups and URA for Admin and User Access plus Logon via RDP"
        $funcComment = "$GPOName"
        Funcwriteout($funcname,$funcDescription,$funcComment)

        #Root of the domain
        $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

        #Path to Sysvol
        $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

        #Get New Group Name and SID = Org
        $del_DomainLocal = "AL_"
        $del_DomainGlobal = "AG_"
        $del_DL_RG_SvcRes_Admin = "$($del_DomainLocal)RG_$($ouTierNameRoot)_$($del_ResGrp_Admin.split(",")[0])"
        $del_DL_RG_SvcRes_User = "$($del_DomainLocal)RG_$($ouTierNameRoot)_$($del_ResGrp_User.split(",")[0])"

        #Service Resource
        try
            {
                $gt_RG_DL_SvcRes_Admin = Get-ADGroup $del_DL_RG_SvcRes_Admin -ErrorAction SilentlyContinue
                Funcwriteout("Get AD Group - GPO-ServiceRes-DelegationGrp - $($del_DL_RG_SvcRes_Admin)")
            }
        catch
            {
                Funcwriteout("Failed to get AD Group - GPO-ServiceRes-DelegationGrp - $($del_DL_RG_SvcRes_Admin)")
            }
    
        try
            {
                $gt_RG_DL_SvcRes_User = Get-ADGroup $del_DL_RG_SvcRes_User -ErrorAction SilentlyContinue
                
            }
        catch
            {
                Funcwriteout("Failed to get AD Group - GPO-ServiceRes-DelegationGrp - $($del_DL_RG_SvcRes_User)") 
            }

        $gt_del_RG_SvcRes_AdminSid = $gt_RG_DL_SvcRes_Admin.SID.Value
        $gt_del_RG_SvcRes_UserSid = $gt_RG_DL_SvcRes_User.SID.Value

        #Server Admin
        $gt_del_RG_Svc_SrvAdminSid = $del_DL_RG_ServerResGp_Admin.SID.Value
        $gt_del_RG_Svc_SrvUserSid = $del_DL_RG_ServerResGp_User.SID.Value

        <#-----------------------------

        Create Member Server top level GPO and set Restricted Groups and URA

        -----------------------------#>
        $gtGPO=@()
        $gpoTargetDN = "OU=$($ouSrvResOU),$($ouSrvResDN)"
        $gtGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        Funcwriteout("Get OU Name $($GPOName)")
            if ($gtGPO -eq $null)
                {
                    $getOUMS = try {Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue | where {$_.DistinguishedName -eq $gpoTargetDN }}catch{}
          
                    #New GPO based on the service and linked to OU        
                    try 
                                                                                                                                                                                                                    {
                        New-GPO -Name $GPOName | New-GPLink -Target $getOUMS.DistinguishedName -ErrorAction SilentlyContinue
                        (Get-GPO -Name $GPOName).GpoStatus="UserSettingsDisabled"
                        Funcwriteout("New GPO - GPO-ServiceRes-DelegationGrp - $($GPOName)")

                        $getGpoId = (Get-GPO $GPOName).id
                        $getGPOPath = (Get-GPO $GPOName -ErrorAction SilentlyContinue).path
                        Set-GPPermission -Guid $getGpoId -PermissionLevel GpoEditDeleteModifySecurity -TargetType Group -TargetName $del_DL_GPOGroupModify

                        $sysvol = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\Machine\Microsoft\Windows NT\SecEdit"
                        $gpt = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\GPT.ini"
                        Set-content $gpt -Value "[General]"
                        Add-Content $gpt -Value "Version=1" 

                        Funcwriteout("New GPO Guid is - GPO-ServiceRes-DelegationGrp - $($getGpoId)")

                        try {
                                New-Item -Path $sysvol -ItemType Directory -Force
                                New-Item -Path $sysvol -Name GptTmpl.inf -ItemType File -Force
                                Funcwriteout("New GPTmpl.inf - GPO-ServiceRes-DelegationGrp - created  at $($sysvol)")
                            }
                        catch
                            {
                                Funcwriteout("Failed to create new GPTmpl.inf - GPO-ServiceRes-DelegationGrp - created  at $($sysvol)")                
                            }

                        $gptFile = "$($sysvol)\GptTmpl.inf"

                        #S-1-5-32-544 = Administrator Group
                        #S-1-5-32-555 = Remote Desktop Group
                        #SeRemoteInteractiveLogonRight = Allow log on through Remote Desktop Services

                        #Admin Group Sids for Restricted Groups
                        $addConAdmin = "*S-1-5-32-544__Members = *$($gt_del_RG_Svc_SrvAdminSid),*$($gt_del_RG_SvcRes_AdminSid)"
                        #RDP Group Sids for Restricted Groups
                        $addConRDP = "*S-1-5-32-555__Members = *$($gt_del_RG_Svc_SrvUserSid),*$($gt_del_RG_SvcRes_UserSid)" 

                        #User Rights Assignments
                        $addConURARemote = "SeRemoteInteractiveLogonRight = *$($gt_del_RG_Svc_SrvAdminSid),*$($gt_del_RG_Svc_SrvUserSid),*$($gt_del_RG_SvcRes_AdminSid),*$($gt_del_RG_SvcRes_UserSid)" 

                        #Update GmpTmpl.inf with URA and Restricted Groups
                        Add-Content -Path $gptFile -Value '[Unicode]'
                        Add-Content -Path $gptFile -Value 'Unicode=yes'
                        Add-Content -Path $gptFile -Value '[Version]'
                        Add-Content -Path $gptFile -Value 'signature="$CHICAGO$"'
                        Add-Content -Path $gptFile -Value 'Revision=1'
                        Add-Content -Path $gptFile -Value '[Group Membership]'
                        Add-Content -Path $gptFile -Value '*S-1-5-32-544__Memberof ='
                        Add-Content -Path $gptFile -Value $addConAdmin 
                        Add-Content -Path $gptFile -Value '*S-1-5-32-555__Memberof ='
                        Add-Content -Path $gptFile -Value $addConRDP 
                        Add-Content -Path $gptFile -Value '[Privilege Rights]'
                        Add-Content -Path $gptFile -Value $addConURARemote    

                        #Set GPMC Machine Extensions so Manual Intervention is both displayed in GPO Administrative and applies to target 
                        Set-ADObject -Identity $getGPOPath -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"}
                        Set-ADObject -Identity $getGPOPath -Replace @{versionNumber="1"}
                    }
                        catch{Funcwriteout("Failed to create new GPO - GPO-ServiceRes-DelegationGrp - $($GPOName)")}
                }
    }

    <#-----------------------------

    FUNCTIONS - Import CIS, SCM and Custom Policies 

    -----------------------------#>

    Function Import_ServiceGPOs
    {
    #Import CIS, SCM Policies - $ouTierNameRootDN
    if ($ouType -eq "clients")
        {
            $gtGPOClient = try {Get-ChildItem "$($Pwdir)\GPOs\Client"}catch{write-host "No Client GPO's available"}
                foreach ($guid in $gtGPOClient)
                    {
                    $gtGPOContent = (get-content "$($Pwdir)\GPOs\Client\$($guid)\gpreport.xml" | Select-String "<Name>")[0]
                    $targetName = $gtGPOContent.ToString().replace("<Name>","").replace("</Name>","").Replace("  ","")
                    $backupID = $guid.name.replace("{","").replace("}","")
                    $gtGPOExist = Get-GPO -Name $targetName -ErrorAction SilentlyContinue
                            
                    if ($gtGPOExist -eq $null)
                        {
                            Import-GPO -Path "$($Pwdir)\GPOs\Client\" -BackupId $backupID -TargetName $targetName -CreateIfNeeded | New-GPLink -Target $ouTierNameRootDN -LinkEnabled Yes -Order 2 -ErrorAction SilentlyContinue
                        }
                    elseif ($gtGPOExist -ne $null)
                        {
                            Get-GPO -Name $targetName | New-GPLink -Target $ouTierNameRootDN -LinkEnabled Yes -Order 2 -ErrorAction SilentlyContinue
                        }      
                    }

            $gtGPOUser = try {Get-ChildItem "$($Pwdir)\GPOs\Users"}catch{write-host "No User GPO's available"}
                foreach ($guid in $gtGPOUser)
                    {
                    $gtGPOContent = (get-content "$($Pwdir)\GPOs\Users\$($guid)\gpreport.xml" | Select-String "<Name>")[0]
                    $targetName = $gtGPOContent.ToString().replace("<Name>","").replace("</Name>","").Replace("  ","")
                    $backupID = $guid.name.replace("{","").replace("}","")
                    $gtGPOExist = Get-GPO -Name $targetName -ErrorAction SilentlyContinue
                            
                    if ($gtGPOExist -eq $null)
                        {
                            Import-GPO -Path "$($Pwdir)\GPOs\Users\" -BackupId $backupID -TargetName $targetName -CreateIfNeeded | New-GPLink -Target $ouTierNameRootDN -LinkEnabled Yes -Order 2 -ErrorAction SilentlyContinue
                        } 
                     elseif ($gtGPOExist -ne $null)
                        {
                            Get-GPO -Name $targetName | New-GPLink -Target $ouTierNameRootDN -LinkEnabled Yes -Order 2 -ErrorAction SilentlyContinue
                        }     
                    }
        }
                    
    if ($ouType -eq "server")
        {
            $gtGPOs = try {Get-ChildItem "$($Pwdir)\GPOs\MemberServer"}catch{write-host "No Server GPO's available"}
            foreach ($guid in $gtGPOs)
                {
                $gtGPOContent = (get-content "$($Pwdir)\GPOs\MemberServer\$($guid)\gpreport.xml" | Select-String "<Name>")[0]
                $targetName = $gtGPOContent.ToString().replace("<Name>","").replace("</Name>","").Replace("  ","")
                $backupID = $guid.name.replace("{","").replace("}","")
                $gtGPOExist = Get-GPO -Name $targetName -ErrorAction SilentlyContinue
                            
                if ($gtGPOExist -eq $null)
                    {
                        Import-GPO -Path "$($Pwdir)\GPOs\MemberServer\" -BackupId $backupID -TargetName $targetName -CreateIfNeeded | New-GPLink -Target  $ouTierNameRootDN -LinkEnabled Yes -Order 2 -ErrorAction SilentlyContinue
                    } 
                elseif ($gtGPOExist -ne $null)
                    {
                            Get-GPO -Name $targetName | New-GPLink -Target $ouTierNameRootDN -LinkEnabled Yes -Order 2 -ErrorAction SilentlyContinue
                    }           
                }
        }
    }

    Function Import_DomainController
    {
        $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

        $dcDN = "OU=Domain Controllers,$rootDSE"

        #Path to Sysvol
        $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

        #Import Corporate GPO's eg SCM, CIS etc
        $gtGPOs = try {Get-ChildItem "$($Pwdir)\GPOs\DC"}catch{write-host "No Domain Controller GPO's available"}
        foreach ($guid in $gtGPOs)
            {
                $gtGPOContent = (get-content "$($Pwdir)\GPOs\DC\$($guid)\gpreport.xml" | Select-String "<Name>")[0]
                $targetName = $gtGPOContent.ToString().replace("<Name>","").replace("</Name>","").Replace("  ","")
                $backupID = $guid.name.replace("{","").replace("}","")
                $gtGPOExist = Get-GPO -Name $targetName -ErrorAction SilentlyContinue
                           
                if ($gtGPOExist -eq $null)
                    {
                        Import-GPO -Path "$($Pwdir)\GPOs\DC\" -BackupId $backupID -TargetName $targetName -CreateIfNeeded | New-GPLink -Target $dcDN -LinkEnabled Yes -Order 1 -ErrorAction SilentlyContinue
                    }  
            }        
        }   

    Function Import_DomainPolicy
    {
        $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

        $dcDN = "$rootDSE"

        #Path to Sysvol
        $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

        #Import Corporate GPO's eg SCM, CIS etc
        $gtGPOs = try {Get-ChildItem "$($Pwdir)\GPOs\Domain"}catch{write-host "No Domain GPO's available"}
        foreach ($guid in $gtGPOs)
            {
                $gtGPOContent = (get-content "$($Pwdir)\GPOs\Domain\$($guid)\gpreport.xml" | Select-String "<Name>")[0]
                $targetName = $gtGPOContent.ToString().replace("<Name>","").replace("</Name>","").Replace("  ","")
                $backupID = $guid.name.replace("{","").replace("}","")
                $gtGPOExist = Get-GPO -Name $targetName -ErrorAction SilentlyContinue
                           
                if ($gtGPOExist -eq $null)
                    {
                        Import-GPO -Path "$($Pwdir)\GPOs\Domain\" -BackupId $backupID -TargetName $targetName -CreateIfNeeded | New-GPLink -Target $dcDN -LinkEnabled Yes -Order 1
                    }  
            }        
        }   

    function Import-ADMX
    {
    <#-----------------------------

    ADMX - Take the content of current working directory\ADMXTemplates and copy adml and admx to PolicyDefinition directory in Sysvol

    NOTE: Creates PolicyDefinition directory and imports admx files if the policydefinition directory does not exist

    -----------------------------#>

        $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

        #Path to Sysvol
        $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

        $polDefFolder = "$($smbSysVol)\Domain\Policies\PolicyDefinitions\"

        $gtPolDef = Test-Path $polDefFolder

        if($gtPolDef -eq $false)
            {
                New-Item -Path $polDefFolder -ItemType directory -Force

                $admxFolder = "$($Pwdir)\ADMXTemplates"

                #copy ADMX to Policy Definition Directory
                Get-ChildItem -Path $admxFolder -Recurse | where {$_.extension -eq ".admx"} | 
                    ForEach-Object {copy-item $_.FullName -Destination $polDefFolder}

                #Get the en-GB or en-something folders and create in Policy Definition directory
                (Get-ChildItem -Path $admxFolder -Recurse | where {$_.directory -match "en-"}).directory  | Select-Object -Unique name | 
                    foreach {New-Item -Path $polDefFolder -Name $_.name -ItemType directory -Force}

                $adml = (Get-ChildItem -Path $admxFolder -Recurse | where {$_.directory -match "en-"}).directory

                #Copy contents of en-Us or en-Gb to corrisponding policy Definition directory
                foreach ($admldir in $adml)
                {
                    Get-ChildItem $admldir.FullName -Recurse | foreach {copy-item -force $_.FullName -Destination "$($polDefFolder)\$($admldir.Name)"}
                }
            }
    }

    <#-----------------------------

    Declare Domain variables

    -----------------------------#>
        #Root of the domain
        $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

        #Path to Sysvol
        $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")
        $adminTaskOU = "Admin Tasks"
        $adminRoles = "Admin Roles"
    <#-----------------------------

    Import JSON for OU configuration

    -----------------------------#>

        $gtOUs = $gtDCPromoJ.OU

        foreach ($ou in $gtOUs.PSObject.Properties.value)
        {
            if ($ou.Type -match "Admin")
            {
                #Parent DN to build structure
                $ouParent = $ou.Path
                if ($ouParent -ne $null){Write-host "$ouParent is present"}else{write-host "$ou.Path is Null" -ForegroundColor Red | pause }
              
                #Name of Tier OU
                $ouTierNameRoot = $ou.Name
                $adminResourceName = $ou.Name
                if ($ouTierNameRoot -ne $null){Write-host "$ouTierNameRoot is present"}else{write-host "$ou.Name is Null" -ForegroundColor Red | pause }

                #Type of structure either Server\Service or Client\User
                $ouType = $ou.Type
                if ($ouType -ne $null){Write-host "$ouType is present"}else{write-host "$ou.Type is Null" -ForegroundColor Red | pause }

                #Protect OUs from deletion
                $ouProtect = [system.convert]::ToBoolean($ou.Protect)

                #Define Name of Administrative OU Administrative Resource (Delegation, URA, Roles) and Service Infrastructure (Named Application\Services OU - SCCM, Exchange, File and Print)
                $ouAdminOU = $ou.AdministrativeOU
                if ($ouAdminOU -ne $null){Write-host "$ouAdminOU is present"}else{write-host "$ou.AdministrativeOU is Null" -ForegroundColor Red | pause }

                #Administrative Resource sub-OUs for ADRoles, ADTasks, URA and AdminAccounts
                $ouAdminRes = $ou.AdministrativeResources
                if ($ouAdminRes-ne $null){Write-host " $ouAdminRes is present"}else{write-host "$ou.AdministrativeResources is Null" -ForegroundColor Red | pause }

    <#-----------------------------

    Create Organisation OU Top Level

    -----------------------------#>
                $gtOUName=@()
                $gtouOrgNameDN=@()

                $ouTierNameRootDN = "OU=$($ouTierNameRoot),$($rootDSE)"
                $gtOUName = try {Get-ADOrganizationalUnit -filter *  -ErrorAction SilentlyContinue | where {$_.DistinguishedName -eq $ouTierNameRootDN}} catch {}
                CreateOU-OrgRoot($ouTierNameRoot,$ouProtect)

    <#-----------------------------

    Administrative Resources
        Separate Administrative Resouces and Service Infrastructure to reduce complexity and dependancy hell

    -----------------------------#>
                    $ouMgmtRtItems = $ouAdminOU.split(",")
                    #Create Administrative OU's Administrative Resources
                    foreach ($ouMgmdRes in $ouMgmtRtItems[0])
                    {
                        #Function to create Administrative OU for each Application or Service eg SCCM, SCOM, Exchange
                        $ouAdminResDN=@()
                        $gtouAdminResDN=@()
                    
                        #$ouAdminResDN = "OU=$($ouMgmdRes),$($ouTierNameRootDN)"
                        $ouAdminResDN = "$($ouTierNameRootDN)"
                        $AdministrativeOU = $ouAdminResDN 
                        $gtouAdminResDN = try {Get-ADOrganizationalUnit $ouAdminResDN -ErrorAction SilentlyContinue} catch {}
                        
                        #Creates OU's Admin Resources
                        CreateOU-AdminRes($ouMgmdRes,$ouTierNameRootDN,$ouProtect)  

                        #select the Administrative Resources to create sub-OUs
                        $ouMgmdResDN = "OU=$($ouMgmdRes),$($ouTierNameRootDN)"
                        $ouMgtRtManResDN = "$($ouMgmdResDN),$($ouMgmdResDN)"    
                            foreach ($ouAdminResItem in $ouAdminRes)
                            {
                                $ouAdminResOU = $ouAdminResItem.split(",")[0]
                                $ouAdminResObj = $ouAdminResItem.split(",")[1]
                    
                                #Creates OU for the Administrative of Server Resouces
                                $ouAdminResOuDN=@()
                                $gtouAdminResOuDN=@()
                            }
                    }
                }
                

            if ($ou.type -notmatch "Admin")
            {
                #Parent DN to build structure
                $ouParent = $ou.Path
                if ($ouParent -ne $null){Write-host "$ouParent is present"}else{write-host "$ou.Path is Null" -ForegroundColor Red | pause }
              
                #Name of Organisation OU
                $ouTierNameRoot = $ou.Name
                if ($ouTierNameRoot -ne $null){Write-host "$ouTierNameRoot is present"}else{write-host "$ou.Name is Null" -ForegroundColor Red | pause }

                #Type of structure either Server\Service or Client\User
                $ouType = $ou.Type
                if ($ouType -ne $null){Write-host "$ouType is present"}else{write-host "$ou.Type is Null" -ForegroundColor Red | pause }

                #Protect OUs from deletion
                $ouProtect = [system.convert]::ToBoolean($ou.Protect)

                #Define Name of Administrative OU Administrative Resource (Delegation, URA, Roles) and Service Infrastructure (Named Application\Services OU - SCCM, Exchange, File and Print)
                $ouAdminOU = $ou.AdministrativeOU
                if ($ouAdminOU -ne $null){Write-host "$ouAdminOU is present"}else{write-host "$ou.AdministrativeOU is Null" -ForegroundColor Red | pause }

                #Administrative Resource sub-OUs for ADRoles, ADTasks, URA and AdminAccounts
                $ouAdminRes = $ou.AdministrativeResources
                if ($ouAdminRes-ne $null){Write-host " $ouAdminRes is present"}else{write-host "$ou.AdministrativeResources is Null" -ForegroundColor Red | pause }

                #Define Servers or Client or Server and Object Type of Computer
                $ouAppResources = $ou.AppResources
                if ($ouAppResources -ne $null){Write-host "$ouAppResources is present"}else{write-host "$ou.AppResources is Null" -ForegroundColor Red | pause }

                #Defines Application\Services OUs and Object type eg Servers = Computer, ApplicationGroup = Groups
                $ouSrvRes = $ou.ServiceResources
                if ($ouSrvRes -ne $null){Write-host "$ouSrvRes is present"}else{write-host "$ou.ServiceResources is Null" -ForegroundColor Red | pause }
          
    <#-----------------------------
    
    Create Organisation OU Top Level

    -----------------------------#>
                $gtOUName=@()
                $gtouOrgNameDN=@()

                $ouTierNameRootDN = "OU=$($ouTierNameRoot),$($rootDSE)"
                $gtOUName = try {Get-ADOrganizationalUnit -filter * -ErrorAction SilentlyContinue | where {$_.DistinguishedName -eq $ouTierNameRootDN}} catch {}
                CreateOU-OrgRoot($ouTierNameRoot,$ouProtect)

                    $ouMgmtRtItems = $ouAdminOU.split(",")
                    #Create Administrative OU's Administrative Resources
                    foreach ($ouMgmdRes in $ouMgmtRtItems[0])
                    {
                        #Function to create Administrative OU for each Application or Service eg SCCM, SCOM, Exchange
                        $ouAdminResDN=@()
                        $gtouAdminResDN=@()
                    
                        $ouAdminResDN = "OU=$($ouMgmdRes),$($ouTierNameRootDN)"
                        $gtouAdminResDN = try {Get-ADOrganizationalUnit $ouAdminResDN -ErrorAction SilentlyContinue} catch {}
                        
                        #Creates top level Administrative OU for each organisation or tier - Member Servers, Clients
                        CreateOU-AdminResSub($ouTierNameRoot,$AdministrativeOU,$ouProtect,$adminTaskOU,$adminRoles)
 
                        #OU to Admin Resource OU and and the Tiered OU
                        $AdminResSubDN = "OU=$ouTierNameRoot,$AdministrativeOU"

                        #Declare top tier and pass into functions - Member Servers, User Services
                        $topTierOU = $ouTierNameRoot

    <#-----------------------------

    Service or Application Groups and OUs eg Exchange, SQL, Clients, File Servers
        Creates OUs for each service, GPO for top-level and Level 1 Restricted Groups and URA
        Creates Full control OU groups and delegated at the Service level - created in the Admin layer
        
    -----------------------------#>
                        $ouCompItem=@()
                        $ouCompSplit = $ouAppResources.split(",")
                        foreach ($ouCompItem in $ouCompSplit)
                        {
                            #Function to create Administrative OU for each Application or Service eg SCCM, SCOM, Exchange
                            $ouSvrCompDN=@()
                            $gtouSvrResMgmtDN=@()

                            $ouSvrCompDN = "OU=$($ouCompItem),$($ouTierNameRootDN)"
                            $gtouSvrResMgmtDN = try {Get-ADOrganizationalUnit $ouSvrCompDN -ErrorAction SilentlyContinue} catch {}
                        
                            #Creates Top-level tiered OU, Admin Resources, Member Servers and User Services
                            #Creates 2nd Level Service OU Admin Management, Services OUs eg Exchange, Certs, Sccm
                            CreateOU-TopTier-Service-Admin($ouCompItem,$ouTierNameRootDN,$ouProtect,$ouTierNameRoot,$adminTaskOU,$adminRoles)
                                                                                                    
                            #Creates Admin Resources service or app OU's Admin Resources > Member Servers 
                            CreateOU-AdminResService-AdminMgmt($ouTierNameRoot,$ouCompItem,$AdministrativeOU,$ouProtect,$adminTaskOU,$adminRoles)

                            #Top level delegation and gpo restricted group and URA - Member Servers and Clients
                            ADGroup-TopTier-Delegation-GPO($topTierOU,$ouTierNameRoot,$AdministrativeOU,$ouProtect,$adminTaskOU,$adminRoles)
                            
                            #Imports GPOs from file system and apply at top level eg Member Servers or Clients
                            Import_ServiceGPOs($ouTierNameRootDN)

                            #Creates the Service level eg Exhange, SCCM AD Groups and delegation of full control
                            ADGroup-ServiceResources($ouTierNameRootDN,$ouTierNameRoot,$ouCompItem,$AdminResSubDN,$ouProtect,$adminTaskOU,$adminRoles)
                            
    <#-----------------------------

    Service or Application Management Groups and OUs 
        Creates the Servers, URA, App Groups and Service Account OU's for each Service
        Creates delegation groups and applies to management groups
        
    -----------------------------#>
                            $ouSrvResDN = "OU=$ouCompItem,$ouTierNameRootDN"
                            $ouSrvResCompDN = "OU=$($ouCompItem),$($ouSvrResDN)"    
                            foreach ($ouSrvResItem in $ouSrvRes)
                            {                            
                                $ouSrvResOU = $ouSrvResItem.split(",")[0]
                                $ouSrvResObj = $ouSrvResItem.split(",")[1]
                            
                                #Function to create Administrative OU for each Application or Service eg SCCM, SCOM, Exchange
                                $ouSvrResMgmtDN=@()
                                $gtouSvrResMgmtDN=@()

                                $ouSvrResMgmtDN = "OU=$($ouSrvResOU),$($ouSrvResCompDN)"
                                $gtouSvrResMgmtDN = try {Get-ADOrganizationalUnit $ouSvrResMgmtDN -ErrorAction SilentlyContinue} catch {}

                                #Creates Management OU for each service eg Exchange > Servers or Exhange > URA
                                CreateOU-Services-Management($ouSrvResOU,$ouSrvResDN,$ouProtect,$adminTaskOU,$adminTaskOU,$adminRoles)

                                #Creates Groups for Service Sub OU's eg URA, Servers, App Groups and delegates to respective groups
                                ADGroup-Services-Management($AdministrativeOU,$ouSrvResDN,$ouSrvResOU,$ouSrvResObj,$ouCompItem,$ouTierNameRoot,$adminTaskOU,$adminRoles) 
                            }
                        }
                    }
                } 
        }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
    <#-----------------------------

    Import DC GPO's and ADMX Files 

    -----------------------------#>
        Import_DomainController
        Import_DomainPolicy
        Import-ADMX

    }
else
    {
        Write-Warning "This script must be executed on the PDC Emulator to prevent inconsistent results"
    }
    <#-----------------------------

    Stop Logging

    -----------------------------#>
    Stop-Transcript
}


