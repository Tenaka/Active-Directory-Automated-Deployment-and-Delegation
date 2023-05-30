<#-----------------------------
Overview.
    Deploy multiple Domain Controllers and a new Forest from the JSON file input
    
Description.
    This is script 4 of 4

    Basic script to deploy somthing
    The creation of OU's, GPO's and the importing of policies MUST be deployed from the PDC   

Version.
230510.1 - workable scripts 
230511.1 - Functions for delegation (CreateOU)
230512.1 - OU structure from JSON (CreateOU)
230513.1 - New OU added for basic structure
230514.1 - New OU Functions
230515.1 - New Groups for Restricted Groups, GPO Delegation
230515.2 - Create new GPO and assigned Admin and User Restricted Groups in to URA
230516.1 - Fixed issue with nesting groups
230518.1 - Group character length exceeded, so adding truncating of names
230519.1 - Added Write-hosts - Support and out to screen what is creating
230519.2 - Fixed issues with Service and Management Resouces OU full delegation not working - renamed to svcRes and MgmtRes and broke if statement
230520.1 - Delegation of Service\Client Sub management OUs
230522.1 - Inherited and service specific Restricted Groups and URA added to GPO for Servers
230523.1 - Created Function to out to display
230523.2 - Added Tries and if exists
230529.1 - Fixed issues with Global and DomainLocal groups mixing up.

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

#TBC

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
write-host " $funcName" -ForegroundColor red
Write-Host " "
Write-Host "Description: " -ForegroundColor Green -NoNewline
Write-Host "$funcDescription" -ForegroundColor Green 
Write-Host "Comment: " -ForegroundColor Green -NoNewline
Write-Host "$funcComment" -ForegroundColor Red
Write-Host " "
Write-Host "-----------------------------#>" -ForegroundColor Green
Write-Host "-----------------------------#>" -ForegroundColor Green
Write-Host " "
}



<#-----------------------------

Disable Scheduled Task and Autologon

-----------------------------#>

    Disable-ScheduledTask -TaskName "schCreateOU"

    #Disable Autologon
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0 -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "" -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value "" -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonSID -Value "" -Force
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 1 -PropertyType string -Force

<#-----------------------------

FUNCTIONS - Delegations

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

    $ouACL = (get-acl -path $delOU_FullOU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $delOU_FullOU

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

    $ouACL = (get-acl -path $delOU_FullOU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $delOU_FullOU

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

    $ouACL = (get-acl -path $delOU_FullOU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $delOU_FullOU

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

    #Group Managed Service Accounts
    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
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

    $ouACL = (get-acl -path $delOU_FullOU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $delOU_FullOU

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
    $funcComment = "$ouOrgNameDN"
    Funcwriteout($funcname,$funcDescription,$funcComment)

    if ($gtouOrgNameDN.DistinguishedName -ne $ouOrgNameDN)
        {
                #Create new Organisation OU 
                try {
                        New-ADOrganizationalUnit -Name $ouOrgName -ProtectedFromAccidentalDeletion $ouProtect
                    }
                catch
                    {
                        Write-host "$ouOrgName already exists" -ForegroundColor Green
                    } 
        }
}
    
function CreateOU-MgmtRes
{
<#-----------------------------

Create Management Resources

OU=Management Resouces,OU=Org2,DC=testdom,DC=loc

-----------------------------#> 
    #Function to write out to screen
    [string]$funcName = "CreateOU-MgmtRes"
    $funcDescription = "Function to create Management Resouces OU under that of the Organisation"
    $funcComment = "$ouOrgNameDN"
    Funcwriteout($funcname,$funcDescription,$funcComment)

    if ($gtouMgmtResDN.DistinguishedName -ne $ouMgmtResDN)
        {
            try {
                    New-ADOrganizationalUnit -Name $ouMgmdRes -Path $ouOrgNameDN -ProtectedFromAccidentalDeletion $ouProtect
                }
            catch
                {
                    write-host "$ouMgmdRes already exists" -ForegroundColor Green
                }
            }
    }

function CreateOU-MgmtResMgmt
{
<#-----------------------------

Create Management Resources

OU=Management Resouces,OU=Org2,DC=testdom,DC=loc

-----------------------------#>
    #Function to write out to screen
    [string]$funcName = "CreateOU-MgmtResMgmt"
    $funcDescription = "Function to create OU's under Management Resouces"
    $funcComment = "$ouMgmtResOU"
    Funcwriteout($funcname,$funcDescription,$funcComment)

    if ($ouMgmtResOUDN.DistinguishedName -ne $ouMgmtResOuDN)
        {
        try {
                New-ADOrganizationalUnit -Name $ouMgmtResOU -Path $ouMgmtResDN -ProtectedFromAccidentalDeletion $ouProtect
            }
        catch
            {
                write-host "$ouSvrResDN already exists" -ForegroundColor Green
            }    
        }
}

function CreateOU-SrvRes
{
<#-----------------------------

Create Service Resources

OU=Service Resouces,OU=Org2,DC=testdom,DC=loc

-----------------------------#>
    #Function to write out to screen
    [string]$funcName = "CreateOU-MgmtResMgmt"
    $funcDescription = "Function to create Service Resouce OU under that of the Organisation - contains Service or Application Resouces"
    $funcComment = "$ouSvrRes"
    Funcwriteout($funcname,$funcDescription,$funcComment)
    
    if ($gtouSvrResDN.DistinguishedName -ne $ouSvrResDN )
        {
        try {
                New-ADOrganizationalUnit -Name $ouSvrRes -Path $ouOrgNameDN -ProtectedFromAccidentalDeletion $ouProtect
            }
        catch
            {
                write-host "$ouSvrResDN already exists" -ForegroundColor Green
            }
        }
     }

function CreateOU-SrvComp
{
<#-----------------------------

Creates OU for Service\Applications eg Exchange, Certs, SCOM, SCCM

-----------------------------#>
    #Function to write out to screen
    [string]$funcName = "CreateOU-SrvComp"
    $funcDescription = "Function to create Service\Application OU under Service Resouces"
    $funcComment = "$ouCompItem at $ouSvrResDN"
    Funcwriteout($funcname,$funcDescription,$funcComment)
   
    if ($gtouSvrResMgmtDN.DistinguishedName -ne $ouSvrCompDN)
    {
        try
            {
                New-ADOrganizationalUnit -Name $ouCompItem -Path $ouSvrResDN -ProtectedFromAccidentalDeletion $ouProtect
            }
        catch
            {
                write-host "$ouSvrCompDN already exists" -ForegroundColor Green
            }
    }
}

function CreateOU-SvcSubMgmtOU
{
<#-----------------------------
#Create management sub-ou for each Service or Application

$ouSrvResOU = OU to Create
$ouSrvResCompDN = DN of parent OU
$ouProtect = Is protected
    
CreateOU-SvcSubMgmtOU($ouSrvResOU,$ouSrvResCompDN,$ouProtect)

-----------------------------#>

    #Function to write out to screen
    [string]$funcName = "CreateOU-SvcSubMgmtOU"
    $funcDescription = "Function to create Service\Application sub-OU to manage Service Accounts, Server Objects"
    $funcComment = "$ouSrvResOU at $ouSrvResCompDN"
    Funcwriteout($funcname,$funcDescription,$funcComment)

    if ($gtouSvrResMgmtDN.DistinguishedName -ne $ouSvrResMgmtDN)
            {
        try 
            {
                New-ADOrganizationalUnit -Name $ouSrvResOU -Path $ouSrvResCompDN -ProtectedFromAccidentalDeletion $ouProtect
            }
        catch
            {
                write-host "$ouSvrResMgmtDN  already exists" -ForegroundColor Green
            }
        }
}

<#-----------------------------

FUNCTIONS - Create Security Groups and link to OUs and GPOs

-----------------------------#>

function ADGroup-ManagedResources 
{
<#-----------------------------

Create nested groups Domain Global into Domain Local and attach Domain Local to the object
AL AG_Managed Resources_OU_FullCtrl

-----------------------------#>   
    #Function to write out to screen
    [string]$funcName = "ADGroup-ManagedResources"
    $funcDescription = "Function to create AD Groups for Restricted Groups and URA for Management\Service Resources OU"
    $funcComment = "No Comment"
    Funcwriteout($funcname,$funcDescription,$funcComment)

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
    $del_Group = $del_DomainLocal,$del_DomainGlobal

    #New Group
    $new_GroupName=@()  
    $adTasksDestination=@() 
    $del_OUGroupName=@()
    $del_RGGroupNameAdmin=@()
    $del_RGGroupNameUser=@()
    $gpoName=@()
    $new_OUGroupName=@()
    $new_RGAdminGroupName=@()
    $new_RGAUserGroupName=@()
    $new_GPOModGroupName=@()

    $SvcResTrun = "SvcRes"
    $mgmtResTruc = "MgmtRes"

    foreach ($del_grp in $del_Group)
        {
            $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)"

            #OU Delegation Group
            $del_OUGroupName = "$($del_grp)OU_$($ouOrgName)_$($mgmtResTruc)_$($del_OU_Full_Acl.split(",")[0])"
       
            #Create new AD Groups
            if ($del_OUGroupName -like "$del_DomainGlobal*")
                {
                    #OU Delegation Group
                    try{New-ADGroup $del_OUGroupName –groupscope Global -Path $adTasksDestination -Description $del_OU_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}

                    #Add to array for group nesting
                    $new_OUGroupName+="$($del_OUGroupName)"
 
                }
            elseif ($del_OUGroupName -like "$del_DomainLocal*")
                {
                    #OU Delegation Group
                    try{New-ADGroup $del_OUGroupName –groupscope DomainLocal -Path $adTasksDestination -Description $del_OU_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}  

                    $delOU_FullOU = $ouMgmtResDN
                    $groupName = $del_OUGroupName

                    #Function to delegate OU Full Control to a named group
                    Delegate_FullControl($delOU_FullOU,$GroupName)  

                    #Add to array for group nesting
                    $new_OUGroupName+="$($del_OUGroupName)"
                    $new_GPOModGroupName+="$($del_GPOGroupModify)"          
                }                  
    }

    #Nested groups
    try
        {                
            Add-ADGroupMember $new_OUGroupName[0] $new_OUGroupName[1]
        }
    catch
        {
            Add-ADGroupMember $new_OUGroupName[1] $new_OUGroupName[0]
        }
}


function ADGroup-ServiceResources 
{
<#-----------------------------

Create nested groups Domain Global into Domain Local and attach Domain Local to the object
AL AG_Managed Resources_OU_FullCtrl

-----------------------------#>   
    #Function to write out to screen
    [string]$funcName = "ADGroup-ServiceResources"
    $funcDescription = "Function to create AD Groups for Restricted Groups and URA for Management\Service Resources OU"
    $funcComment = "No Comment"
    Funcwriteout($funcname,$funcDescription,$funcComment)

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

    $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)" 

    #Local and Global
    $del_DomainLocal = "AL_"
    $del_DomainGlobal = "AG_"
    $del_Group = $del_DomainLocal,$del_DomainGlobal

    $SvcResTrun = "SvcRes"
    $mgmtResTruc = "MgmtRes"

    #OU Delegation Group
    $del_DL_OUGroupName = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($del_OU_Full_Acl.split(",")[0])"
    $del_DG_OUGroupName = "$($del_DomainGlobal)OU_$($ouOrgName)_$($SvcResTrun)_$($del_OU_Full_Acl.split(",")[0])"

    #Restriced Group 
    $del_DL_RGGroupNameAdmin = "$($del_DomainLocal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_Admin.split(",")[0])"
    $del_DG_RGGroupNameAdmin = "$($del_DomainGlobal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_Admin.split(",")[0])"


    $del_DL_RGGroupNameUser = "$($del_DomainLocal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_User.split(",")[0])"
    $del_DG_RGGroupNameUser = "$($del_DomainGlobal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_User.split(",")[0])"

    #GPO Modify
    $del_DL_GPOGroupModify = "$($del_DomainLocal)GPO_$($ouOrgName)_$($SvcResTrun)_$($del_GPO_Modify_ACL.split(",")[0])"
    $del_DG_GPOGroupModify = "$($del_DomainGlobal)GPO_$($ouOrgName)_$($SvcResTrun)_$($del_GPO_Modify_ACL.split(",")[0])"

    #OU Delegation Group
    try{New-ADGroup $del_DL_OUGroupName –groupscope DomainLocal -Path $adTasksDestination -Description $del_OU_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    try{New-ADGroup $del_DG_OUGroupName –groupscope Global -Path $adTasksDestination -Description $del_OU_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}  
    Add-ADGroupMember $del_DL_OUGroupName $del_DG_OUGroupName

    #Restriced Group 
    try{New-ADGroup $del_DL_RGGroupNameAdmin –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_Admin_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    try{New-ADGroup $del_DG_RGGroupNameAdmin –groupscope Global -Path $adTasksDestination -Description $del_RG_Admin_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    Add-ADGroupMember $del_DL_RGGroupNameAdmin $del_DG_RGGroupNameAdmin 
                
    try{New-ADGroup $del_DL_RGGroupNameUser –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_User_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen} 
    try{New-ADGroup $del_DG_RGGroupNameUser –groupscope Global -Path $adTasksDestination -Description $del_RG_User_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    Add-ADGroupMember $del_DL_RGGroupNameUser $del_DG_RGGroupNameUser          
                
    #GPO Modify
    try{New-ADGroup $del_DL_GPOGroupModify –groupscope DomainLocal -Path $adTasksDestination -Description $del_GPO_Modify_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    try{New-ADGroup $del_DG_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    Add-ADGroupMember $del_DL_GPOGroupModify $del_DG_GPOGroupModify
        
    $delOU_FullOU = $ouSvrResDN
    $groupName = $del_DL_OUGroupName
    $del_GPOGroupModify = $del_DL_GPOGroupModify

    #Function to delegate OU Full Control to a named group
    Delegate_FullControl($delOU_FullOU,$GroupName)  
                              
    #Get New Group Name and SID
    $gt_del_RG_SvcRes_AdminSid=@()
    $del_RG_DL_SvcResUser=@()
    $gpoName = "GPO_$($ouOrgName)_$($ouSvrRes)_Custom"
    $del_RG_DL_SvcResAdmin = Get-ADGroup $del_DL_RGGroupNameAdmin
    $del_RG_DL_SvcResUser = Get-ADGroup $del_DL_RGGroupNameUser
             
    GPO-ServiceResource-URA-ResGps($gpoName,$del_RG_DL_SvcResAdmin,$del_RG_DL_SvcResUser,$ouOrgName,$del_GPOGroupModify)
                           
}


function ADGroup-ServiceRes-DelegationGrp 
{
<#-----------------------------
                    
Create nested groups Domain Global into Domain Local and attach Domain Local to the object
AL AG_Managed Resources_OU_FullCtrl

-----------------------------#> 
#>
    #Function to write out to screen
    [string]$funcName = "ADGroup-ServiceRes-DelegationGrp"
    $funcDescription = "Function to create AD Groups for delegation of Service\Application sub-Ous, Service Accounts, Servers etc"
    $funcComment = "No Comment"
    Funcwriteout($funcname,$funcDescription,$funcComment)

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

    #Truncate Service Resouce - to limit character limit for groups
    $SvcResTrun = "SvcRes"

    if ($ouSrvResOU -eq "Application Groups"){$ouSrvResOU = "AppGrp"}
    if ($ouSrvResOU -eq "Service Accounts"){$ouSrvResOU = "SvcAccts"}

    $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)" 
    $adRoleDestination = "OU=AD Roles,$($ouMgmtResDN)" 

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

    #Group Descriptions
    #$del_Description = "Members of this group have $($groupSub.split(",")[1])"

    #Local and Global
    $del_DomainLocal = "AL_"
    $del_DomainGlobal = "AG_"
    $del_DomainLocalRole = "RL_"
    $del_DomainGlobalRole = "RG_"

    #Role up for Service
    $del_DL_SvcRoleGroup = "$($del_DomainLocalRole)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_AdminRole"
    $del_DG_SvcRoleGroup = "$($del_DomainGlobalRole)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_AdminRole"

    $del_GP_Role_Description = "Members of this group have delegated permissions to manage $($ouCompItem)"

    try{New-ADGroup $del_DL_SvcRoleGroup –groupscope DomainLocal -Path $adRoleDestination -Description $del_GP_Role_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    try{New-ADGroup $del_DG_SvcRoleGroup –groupscope Global -Path $adRoleDestination -Description $del_GP_Role_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    
    Add-ADGroupMember $del_DL_SvcRoleGroup $del_DG_SvcRoleGroup

    #OU Delegation Group
    $del_DL_SrvOUGroup = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($groupSub.split(",")[0])"
    $del_DG_SrvOUGroup = "$($del_DomainGlobal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($groupSub.split(",")[0])"

    try{New-ADGroup $del_DL_SrvOUGroup –groupscope DomainLocal -Path $adTasksDestination -Description $del_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    try{New-ADGroup $del_DG_SrvOUGroup –groupscope Global -Path $adTasksDestination -Description $del_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
    
    Add-ADGroupMember $del_DL_SrvOUGroup $del_DG_SrvOUGroup
    Add-ADGroupMember $del_DL_SvcRoleGroup $del_DG_SrvOUGroup
  
    #Create Delegation Groups
    $GroupName = $del_DL_SrvOUGroup 
    $delOU_FullOU = $ouSrvResServiceDN

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
        Delegate_User($GroupName,$delOU_FullOU)   
    }
    elseif ($ouSrvResObj -eq "computer")
    {
        Delegate_Computer($GroupName,$delOU_FullOU)   
    

        #Restriced Group 
        $del_DL_RGGroupNameAdmin = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_Admin.split(",")[0])"
        $del_DG_RGGroupNameAdmin = "$($del_DomainGlobal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_Admin.split(",")[0])"

        $del_DL_RGGroupNameUser = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_User.split(",")[0])"
        $del_DG_RGGroupNameUser = "$($del_DomainGlobal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_User.split(",")[0])"

        #GPO Modify
        $del_DL_GPOGroupModify = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_GPO_Modify_ACL.split(",")[0])"
        $del_DG_GPOGroupModify = "$($del_DomainGlobal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_GPO_Modify_ACL.split(",")[0])"
   
        #Restriced Group 
        try{New-ADGroup $del_DL_RGGroupNameAdmin –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_Admin_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
        try{New-ADGroup $del_DG_RGGroupNameAdmin –groupscope Global -Path $adTasksDestination -Description $del_RG_Admin_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
        Add-ADGroupMember $del_DL_RGGroupNameAdmin $del_DG_RGGroupNameAdmin
        Add-ADGroupMember $del_DL_SvcRoleGroup $del_DG_RGGroupNameAdmin

        try{New-ADGroup $del_DL_RGGroupNameUser –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_User_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
        try{New-ADGroup $del_DG_RGGroupNameUser –groupscope Global -Path $adTasksDestination -Description $del_RG_User_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
        Add-ADGroupMember $del_DL_RGGroupNameUser $del_DG_RGGroupNameUser
        #Add-ADGroupMember $del_DL_SvcRoleGroup $del_DL_RGGroupNameUser
                
        #GPO Modify
        try{New-ADGroup $del_DL_GPOGroupModify –groupscope DomainLocal -Path $adTasksDestination -Description $del_GPO_Modify_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
        try{New-ADGroup $del_DG_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description}catch{Write-Host "Group exists" -ForegroundColor DarkGreen}
        Add-ADGroupMember $del_DL_GPOGroupModify $del_DG_GPOGroupModify
        Add-ADGroupMember $del_DL_SvcRoleGroup $del_DG_GPOGroupModify

        $gpoName = "GPO_$($ouOrgName)_$($ouSvrRes)_$($ouCompItem)_$($ouSrvResOU)_Custom"

        $del_RG_DL_ServerAdmin = Get-ADGroup $del_DL_RGGroupNameAdmin
        $del_RG_DL_ServerUser = Get-ADGroup $del_DL_RGGroupNameUser

        GPO-ServerOU-URA-ResGps($gpoName,$ouSrvResServiceDN,$ouSrvResOU,$del_RG_DL_ServerAdmin, $del_RG_DL_ServerUser,$del_DL_GPOGroupModify) 
        
    }       
}




<#-----------------------------

FUNCTIONS - Update User Rights Assignments and Restricted Groups

-----------------------------#>

Function GPO-ServiceResource-URA-ResGps
{
<#-----------------------------

OU=AD Tasks,OU=Service Resources,OU=Org3,DC=testdom,DC=loc
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

        $getOUMS = Get-ADOrganizationalUnit -Filter * | where {$_.DistinguishedName -eq $ouSvrResDN} 
        #New GPO based on the service and linked to OU
        New-GPO -Name $GPOName | New-GPLink -Target $getOUMS.DistinguishedName

        $getGpoId = (Get-GPO $GPOName).id
        $getGPOPath = (Get-GPO $GPOName).path
        $del_GPO_Edit_Acl
        Set-GPPermission -Guid $getGpoId -PermissionLevel GpoEditDeleteModifySecurity -TargetType Group -TargetName $del_GPOGroupModify

        $sysvol = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\Machine\Microsoft\Windows NT\SecEdit"
        $gpt = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\GPT.ini"
        Set-content $gpt -Value "[General]"
        Add-Content $gpt -Value "Version=1" 

        New-Item -Path $sysvol -ItemType Directory -Force
        New-Item -Path $sysvol -Name GptTmpl.inf -ItemType File -Force

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

        #Set GPMC Machine Extensions so Manual Intervention is both displayed in GPO Management and applies to target 
        Set-ADObject -Identity $getGPOPath -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"}
        Set-ADObject -Identity $getGPOPath -Replace @{versionNumber="1"}
}

Function GPO-ServerOU-URA-ResGps
{
<#-----------------------------

OU=AD Tasks,OU=Service Resources,OU=Org3,DC=testdom,DC=loc
AL_OU_ORG1_SvcRes_SCCM_URA_GroupMgmt

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
    $del_DL_RG_SvcRes_Admin = "$($del_DomainLocal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_Admin.split(",")[0])"
    $del_DL_RG_SvcRes_User = "$($del_DomainLocal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_User.split(",")[0])"

    #Service Resource
    $gt_RG_DL_SvcRes_Admin = Get-ADGroup $del_DL_RG_SvcRes_Admin
    $gt_RG_DL_SvcRes_User = Get-ADGroup $del_DL_RG_SvcRes_User

    $gt_del_RG_SvcRes_AdminSid = $gt_RG_DL_SvcRes_Admin.SID.Value
    $gt_del_RG_SvcRes_UserSid = $gt_RG_DL_SvcRes_User.SID.Value

    #Server Admin
    $gt_del_RG_Svc_SrvAdminSid = $del_RG_DL_ServerAdmin.SID.Value
    $gt_del_RG_Svc_SrvUserSid = $del_RG_DL_ServerUser.SID.Value

    <#-----------------------------

    Create Member Server top level GPO and set Restricted Groups and URA

    -----------------------------#>
    $gtGPO=@()
    $gtGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

        $getOUMS = Get-ADOrganizationalUnit -Filter * | where {$_.DistinguishedName -eq $ouSrvResServiceDN} 
        #New GPO based on the service and linked to OU
        New-GPO -Name $GPOName | New-GPLink -Target $getOUMS.DistinguishedName

        $getGpoId = (Get-GPO $GPOName).id
        $getGPOPath = (Get-GPO $GPOName).path
        Set-GPPermission -Guid $getGpoId -PermissionLevel GpoEditDeleteModifySecurity -TargetType Group -TargetName $del_DL_GPOGroupModify

        $sysvol = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\Machine\Microsoft\Windows NT\SecEdit"
        $gpt = "$($smbSysvol)\domain\Policies\{$($getGpoId)}\GPT.ini"
        Set-content $gpt -Value "[General]"
        Add-Content $gpt -Value "Version=1" 

        New-Item -Path $sysvol -ItemType Directory -Force
        New-Item -Path $sysvol -Name GptTmpl.inf -ItemType File -Force

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

        #Set GPMC Machine Extensions so Manual Intervention is both displayed in GPO Management and applies to target 
        Set-ADObject -Identity $getGPOPath -Replace @{gPCMachineExtensionNames="[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"}
        Set-ADObject -Identity $getGPOPath -Replace @{versionNumber="1"}

}

<#-----------------------------

Declare Domain variables

-----------------------------#>
    #Root of the domain
    $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

    #Path to Sysvol
    $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

<#-----------------------------

Import JSON for OU configuration

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

    $gtOUs = $gtDCPromoJ.OU

    foreach ($ou in $gtOUs.PSObject.Properties.value)
    {
        if ($ou.type -match "")
        {
            #Parent DN to build structure
            $ouParent = $ou.Path

            #Name of Organisation OU
            $ouOrgName = $ou.Name

            #Type of structure either Server\Service or Client\User
            $ouType = $ou.Type

            #Protect OUs from deletion
            $ouProtect = [system.convert]::ToBoolean($ou.Protect)

            #Define Name of Management OU Managed Resource (Delegation, URA, Roles) and Service Resources (Named Application\Services OU - SCCM, Exchange, File and Print)
            $ouMgmtRoot = $ou.ManagementOU

            #Managed Resource sub-OUs for ADRoles, ADTasks, URA and AdminAccounts
            $ouMgmtRes = $ou.ManagedResources

            #Define Servers or Client or Server and Object Type of Computer
            $ouComp = $ou.computers

            #Defines Application\Services OUs and Object type eg Servers = Computer, ApplicationGroup = Groups
            $ouSrvRes = $ou.ServersResources

<#-----------------------------

Create Organisation OU Top Level

-----------------------------#>
            $gtOUName=@()
            $gtouOrgNameDN=@()

            $ouOrgNameDN = "OU=$($ouOrgName),$($rootDSE)"
            $gtOUName = try {Get-ADOrganizationalUnit -filter * | where {$_.DistinguishedName -eq $ouOrgNameDN}} catch {}
            CreateOU-OrgRoot($ouOrgName,$ouProtect)

<#-----------------------------

Managed Resources
    Separate Managed Resouces and Service Resources to reduce complexity and dependancy hell

-----------------------------#>
                $ouMgmtRtItems = $ouMgmtRoot.split(",")
                #Create Management OU's Managed Resources
                foreach ($ouMgmdRes in $ouMgmtRtItems[0])
                {
                    #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                    $ouMgmtResDN=@()
                    $gtouMgmtResDN=@()
                    
                    $ouMgmtResDN = "OU=$($ouMgmdRes),$($ouOrgNameDN)"
                    $gtouMgmtResDN = try {Get-ADOrganizationalUnit $ouMgmtResDN -ErrorAction SilentlyContinue} catch {}
                    CreateOU-MgmtRes($ouMgmdRes,$ouOrgNameDN,$ouProtect)  

                    #select the Managed Resources to create sub-OUs
                    $ouMgmdResDN = "OU=$($ouMgmdRes),$($ouOrgNameDN)"
                    $ouMgtRtManResDN = "$($ouMgmdResDN),$($ouMgmdResDN)"    
                        foreach ($ouMgmtResItem in $ouMgmtRes)
                        {
                            $ouMgmtResOU = $ouMgmtResItem.split(",")[0]
                            $ouMgmtResObj = $ouMgmtResItem.split(",")[1]
                    
                            #Creates OU for the Management of Server Resouces
                            $ouMgmtResOuDN=@()
                            $gtouMgmtResOuDN=@()
                    
                            $ouMgmtResOuDN = "OU=$($ouMgmtResOU),$($ouMgmdResDN)"
                            $gtouMgmtResOuDN = try {Get-ADOrganizationalUnit $ouMgmtResOUDN -ErrorAction SilentlyContinue} catch {}
                            CreateOU-MgmtResMgmt($ouMgmtResOU,$ouMgmtResDN,$ouProtect)
                        }
                    
                    #Function Create Grouos for Managed Resources OU
                    $ManSrvChoice = "Managed"
                    ADGroup-ManagedResources($ManSrvChoice,$ouSvrResDN,$ouOrgName)  
                }
<#-----------------------------

Service Resources
    Separate Managed Resouces and Service Resources to reduce complexity and dependancy hell

-----------------------------#>
                #Create Management OU's Service Resources
                foreach ($ouSvrRes in $ouMgmtRtItems[1])
                {
                    #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                    $ouSvrResDN=@()
                    $gtouSvrResDN=@()
                
                    $ouSvrResDN = "OU=$($ouSvrRes),$($ouOrgNameDN)"
                    $gtouSvrResDN = try {Get-ADOrganizationalUnit $ouSvrResDN -ErrorAction SilentlyContinue} catch {}
                    
                    #Function
                    CreateOU-SrvRes($ouSvrRes,$ouOrgNameDN,$ouProtect,$ouOrgName)    
              
                    #select the Service Resources to create sub-OUs
                    $ouSvrResDN = "OU=$($ouSvrRes),$($ouOrgNameDN)"

                    #Management or Service Resources
                    $ManSrvChoice = "Server"
                    
                    #Function - 
                    ADGroup-ServiceResources($ManSrvChoice,$ouSvrResDN,$ouOrgName) 

                    $ouCompItem=@()

                    $ouCompSplit = $ouComp.split(",")
                    foreach ($ouCompItem in $ouCompSplit)
                    {
                        #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                        $ouSvrCompDN=@()
                        $gtouSvrResMgmtDN=@()
                    
                        $ouSvrCompDN = "OU=$($ouCompItem),$($ouSvrResDN)"
                        $gtouSvrResMgmtDN = try {Get-ADOrganizationalUnit $ouSvrCompDN -ErrorAction SilentlyContinue} catch {}
                        
                        #Function
                        CreateOU-SrvComp($ouCompItem,$ouSvrResDN,$ouProtect,$ouOrgName)

                        #Create management OUs for each Applications or Service
                        #OU=SCCM,OU=Service Resources,OU=not193,DC=testdom,DC=loc 
                        $ouSrvResCompDN = "OU=$($ouCompItem),$($ouSvrResDN)"    
                        foreach ($ouSrvResItem in $ouSrvRes)
                        {                            
                            $ouSrvResOU = $ouSrvResItem.split(",")[0]
                            $ouSrvResObj = $ouSrvResItem.split(",")[1]
                            
                            #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                            $ouSvrResMgmtDN=@()
                            $gtouSvrResMgmtDN=@()

                            $ouSvrResMgmtDN = "OU=$($ouSrvResOU),$($ouSrvResCompDN)"
                            $gtouSvrResMgmtDN = try {Get-ADOrganizationalUnit $ouSvrResMgmtDN -ErrorAction SilentlyContinue} catch {}

                            #Function
                            CreateOU-SvcSubMgmtOU($ouSrvResOU,$ouSrvResCompDN,$ouProtect,$ouSvrResDN,$ouCompItem,$ouOrgName)

                            $ouSrvResServiceDN=@()
                            $ouSrvResServiceDN = "OU=$($ouSrvResOU),$($ouSrvResCompDN)"

                            #Function create Service Management OUs
                            ADGroup-ServiceRes-DelegationGrp($ouSrvResServiceDN,$ouSrvResOU,$ouSrvResObj,$ouMgmtResDN,$ouCompItem,$ouSvrRes,$ouOrgName) 
                        }
                    }
                }
            }
    }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              

<#-----------------------------

Stop Logging

-----------------------------#>

        Stop-Transcript


}



