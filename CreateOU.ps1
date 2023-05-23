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
230322.1 - Inherited and service specific Restricted Groups and URA added to GPO for Servers

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
    write-host "Function Delegate User for $GroupName at $delOU_FullOU" -ForegroundColor Green
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
    write-host "Function Delegate Group for $GroupName at $delOU_FullOU" -ForegroundColor Green   
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
    write-host "Function Delegate Computer for $GroupName at $delOU_FullOU" -ForegroundColor Green
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
    write-host "Function Delegate Service Accounts for $GroupName at $delOU_FullOU" -ForegroundColor Green

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
    write-host "Function Delegate Full Control for $GroupName at $delOU_FullOU" -ForegroundColor Green
   
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
    write-host "Function CreateOU Organisation $ouOrgNameDN" -ForegroundColor Green
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
    
#Create Management Resource level OU
function CreateOU-MgmtRes
{
<#-----------------------------

Create Management Resources

OU=Management Resouces,OU=Org2,DC=testdom,DC=loc

-----------------------------#> 
    write-host "Function CreateOU Management Resouces at $ouOrgNameDN" -ForegroundColor Green   
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

#Creates OU for Managment of the Service Resources
function CreateOU-MgmtResMgmt
{
<#-----------------------------

Start Some Basic Logging

-----------------------------#>
    write-host "Function CreateOU Management Resouces at $ouOrgNameDN" -ForegroundColor Green      
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

#Create Server Resource level OU
function CreateOU-SrvRes
{
<#-----------------------------

Start Some Basic Logging

-----------------------------#>
    #$ouSvrRes = OU to Create
    #$ouOrgNameDN = DN of parent OU
    #$ouProtect = Is protected
    
    #CreateOU-SvcSubMgmtOU($ouSrvResOU,$ouSrvResCompDN,$ouProtect)
    write-host "Function CreateOU Service Resouces at $ouOrgNameDN" -ForegroundColor Green   
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

#Create Server or Application level sub-ou 
function CreateOU-SrvComp
{
<#-----------------------------

Start Some Basic Logging

-----------------------------#>
    write-host "Function CreateOU $ouCompItem at $ouSvrResDN" -ForegroundColor Green
    #$ouSvrRes = OU to Create
    #$ouOrgNameDN = DN of parent OU
    #$ouProtect = Is protected
    
    #CreateOU-SvcSubMgmtOU($ouSrvResOU,$ouSrvResCompDN,$ouProtect)
    
    if ($gtouSvrResMgmtDN.DistinguishedName -ne $ouSvrCompDN)
    {
        try
            {
                New-ADOrganizationalUnit -Name $ouCompItem -Path $ouSvrResDN -ProtectedFromAccidentalDeletion $ouProtect
            }
        catch
            {
                write-host "$ouSvrCompDN  already exists" -ForegroundColor Green
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
write-host "Function CreateOU Service Management $ouSrvResOU at $ouSrvResCompDN" -ForegroundColor Green
if ($gtouSvrResMgmtDN.DistinguishedName -ne $ouSvrResMgmtDN)
        {
    try 
        {
            New-ADOrganizationalUnit -Name $ouSrvResOU -Path $ouSrvResCompDN -ProtectedFromAccidentalDeletion $ouProtect
            Write-Host "new AD OU $ouSrvResOU at $ouSrvResCompDN" -ForegroundColor Yellow
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

function ADGroup-ManagedServerResources 
{
<#-----------------------------

Create nested groups Domain Global into Domain Local and attach Domain Local to the object
AL AG_Managed Resources_OU_FullCtrl

-----------------------------#>                    
    write-host "Function Create ADGroup Managed and Service Groups" -ForegroundColor Green

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
        
        if ($ManSrvChoice -match "Managed")
            {
                $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)"

                #OU Delegation Group
                $del_OUGroupName = "$($del_grp)OU_$($ouOrgName)_$($mgmtResTruc)_$($del_OU_Full_Acl.split(",")[0])"
            }
        elseif ($ManSrvChoice -match "Server")
            {
                $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)" 

                #OU Delegation Group
                $del_OUGroupName = "$($del_grp)OU_$($ouOrgName)_$($SvcResTrun)_$($del_OU_Full_Acl.split(",")[0])"

                #Restriced Group 
                $del_RGGroupNameAdmin = "$($del_grp)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_Admin.split(",")[0])"
                $del_RGGroupNameUser = "$($del_grp)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_User.split(",")[0])"

                #GPO Modify
                $del_GPOGroupModify = "$($del_grp)GPO_$($ouOrgName)_$($SvcResTrun)_$($del_GPO_Modify_ACL.split(",")[0])"
            }
        
        #Create new AD Groups
        if ($del_OUGroupName -like "$del_DomainGlobal*")
            {
                #OU Delegation Group
                New-ADGroup $del_OUGroupName –groupscope Global -Path $adTasksDestination -Description $del_OU_Description  
                
                #Restriced Group 
                New-ADGroup $del_RGGroupNameAdmin –groupscope Global -Path $adTasksDestination -Description $del_RG_Admin_Description
                New-ADGroup $del_RGGroupNameUser –groupscope Global -Path $adTasksDestination -Description $del_RG_User_Description 
                
                #GPO Modify
                New-ADGroup $del_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description

                #Add to array for group nesting
                $new_OUGroupName+="$($del_OUGroupName)"
                $new_RGAdminGroupName+="$($del_RGGroupNameAdmin)"
                $new_RGAUserGroupName+="$($del_RGGroupNameUser)" 
                $new_GPOModGroupName+="$($del_GPOGroupModify)"    
            }
        elseif ($del_OUGroupName -like "$del_DomainLocal*")
            {
                #OU Delegation Group
                New-ADGroup $del_OUGroupName –groupscope DomainLocal -Path $adTasksDestination -Description $del_OU_Description  
                
                #Restriced Group 
                New-ADGroup $del_RGGroupNameAdmin –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_Admin_Description
                New-ADGroup $del_RGGroupNameUser –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_User_Description

                #GPO Modify
                New-ADGroup $del_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description

                #$delOU_FullOU=@()
                #$groupName=@()
                
                if ($del_OUGroupName -match "SvcRes"){$delOU_FullOU = $ouSvrResDN}
                elseif ($del_OUGroupName -match "MgmtRes"){$delOU_FullOU = $ouMgmtResDN}
                $groupName = $del_OUGroupName

                #Function to delegate OU Full Control to a named group
                Delegate_FullControl($delOU_FullOU,$GroupName)  
                              
                #Get New Group Name and SID
                $gpoName = "GPO_$($ouOrgName)_$($ouSvrRes)_Custom"
                $del_RG_DL_SvcResAdmin = Get-ADGroup $del_RGGroupNameAdmin
                $del_RG_DL_SvcResUser = Get-ADGroup $del_RGGroupNameUser
             
                write-host "Function GPO-ServiceResource-URA-ResGps($gpoName,$del_RG_DL_SvcResAdmin,$del_RG_DL_SvcResUser,$ouOrgName,$del_GPOGroupModify) and variables passed" -ForegroundColor Red
                GPO-ServiceResource-URA-ResGps($gpoName,$del_RG_DL_SvcResAdmin,$del_RG_DL_SvcResUser,$ouOrgName,$del_GPOGroupModify)
                
                #Add to array for group nesting
                $new_OUGroupName+="$($del_OUGroupName)"
                $new_RGAdminGroupName+="$($del_RGGroupNameAdmin)"
                $new_RGAUserGroupName+="$($del_RGGroupNameUser)" 
                $new_GPOModGroupName+="$($del_GPOGroupModify)"          
            }                  
    }

    #Nested groups
    try
        {                
            Add-ADGroupMember $new_OUGroupName[0] $new_OUGroupName[1]
            Add-ADGroupMember $new_RGAdminGroupName[0] $new_RGAdminGroupName[1]
            Add-ADGroupMember $new_RGAUserGroupName[0] $new_RGAUserGroupName[1]
            Add-ADGroupMember $new_GPOModGroupName[0] $new_GPOModGroupName[1]
        }
    catch
        {
            Add-ADGroupMember $new_OUGroupName[1] $new_OUGroupName[0]
            Add-ADGroupMember $new_RGAdminGroupName[1] $new_RGAdminGroupName[0]
            Add-ADGroupMember $new_RGAUserGroupName[1] $new_RGAUserGroupName[0]
            Add-ADGroupMember $new_GPOModGroupName[1] $new_GPOModGroupName[0]
        }
}

function ADGroup-ServiceRes-DelegationGrp 
{
<#-----------------------------

                    
Create nested groups Domain Global into Domain Local and attach Domain Local to the object
AL AG_Managed Resources_OU_FullCtrl

-----------------------------#> 
#>
    write-host "Function Create ADGroup Delegation Groups" -ForegroundColor Green

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

    #Truncate Service Resouce
    $SvcResTrun = "SvcRes"

    if ($ouSrvResOU -eq "Application Groups"){$ouSrvResOU = "AppGrp"}
    if ($ouSrvResOU -eq "Service Accounts"){$ouSrvResOU = "SvcAccts"}

    $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)" 

    if ($ouSrvResObj -eq "Group")
    {$groupSub = $del_OU_Group_Acl}


    if ($ouSrvResObj -eq "User")
    {$groupSub = $del_OU_User_Acl}


    if ($ouSrvResObj -eq "Computer")
    {$groupSub = $del_OU_Computer_Acl}

    if ($ouSrvResObj -eq "SvcAccts")
    {$groupSub = $del_OU_Service_Acl}    

    #Group Descriptions
    $del_Description = "Members of this group have $($groupSub.split(",")[1])"

    #Local and Global
    $del_DomainLocal = "AL_"
    $del_DomainGlobal = "AG_"

    #OU Delegation Group
    $del_DL_SrvOUGroup = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($groupSub.split(",")[0])"
    $del_DG_SrvOUGroup = "$($del_DomainGlobal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($groupSub.split(",")[0])"

    New-ADGroup $del_DL_SrvOUGroup –groupscope DomainLocal -Path $adTasksDestination -Description $del_Description
    New-ADGroup $del_DG_SrvOUGroup –groupscope Global -Path $adTasksDestination -Description $del_Description
    
    Add-ADGroupMember $del_DL_SrvOUGroup $del_DG_SrvOUGroup

    $GroupName = $del_DL_SrvOUGroup 
    $delOU_FullOU = $ouSrvResServiceDN

    Write-Host "$adTasksDestination - Server Management groups" -ForegroundColor DarkYellow
    Write-Host "$del_DL_SrvOUGroup - new group" -ForegroundColor Yellow
    Write-Host "$del_DG_SrvOUGroup - new group" -ForegroundColor Yellow
    Write-Host " "

    #Delegate group to OU with acls required
    if ($ouSrvResObj -eq "Group")
    {
        Delegate_Group($GroupName,$delOU_FullOU)   
    }
    elseif ($ouSrvResObj -eq "User")
    {
        Delegate_User($GroupName,$delOU_FullOU)   
    }
    elseif ($ouSrvResObj -eq "computer")
    {
        Delegate_Computer($GroupName,$delOU_FullOU)   

        Write-Host "Delegation_SvcAccts($GroupName,$delOU_FullOU)" -ForegroundColor Red
        Delegation_SvcAccts($GroupName,$delOU_FullOU)  
        #pause

        #Restriced Group 
        $del_DL_RGGroupNameAdmin = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_Admin.split(",")[0])"
        $del_DG_RGGroupNameAdmin = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_Admin.split(",")[0])"

        $del_DL_RGGroupNameUser = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_User.split(",")[0])"
        $del_DG_RGGroupNameUser = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_ResGrp_User.split(",")[0])"

        #GPO Modify
        $del_DL_GPOGroupModify = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_GPO_Modify_ACL.split(",")[0])"
        $del_DG_GPOGroupModify = "$($del_DomainLocal)OU_$($ouOrgName)_$($SvcResTrun)_$($ouCompItem)_$($ouSrvResOU)_$($del_GPO_Modify_ACL.split(",")[0])"
        

        #Restriced Group 
        New-ADGroup $del_DL_RGGroupNameAdmin –groupscope Global -Path $adTasksDestination -Description $del_RG_Admin_Description
        New-ADGroup $del_DG_RGGroupNameAdmin –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_Admin_Description
        
        New-ADGroup $del_DL_RGGroupNameUser –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_User_Description
        New-ADGroup $del_DG_RGGroupNameUser –groupscope Global -Path $adTasksDestination -Description $del_RG_User_Description 
                
        #GPO Modify
        New-ADGroup $del_DL_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description
        New-ADGroup $del_DG_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description

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
    write-host "Function GPO Restricted Group for Services at $GPOName" -ForegroundColor Green
    #Root of the domain
    $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

    #Path to Sysvol
    $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

    #Get New Group Name and SID
    $gt_del_RG_SvcRes_AdminSid = $del_RG_DL_SvcResAdmin.SID.Value
    $gt_del_RG_SvcRes_UserSid = $del_RG_DL_SvcResUser.SID.Value

    <#-----------------------------

    Create Member Server top level GPO and set Restricted Groups and URA

    -----------------------------#>
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
    write-host "Function GPO Restricted Group for Services at $GPOName" -ForegroundColor Green
    #Root of the domain
    $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

    #Path to Sysvol
    $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

    #Get New Group Name and SID = Org
    $del_DomainLocal = "AL_"
    $del_DomainGlobal = "AG_"
    $del_DL_RG_SvcRes_Admin = "$($del_DomainLocal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_Admin.split(",")[0])"
    $del_DL_RG_SvcRes_User = "$($del_DomainLocal)RG_$($ouOrgName)_$($SvcResTrun)_$($del_ResGrp_User.split(",")[0])"

    Write-host $del_RGGroupNameAdmin -ForegroundColor Magenta

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
    $getOUMS = Get-ADOrganizationalUnit -Filter * | where {$_.DistinguishedName -eq $ouSrvResServiceDN} 
    #New GPO based on the service and linked to OU
    New-GPO -Name $GPOName | New-GPLink -Target $getOUMS.DistinguishedName

    $getGpoId = (Get-GPO $GPOName).id
    $getGPOPath = (Get-GPO $GPOName).path
    $del_GPO_Edit_Acl
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

            write-host $ouOrgName
            write-host $ouParent
            write-host $ouType
            write-host $ouMgmtRoot
            write-host $ouMgmtRes
            write-host $ouComp
            write-host $ouSrvRes

<#-----------------------------

Create Organisation OU Top Level

-----------------------------#>
            $gtOUName=@()
            $gtouOrgNameDN=@()

            $ouOrgNameDN = "OU=$($ouOrgName),$($rootDSE)"
            $gtOUName = try {Get-ADOrganizationalUnit -filter * | where {$_.DistinguishedName -eq $ouOrgNameDN}} catch {}
            CreateOU-OrgRoot($ouOrgName,$ouProtect)
            write-host "Function CreateOU-OrgRoot($ouOrgName,$ouProtect) with variables passed" -ForegroundColor Green

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
                    ADGroup-ManagedServerResources($ManSrvChoice,$ouSvrResDN)  

                }
<#-----------------------------

Service Resources
    Separate Managed Resouces and Service Resources to reduce complexity and dependancy hell

-----------------------------#>
                #Create Management OU's Managed Resources
                foreach ($ouSvrRes in $ouMgmtRtItems[1])
                {
                    #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                    $ouSvrResDN=@()
                    $gtouSvrResDN=@()
                
                    $ouSvrResDN = "OU=$($ouSvrRes),$($ouOrgNameDN)"
                    $gtouSvrResDN = try {Get-ADOrganizationalUnit $ouSvrResDN -ErrorAction SilentlyContinue} catch {}
                    
                    Write-Host "Create Service Management OU - ura servers" -ForegroundColor Cyan
                    Write-Host "$ouSvrResDN" -ForegroundColor Green

                    #Function - 
                    CreateOU-SrvRes($ouSvrRes,$ouOrgNameDN,$ouProtect)    
              
                    #select the Service Resources to create sub-OUs
                    $ouSvrResDN = "OU=$($ouSvrRes),$($ouOrgNameDN)"

                    #Management or Service Resources
                    $ManSrvChoice = "Server"
                    
                    #Function - 
                    ADGroup-ManagedServerResources($ManSrvChoice,$ouSvrResDN) 

                    $ouCompItem=@()

                    $ouCompSplit = $ouComp.split(",")
                    foreach ($ouCompItem in $ouCompSplit)
                    {
                        Write-Host "$ouCompItem" -ForegroundColor Green
                        #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                        $ouSvrCompDN=@()
                        $gtouSvrResMgmtDN=@()
                    
                        $ouSvrCompDN = "OU=$($ouCompItem),$($ouSvrResDN)"
                        $gtouSvrResMgmtDN = try {Get-ADOrganizationalUnit $ouSvrCompDN -ErrorAction SilentlyContinue} catch {}
                        
                        Write-Host "$ouSvrCompDN" -ForegroundColor Magenta

                        #Function
                        CreateOU-SrvComp($ouCompItem,$ouSvrResDN,$ouProtect)

                        Write-Host "function CreateOU-SrvCompy $ouCompItem"

                        #Create management OUs for each Applications or Service
                        #OU=SCCM,OU=Service Resources,OU=not193,DC=testdom,DC=loc 
                        $ouSrvResCompDN = "OU=$($ouCompItem),$($ouSvrResDN)"    
                        foreach ($ouSrvResItem in $ouSrvRes)
                        {                            
                            $ouSrvResOU = $ouSrvResItem.split(",")[0]
                            $ouSrvResObj = $ouSrvResItem.split(",")[1]

                            Write-Host "$ouSrvResItem" -ForegroundColor Gray
                            Write-Host "$ouSrvResOU" -ForegroundColor Green
                            Write-Host "$ouSrvResObj" -ForegroundColor Green
                            
                            #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                            $ouSvrResMgmtDN=@()
                            $gtouSvrResMgmtDN=@()

                            $ouSvrResMgmtDN = "OU=$($ouSrvResOU),$($ouSrvResCompDN)"
                            $gtouSvrResMgmtDN = try {Get-ADOrganizationalUnit $ouSvrResMgmtDN -ErrorAction SilentlyContinue} catch {}
                            
                            Write-Host "$ouSvrResMgmtDN" -ForegroundColor Magenta

                            #Function
                            CreateOU-SvcSubMgmtOU($ouSrvResOU,$ouSrvResCompDN,$ouProtect,$ouSvrResDN,$ouCompItem)

                            write-host "Function CreateOU-SvcSubMgmtOU($ouSrvResOU,$ouSrvResCompDN,$ouProtect,$ouSvrResDN,$ouCompItem) with variables passed" -ForegroundColor Green
                            
                            $ouSrvResServiceDN=@()
                            $ouSrvResServiceDN = "OU=$($ouSrvResOU),$($ouSrvResCompDN)"

                            #Function create Service Management OUs
                            ADGroup-ServiceRes-DelegationGrp($ouSrvResServiceDN,$ouSrvResOU,$ouSrvResObj,$ouMgmtResDN,$ouCompItem,$ouSvrRes) 

                            write-host "Function ADGroup-ServiceRes-DelegationGrp($ouSrvResServiceDN,$ouSrvResOU,$ouSrvResObj,$ouMgmtResDN,$ouCompItem) with variables passed" -ForegroundColor Green                            

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



