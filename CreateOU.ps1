<#-----------------------------
Overview.
    Deploy multiple Domain Controllers and a new Forest from the JSON file input
    
Description.
    This is script 4 of 4

    Basic script to deploy somthing
    The creation of OU's, GPO's and the importing of policies MUST be deployed from the PDC   


Version.
230510.1 - Created 

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

    #Start-Transcript -Path "$($Pwdir)\4_CreateOUs.log" -Append -Force

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

-----------------------------#>

Function Delegate_User
{
    Set-Location AD:

    #delOU_UsrOU = "OU=Resources,DC=tenaka,DC=loc"
    #$delOU_UsrGrp = "TESTGP"
    #Delegate_User(delOU_UsrOU,$delOU_UsrGrp)

    $ouACL = (get-acl -path $OU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $OU

    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $InheritedObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL
}

Function Delegate_Group 
{
    #delOU_GrpOU = "OU=Resources,DC=tenaka,DC=loc"
    #$delOU_GrpGrp = "TESTGP"
    #Delegate_Group(delOU_GrpOU,$delOU_GrpGrp)
    
    Set-Location AD:

    $ouACL = (get-acl -path $OU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $OU

    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $InheritedObjectType = [guid] "bf967a9c-0de6-11d0-a285-00aa003049e2"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967a9c-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967a9c-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType


     $ouACL.AddAccessRule($ACE)
     Set-Acl -Path $OU -AclObject $ouACL


}

Function Delegate_Computer
{
    #delOU_CompOU = "OU=Resources,DC=tenaka,DC=loc"
    #$delOU_CompGrp = "TESTGP"
    #Delegate_Computer(delOU_CompOU,$delOU_CompGrp)
   
    Set-Location AD:

    $ouACL = (get-acl -path $OU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $OU

    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $InheritedObjectType = [guid] "bf967a86-0de6-11d0-a285-00aa003049e2"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967a86-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967a86-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType


     $ouACL.AddAccessRule($ACE)
     Set-Acl -Path $OU -AclObject $ouACL

}

Function Delegation_SvcAccts
{
    #delOU_SvcAccOU = "OU=Resources,DC=tenaka,DC=loc"
    #$delOU_SvcAccGrp = "TESTGP"
    #Delegate_SvcAccts(delOU_SvcAccOU,$delOU_SvcAccGrp)

    Set-Location AD:

    $ouACL = (get-acl -path $OU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $OU

    #Users
    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $InheritedObjectType = [guid] "ce206244-5827-4a86-ba1c-1c0c386c1b64"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "ce206244-5827-4a86-ba1c-1c0c386c1b64"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "ce206244-5827-4a86-ba1c-1c0c386c1b64"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    #ManagedServiceAccount
    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $InheritedObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "bf967aba-0de6-11d0-a285-00aa003049e2"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    #Group Managed Service Accounts
    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $InheritedObjectType = [guid] "7b8b558a-93a5-4af7-adca-c017e67f1057"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "7b8b558a-93a5-4af7-adca-c017e67f1057"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "7b8b558a-93a5-4af7-adca-c017e67f1057"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

}

Function Delegate_FullControl
{
    #delOU_FullOU = "OU=Resources,DC=tenaka,DC=loc"
    #$delOU_FullGrp = "TESTGP"
    #Delegate_FullControl(delOU_FullOU,$delOU_FullGrp)
   
    Set-Location AD:

    $delOU_FullOU = $OU

    $ouACL = (get-acl -path $OU).Access
    $getGp = Get-ADGroup -Identity $GroupName
    $GroupSID = [System.Security.Principal.SecurityIdentifier] $getGp.SID
    $ouACL = Get-Acl -Path $OU

    $gpIndent = [System.Security.Principal.IdentityReference] $GroupSID
    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

    $ActiveDirectoryRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
    $ObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
    $InheritedObjectType = [guid] "00000000-0000-0000-0000-000000000000"
    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $gpIndent, $ActiveDirectoryRights, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType

    $ouACL.AddAccessRule($ACE)
    Set-Acl -Path $OU -AclObject $ouACL

}

<#-----------------------------

Functions for Create OUs

-----------------------------#>
#Create Organisation level OU
function CreateOU-OrgRoot
{
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

#Creates OU for Managment of the Server Resources
function CreateOU-MgmtResMgmt
{
        
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
    #$ouSvrRes = OU to Create
    #$ouOrgNameDN = DN of parent OU
    #$ouProtect = Is protected
    
    #CreateOU-SrvMgmt($ouSrvResOU,$ouSrvResCompDN,$ouProtect)
   
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
        #$ouSvrRes = OU to Create
        #$ouOrgNameDN = DN of parent OU
        #$ouProtect = Is protected
    
        #CreateOU-SrvMgmt($ouSrvResOU,$ouSrvResCompDN,$ouProtect)
    
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

#Create managment ou for each Server or Applicaiton
function CreateOU-SrvMgmt
{
            #$ouSrvResOU = OU to Create
            #$ouSrvResCompDN = DN of parent OU
            #$ouProtect = Is protected
    
            #CreateOU-SrvMgmt($ouSrvResOU,$ouSrvResCompDN,$ouProtect)
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

function ADGroup_ManagedServerResources 
{                    
    #Create nested groups Domain Global into Domain Local and attach Domain Local to the object
    #AL AG_Managed Resources_OU_FullCtrl

    #Group Acl and Description
    $del_OU_Full_Acl = "FullCtrl","Full Control of all OU objects"
    $del_OU_Computer_Acl = "CompMgmt","Manage Computer Objects"
    $del_OU_Group_Acl = "GroupMgmt","Manage Group objects"
    $del_OU_User_Acl = "UserMgmt","Manage User objects"
    $del_OU_Service_Acl = "SvcMgmt","Manage Service Accounts"
    $del_GPO_Edit_Acl = "GPOedit","Edit Group Policy Objects"
    $del_ResGrp_Admin = "ResGrpAdmin","Local Administrative access"
    $del_ResGrp_User = "ResGrpUser","Local User access"

    #Group Descriptions
    $del_OU_Description = "Members of this group have $($del_OU_Full_Acl.split(",")[1])"

    #Local and Global
    $del_DomainLocal = "AL_"
    $del_DomainGlobal = "AG_"
    $del_Group = $del_DomainLocal,$del_DomainGlobal

    #New Group
    $new_GroupName=@()   

    foreach ($del_grp in $del_Group)
        {
        
        if ($ManSrvChoice -match "Managed")
            {
                $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)"

                $del_GroupName = "$($del_grp)OU_$($ouOrgName)_$($ouMgmdRes)_$($del_OU_Full_Acl.split(",")[0])"
            }
        elseif ($ManSrvChoice -match "Server")
            {
                $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)" 

                $del_GroupName = "$($del_grp)OU_$($ouOrgName)_$($ouSvrRes)_$($del_OU_Full_Acl.split(",")[0])"
            }
        
        #Create new AD Groups
        if ($del_GroupName -like "$del_DomainGlobal*")
            {
                New-ADGroup -Name $del_GroupName –groupscope Global -Path $adTasksDestination -Description $del_OU_Description 
                
              #  $ou=@()
              #  $groupName=@()

              #  $ou = $ouMgmtResDN 
              #  $groupName = $del_GroupName
              #  Delegate_FullControl($ou,$GroupName)             
            }
        elseif ($del_GroupName -like "$del_DomainLocal*")
            {
                New-ADGroup -Name $del_GroupName –groupscope DomainLocal -Path $adTasksDestination -Description $del_OU_Description  
                
                #$get_GroupName = Get-ADGroup $del_GroupName
                #$get_GroupName_Sid = $get_GroupName.SID.Value
                $ou=@()
                $groupName=@()

                if ($del_GroupName -match "Server Resources"){$ou = $ouSvrResDN}
                elseif ($del_GroupName -match "Managed Resources"){$ou = $ouMgmtResDN}
                $groupName = $del_GroupName
                Delegate_FullControl($ou,$GroupName)
                
                             
            } 
                        
        $new_GroupName+=$del_GroupName -join ","               
    }

    #Nest groups
    try
        {                
            Add-ADGroupMember $new_GroupName[0] $new_GroupName[1]
        }
    catch
        {
            Add-ADGroupMember $new_GroupName[1] $new_GroupName[0]
        }
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

            #Define Name of Management OU Managed Resource (Delegation, URA, Roles) and Server Resources (Named Application\Services OU - SCCM, Exchange, File and Print)
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

<#-----------------------------

Managed Resources
    Separate Managed Resouces and Server Resources to reduce complexity and dependancy hell

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
                    ADGroup_ManagedServerResources($ManSrvChoice)  

                }
<#-----------------------------

Server Resources
    Separate Managed Resouces and Server Resources to reduce complexity and dependancy hell

-----------------------------#>
                #Create Management OU's Managed Resources
                foreach ($ouSvrRes in $ouMgmtRtItems[1])
                {
                    #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                    $ouSvrResDN=@()
                    $gtouSvrResDN=@()
                    
                    $ouSvrResDN = "OU=$($ouSvrRes),$($ouOrgNameDN)"
                    $gtouSvrResDN = try {Get-ADOrganizationalUnit $ouSvrResDN -ErrorAction SilentlyContinue} catch {}
                    CreateOU-SrvRes($ouSvrRes,$ouOrgNameDN,$ouProtect)    
              
                    #select the Server Resources to create sub-OUs
                    $ouSvrResDN = "OU=$($ouSvrRes),$($ouOrgNameDN)"

                    $ManSrvChoice = "Server"
                    ADGroup_ManagedServerResources($ManSrvChoice) 

                    $ouCompSplit = $ouComp.split(",")
                    foreach ($ouCompItem in $ouCompSplit)
                    {
                        #Function to create managment OU for each Application or Service eg SCCM, SCOM, Exchange
                        $ouSvrCompDN=@()
                        $gtouSvrResMgmtDN=@()
                    
                        $ouSvrCompDN = "OU=$($ouCompItem),$($ouSvrResDN)"
                        $gtouSvrResMgmtDN = try {Get-ADOrganizationalUnit $ouSvrCompDN -ErrorAction SilentlyContinue} catch {}
                        CreateOU-SrvComp($ouCompItem,$ouSvrResDN,$ouProtect)

                        #Create management OUs for each Applications or Service 
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
                            CreateOU-SrvMgmt($ouSrvResOU,$ouSrvResCompDN,$ouProtect)

                            
                        }
                    }
                }
            }
    }


<#-----------------------------

Stop Logging

-----------------------------#>

       # Stop-Transcript -Force


}



