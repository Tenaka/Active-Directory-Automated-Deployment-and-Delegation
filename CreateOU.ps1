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


    foreach ($del_grp in $del_Group)
        {
        
        if ($ManSrvChoice -match "Managed")
            {
                $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)"

                #OU Delegation Group
                $del_OUGroupName = "$($del_grp)OU_$($ouOrgName)_$($ouMgmdRes)_$($del_OU_Full_Acl.split(",")[0])"
            }
        elseif ($ManSrvChoice -match "Server")
            {
                $adTasksDestination = "OU=AD Tasks,$($ouMgmtResDN)" 

                #OU Delegation Group
                $del_OUGroupName = "$($del_grp)OU_$($ouOrgName)_$($ouSvrRes)_$($del_OU_Full_Acl.split(",")[0])"

                #Restriced Group 
                $del_RGGroupNameAdmin = "$($del_grp)RG_$($ouOrgName)_$($ouSvrRes)_$($del_ResGrp_Admin.split(",")[0])"
                $del_RGGroupNameUser = "$($del_grp)RG_$($ouOrgName)_$($ouSvrRes)_$($del_ResGrp_User.split(",")[0])"

                #GPO Modify
                $del_GPOGroupModify = "$($del_grp)GPO_$($ouOrgName)_$($ouSvrRes)_$($del_GPO_Modify_ACL.split(",")[0])"
            }
        
        #Create new AD Groups
        if ($del_OUGroupName -like "$del_DomainGlobal*")
            {
                #OU Delegation Group
                New-ADGroup -Name $del_OUGroupName –groupscope Global -Path $adTasksDestination -Description $del_OU_Description  
                
                #Restriced Group 
                New-ADGroup -Name $del_RGGroupNameAdmin –groupscope Global -Path $adTasksDestination -Description $del_RG_Admin_Description
                New-ADGroup -Name $del_RGGroupNameUser –groupscope Global -Path $adTasksDestination -Description $del_RG_User_Description 
                
                #GPO Modify
                New-ADGroup -Name $del_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description

                #Add to array for group nesting
                $new_OUGroupName+="$($del_OUGroupName)"
                $new_RGAdminGroupName+="$($del_RGGroupNameAdmin)"
                $new_RGAUserGroupName+="$($del_RGGroupNameUser)" 
                $new_GPOModGroupName+="$($del_GPOGroupModify)"

                      
            }
        elseif ($del_OUGroupName -like "$del_DomainLocal*")
            {
                #OU Delegation Group
                New-ADGroup -Name $del_OUGroupName –groupscope DomainLocal -Path $adTasksDestination -Description $del_OU_Description  
                
                #Restriced Group 
                New-ADGroup -Name $del_RGGroupNameAdmin –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_Admin_Description
                New-ADGroup -Name $del_RGGroupNameUser –groupscope DomainLocal -Path $adTasksDestination -Description $del_RG_User_Description

                #GPO Modify
                New-ADGroup -Name $del_GPOGroupModify –groupscope Global -Path $adTasksDestination -Description $del_GPO_Modify_Description

                $ou=@()
                $groupName=@()

                if ($del_OUGroupName -match "Server Resources"){$ou = $ouSvrResDN}
                elseif ($del_OUGroupName -match "Managed Resources"){$ou = $ouMgmtResDN}
                $groupName = $del_OUGroupName

                #Function to delegate OU Full Control to a named group
                Delegate_FullControl($ou,$GroupName)  
                              
                #Get New Group Name and SID
                $gpoName = "GPO_$($ouOrgName)_$($ouSvrRes)_Custom"
                $getRtRGAdmin = Get-ADGroup $del_RGGroupNameAdmin
                $getRtRGRDP = Get-ADGroup $del_RGGroupNameUser

                GPORestrictedGroups-ServerRes($gpoName,$getRtRGAdmin,$getRtRGRDP,$ouOrgName,$del_GPOGroupModify)

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


Function GPORestrictedGroups-ServerRes
{
    #Root of the domain
    $rootDSE = (Get-ADRootDSE).rootDomainNamingContext

    #Path to Sysvol
    $smbSysVol = ((Get-SmbShare -name "sysvol").path).replace("SYSVOL\sysvol","sysvol")

    #Get New Group Name and SID
    #$getRtRGAdmin = Get-ADGroup $rgRtAdminGp
    #$getRtRGRDP = Get-ADGroup $rgRtRDPGp

    $getRtRGAdminSid = $getRtRGAdmin.SID.Value
    $getRtRGRDPSid = $getRtRGRDP.SID.Value

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
    $addConAdmin = "*S-1-5-32-544__Members = *$($getRtRGAdminSid)"
    #RDP Group Sids for Restricted Groups
    $addConRDP = "*S-1-5-32-555__Members = *$($getRtRGRDPSid)" 

    #User Rights Assignments
    $addConURARemote = "SeRemoteInteractiveLogonRight = *$($getRtRGAdminSid),*$($getRtRGRDPSid)" 

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
                            CreateOU-SrvMgmt($ouSrvResOU,$ouSrvResCompDN,$ouProtect,$ouSvrResDN)
  
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



