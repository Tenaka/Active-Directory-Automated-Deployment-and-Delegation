# AD-DCPromo_OUDelegation

This is for rapidly deploying Active Directory and a full OU delegation model based on input from JSON.

Not fully tested and should not be deployed into Live or rerun over the top of a previous deployment.

Overview.
    Deploy multiple Domain Controllers and a new Forest from the JSON file input.
    First DC (PDC) will auto-start, logon and then deploy a delegated OU structure.
    
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
            Deploys the Domain configuration eg OU and delegation.
            Creates tiered OU structure for Member Servers and Clients
            Creates 3 levels of GPO Restricted Groups and User Rights Assignments
            Creates nested AD Groups and delegates OU's as Tasks and Roles
            Imports ADMX files.
            Imports Microsoft SCM Group Policies for Office, Edge, Server, Domain Controller and Clients
            Assign SCM policies against target OU
       
