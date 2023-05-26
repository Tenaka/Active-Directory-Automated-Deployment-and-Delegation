# AD-DCPromo_OUDelegation

This is for rapidly deploying Active Directory and a full OU delegation model based on input from JSON.


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
            Deploys the Domain configutation eg OU and delgation based on:
            https://github.com/Tenaka/AD-Delegation
           
       
