<#
.SYNOPSIS
    Retrieves or removes the GroupTag value from Windows Autopilot device identities 
    and updates the local registry accordingly.

.DESCRIPTION
    This script authenticates against Microsoft Graph using an application ID and secret,
    retrieves the GroupTag for the current Autopilot device, and writes it to the registry.
    If the -Remove switch is specified, it removes the GroupTag from the registry.

.PARAMETER TenantID
    The Azure AD tenant ID (GUID) for authentication.

.PARAMETER ApplicationID
    The Azure AD application (client) ID used for authentication.

.PARAMETER AppSecret
    The client secret associated with the application ID.

.PARAMETER CompanyName
    The company name used to create the registry path (HKLM:\SOFTWARE\<CompanyName>).

.PARAMETER Remove
    Switch to remove the GroupTag from the registry instead of adding it.

.EXAMPLE
    .\Set-APGroupTag.ps1  

.EXAMPLE
    .\Set-APGroupTag.ps1-TenantID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                       -ApplicationID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                       -AppSecret "your-secret" `
                       -CompanyName "Contoso"

.EXAMPLE
    .\Set-APGroupTag.ps1 -Remove

.NOTES
    Author: Victor Storsjö
    Version: 1.0
    Requires: PowerShell 5.1 or later, Internet connectivity, Microsoft Graph API permissions

    Requires script to run in x64 powershell since geting values from the registry.
    Example in intune installation string:
    %WINDIR%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass .\Set-APGroupTag.ps1
#>


param (
    
    [string]$TenantID = "<Your-Tenant-ID-GUID>",

    [string]$ApplicationID = "<Your-Application-ID-GUID>",

    [string]$AppSecret = "<Your-Application-Secret>",

    [string]$CompanyName = 'VSTRJ',

    [switch]$Remove
)

#region Functions
Function Get-MSGraphAuthToken {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $true)]
        [pscredential]$Credential,
        [parameter(Mandatory = $true)]
        [string]$tenantID
    )
    
    #Get token
    $AuthUri = "https://login.microsoftonline.com/$TenantID/oauth2/token"
    $Resource = 'graph.microsoft.com'
    $AuthBody = "grant_type=client_credentials&client_id=$($credential.UserName)&client_secret=$($credential.GetNetworkCredential().Password)&resource=https%3A%2F%2F$Resource%2F"
 
    $Response = Invoke-RestMethod -Method Post -Uri $AuthUri -Body $AuthBody
    If ($Response.access_token) {
        return $Response.access_token
    }
    Else {
        Throw "Authentication failed"
    }
}
#endregion Functions

#region Script
$registryPath = "HKLM:\SOFTWARE\$CompanyName"
$registryKey = "GroupTag"

if (!$Remove) {
    # Normal execution path
    $PolicyJsonCache = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache -Name "PolicyJsonCache").PolicyJsonCache | ConvertFrom-Json
    $ZtdID = $PolicyJsonCache.ZtdRegistrationId 

    $Credential = New-Object System.Management.Automation.PSCredential($ApplicationID, (ConvertTo-SecureString $AppSecret -AsPlainText -Force))
    $Token = Get-MSGraphAuthToken -credential $Credential -TenantID $TenantID


    $ResourceURL = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$ZtdID"
    $managedDevices = Invoke-RestMethod -Headers @{"Authorization" = "$token" } -Method GET -Uri "$ResourceURL"

    $GroupTag = $managedDevices.groupTag 
    $registryValue = $GroupTag

    if (-not (Test-Path $registryPath)) {
        try {
            New-Item -Path $registryPath -Force -ErrorAction Stop
        }
        Catch {
            Write-Host "Could not create $registryPath  Error $_"
            Exit 1
        } 
    }
    try {
        Set-ItemProperty -Path $registryPath -Name $registryKey -Value $registryValue -ErrorAction Stop
    }
    Catch {
        Write-Host "Could not create $registryKey under $registryPath  $_"
        Exit 1
    }
}

#Remove Grouptag
else {
    if (Test-Path "$registryPath") {
        try {
            $existingValue = Get-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction SilentlyContinue
            if ($null -ne $existingValue) {
                Remove-ItemProperty -Path $registryPath -Name $registryKey -ErrorAction Stop
                Write-Host "Removed Grouptag from Registry"
                Exit 0
            }
            else {
                Write-Host "Grouptag was not found. Nothing to remove"
                Exit 0
            }
        }
        catch {
            Write-Host "Failed to remove registry value: $_"
            Exit 1
        }
    }
    else {
        Write-Host "Company reg Key was not found. Nothing to remove"
        Exit 0
    }
}

#endregion Script
