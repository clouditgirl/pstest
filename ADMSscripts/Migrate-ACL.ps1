<#
.SYNOPSIS
This script is intended to support a specific Windows 10 migration

.DESCRIPTION
The script will grant the specified user full control to the target profile and 

.EXAMPLE
.\Migrate-ACL.ps1 -UserName Bob.Smith -Domain Contoso -Registry -Verbose

This command will add Full Control Permissions to target user's profile and registry hive.  Includes verbose output

.NOTES

.LINK

.PARAMETER UserName
Specify SamAccountName of target user account

.PARAMETER Domain
Specify NETBIOS name of target user domain

.PARAMETER LogFolder
Optionally specify the path for log output.  Defaults to script directory

.PARAMETER Switch
Will allow the script to target user registry hive permission changes

#>


Param
(
    [cmdletbinding()]

    [Parameter(Mandatory=$True)]
    [String]$UserName,
 
    [Parameter(Mandatory=$True)]
    [String]$Domain,

    [Parameter(Mandatory=$False)]
    [String]$LogFolder = (Split-Path $script:MyInvocation.MyCommand.Path),

    [Parameter(Mandatory=$False)]
    [Switch]$Registry

)

Function Get-UserSID{

    Param
    (
        [Parameter(Mandatory=$True)]
        [String]$UserName,
 
        [Parameter(Mandatory=$True)]
        [String]$Domain
    )

    $User = New-Object System.Security.Principal.NTAccount($Domain, $Username)
    
    try
    {
        $SID = $User.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch 
    {
        $_.Exception
    }
        
    Return $SID.Value

}

Function New-LogEntry {

	Param(
	[Parameter(Mandatory=$True)]
	[string]$Message,
	
	[Parameter(Mandatory=$True)]
	[string]$Status

	)

    Switch($Status){
        1 {$Status = "[INFO]    "}
        2 {$Status = "[WARNING] "}
        3 {$Status = "[ERROR]   "}
    }
    
    $LogDate = Get-Date -Format MM-dd-yyyy
	$LogTime = Get-Date -Format HH:mm:ss.fff
	$LogEntry = "$Status <$LogDate $LogTime> $message"
	Add-Content -Path "$LogFolder\$LogFile" -Value $LogEntry
	Write-verbose $LogEntry
}

$error.Clear()
#Configure Logging
$logfile = "Migrate-ACLs_" + $(Get-Date -format MM-dd-yyyy) + "_" + $(Get-Date -Format HHmm) + ".log"
$Transcript = "Migrate-ACLs_Transcript_" + $(Get-Date -format MM-dd-yyyy) + "_" + $(Get-Date -Format HHmm) + ".log"
Start-Transcript -Path "$LogFolder\$Transcript"
New-LogEntry -Message "Starting $($script:MyInvocation.MyCommand.name) " -Status 1

#region RegistryUpdate
If($Registry){
    New-LogEntry -Message "Begin Registry ACL update" -Status 1
    New-PSDrive -name HKU -PSProvider Registry -Scope Global -Root HKEY_USERS
    $SIDValue = Get-UserSID -UserName $UserName -Domain $Domain

    #Registry Paths to update
    $Hives = @()
    $Hives = @("HKU:\$SIDValue","HKU:\$($SIDValue)_classes","HKU:\$($SIDValue)_classes\Local Settings","HKU:\$($SIDValue)_classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SIDValue")

    #Update registry ACLs
    $RegACL = $Hives |Get-ACL
    $Rule = New-Object Security.AccessControl.RegistryAccessRule($UserName,"FullControl","Allow")
    $RegACL.AddAccessRule($Rule)
    $RegACL | Set-ACL

    $Error.exception | %{New-LogEntry -Message $_.message -Status 3}
    $Error.Clear()

}
#endregion RegistryUpdate

#region Profile
New-LogEntry -Message "Begin Profile ACL update" -Status 1

#Build ACE
$FileSystemRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None 
$AccessControlType =[System.Security.AccessControl.AccessControlType]::Allow
$ACE = New-Object System.Security.AccessControl.FileSystemAccessRule($UserName, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType) 

#Root Profile Path
$RootACL = Get-ACL -Path C:\Users\$Username
$RootACL.AddAccessRule($ACE)
$RootACL | Set-ACL

#Profile Subdirectories
$Profile = Get-ChildItem -Path C:\Users\$Username -Recurse -Force| ? FullName -NotLike "*Microsoft.Windows.Cortana*" 
$Error.exception | %{New-LogEntry -Message $_.message -Status 3}
$Error.Clear()

$ProfileACL = $Profile | Get-ACL

#Apply ACE
$ProfileACL.AddAccessRule($ACE)
$ProfileACL | Set-ACL
#endregion ProfileUpdate

Stop-Transcript