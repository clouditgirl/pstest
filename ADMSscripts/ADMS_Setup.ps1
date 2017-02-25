#Requires -RunAsAdministrator
#Author: Chris Oglesby
#Reviewer: Bob Tucker
#Version: 12c - 11/16/2016

# Define the script parameters
Param
(
    [switch] $Prep_Jump_Box = $false, #use this switch to run the jump box routines
    [switch] $Perform_Analysis = $false, #use this switch to run the analysis routines (MUST RUN FROM THE ANALYSIS SERVER)
    [switch] $TestTarget_Extend_Schema = $false, #use this switch to extend the testtarget.local domain schema for Exchange (MUST RUN FROM THE testtarget.local DOMAIN CONTROLLER)
    [switch] $Test_Domain_Connectivity = $false, #use this switch in combination with the $Domain_To_Test param to probe all domain controllers for connectivity to port 389
    [switch] $Install_VS = $false, #use this switch to install Visual Studio 2015
    [switch] $Install_MIMSync = $false, #use this switch to install MIM Sync
    [string] $Domain_To_Test = "", #use this option in combination with $Test_Domain_Connectivity
    #THE FOLLOWING PARAMS ARE PATHS USED THROUGHOUT THIS SCRIPT. THEY CAN BE PASSED IN AS VARIABLES TO OVERRIDE VALUES AS NEEDED.
    [string] $FIM_Config_XML = "E:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Extensions\FIM-config.xml",
    [string] $FIMConfig_XML = "E:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Extensions\FIMConfig.xml",
    [string] $DomainInfo_File = "E:\ADMS\DomainInfo.csv",
    [string] $SQL_Server = "localhost",
    [string] $Exchange_DL = "https://download.microsoft.com/download/3/9/B/39B8DDA8-509C-4B9E-BCE9-4CD8CDC9A7DA/Exchange2016-x64.exe",
    [string] $VS_DL = "https://download.microsoft.com/download/6/4/7/647EC5B1-68BE-445E-B137-916A0AE51304/vs_enterprise.exe",
    [string] $VS_Local = "F:\Software\VS2015\vs_enterprise.exe",
    [string] $MIM_ExtensionZipFile = "F:\Software\adms-current-build\FIMSQL\Analysis\FIM\Extensions\FIMExtensionsDirectoryFiles.zip",
    [string] $MIM_InstallDir = "E:\Program Files\Microsoft Forefront Identity Manager\2010",
    [string] $MIM_InstallerPath = "F:\software\Msft\Synchronization Service\Synchronization Service\Synchronization Service.msi"
) 

#######################################
###########FUNCTIONS SECTION###########
#######################################


function Update-SQLLogins([string]$loginid, [string]$adms_sa_pwd, [switch]$UsePassword=$false, [switch]$AddToSysadmin=$false)
{
    $ql = "SELECT COUNT(1) AS countOf FROM syslogins WHERE name = '{0}'";
    $qr = "SELECT COUNT(1) AS countOf FROM sys.server_principals p JOIN sys.syslogins s ON p.sid = s.sid WHERE s.sysadmin = 1 AND p.name = '{0}'"
    try
    {
        if ($UsePassword)
        { $x = Invoke-Sqlcmd -Username "$env:COMPUTERNAME\adms_sa" -Password $adms_sa_pwd -Query ($ql -f $loginid) -ServerInstance $SQL_Server; }
        else
        { $x = Invoke-Sqlcmd -Query ($ql -f $loginid) -ServerInstance $SQL_Server; }
        if ($x)
        {
            if ($x.countOf -eq 0) #if we didn't find the login, then create it
            {
                write-host -ForegroundColor Gray ("Creating SQL login for '{0}'..." -f $loginid)
                if ($UsePassword)
                { Invoke-Sqlcmd -Query ("CREATE LOGIN [{0}] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]" -f $loginid) -ServerInstance $SQL_Server -Username "$env:COMPUTERNAME\adms_sa" -Password $adms_sa_pwd; }
                else
                { Invoke-Sqlcmd -Query ("CREATE LOGIN [{0}] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]" -f $loginid) -ServerInstance $SQL_Server; }

                if ($AddToSysadmin)
                {
                    write-host -ForegroundColor Gray ("Adding SQL login '{0}' to 'sysadmin' role..." -f $loginid)
                    if ($UsePassword)
                    { Invoke-Sqlcmd -Query ("ALTER SERVER ROLE [sysadmin] ADD MEMBER [{0}]" -f $loginid) -ServerInstance $SQL_Server -Username "$env:COMPUTERNAME\adms_sa" -Password $adms_sa_pwd; }
                    else
                    { Invoke-Sqlcmd -Query ("ALTER SERVER ROLE [sysadmin] ADD MEMBER [{0}]" -f $loginid) -ServerInstance $SQL_Server; }
                }
            }
            elseif ($AddToSysadmin) #so we have a login, need to verify it is in sysadmin role
            {
                if ($UsePassword)
                { $x = Invoke-Sqlcmd -Username "$env:COMPUTERNAME\adms_sa" -Password $adms_sa_pwd -Query ($qr -f $loginid) -ServerInstance $SQL_Server }
                else
                { $x = Invoke-Sqlcmd -Query ($qr -f $loginid) -ServerInstance $SQL_Server }
                if ($x)
                {
                    if ($x.countOf -eq 0) #not authorized for sysadmin, need to adjust role
                    {
                        write-host -ForegroundColor Gray ("Adding SQL login '{0}' to 'sysadmin' role..." -f $loginid)
                        if ($UsePassword)
                        { Invoke-Sqlcmd -Query ("ALTER SERVER ROLE [sysadmin] ADD MEMBER [{0}]" -f $loginid) -ServerInstance $SQL_Server -Username "$env:COMPUTERNAME\adms_sa" -Password $adms_sa_pwd; }
                        else
                        { Invoke-Sqlcmd -Query ("ALTER SERVER ROLE [sysadmin] ADD MEMBER [{0}]" -f $loginid) -ServerInstance $SQL_Server; }
                    }
                }
            }
        }
    }
    catch
    {
        write-host -ForegroundColor Red -BackgroundColor Black ("Error talking to SQL: {0}" -f $_.Exception.Message)
    }

}

function Update-MIMGroups
{
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME,computer"

    #we must wrap the .Find() function in a try block because it will throw an exception if the group does not exist

    #FIMSyncAdmins
    try
    { $x = $adsi.Children.Find("FIMSyncAdmins", "group") }
    catch {}

    if ($x)
    {
        #rather than write code to fetch group members and update them, we will simply add the members we want, and discard any errors such as "user already a member"

        try { $x.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators"); } catch {}
        try { $x.Add("WinNT://$env:COMPUTERNAME/adms_sa"); } catch {}
    }
    else #group doesn't exist, create and populate
    {
        $g = $adsi.Create("group", "FIMSyncAdmins");
        $g.SetInfo();
        $g.description = "Forefront Identity Manager Administrators";
        $g.SetInfo()
        $g.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators")
        $g.Add("WinNT://$env:COMPUTERNAME/adms_sa")
    }

    #FIMSyncBrowse
    try
    { $x = $adsi.Children.Find("FIMSyncBrowse", "group") }
    catch {}

    if ($x)
    {
        #rather than write code to fetch group members and update them, we will simply add the members we want, and discard any errors such as "user already a member"

        try { $x.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators"); } catch {}
        try { $x.Add("WinNT://$env:COMPUTERNAME/adms_sa"); } catch {}
    }
    else #group doesn't exist, create and populate
    {
        $g = $adsi.Create("group", "FIMSyncBrowse");
        $g.SetInfo();
        $g.description = "Forefront Identity Manager Browse";
        $g.SetInfo()
        $g.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators")
        $g.Add("WinNT://$env:COMPUTERNAME/adms_sa")
    }

    #FIMSyncJoiners
    try
    { $x = $adsi.Children.Find("FIMSyncJoiners", "group") }
    catch {}

    if ($x)
    {
        #rather than write code to fetch group members and update them, we will simply add the members we want, and discard any errors such as "user already a member"

        try { $x.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators"); } catch {}
        try { $x.Add("WinNT://$env:COMPUTERNAME/adms_sa"); } catch {}
    }
    else #group doesn't exist, create and populate
    {
        $g = $adsi.Create("group", "FIMSyncJoiners");
        $g.SetInfo();
        $g.description = "Forefront Identity Manager Joiners";
        $g.SetInfo()
        $g.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators")
        $g.Add("WinNT://$env:COMPUTERNAME/adms_sa")
    }

    #FIMSyncOperators
    try
    { $x = $adsi.Children.Find("FIMSyncOperators", "group") }
    catch {}

    if ($x)
    {
        #rather than write code to fetch group members and update them, we will simply add the members we want, and discard any errors such as "user already a member"

        try { $x.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators"); } catch {}
        try { $x.Add("WinNT://$env:COMPUTERNAME/adms_sa"); } catch {}
    }
    else #group doesn't exist, create and populate
    {
        $g = $adsi.Create("group", "FIMSyncOperators");
        $g.SetInfo();
        $g.description = "Forefront Identity Manager Operators";
        $g.SetInfo()
        $g.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators")
        $g.Add("WinNT://$env:COMPUTERNAME/adms_sa")
    }

    #FIMSyncPasswordSet
    try
    { $x = $adsi.Children.Find("FIMSyncPasswordSet", "group") }
    catch {}

    if ($x)
    {
        #rather than write code to fetch group members and update them, we will simply add the members we want, and discard any errors such as "user already a member"

        try { $x.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators"); } catch {}
        try { $x.Add("WinNT://$env:COMPUTERNAME/adms_sa"); } catch {}
    }
    else #group doesn't exist, create and populate
    {
        $g = $adsi.Create("group", "FIMSyncPasswordSet");
        $g.SetInfo();
        $g.description = "Forefront Identity Manager Password Set and Change";
        $g.SetInfo()
        $g.Add("WinNT://$env:USERDOMAIN/ADMS.Administrators")
        $g.Add("WinNT://$env:COMPUTERNAME/adms_sa")
    }
}

function Push-MIMGroups([System.Management.Automation.PSCredential]$creds)
{
    #this function will connect to the analysis and QA boxes to create the FIM groups via WSMan/Remote Powershell

    $ip = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp).IPAddress;
    $ipprefix = $ip.SubString(0,$ip.LastIndexOf(".")); 

    #set this server's policy to connect (send credentials) to Powershell on the local subnet
    Set-Item wsman:\localhost\client\trustedhosts ($ipprefix + ".*") -Force

    #analysis box
    try
    {
        $aip = $ipprefix + ".25";
        $sa = New-PSSession -ComputerName $aip -Credential $creds -EnableNetworkAccess

        if ($sa.State -eq "Opened")
        {
            #the following commands will be invoked on the remote servers
            #functions included within this script will be copied as a ScriptBlock to the remote session

            Invoke-Command -Session $sa -ScriptBlock ${function:Update-MIMGroups}
            Remove-PSSession -Session $sa
        }
        else
        {
            write-host -ForegroundColor Red -BackgroundColor Black ("Unable to connect to the analysis server, session state is '{0}'" -f $sa.State)
        }

    }
    catch
    {
        write-host -ForegroundColor Red -BackgroundColor Black ("Exception while trying to connect to analysis server: {0}" -f $_.Exception.Message)
    }

    #QA box
    try
    {
        $qaip = $ipprefix + ".26";
        $sa = New-PSSession -ComputerName $qaip -Credential $creds -EnableNetworkAccess

        if ($sa.State -eq "Opened")
        {
            #the following commands will be invoked on the remote servers
            #functions included within this script will be copied as a ScriptBlock to the remote session

            Invoke-Command -Session $sa -ScriptBlock ${function:Update-MIMGroups}
            Remove-PSSession -Session $sa
        }
        else
        {
            write-host -ForegroundColor Red -BackgroundColor Black ("Unable to connect to the QA server, session state is '{0}'" -f $sa.State)
        }

    }
    catch
    {
        write-host -ForegroundColor Red -BackgroundColor Black ("Exception while trying to connect to QA server: {0}" -f $_.Exception.Message)
    }

}

function Get-PendingReboot()
{ 
    try 
    { 
        [switch] $ret = $false;
                
        ## Querying WMI for build version 
        $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ErrorAction Stop;

        ## Making registry connection to the local/remote computer 
        $HKLM = [UInt32] "0x80000002";
        $WMI_Reg = [WMIClass] "\\.\root\default:StdRegProv";

        ## If Vista/2008 & Above query the CBS Reg Key 
        If ([Int32]$WMI_OS.BuildNumber -ge 6001)
        { 
            $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\");
            if ($RegSubKeysCBS.sNames -contains "RebootPending")
            {
                write-host -ForegroundColor Yellow "WARNING: Reboot pending from Windows Component Based Servicing engine."
                $ret = $true;
            }     
        }   
        ## Query WUAU from the registry 
        $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
        if ($RegWUAURebootReq.sNames -contains "RebootRequired")
        {
            write-host -ForegroundColor Yellow "WARNING: Reboot pending from Windows Update."
            $ret = $true;
        }        
        ## Query PendingFileRenameOperations from the registry 
        $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations");
        $RegValuePFRO = $RegSubKeySM.sValue;
                
        ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true 
        If ($RegValuePFRO)
        {
            write-host -ForegroundColor Yellow "WARNING: Reboot pending from File Rename."
            $ret = $true;
        }  
        return $ret;
    } 
    catch { Write-Warning $_ }
}

function Get-FIMMAName([string]$DomainDNS)
{
    #build the DN for the domain from the DNS name (NOTE: 90% solution; 100% would be to query the domain's RootDSE for this value)
    $dn = "DC=" + $DomainDNS.Replace(".",",DC=");
    $q = "SELECT dbo.mms_management_agent.ma_name FROM dbo.mms_management_agent INNER JOIN dbo.mms_partition ON dbo.mms_management_agent.ma_id = dbo.mms_partition.ma_id where dbo.mms_partition.partition_name = '{0}'" -f $dn;
    $ma = Invoke-Sqlcmd -Query $q -ServerInstance $SQL_Server -Database "FIMSynchronizationService" -ErrorAction SilentlyContinue;
    if ($ma)
    {
        if ($ma.GetType().Name -eq "DataRow")
        {
            return [string]$ma.ma_name;
        }
        elseif ($ma.Count -gt 1)
        {
            write-host "There are more than 1 Management Agents that have a partition matching this domain:"
            write-host $ma
            write-host ""
            write-host ("Please type the name of the MA you want to use for domain {0}" -f $DomainDNS)
            return [string](read-host);
        }
        else
        {
            write-host -ForegroundColor Yellow "An error occured while trying to fetch data from SQL."
            write-host ("Please type the name of the MA you want to use for domain {0}" -f $DomainDNS)
            return [string](read-host);
        }
    }
    else
    {
        write-host -ForegroundColor Yellow ("{0} - Could not query FIM database for MA name." -f $DomainDNS)
        write-host ("Please type the name of the MA you want to use for domain {0}" -f $DomainDNS)
        return [string](read-host);
    }
}

function Get-FIMRunProfile-Status([System.Management.ManagementObject]$managementAgent)
{
    $result = $managementAgent.RunStatus().ReturnValue.ToString()
    if ( $result -eq 'success' )
    {
        Write-Host $result -ForegroundColor Green
    }
    else
    {
        Write-Host $result -ForegroundColor Cyan
        write-Host 'Please check event log for more information.' -ForegroundColor Red
    }
}

function Invoke-FIMRunProfile-Multiple([string]$SearchFilter, [string]$ProfileName, [switch]$Parallel=$false)
{
    $MAs = Get-WmiObject -Class MIIS_ManagementAgent -Namespace root/MicrosoftIdentityIntegrationServer -Filter $SearchFilter
    if ($Parallel)
    {
        foreach ($me in $MAs)
        {
            Write-host ("Starting parallel run profile '{0}' on {1}..." -f $ProfileName,$me.Name)
            Start-Job -ArgumentList $me.Name, $ProfileName -ScriptBlock `
            {
                param([string]$maName, [string]$ProfileName)
                $tma = Get-WmiObject -Class MIIS_ManagementAgent -Namespace root/MicrosoftIdentityIntegrationServer -Filter "name='$maName'"; 
                $result = $tma.Execute($ProfileName).ReturnValue;
                Write-Host ("{0} result: {1}" -f $maName, $result)
            }  | Out-Null
        }
        # Get the jobs and wait for all to complete
        Get-Job | Wait-Job | select Id,Name,State,HasMoreData
        write-host ""
        # Review the output from each job
        Get-Job | Receive-Job
        # Remove the jobs
        Get-Job | Remove-Job 
    }
    else
    {
        foreach ($me in $MAs)
        { Invoke-FIMRunProfile $me $ProfileName; }
    }
}

function Invoke-FIMRunProfile([System.Management.ManagementObject]$MA, [string]$ProfileName)
{
    $displayString = $MA.Name + " [$ProfileName]"
    $displayString = $displayString.PadRight(60)
    Write-Host $displayString -NoNewLine -ForegroundColor Yellow
    $MA.Execute($ProfileName) > $null
    Get-FIMRunProfile-Status $MA
}

function Write-FIM-Config-XML($DomainInfo)
{
    #$DomainInfo must be populated prior to calling this function
    if (!$DomainInfo)
    {
        write-host -ForegroundColor Red -BackgroundColor Black "Error in Write-FIM-Config-XML(): 'DomainInfo' is null!"
        return;
    }
    if (test-path $FIM_Config_XML) { Remove-Item $FIM_Config_XML -Force; }
    $xml = New-Object System.XMl.XmlTextWriter($FIM_Config_XML,$Null);
    $xml.Formatting = 'Indented';
    $xml.Indentation = 1;
    $Xml.IndentChar = "`t";
    $xml.WriteStartElement('Domains');
    
    foreach ($me in $DomainInfo)
    {
        $xml.WriteStartElement('DomainName');
        $xml.WriteElementString('domainDNS', $me.DomainDNS);
        $xml.WriteElementString('domainNB', $me.NBName);
        $xml.WriteEndElement();
    }
    $xml.WriteEndElement();
    $xml.Flush();
    $xml.Close();
}

function Write-FIMConfig-XML([string]$TargetFQDN, [string]$Password)
{
    $xml = [xml](cat "F:\Software\ADMS-Current-Build\FIMSQL\Analysis\FIM\MAExports\FIMConfig.xml")
    if ($xml -and (test-path $FIMConfig_XML)) {Remove-Item $FIMConfig_XML -Force}
    $ParentNode = $xml."FIM-Configuration"."rules-extension-properties".MSMAnalysis
    $ParentNode.labpwd = $Password
    
    $ContosoNode = $ParentNode.SelectSingleNode("contoso.com");

    $NewNode = $xml.CreateElement($TargetFQDN);
    $NewNode.InnerXML = $ContosoNode.InnerXML;
    [void]$ParentNode.AppendChild($NewNode);
    [void]$ParentNode.RemoveChild($ContosoNode);
    $xml.Save($FIMConfig_XML);
}

function Test-DC-Connection([string]$DomainName)
{
    $r = Resolve-DnsName $DomainName -Type A;
    if ($r.Count -gt 0)
    {
        $table = New-Object system.Data.DataTable;
        $table.Columns.Add((New-Object system.Data.DataColumn "DomainName",([string])));
        $table.Columns.Add((New-Object system.Data.DataColumn "DC_IP",([string])));
        $table.Columns.Add((New-Object system.Data.DataColumn "PingStatus",([string])));
        $table.Columns.Add((New-Object system.Data.DataColumn "Port389Status",([string])));

        foreach ($me in $r)
        {
            $row = $table.NewRow();
            $row.DomainName = $DomainName;
            $row.DC_IP = $me.IPAddress;

            $x = Test-NetConnection $me.IPAddress -Port 389;

            if ($x.PingSucceeded) {$row.PingStatus = "SUCCESS"}
            else {$row.PingStatus = "FAILED"}
            
            if ($x.TcpTestSucceeded) {$row.Port389Status = "SUCCESS"}
            else {$row.Port389Status = "FAILED"}
            

            $table.Rows.Add($row);
        }
        return $table
    }
    else
    {
        write-host -ForegroundColor Red -BackgroundColor Black "No host (A) records returned for this domain name!"
    }
}

function Install-VisualStudio()
{
    #before installing, lets check to see if it already is. Rather than parse the registry for installed software, lets just look for the primary executable
    if (test-path "E:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv.exe")
    {
        write-host -ForegroundColor Yellow "Visual Studio is already installed on this system."
    }
    elseif (Get-PendingReboot)
    {
        write-error "Aborting Visual Studio install because a reboot is pending, please reboot and try again."
    }
    else
    {    
        $l = $env:TEMP + "\VS2015_install.log"

        if (!(test-path $VS_Local))
        {
            New-Item "F:\Software\VS2015" -ItemType Directory -ErrorAction SilentlyContinue
            Start-BitsTransfer $VS_DL $VS_Local
        }

        if (test-path $VS_Local)
        {
            $p = Start-Process $VS_Local -ArgumentList "/CustomInstallPath ""E:\Program Files (x86)\Microsoft Visual Studio 14.0"" /passive /norestart /l $l" -Wait -PassThru

            switch ($p.ExitCode)
            {
                0
                {
                    #success, no reboot
                    write-host -ForegroundColor Green "Successfully installed Visual Studio.";
                }
                3010
                {
                    #success, reboot needed
                    write-host -ForegroundColor Yellow "Setup was successful, however a reboot is required."
                }
                -2147185721
                {
                    write-host -ForegroundColor Yellow "Setup incomplete: Restart is required before installation can continue." 
                }
                -2147205120
                {
                    write-host -ForegroundColor Yellow "Setup incomplete: Setup was blocked, check for pending updates and other running installers."
                }
                default
                {
                    if ($p.ExitCode)
                    {
                        write-host -ForegroundColor Red -BackgroundColor Black ("Did not recognize exit code '{0}'." -f $p.ExitCode)
                    }
                    elseif (Test-Path $l)
                    {
                        $x = Get-Content $l | select -last 10
                        if ($x)
                        {
                            write-host -ForegroundColor Yellow "The following are the last 10 lines in the installation log:"
                            foreach ($line in $l)
                            {
                                write-host $line
                            }
                        }
                        else 
                        {
                            write-host -ForegroundColor Red -BackgroundColor Black "Could not parse the log file to determine setup status!";
                        }
                    }
                    write-host -ForegroundColor Red -BackgroundColor Black "---------------------------";
                    write-host -ForegroundColor Red -BackgroundColor Black "The Visual Studio setup operation was NOT successful!";
                    write-host -ForegroundColor Red -BackgroundColor Black "Review the log file at $l";
                    exit
                }
            }
        }
        else 
        {
            write-host -ForegroundColor Red -BackgroundColor Black "---------------------------";
            write-host -ForegroundColor Red -BackgroundColor Black "The Visual Studio setup exe was NOT downloaded successfully!";
            exit
        }
    }
}

Function Test-RegistryValue($regkey, $name) 
{
    try
    {
        $exists = Get-ItemProperty $regkey $name -ErrorAction SilentlyContinue
        Write-Host "Test-RegistryValue: $exists"
        if (($exists -eq $null) -or ($exists.Length -eq 0))
        { return $false }
        else
        { return $true }
    }
    catch
    { return $false }
}

function Install-MIMSync([string]$SvcUserName,[string]$SvcPassword,[string]$SvcDomain,[switch]$ExpandZipFile=$false)
{   
    try
    {
        $extensionsDir = $MIM_InstallDir + "\Synchronization Service\Extensions"
        $a = "/qr /i ""{0}"" SERVICEACCOUNT={1} SERVICEPASSWORD={2} SERVICEDOMAIN={3} GROUPADMINS=FIMSyncAdmins GROUPOPERATORS=FIMSyncOperators " 
        $a += "GROUPACCOUNTJOINERS=FIMSyncJoiners GROUPBROWSE=FIMSyncBrowse GROUPPASSWORDSET=FIMSyncPasswordSet FIREWALL_CONF=1 installdir=""{4}"" /L*v ""{5}"""
        $a = $a -f $MIM_InstallerPath,$SvcUserName,$SvcPassword,$SvcDomain,$MIM_InstallDir,"F:\Software\MSFT\FimInstalllog.txt"
        
        start-process -filepath "msiexec" -ArgumentList $a -wait -passthru

        start-process -filepath "sc" -argumentList "config FIMSynchronizationService start=delayed-auto" -Wait -PassThru

         # Check to see if the ADMAUseACLSecurity registry key is present, if not it is added
        $ACLPresent=get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\Parameters
        if($ACLPresent.ADMAUseACLSecurity -eq $null)
        {
            New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\Parameters -Name ADMAUseACLSecurity -Value 1 | out-null
            #verify creation was successful
            $ACLPresent=get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\Parameters
            if($ACLPresent.ADMAUseACLSecurity -eq $null)
            {
                write-host -ForegroundColor Yellow "FAILED to set the 'ADMAUseACLSecurity' registry entry, please set it manually."
                pause
            }
        }
        if ($ExpandZipFile)
        {
            if(test-path($MIM_ExtensionZipFile))
            {    
                $shellApplication = new-object -com shell.application
                $zipPackage = $shellApplication.NameSpace($MIM_ExtensionZipFile)
                $destinationFolder = $shellApplication.NameSpace($extensionsDir)
                $destinationFolder.CopyHere($zipPackage.Items(),16)
            } 
            else
            { 
                write-host -ForegroundColor Yellow "The Extension ZIP file does not exist in the path"
                write-host -ForegroundColor Yellow "Please manually populate the Extension folder."
                pause
            }
        }
    }
    catch
    {
        write-host -ForegroundColor Red -BackgroundColor Black ("Exception in Install-MIMSync(): {0}" -f $_.Exception.Message)
    }
}

#######################################
#########FUNCTIONS SECTION END#########
#######################################


#options are mutually exclusive since they must be performed on different servers
if ($Perform_Analysis -and $Prep_Jump_Box)
{
    write-host -ForegroundColor Red -BackgroundColor Black "---------------------------";
    Write-Host -ForegroundColor Red -BackgroundColor Black "Cannot perform analysis and prep the jump box in the same execution!"
    exit
}

if (($Perform_Analysis -or $Prep_Jump_Box) -and $TestTarget_Extend_Schema)
{
    write-host -ForegroundColor Red -BackgroundColor Black "---------------------------";
    write-host -ForegroundColor Red -BackgroundColor Black "The extend schema option must be supplied while running on a DC, NOT while performing analysis or prepping the jump box!"
    exit
}

#utility functionality: use this to test DNS resolution and a ping/port test for all DCs in each domain
if ($Test_Domain_Connectivity)
{
    if ($Domain_To_Test)
    {
        Test-DC-Connection $Domain_To_Test
    }
    else 
    {
        $domains = import-csv "E:\ADMS\Scripts\AnalysisServer\domaininfo.csv"
        if ($domains)
        {
            foreach ($d in $domains)
            {
                $t += Test-DC-Connection $d.DomainDNS
            }
            if ($t)
            {
                $t | export-csv "E:\ADMS\Scripts\AnalysisServer\DC-test.csv" -NoTypeInformation
                $t | ft
                write-host -ForegroundColor Green "The output table shows the current connectivity status."
                write-host -ForegroundColor Green "This table was also saved to the file 'E:\ADMS\Scripts\AnalysisServer\DC-test.csv'."
            }
        }
        else 
        {
            write-host -ForegroundColor Red -BackgroundColor Black "No Domain to test was supplied AND could not load the domaininfo.csv file!"
        }
    }
}

if ($TestTarget_Extend_Schema)
{
    #use this option if the testtarget domain needs to be extended with Exchange attributes
    #run this from a DC in the testtarget domain
    if (Get-PendingReboot)
    {
        write-error "Aborting schema extension because a reboot is pending, please reboot and try again."
        exit
    }
    
    #NOTE: Using temporary storage D: drive to store Exchange install media
    if (!(test-path "F:\Software\Exchange\setup.exe"))
    {
        New-Item "F:\Software\Exchange" -ItemType Directory -ErrorAction SilentlyContinue
        Start-BitsTransfer $Exchange_DL "D:\Exchange2016-x64.exe"
        Start-Process "D:\Exchange2016-x64.exe" -ArgumentList "/extract:F:\Software\Exchange /passive" -Wait
        if (!(test-path "F:\Software\Exchange\setup.exe"))
        {
            write-host -ForegroundColor Red "FAILED to stage the Exchange setup files, cannot continue."
            exit
        }
    }

    $p = Start-Process "F:\Software\Exchange\setup.exe" -ArgumentList "/Prepareschema /IAcceptExchangeServerLicenseTerms" -NoNewWindow -Wait -PassThru

    if ($p.ExitCode -eq 0)
    {
        write-host -ForegroundColor Green "Successfully extended AD schema for Exchange attributes.";
    }
    else 
    {
        write-host -ForegroundColor Red -BackgroundColor Black "---------------------------";
        write-host -ForegroundColor Red -BackgroundColor Black "The Exchange setup operation was NOT successful!";
        exit
    }
}

if ($Install_MIMSync)
{
    $sp = read-host ("Please enter the password for ({0}\adms_sa): " -f $env:COMPUTERNAME) -AsSecureString
    $spplain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp))
    Install-MIMSync adms_sa $spplain $env:COMPUTERNAME
}

if ($Install_VS)
{
    Install-VisualStudio
}

if ($Prep_Jump_Box)
{
    #Import Active Directory module
    import-module activedirectory

    #step 1 - Create folder
    if((Test-Path "E:\ADMS") -eq $false) { New-Item "E:\ADMS" -type directory}
    

    #copy the domaininfo.csv file manually
    write-host "Copy the domaininfo.csv file to E:\ADMS."
    Pause

    #create accounts from roster
    write-host "Verify roster file (F:\Software\ADMS-Current-Build\FIMSQL\Analysis\Deploy\ADMS_Roster.csv) is accurate before continuing..."    
    Pause

    # Create a password to be used for all of the service accounts
    $sp = Read-Host "Please type the default password for this customer" -AsSecureString
    # Create the ADMS.Administrators group
    try { New-ADGroup -name ADMS.Administrators -GroupCategory Security -GroupScope Global -SamAccountName ADMS.Administrators; } catch {}

    # Add the ADMS.Administrators group to Domain Admins
    try { Add-ADGroupMember -Identity "Domain Admins" -Members ADMS.Administrators} catch {}
    #Import users from ADMS_Roster.csv file
    $Users=import-csv -Path 'F:\Software\ADMS-Current-Build\FIMSQL\Analysis\Deploy\ADMS_Roster.csv'
    #Create user for each entry in the file
    foreach ($User in $Users)
    {
        try
        {
        $givenName=$user.givenName 
        $sn=$user.sn
        $alias=$user.alias   
        New-ADUser -SamAccountName $alias -name "$givenName $sn" -AccountPassword $sp -GivenName $giveName -Surname $user.sn `
         -EmailAddress $user.mail -PasswordNeverExpires $true -Enabled $true -UserPrincipalName "$alias@adms.local"

        Add-ADGroupMember -identity ADMS.Administrators -Members $user.alias
        }
        catch
        { write-host -ForegroundColor Red -BackgroundColor Black ("Exception while adding a user from roster: {0}" -f $_.Exception.Message) }
    }

    
    #add DNS forwarders
    #
    $arrCommands=@()
    $replicationScope="Domain"
    #
    # # Find all of the Jump Servers
    # $JumpServers=(get-adcomputer -filter {name -Like "*JUMP0*"}) | Sort-Object Name
    # Check all Jump Servers for DNS Server Tools
    # foreach ($JumpServer in $JumpServers)
    # {
    #     $DNSStat=Get-WindowsFeature -Name "RSAT-DNS-Server" -ComputerName $JumpServer.Name
    #     If ($DNSStat.Installed -eq $false) { Add-WindowsFeature "RSAT-DNS-Server" -ComputerName $JumpServer.Name }
    # }
    $DNSStat=Get-WindowsFeature -Name "RSAT-DNS-Server";
    If ($DNSStat.Installed -eq $false) { Add-WindowsFeature "RSAT-DNS-Server"; }

    # Get the name of the DNS server for this subscription
    $DNSServer=(get-adcomputer -filter {name -Like "*dnsdc01"}).Name
    #
    # Get the input file with the zone name and IP addresses
    $conditionalForwarders=import-csv -Path $DomainInfo_File
    #
    # Loop through the file and add the conditional forwarders to dns
    Foreach ($conditionalForwarder in $conditionalForwarders)
    {
        $arrIP=@()
        $arrIP+=$conditionalForwarder.DNS_IP1.Trim()
        # Check to see if a second address exists before adding to the array
        If ($conditionalForwarder.DNS_IP2 -ne "")
        {
            $arrIP+=$conditionalForwarder.DNS_IP2.Trim()
        }
        #
        try { Add-DnsServerConditionalForwarderZone -ComputerName $DNSServer -Name $conditionalForwarder.DomainDNS -ReplicationScope "Domain" -MasterServers $arrIP -PassThru } 
        catch 
        { write-host -ForegroundColor Red -BackgroundColor Black ("Exception while trying to add DNS forwarders: {0}" -f $_.Exception.Message) }
    }

    write-host "Please validate the DNS forwarders are correct"
    Pause

    #run the Update-DomainInfo.ps1 Script
    write-host "Updating DomainInfo.csv"
    . F:\Software\ADMS-Current-Build\FIMSQL\Analysis\Deploy\Update-DomainInfo.ps1 -Discover -Save -Verbose -FilePath $DomainInfo_File
    write-host "Review the domaininfo.csv file and verify all the fields are populated"
    Pause

    #Prepare the testtarget.local domain with service accounts and groups
    $c = New-Object System.Management.Automation.PSCredential ("testtarget\adms_sa", $sp)

    foreach ($me in @("adms.sync.svc","adms.core.svc","adms.mig.svc","adms.join.svc","adms.wks.svc"))
    {
        if (!(Get-ADUser -Filter { SamAccountName -eq $me } -Server "testtarget.local" -Credential $c))
        {
            New-ADUser -SamAccountName $me -name $me -Server "testtarget.local" -Credential $c;
            Set-ADAccountPassword -identity $me -NewPassword $sp -Server "testtarget.local" -Credential $c;
            Set-ADUser -identity $me -Enabled 1 -PasswordNeverExpires 1 -Server "testtarget.local" -Credential $c;
        }
    }

    foreach ($me in @("ADMS.Administrators","ADMS.Bulk.Migrators","ADMS.Portals.Admins","ADMS.SQLReports"))
    {
        if (!(Get-ADGroup -Filter { SamAccountName -eq $me -or name -eq $me } -Server "testtarget.local" -Credential $c))
        {
            New-ADGroup -name $me -GroupCategory Security -GroupScope Global -SamAccountName $me -Server "testtarget.local" -Credential $c;
            if ($me -eq "ADMS.Administrators")
            { Add-ADGroupMember -identity $me -Members adms.wks.svc,adms.sync.svc,adms.core.svc,adms.mig.svc,adms_sa -Server "testtarget.local" -Credential $c; }
            elseif ($me -eq "ADMS.Bulk.Migrators")
            { Add-ADGroupMember -identity $me -Members adms.mig.svc -Server "testtarget.local" -Credential $c; }
        }
    }

    #connect to the analysis and QA servers and create the MIM Groups
    Push-MIMGroups $c

    write-host -ForegroundColor Green "Jump box complete, now log into AnalysisServer (x.y.z.25) with local admin (.\adms_sa) to continue."
}

if ($Perform_Analysis)
{
    #get the password for this customer for use later in this routine
    $sp = read-host ("Please enter the password for ({0}\adms_sa): " -f $env:COMPUTERNAME) -AsSecureString
    $spplain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp))
    
    #Add SQL logins and roles
    #NOTE: for these commands to work correctly, you MUST be logged in as the local adms_sa user!
    
    #check for 'testtarget\adms_sa' and create if it doesn't exist
    Update-SQLLogins "TESTTARGET\adms_sa" $null $false $true; #$null = no password / $false =  do not use a password / $true = add to sysadmin role
    #check for 'testtarget\adms.core.svc' and create if it doesn't exist
    Update-SQLLogins "TESTTARGET\adms.core.svc" $null $false $true;
    #check for 'testtarget\adms.mig.svc' and create if it doesn't exist
    Update-SQLLogins "TESTTARGET\adms.mig.svc" $null $false $true;
    
    #Get user to copy Domaininfo.csv and then start CallAll
    Write-Host -ForegroundColor Yellow ("Copy the '{0}' file from the jump box to the same location on this server." -f $DomainInfo_File)
    Pause

    if (!(test-path $DomainInfo_File))
    {
        Write-Host -ForegroundColor Red ("Could not find '{0}', process aborting." -f $DomainInfo_File)
        Exit
    }

    $mydata = import-csv $DomainInfo_File

    # Run the GenerateDBObjects.sql script to build the database
    Invoke-Sqlcmd -InputFile "F:\Software\ADMS-Current-Build\FIMSQL\Analysis\SQLScripts\GenerateDBObjects.sql" 
    

    #Create CallAll.cmd
    if (!(test-path "E:\ADMS\DiscoveryTools")) 
    { New-Item "E:\ADMS\DiscoveryTools" -type directory}
        
    $arrCommands=@()
    $admsAccount="adms.sync.svc"
    $getComputersCommandPart1='call F:\Software\ADMS-Current-Build\FIMSQL\Analysis\DiscoveryTools\GetComputers.cmd '
    $getGroupsPart1='call F:\Software\ADMS-Current-Build\FIMSQL\Analysis\DiscoveryTools\GetGroups.cmd '
    $getUsersCommandPart1='call F:\Software\ADMS-Current-Build\FIMSQL\Analysis\DiscoveryTools\GetUsers.cmd '
    $getContactsCommandPart1='call F:\Software\ADMS-Current-Build\FIMSQL\Analysis\DiscoveryTools\GetContacts.cmd '
    $getOUsCommandPart1='call F:\Software\ADMS-Current-Build\FIMSQL\Analysis\DiscoveryTools\GetOUs.cmd '

    foreach ($domain in $mydata)
    {
        #$domain.DomainDNS
        $domainDN="DC=" + $domain.DomainDNS.Replace(".",",DC=")
        $domainDN='"' + $domainDN + '"'
        $arrCommands+="REM  Get information for $domainDN"
        $arrCommands+="REM  "
        # set up the domain specific part of the command
        $getCommandPart2 = $domainDN + ' ' + $domain.DC_IP + ' ' + $domain.NBName + ' ' + $admsAccount  + ' ' + $domain.DomainDNS  + ' "' + $domain.password + '" '
        #
        # prepend the .cmd file to be run
        # Create the GetComputers.cmd command
        $getComputersCommand=$getComputersCommandPart1 + $getCommandPart2
        $arrCommands+=$getComputersCommand
        #
        # Create the GetGroups.cmd command
        $getGroupsCommand=$getGroupsPart1 + $getCommandPart2
        $arrCommands+=$getGroupsCommand
        #
        # Create the GetUsers.cmd command
        $getUsersCommand=$getUSersCommandPart1 + $getCommandPart2
        $arrCommands+=$getUsersCommand
        #
        # Create the GetContacts.cmd command
        $getContactsCommand=$getContactsCommandPart1 + $getCommandPart2
        $arrCommands+=$getContactsCommand
        #
        # Create the GetOUs.cmd command
        $getOUsCommand=$getOUsCommandPart1 + $getCommandPart2
        $arrCommands+=$getOUsCommand
        #
        $arrCommands+="REM "
        $arrCommands+="REM "

    }

    $arrCommands | Out-File -FilePath "E:\ADMS\DiscoveryTools\CallAll.cmd" -Encoding ascii

    if (!(test-path "E:\ADMS\DiscoveryTools\Discovery"))  { New-Item "E:\ADMS\DiscoveryTools\Discovery" -type directory}


    write-host "Starting domain discovery..."

    Start-Process 'E:\ADMS\DiscoveryTools\CallAll.cmd' -NoNewWindow -Wait -PassThru

    #Verify status
    write-host -ForegroundColor Yellow "Verify that CallAll.cmd was successful."    
    Pause

    #Run importLdifs.ps1 file
    
    $path = "E:\ADMS\DiscoveryTools\Discovery\"
    $files=Get-ChildItem -Path $path
    foreach($file in $files)
    {
        $file.Name  
        $fullFile = $path + $file.name
        . F:\Software\ADMS-Current-Build\FIMSQL\Analysis\DiscoveryTools\AttribAnalyzer.ps1 $fullFile
    }

    #Run the AttributeFrequencies.sql script
    $c = Read-Host "Please provide the customer name"
    $t = Invoke-Sqlcmd -InputFile "F:\Software\ADMS-Current-Build\FIMSQL\Analysis\SQLScripts\AttributeFrequencies.sql"
    $p = "E:\ADMS\DiscoveryTools\DataDiscovery-{0}.csv" -f $c
    $t | Export-Csv -Path $p -NoTypeInformation

    write-host -ForegroundColor Yellow "The attribute frequency table has been exported to the file below. "
    write-host -ForegroundColor Yellow "Open this table in Excel and prepare the data for presentation."
    write-host -ForegroundColor Yellow $p
    write-host -ForegroundColor Green "MIM will be installed next."
    Pause

    #Install MIM
    # write-host -ForegroundColor Yellow "When prompted for credentials, use the local '.\adms_sa' account."
    # . F:\Software\ADMS-Current-Build\FIMSQL\Analysis\Deploy\MIMInstall.ps1
    Install-MIMSync adms_sa $spplain $env:COMPUTERNAME -ExpandZipFile
    
    #Import the MIM config (manual process)
    write-host ""
    write-host -ForegroundColor Yellow "MANUALLY Open Sync Manager, go to Metaverse Designer and use Actions | Import Metaverse Schema"
    write-host -ForegroundColor Yellow "F:\Software\ADMS-Current-Build\FIMSQL\Analysis\FIM\MAExports\mv.xml"

    Pause

    Write-Host ""
    write-host -ForegroundColor Yellow "MANUALLY Import MA 'SourceDomain-Analysis.xml' for EACH source domain; use the name 'ADMS-Analysis-domain'"
    Pause

    Write-Host ""
    write-host -ForegroundColor Yellow "MANUALLY Import MA 'TargetDomain-Analysis.xml' for EACH target domain; use the name 'ADMS-Analysis-domain'"
    Pause

    
    #The 'FIM-config.xml' file must be populated with the domain info from the csv file. The embedded function will write out the XML document, please verify.
    Write-FIM-Config-XML $mydata
    write-host -ForegroundColor Yellow "Open the 'FIM-config.xml' in Extensions folder and verify all domains are properly populated."
    Pause

    write-host -ForegroundColor Yellow "MANUALLY Turn on Provisioning in FIM from Tools | Options"
    write-host -ForegroundColor Yellow "Select 'Enable metaverse rules extension' checkbox, Set Rules Extension name to 'MVExtension_AnalysisDB.dll', Select 'Enable Provisioning Rules Extension' checkbox."
    Pause

    #Full import on source and target MAs
    # $MAs = Get-WmiObject -Class MIIS_ManagementAgent -Namespace root/MicrosoftIdentityIntegrationServer -Filter "name like 'ADMS-Analysis%'"
    write-host "Starting concurrent Full Imports for each MA with a name that starts with 'ADMS-Analysis'..."
    Invoke-FIMRunProfile-Multiple "name like 'ADMS-Analysis%'" "FI" -Parallel

    write-host -ForegroundColor Yellow "VERIFY ALL IMPORTS TO FINISHED SUCCESSFULLY BEFORE PROCEEDING!"
    Pause

    #Full Sync on source and target MAs
    foreach ($me in $MAs)
    {
        # FIM-RunProfile $me "FS" -WaitForCompletion
        Invoke-FIMRunProfile $me "FS"
    }

    #Run exports on DataAnalysis MAs
    $MAs = Get-WmiObject -Class MIIS_ManagementAgent -Namespace root/MicrosoftIdentityIntegrationServer -Filter "name like 'ADMS-DataAnalysis%'"
    foreach ($me in $MAs)
    {
        Invoke-FIMRunProfile $me "E"
    }

    #Get totals
    . "F:\Software\ADMS-Current-Build\FIMSQL\Analysis\SQLScripts\Create-ComputerTotals.ps1"
    . "F:\Software\ADMS-Current-Build\FIMSQL\Analysis\SQLScripts\Create-GroupTotals.ps1"
    . "F:\Software\ADMS-Current-Build\FIMSQL\Analysis\SQLScripts\Create-UserTotals.ps1"

    #open the html files
    Invoke-Item "E:\ADMS\DiscoveryTools\Computer_Totals.html"
    Invoke-Item "E:\ADMS\DiscoveryTools\Group_Totals.html"
    Invoke-Item "E:\ADMS\DiscoveryTools\User_Totals.html"

    #gather output files and update powerpoint
    write-host -ForegroundColor Green "Data gathering process is now complete."
    write-host -ForegroundColor Yellow "Next steps:"
    write-host -ForegroundColor Yellow "Use the .html total files to update the Powerpoint slides"
    write-host -ForegroundColor Yellow "Take the excel file generated from $p and update the Powerpoint slides."
    Pause

    write-host ""
    Write-Host -ForegroundColor Green "Data Analysis complete and Powerpoint deck should be ready for workshop."
    write-host -ForegroundColor Green "Next step: Populate the TestTarget AD with data from customer's target (step 11)."
    Pause

    #populate TestTarget
    #Extend schema if needed
    write-host ""
    write-host -ForegroundColor Yellow "If the customer's target domain schema has been extended for Exchange, then the testtarget.local domain should also be extended."
    write-host -ForegroundColor Yellow "If the schema extension needs to be performed, log into the DC for testtarget.local and use the switch option 'TestTarget_Extend_Schema'"
    Pause
    
    #import the testtarget MA
    write-host -ForegroundColor Yellow "MANUALLY Import MA 'F:\Software\ADMS-Current-Build\FIMSQL\Analysis\FIM\MAExports\TESTTARGET-AD.xml'; do NOT change the MA name."
    write-host -ForegroundColor Yellow "If the schema was NOT extended, then attribute maps for those attributes must be manually removed."
    Pause

    #create the FIMConfig.xml file
    #1st, we need to get the target from the DomainInfo.csv file
    foreach ($me in $mydata)
    {
        if ($me.isTarget.ToUpper() -eq "TRUE") {$t = @($me.DomainDNS.ToString(), $me.Password.ToString())}
    }
    if ($t) { Write-FIMConfig-XML $t[0] $t[1] }
    else 
    {
        write-host -ForegroundColor Red -BackgroundColor Black "---------------------------";
        write-host -ForegroundColor Red -BackgroundColor Black "Failed to discover the target domain from the DomainInfo.csv file!";
        exit
    }

    #Change FIM MV extension
    write-host ""
    write-host -ForegroundColor Yellow "In Synchronization Engine, go to Tools | Options and change the Rules Extension to 'MVExtension_Provision_Lab.dll'"
    Pause

    #Run a Full import on TestTarget MA
    $TTMA = Get-WmiObject -Class MIIS_ManagementAgent -Namespace root/MicrosoftIdentityIntegrationServer -Filter "name='TESTTARGET-AD'"
    Invoke-FIMRunProfile $TTMA "FI"

    #run a Full Sync against customer's target MA
    write-host -ForegroundColor Yellow "Please enter the name of the target Managment Agent for this customer:"
    $targetMAName = read-host
    $targetMA = Get-WmiObject -Class MIIS_ManagementAgent -Namespace root/MicrosoftIdentityIntegrationServer -Filter ("name='{0}'" -f $targetMAName) -ErrorAction SilentlyContinue
    if ($targetMA)
    {
        Invoke-FIMRunProfile $targetMA "FS"
    }
    else 
    {
        write-host -ForegroundColor Red -BackgroundColor Black "---------------------------";
        write-host -ForegroundColor Red -BackgroundColor Black "Failed to find a MA with the name provided, MANUALLY perform a Full Sync on the target MA and an Export on the 'TESTTARGET-AD' MA.";
        exit
    }

    #Export to TestTarget
    Invoke-FIMRunProfile $TTMA "E"
    
    write-host ""
    write-host -ForegroundColor Green "The testtarget.local domain should now be populated with the same objects as the customer's target domain."
    write-host -ForegroundColor Green "This completes the Analysis Server phase of the solution, the next phase is QA."
}
