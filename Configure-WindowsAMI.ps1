<# 
.SYNOPSIS 
	Automates the process of Windows 2012 AMI configuration.
.DESCRIPTION 
	Pulls system name from AWS Tags. Modifies IP configuration to static. Joins domain.
.EXAMPLE
	Runs Unattended.
.NOTES 
	Name: Configure-WindowsAMI
	Author: Chris Spanton 
	Created: 2016.01.14
	LastEdit: 2016.03.07

	-Set hostname
	-Set IP to static from DHCP
	-Set DNS IPs properly
	-Install latest Windows Updates	
	-Join domain and be placed into proper OU or Staging.
	-Delete account used (badmin)
		
	####################################
	#
	#
	# THIS NEEDS TO BE DONE ON THE AMI
	#
	#
	####################################
	
	-Configure backup user (badmin)
		-Then, as Badmin:
	-Place script within user profile (C:\temp\configure-windowsami.ps1)
	-Add Sysprep file
	-Ensure DNS Set
	
	Set-ExecutionPolicy RemoteSigned

	Add-WindowsFeature RSAT-AD-PowerShell

	#Key is a 32-integer array, each less than 256. Since each int is 8 bits, this is a 256bit AES key.
	$Key = @()
	for($i = 0; $i -lt 32; $i++)
	{
		$Key += (Get-Random -Maximum 255)
	}
	#Securely read password (svc_adds_joindom) and store it in HKCU as AES256 encrypted text
	#Then, store the encryption key as well.
	$SecurePassword = Read-Host -Prompt "Enter password for: svc_adds_joindom" -AsSecureString
	$EncryptedString = $SecurePassword | ConvertFrom-SecureString -Key $Key 
	$RegPath = 'HKCU:\Software'
	$RegKey = 'HKCU:\Software\AMI'
	New-Item -Path $RegPath -Name AMI
	New-ItemProperty $RegKey -Name 'Storage1' -Value $EncryptedString -PropertyType String
	New-ItemProperty $RegKey -Name 'Storage2' -Value $Key -PropertyType String
	$SecurePassword = Read-Host -Prompt "Enter AWS Secret Key" -AsSecureString
	$EncryptedString = $SecurePassword | ConvertFrom-SecureString -Key $Key 
	New-ItemProperty $RegKey -Name 'Storage3' -Value $EncryptedString -PropertyType String

	# This enables the running of script on first login
	$RegValue = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command &{C:\temp\Configure-WindowsAMI.ps1}"
	$RegKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
	New-ItemProperty $RegKey -Name 'AMIConfig' -Value $RegValue -PropertyType String

	####################################
	#
	#
	# END AMI CONFIGS
	#
	#
	####################################

	
	Version History:
	
	2016.02.25
	----------	
	
	-Added code to handle removal of user account (badmin)
	-Implemented Find-InstanceName function. Completes need for complex name finding.
	-Implemented handling for using a single DC for all domain functions
	-Implemented addition of $InstanceID as vmID property of AD computer account. 
	
	2016.03.07
	----------	
	
	-Now removing script file and sysprep file in script.
	-Added RunOnce handling for executing script
	-Added delay before executing domain join
		-Handles situations with no Windows Updates.
	
#>

Function Add-WindowsUpdate
{
    param ($Criteria = "IsInstalled=0 and Type='Software'" , [switch]$AutoRestart) 

    $resultcode = @{0 = "Not Started"; 1 = "In Progress"; 2 = "Succeeded"; 3 = "Succeeded With Errors"; 4 = "Failed" ; 5 = "Aborted" }
	#create new update session
    $updateSession = new-object -com "Microsoft.Update.Session"
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 1 -Message "Checking available Windows Updates"
	Write-Host ("Checking available Windows Updates")
	#create update searcher from update session
    $updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates

    if ($Updates.Count -eq 0)
    {
		#If there are no updates available
		Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 10 -Message "No additional Windows Updates"
	    return $false
    }   
    else 
    { 
		#Create an update downloader from the update session
	    $downloader = $updateSession.CreateUpdateDownloader()   
	    $downloader.Updates = $Updates  
		Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 2 -Message "Downloading $($downloader.Updates.count) Windows Updates"
		Write-Host ("Downloading Windows Updates")
		$Result= $downloader.Download()  
		#Based on the results of the download...
	    if (($Result.Hresult -eq 0) -and (($result.resultCode -eq 2) -or ($result.resultCode -eq 3)))
	    {
		    $updatesToInstall = New-object -com "Microsoft.Update.UpdateColl"

		    $Updates | where {$_.isdownloaded} | foreach-Object {$updatesToInstall.Add($_) | out-null }
			#Create an update installer from the update session
		    $installer = $updateSession.CreateUpdateInstaller()
		    $installer.Updates = $updatesToInstall
			Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 3 -Message "Installing $($Installer.Updates.count) Windows Updates"
		    Write-Host ("Installing Windows Updates")
			$installationResult = $installer.Install()
		    $Global:counter = -1
		    $installer.updates | Format-Table -autosize -property Title,EulaAccepted,@{label='Result';
							       expression={$ResultCode[$installationResult.GetUpdateResult($Global:Counter++).resultCode ] }} 
		    if ($autoRestart -and $installationResult.rebootRequired)
		    { 
			    Write-EventLog -LogName $EventLog -Source $EventLog -EntryType warning -EventID 5 -Message "Windows Updates Complete - AutoRestart Selected"
				shutdown.exe /t 0 /r 
		    }
	    }
    }
} #END Add-WindowsUpdate
Function Find-InstanceName ($InstanceID, $DomCreds, $EventLog)
{

	$AWS = ('us-east-1','us-west-2')
	try
	{
		# Try building a list of AWS Account ID's
		$AccountList = (Get-ADGroup -filter {cn -like "r_aws_*"} -Credential $DomCreds -Server "corporate.t-mobile.com" -ErrorAction STOP).name | ForEach-Object { $_.split("_")[2]} | Sort-Object | Get-Unique
		Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Generated Account List"

	}
	catch
	{
		Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Error -EventID 97 -Message "Unable to generate account list. `r`n$_"
	}
	# For each account
	foreach ($account in $AccountList)
	{
		# For each dynamically generated account, based on AD Roles
		try
		{
			$ARN = "arn:aws:iam::$($account):role/ReadOnly_API"
			$Creds = (Use-STSRole -RoleArn $ARN -RoleSessionName $account -ErrorAction STOP).Credentials
		}
		catch
		{
			Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Error -EventID 97 -Message "Unable to generate STS Role credentials. `r`n$_"
		}
		# For each region
		foreach($region in $AWS)
		{
			# look at each EC2 region, and see if it exists there.
			try
			{
				# Try getting the name tag value of an instance with an ID matching the InstanceID from local metadata
				$Computer = (Get-EC2Tag -Credential $Creds -Region $Region -ErrorAction STOP | where {($_.ResourceId -eq $InstanceID) -and ($_.Key -eq 'Name')}).value
				if ($Computer)
				{
					Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Instance Name Found: $Computer"
					return $Computer
				}
			}
			catch
			{
				Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Error -EventID 97 -Message "Unable to query for EC2 Tags. `r`n$_"
			}
		}
	}
} #END Find-InstanceName

#   ------->   Main

$EventLog = "Configure-WindowsAMI"
#Create a new event log for tracking the script's events.
New-EventLog -LogName $EventLog -Source $EventLog
rm 'c:\program files\amazon\ec2configservice\sysprep2008.xml'
#Pull the encrypted password, and its key, from HKCU. Restore the password into usable format.
$RegKey = 'HKCU:\Software\AMI'
$EncryptedString = (Get-ItemProperty -Path "$RegKey" | select Storage1).Storage1
$Key = ((Get-ItemProperty -Path "$RegKey" | select Storage2).Storage2).Split(" ")
$SecureString = $EncryptedString | ConvertTo-SecureString -Key $Key
$DomCreds = New-Object System.Management.Automation.PSCredential ("corp\svc_adds_joindom", $SecureString)
#Pull the AWS SecretKey from HKCU
$EncryptedString = (Get-ItemProperty -Path "$RegKey" | select Storage3).Storage3
$SecureString = $EncryptedString | ConvertTo-SecureString -Key $Key
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
$SecretKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) 
Remove-Item -Path $RegKey
Set-AWSCredentials -AccessKey AKIAIERLNFAADIU3MUQA -SecretKey $SecretKey -StoreAs AWS.API.Profile
Initialize-AWSDefaults -ProfileName AWS.API.Profile -Region us-west-2
$SecretKey = $null
#Collect InstanceID from AWS, to use for querying the name tag
$InstanceID = (New-Object System.Net.WebClient).DownloadString("http://169.254.169.254/latest/meta-data/instance-id")
#Collect an object containing the existing hostname
$OrigName = $(hostname)
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Original Hostname: $OrigName"
$ComputerName = Find-InstanceName $InstanceID $DomCreds $EventLog

if (-not($ComputerName))
{
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Error -EventID 96 -Message "Unable to query AWS for Instance Name. Setting to $OrigName"
	$ComputerName = $OrigName
}
$DC = ((Get-ADDomainController -Discover -DomainName corporate.t-mobile.com).HostName)[0]
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Original Hostname: $OrigName"
#decipher between formatting options for $ComputerName
if ($ComputerName -like "*-*")
{
	$NameSplit = $ComputerName.split("-")
    $ComputerName = $null
	for($i = 0; $i -lt $($NameSplit.count); $i++)
	{
		$ComputerName += $NameSplit[$i]
	}
}
$AppID = $ComputerName.Substring(3,3)
$Environment = $ComputerName.Substring(0,3)
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "New Computer Name: $ComputerName"
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Environment set as: $Environment"
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "AppID set as: $AppID"

#Collect Network Configuration variables
$IfName = (Get-NetIPInterface -AddressFamily IPv4 -Dhcp Enabled).InterfaceAlias
$IfIndex = (Get-NetIPInterface -AddressFamily IPv4 -Dhcp Enabled).ifIndex
$IP = (Get-NetIPConfiguration -InterfaceIndex $IfIndex | Select-Object -ExpandProperty IPv4Address).IPv4Address
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "IP Address set as: $IP"
$Gateway = (Get-NetIPConfiguration -InterfaceIndex $IfIndex | Select-Object -ExpandProperty IPv4DefaultGateway).NextHop
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Gateway set as: $Gateway"
$DNSServers = @()
$DNS = @()
$DNS = Get-DnsClientServerAddress -InterfaceIndex $IfIndex | Select-Object -ExpandProperty ServerAddresses
for ($i=0; $i -lt ($DNS.count); $i++) 
{
    if($DNS.count -eq 1)
    {
		$DNSServers += $DNS
    }
    else
    {
	    $DNSServers += $DNS[$i]
        if ($i -lt ($DNS.count)-1) {$DNSServers += "," }
    }
}
#Set local system variable with AppID - will be used by GPO to determine appropriate admin users
[Environment]::SetEnvironmentVariable("AppID", "$AppID", "Machine")
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Environment Variable AppID set as: $AppID"
#Environmental variables 
$Domain = "Corporate.T-Mobile.com"
$ProdEnvArray = @('PRD', 'PQA', 'PST', 'AUX', 'DRP', 'COM', 'AUT', 'PPR')
$DevEnvArray = @('DEV', 'POC', 'UAT', 'TES', 'TST', 'SIT', 'UAT', 'PPD', 'TMP', 'REG')
#If these scripts (name, and domain join) are seperated, $AppID (used below)
#Will need to be set in the Join script based on the environmental variable
$ProdOU = "OU=$AppID,OU=Windows,OU=Production,OU=Servers,OU=Devices,DC=Corporate,DC=T-Mobile,DC=Com"
$DevOU = "OU=$AppID,OU=Windows,OU=Non-production,OU=Servers,OU=Devices,DC=Corporate,DC=T-Mobile,DC=Com"
$StageOU = "OU=Windows,OU=Staging,OU=Servers,OU=Devices,DC=Corporate,DC=T-Mobile,DC=Com"
$DMZOU = "OU=DMZ,OU=Windows,OU=Production,OU=Servers,OU=Devices,DC=External,DC=T-Mobile,DC=Com"


#...and action!

Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Preparing to modify IP configuration"
#remove existing IP configuration, then reconfigure new static IP configuration
Remove-NetIPAddress -IPAddress $IP -DefaultGateway $Gateway -Confirm:$false
New-NetIPAddress -InterfaceIndex $IfIndex -IPAddress $IP -PrefixLength 22 -DefaultGateway $Gateway -Confirm:$false
Set-DnsClientServerAddress -InterfaceIndex $IfIndex -ServerAddresses "$DNSServers" -Confirm:$false
Set-NetAdapterBinding -Name $IfName -DisplayName "Internet Protocol Version 6 (TCP/IPv6)" -Enabled:$false -Confirm:$false
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "IP modifications complete"

#Set time zone to PST
$process = New-Object System.Diagnostics.Process   
$process.StartInfo.WindowStyle = "Hidden"  
$process.StartInfo.FileName = "tzutil.exe"  
$process.StartInfo.Arguments = "/s `"Pacific Standard Time`""  
$process.Start() | Out-Null  
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "Time Zone Set"

#Evaluate the environment, and set the join location appropriately.
#IF the OU doesnt exist, it should be put into stage.
if ($ProdEnvArray -contains $Environment)
{
	$OU = $ProdOU
}
elseif ($DevEnvArray -contains $Environment)
{
	$OU = $DevOU
}
elseif ($Environment -eq "STG")
{
	$OU = $StageOU
}
elseif ($Environment -eq "DMZ")
{
	$OU = $DMZOU
	$Domain = "External.T-Mobile.com"
}
else
{
	$OU = $StageOU
}
#Confirm OU exists, otherwise put it in Stage.
try 
{
    $OUSearch = Get-ADObject -filter {ObjectClass -eq "organizationalUnit"} -SearchBase "OU=Servers,OU=Devices,DC=Corporate,DC=T-Mobile,DC=Com" -server $Domain -Credential $DomCreds
} 
catch 
{
    # If invalid format, error is thrown.
    Write-Debug ("Supplied Path is invalid.`n$_")
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Warning -EventID 25 -Message "OU location not found. Setting as Stage"
}
if (-not ($OUSearch.DistinguishedName -contains $OU))
{
    $OU = $StageOU
}
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 15 -Message "OU set as: $OU"
#Set Windows Update to automatic, then run updates.
cscript c:\Windows\system32\scregedit.wsf /au 4
Start-Sleep -s 1
$i = 0
do
{
    $i++ 
    $Update = Add-WindowsUpdate
}
while ($Update -ne $false)
try
{
	Start-Sleep -s 4
	#Join the domain with established details.
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 31 -Message "Preparing to join domain at `n Domain: $Domain `n OU: $OU `n ComputerName: $ComputerName"
	Add-Computer -DomainName $Domain -Server $DC -Credential $DomCreds -OuPath $OU -PassThru -NewName $ComputerName -Confirm:$false -force
	Set-ADComputer -identity $ComputerName -Credential $DomCreds -Add @{vmID = $InstanceID} -Server $DC -ErrorAction STOP
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 32 -Message "Successfully joined domain at `n Domain: $Domain `n OU: $OU `n ComputerName: $ComputerName"
}
catch
{
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Error -EventID 99 -Message "Domain join failed with error:`n$_"
}

try
{
	[ADSI]$server = "WinNT://localhost"
	$server.delete("user","badmin")
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 79 -Message "Local user (badmin) deleted."
}
catch
{
	Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Error -EventID 98 -Message "Unable to delete local user.`n$_"
}

Clear-AWSCredentials -ProfileName AWS.API.Profile
Clear-AWSDefaults
$DomCreds = $null
Write-EventLog -LogName $EventLog -Source $EventLog -EntryType Information -EventID 100 -Message "Script Complete"
rm c:\temp\configure-windowsami.ps1
#Test the execution Policy change...
Set-ExecutionPolicy Default -force
Restart-Computer