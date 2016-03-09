<#
Created 2016.01.26
Version 2016.01.26
By: Chris Spanton


Parameters:
	OwnerNTID 		- CORP NTID of the service account owner
	AccountName 	- Name of the service account
	OU 				- What OU to put the account in (POSIX, Windows, LDAPS)
	Description		- If this has an exception, must include FND # and RP #
	Lifespan		- In days. Default is 365.
	Interactive		- Currently not utilized
#>


[CmdletBinding()]
Param
(
	[Parameter(Mandatory=$True)]
	[string]$OwnerNTID,
	
	[Parameter(Mandatory=$True)]
	[string]$AccountName,	
	
	[Parameter(Mandatory=$True)]
	[string]$OU,	
	
	[Parameter(Mandatory=$True)]
	[string]$Description,	
	
	[Parameter(Mandatory=$False)]
	[string]$Lifespan = 365,
	
	[switch]$Interactive
)

function Get-RandomPassword 
{
    #Function receives parameters (length and characters) outputs random string
	param
	(
		$length = 10,
		$characters = 
		'abcdefghkmnprstuvwxyzABCDEFGHKLMNPRSTUVWXYZ123456789!"ยง$%&/()=?*+#_'
	)
	# select random characters
	$random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
	# output random pwd
	$private:ofs=""
	[String]$characters[$random]
}
function Randomize-Text 
{
    #Function will receive parameters (text) and randomize the order
	param
	(
		$text
	)
	$anzahl = $text.length -1
	$indizes = Get-Random -InputObject (0..$anzahl) -Count $anzahl
	
	$private:ofs=''
	[String]$text[$indizes]
}
function Get-ComplexPassword 
{
    #Function will call Get-RandomPassword, utilizing specific parameters, and concatenate
    #Function will then call Randomize-Text passing the output from Get-RandomPassword
	$password = Get-RandomPassword -length 8 -characters 'abcdefghiklmnprstuvwxyz'
	$password += Get-RandomPassword -length 8 -characters '#*+)'
	$password += Get-RandomPassword -length 8 -characters '123456789'
	$password += Get-RandomPassword -length 8 -characters 'ABCDEFGHKLMNPRSTUVWXYZ'
	
	Randomize-Text $password
}
function Clear-Exit
{
    #function will exit after clearing password variable
	Clear-Variable password
	exit
}

#Main

#Input Validation block
If ($AccountName.Substring(0,4) -ne "SVC_")
{
	Throw "Service account name must begin with `"SVC_`"."
}
If (-not ($OU -eq "POSIX" -Or $OU -eq "Windows" -Or $OU -eq "LDAPS"))
{
	Throw "OU $OU must equal POSIX LDAPS or Windows"
}
#Create object for owner
$Owner = Get-ADUser -Properties * -Identity $OwnerNTID	
If ($Owner.CN -eq $NULL)
{
	Throw  "Selected owner does not exist in corporate.t-mobile.com."
}
If (($Owner.EmployeeID).Substring(0,1) -ne "P")
{
	Throw "Selected owner must be a T-Mobile FTE."
}


$password = Get-ComplexPassword
$OUPath = "OU=$OU,OU=Production,OU=Services,OU=Accounts,DC=corporate,DC=t-mobile,DC=com"
$GivenName = ($AccountName.Split("_"))[1]
$Surname = ($AccountName.Split("_"))[2]

#set expiration date - default is 365 days
$ExpirationDate = ((Get-Date).date).AddDays($Lifespan)

#Create Corp service account in appropriate OU
Write-Host -ForegroundColor Green ("Creating $OU service account in Corporate.T-Mobile.Com")
Write-Host -ForegroundColor Red ("Service account created with interactive logon!")
New-ADUser -Name $AccountName `
-GivenName $GivenName `
-Surname $Surname `
-SamAccountName $AccountName `
-DisplayName $AccountName `
-Manager $Owner.DistinguishedName `
-Enabled $true `
-UserPrincipalName $($AccountName + "@corporate.t-mobile.com") `
-AccountExpirationDate $ExpirationDate `
-CannotChangePassword $True `
-PasswordNeverExpires $True `
-AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
-Path $OUPath `
-Description $Description `
-ErrorAction Stop

#enable unix login, if appropriate
If ($OU -eq "POSIX")
{
	Enable-QasUnixUser -UserName $AccountName
}
#If there is no email address for the owner, simply display the password
If ( -NOT $Owner.EmailAddress ) 
{ 
	Write-Host -ForegroundColor Red "No Email Address found for Owner"
	Write-Host -ForegroundColor Green "The password for $AccountName is: $password" 
}
Else 
{ 
	#Capture email address of admin running script for email FROM
	$AdminEmail = (Get-ADUser -Identity $([Environment]::Username) -Properties EmailAddress).EmailAddress

	Send-MailMessage -To $Owner.EmailAddress -From $AdminEmail -Cc $AdminEmail -SmtpServer PRDMSHUB05.GSM1900.ORG -Body "Congratulations. Your service account in the new CORPORATE domain has been created. The username is $AccountName. The password will arive shortly. It will be the only information in the body of the email." -Subject "New Account"
	Send-MailMessage -To $Owner.EmailAddress -From $AdminEmail -SmtpServer PRDMSHUB05.GSM1900.ORG -Body $password -Subject "New Account Part 2"
	Write-Host ("The password for $AccountName has been emailed to $($Owner.EmailAddress).")

}

Clear-Exit