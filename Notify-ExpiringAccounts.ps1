<# 
.SYNOPSIS 
	Sends notifications for expiring accounts. 
.DESCRIPTION 
	Sends notifications to owners of CORP service accounts which are expiring.
    Seperately sends notifications to user accounts which are expiring
	Uses several time bands to ensure multiple notifications are delivered before expiration.
.EXAMPLE 
	Runs unattended.
	"null" 
.NOTES 
	Name: Notify-ExpiringAccounts
	Author: Chris Spanton 
	Created: 2016.01.25
	LastEdit: 2016.02.18

	Script will use the Searchbase (OU=Services,OU=Accounts,DC=Corporate,DC=CONTOSO,DC=Com)
	to find domain service accounts set to expire soon.

	Soon is equal to the periods set in the array $Days (currently 90,60,30,14,7,1 days)

	Currently the script time-bands groups of users between identified days, 
	creating objects of each account.
	Script then emails the owner of accounts which tick over into a new time band.
	
	Version 2016.02.18:
		- Modified logging to write to the application event log $Log
#>

try
{
    $Log = "Notify-ExpiringAccounts"
	New-EventLog -LogName $Log -Source $Log -ErrorAction STOP
}
catch
{
	$NewLog = $_
}


#modifying this array will adjust the time bands for notification.
$Days = @(90, 60, 30, 14, 7, 3, 1, 0)
Write-EventLog -LogName $Log -Source $Log -EntryType Information -EventID 1 `
	-Message "Search: $(get-date)"

#This loops notifies the manager of an expiring service account.
for ($i = 0; $i -lt ($Days.Length-1); $i++)
{
	#actions in this loop are performed once per time band
	
    $ExpirationMax = ((Get-Date).date).AddDays($days[$i])
    $ExpirationMin = ((Get-Date).date).AddDays($days[$i+1])
    $Users = Get-ADUser `
                -filter {(AccountExpirationDate -le $ExpirationMax) -and (AccountExpirationDate -gt $ExpirationMin)} `
                -properties * `
                -SearchBase "OU=Services,OU=Accounts,DC=Corporate,DC=CONTOSO,DC=Com"
    foreach ($element in $users)
    {
		#actions in this loop are performed once per account which is within any time band
		
        If ($element.AccountExpirationDate.AddDays(1) -eq $ExpirationMax.AddDays(1))
        {
			#actions in this loop are performed once each time an account ticks into a new time band
			try
            {
			    $ManagerEmail = (Get-ADUser -Filter {DistinguishedName -eq $element.Manager} -Properties EmailAddress -ErrorAction STOP).EmailAddress
			    $Body = "A service account you own `(" + $element.sAMAccountName + "`) is set to expire in " + $days[$i] + " day`(s`)."
			    $Subject = "Service Account Expiring in " + $days[$i] + " day`(s`)!"
			    Send-MailMessage -To $ManagerEmail -From noreply@corporate.CONTOSO.com -SmtpServer PRDMSHUB05.CONTOSO.ORG -Body $Body -Subject $Subject -ErrorAction STOP
                Write-EventLog -LogName $Log -Source $Log -EntryType Warning -EventID 10 `
                    -Message "Found Service Account: $($element.sAMAccountName) | $($element.manager) | $($days[$i])"
            }
            catch
            {
                Write-EventLog -LogName $Log -Source $Log -EntryType Error -EventID 99 `
                    -Message "Error sending mail. `r`n$_"
            }
        }
    }
}


#This loop notifies individuals with an expiring account in the production OU
for ($i = 0; $i -lt ($Days.Length-1); $i++)
{
	#actions in this loop are performed once per time band
	
    $ExpirationMax = ((Get-Date).date).AddDays($days[$i])
    $ExpirationMin = ((Get-Date).date).AddDays($days[$i+1])
    $Users = Get-ADUser `
                -filter {(AccountExpirationDate -le $ExpirationMax) -and (AccountExpirationDate -gt $ExpirationMin)} `
                -properties * `
                -SearchBase "OU=Production,OU=Users,OU=Accounts,DC=corporate,DC=CONTOSO,DC=com"
    foreach ($element in $users)
    {
		#actions in this loop are performed once per account which is within any time band
		
        If ($element.AccountExpirationDate.AddDays(1) -eq $ExpirationMax.AddDays(1))
        {
			#actions in this loop are performed once each time an account ticks into a new time band
			try
            {
			    $ManagerEmail = $element.EmailAddress
			    $Body = "Your CORP domain account `(" + $element.sAMAccountName + "`) is set to expire in " + $days[$i] + " day`(s`)."
			    $Subject = "CORP Account Expiring in " + $days[$i] + " day`(s`)!"
			    Send-MailMessage -To $ManagerEmail -From noreply@corporate.CONTOSO.com -SmtpServer PRDMSHUB05.CONTOSO.ORG -Body $Body -Subject $Subject -ErrorAction STOP
                Write-EventLog -LogName $Log -Source $Log -EntryType Warning -EventID 11 `
                    -Message "Found User Account: $($element.sAMAccountName) | $($days[$i])"
            }
            catch
            {
                Write-EventLog -LogName $Log -Source $Log -EntryType Error -EventID 99 `
                    -Message "Error sending mail. `r`n$_"
            }
        }
    }
}