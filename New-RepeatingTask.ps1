<# 
.SYNOPSIS 
	Creates a new scheduled task (run by gMSA) which will repeat every 15 minutes for 1 day.
.DESCRIPTION 
	A parent Scheduled Task should call this. That task can be created to run daily, at say 11:00 PM.
    This then will create a new task to run once, for a day, repeating. 
    The end effect will be a task that runs every 15 minutes, forever.  
.EXAMPLE 
	Example Scheduled task, which is used to calls this script:

    $action = New-ScheduledTaskAction –Execute "PowerShell.exe" –Argument "-NoProfile -Command &{C:\temp\New-RepeatingTask.ps1}"
    $trigger = New-ScheduledTaskTrigger -At 01:00 -Daily 
    $principal = New-ScheduledTaskPrincipal -UserID CORP\svc_adds_gmsa$ -LogonType Password

    Register-ScheduledTask New-RepeatingTask –Action $action –Trigger $trigger –Principal $principal

.NOTES 
	Name: New-RepeatingTask
	Author: Chris Spanton 
	Created: 2016.02.19
	LastEdit: 2016.02.23
    Version History:

    2016.02.23
    ----------

    -Added logic to unregister task if it is existing at time of script run

#>

$Task = "Clean-RBACGroups"

try
{
    if (Get-ScheduledTask $Task -ErrorAction STOP)
    {
        Unregister-ScheduledTask $Task -Confirm:$false -ErrorAction STOP
    }
}
catch
{
    $CatchError = $_
}
$action = New-ScheduledTaskAction –Execute "PowerShell.exe" –Argument "-NoProfile -Command &{C:\temp\Clean-RBACGroups.ps1}"
$trigger = New-ScheduledTaskTrigger -Once -At 01:15 -RepetitionDuration  (New-TimeSpan -Days 1)  -RepetitionInterval  (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserID CORP\svc_adds_gmsa$ -LogonType Password

Register-ScheduledTask $Task –Action $action –Trigger $trigger –Principal $principal