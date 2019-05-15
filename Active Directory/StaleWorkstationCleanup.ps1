<#
	.SYNOPSIS
		Looks for all workstations in Active Directory that have not been connected to the network in over 90 days, disables and moves them to a segerated OU,
		then deletes any PC's that have not connected to AD in 120 days.

	.DESCRIPTION
		Queries all of Active Directory and moves any workstation that has not contacted the domain in over 90 days, after 120 they are deleted from AD.
		It records the LAPS password (local admin) and logs it.

	.NOTES
		The Active Directory module is required for this script to function, it is intended to 
		run as a scheduled task. 

#>

# Global Variables
Import-Module -Name ActiveDirectory

$Today = Get-Date -Format MM-dd-yyyy
$DaysToMove = 90 # Adjust to fit your needs
$MoveTime = (Get-Date).Adddays(- ($DaysToMove))
$DaysToDelete = 120 # Adjust to fit your needs
$DeleteTime = (Get-Date).Adddays(- ($DaysToDelete))

function Move-StaleWorkstations
{
	<#
		.SYNOPSIS
			This function searches through Active Directory and looks for any computer object that have not contacted AD in over 90 days. If any are found
			they are logged, disabled and moved to a segerated OU for the Remove-StaleWorkstations function to process

	#>

	$RecOldWorkstations = Get-ADComputer -Filter { LastLogonDate -lt $MoveTime } -SearchBase "OU=Workstations,DC=acme,DC=int" -Properties SamAccountName, LastLogonDate, ms-Mcs-AdmPwd 
	$RecOldWorkstations | Export-Csv "\\Path\to\Stale Workstation Automation\Moves\$Today.csv" -Append -Force
	Get-ADComputer -Filter { LastLogonDate -lt $MoveTime } -SearchBase "OU=Workstations,DC=acme,DC=int" | Disable-ADAccount -Confirm:$false | Move-ADObject -TargetPath "OU=Stale Workstations,DC=acme,DC=int" -Confirm:$false

}

Function Remove-StaleWorkstations
{
	<#
		.SYNOPSIS
			This function searches through the segerated OU that the Move-StaleWorkstations function moves computer objects to. If any of those workstations
			have not contacted Active Directory in over 120 days, they are logged and deleted from Active Directory.

	#>

	$RecOldWorkstations = Get-ADComputer -Filter { LastLogonDate -lt $DeleteTime } -SearchBase "OU=Stale Workstations,DC=acme,DC=int" -Properties SamAccountName, LastLogonDate, ms-Mcs-AdmPwd
	$RecOldWorkstations | Export-Csv "\\Path\to\Stale Workstation Automation\Deletes\$Today.csv" -Append -Force
	Get-ADComputer -Filter { LastLogonDate -lt $DeleteTime } -SearchBase "OU=Stale Workstations,DC=acme,DC=int" | Remove-ADObject -Confirm:$false

}

Move-StaleWorkstations
Remove-StaleWorkstations
