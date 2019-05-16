<#
.SYNOPSIS
	Controller script to disable, move and remove group membership for AD accounts. Accounts are feed by a CSV that is produced by a ticketing system. 

.DESCRIPTION
	This controller script is intended to schedule and automate the termination on Active Directory users, upon seperation from the company.
	See each functions comment base help for more information on their roles. 

.NOTES
    Requires the active directory module, intended to run as a scheduled task. Developed in PowerShell version 5. 


#>
[CmdletBinding()]
Param ()

Import-Module ActiveDirectory

$timestamp = Get-Date -format yyyy-MM-dd
$LogFile = "\\path\for\Terminations_$timestamp.txt"

Function Logwrite
{
	Param ([string]$logstring)
	
	Add-content $Logfile -value $logstring
}

function Terminate-Users
{
<#
	.SYNOPSIS
		Function that terminates users and places them in spcefic OU's based on the access that is needed 

	.DESCRIPTION
		This function terminates users and treates user accounts differently based on the access that is outlined in the CSV.
		If Mailbox Access and/or OneDrive access is requested, the account is disabled, the last day of work is prepended in the users 
		Description field, and it is placed in a segerated OU that is being synced with Office 365 (to be processed later by the Remove-DisabledUsers function); 
		the Out of Office is also setfor that users mailbox and mailbox access is grantd automaticly. If no access is requested, its group membership gets recorded
		and it is deleted from Active Directory. 

		This does need to connect to Exchange Online, see the .LINK for a guide to securily store logon information for automated processes
	
	.LINK
		https://www.pdq.com/blog/secure-password-with-powershell-encrypting-credentials-part-2/

	.NOTES
		This is intended to run as part of a controller script. A connection to Exchange Online and Active Directory is required. 

#>
	[CmdletBinding()]
	Param ()
	
	Logwrite "***Beginning the function Terminate-Users***"
	Try
	{

		Import-Module -Name ActiveDirectory

		$User = "MyUserName"
		$PasswordFile = "\\Machine1\SharedPath\Password.txt"
		$KeyFile = "\\Machine1\SharedPath\AES.key"
		$key = Get-Content $KeyFile
		$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential `
								   -ArgumentList $User, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)
		$MsolConnectSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell -Authentication Basic -AllowRedirection -Credential $MyCredential
		Connect-MsolService -Credential $MyCredential
		Import-PSSession $MsolConnectSession

	}
	Catch
	{

		Write-Error "[Error] - Modules and variables failed to load for the Terminate Users Function! See Error below:"
		Write-Error $Error[0]
		Logwrite "[Error] - Modules and variables failed to load for the Terminate Users Function! See Error below:"
		Logwrite $Error[0]

	}
	
	Import-Csv "\\Path\to\DailyTerminations.csv" | ForEach-Object {
		
		$TicketNumber = $_.TicketNumber
		$samAccountName = $_.username
		$lastdayofwork = $_.LastDayOfWork
		$MailboxAccess1 = Get-ADUser -Filter { DisplayName -eq $_.MailboxWhoNeedsAccess } # First user that needs mailbox access
		$MailboxAccess2 = Get-ADUser -Filter { DisplayName -eq $_.MailboxWhoNeedsAccess2 } # Second user that needs mailbox access
		
		$OldDesc = Get-ADUser -Identity $samAccountName -Properties Description
		$ADLoc = Get-ADUser -Identity $samAccountName | Select-Object DistinguishedName
		
		Logwrite " "
		Logwrite "Processing $samAccountName, Ticket number: $TicketNumber."
		
		If ($ADloc.DistinguishedName -like "*OU=DisabledUsers,OU=CompanyUsers,DC=acme,DC=int*")
		{
			# In the off chance your ticketing system spits out the same user two days in a row (I've seen some things, man)
			Logwrite "$samAccountName has already been disabled!"; return

		}
		Elseif ($OldDesc.Description -notlike "*$lastdayofwork*" -and $_.MailboxAccessNeeded -eq "Yes" -or $_.OneDriveNeeded -eq "Yes")
		{

			# If mailbox access is needed the account is moved to Disabled users and mail/ODFB is avaiable for 30 days
			$OutofOfficeMessage = Get-Content "\\path\to\OutOfOffice.html"
			$User = Get-ADUser -Identity $samAccountName -Properties UserPrincipalName
			
			Get-ADUser -Identity $samAccountName | Disable-ADAccount
			Logwrite "$samaccountname has been disabled and moved to the Disabled Users OU for 30 days."
			Get-ADUser -Identity $samAccountName -Properties Description | Set-ADUser -Description "$lastdayofwork, $($OldDesc.Description)"
			Get-ADUser -Identity $samAccountName | Move-ADObject -TargetPath "OU=DisabledUsers,OU=CompanyUsers,DC=acme,DC=int"
			
			# Sets the Out of Office for the user
			Set-MailboxAutoReplyConfiguration -Identity $User.UserPrincipalName -AutoReplyState Enabled -InternalMessage $OutofOfficeMessage -ExternalMessage $OutofOfficeMessage
			
			# Adds mailbox permisisons 
			Add-MailboxPermission -Identity $User.UserPrincipalName -User $MailboxAccess1.UserPrincipalName -AccessRights FullAccess -AutoMapping:$True
			
			If ($_.MailboxWhoNeedsAccess2 -ne "")
			{
				
				Add-MailboxPermission -Identity $User.UserPrincipalName -User $MailboxAccess2.UserPrincipalName -AccessRights FullAccess -AutoMapping:$True
				
			}
			
		}
		ElseIf ($_.MailboxAccessNeeded -eq "No" -and $_.OneDriveNeeded -eq "No")
		{

			# If no mailbox/ODFB access is needed, the group membership gets recorded and the account is deleted from AD
			$ADGroupRec = Get-ADPrincipalGroupMembership -Identity $samAccountName | Select-Object Name | Out-String
			Logwrite "There is no access requested for the user $samaccountname. This account will be deleted from Active Directory"
			Logwrite "$samAccountName has been removed from the following groups:"
			Logwrite $ADGroupRec
			Get-ADUser -Identity $samAccountName | Remove-ADObject -Confirm:$false

		}
		Logwrite " "

	}

	Remove-PSSession $MsolConnectSession

}

function Remove-DisabledUsers
{
	<#
	.SYNOPSIS
		Function that processes seperated users that have had access requested. Takes the last day of work in the Description field and checks
		it has been over 30 days. If so, the account is deleted from Active Directory.

	.LINK
		https://youtu.be/gENVB6tjq_M

	.NOTES
		This is intended to run as part of a controller script and the Active Directory module is required. 

	#>

	Logwrite "***Begining the function Remove-DisabledUsers***"
	Logwrite " "
	$DisabledUsers = Get-ADUser -Filter * -SearchBase "OU=DisabledUsers,OU=CompanyUsers,DC=acme,DC=int" -Properties *
	ForEach ($User in $DisabledUsers)
	{
		
		$samAccountName = $User.samAccountName
		[datetime]$LastDayofWork = ($User.Description -split ' ')[0]
		$MoveDay = (get-date).adddays(-30) # Change the days as you see fit.
		$ADGroupRec = Get-ADPrincipalGroupMembership -Identity $samAccountName | Select-Object Name | Out-String
		
		If ($LastDayofWork -le $MoveDay)
		{

			Logwrite "Deleting the account $samAccountName, its been 30 days."
			Logwrite " "
			Logwrite "$samAccountName has been removed from the following groups:"
			Logwrite $ADGroupRec
			Get-ADUser -Identity $samAccountName | Remove-ADObject -Confirm:$false

		}
		Else
		{

			$null

		}
		
	}
	Logwrite " "
	
}

Logwrite "Start Script"

Terminate-Users
Remove-DisabledUsers
Logwrite " "
Logwrite "End Script"
