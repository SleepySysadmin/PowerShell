<#
    .SYNOPSIS
        Script to gather and audit information pretaining to a forensic investigation. A new directory will be made on the users Desktop folder with todays date.
        Any relevent information will be sent there.  

    .DESCRIPTION
        To assist in Office 365 investigation, this script assists investigators and engineers in finding malicious alterations to an Office 365 environment.
        The following information is gathered from the Office 365 tenant:
        - Basic information and configuration data about the tenant
        - Mailbox forward addresses
        - Inbox Rules wityh questionable delete and forward actions
        - Recent Exchange Online mail flow rules
        - Newly created MSOL Users
        - Newly created mailboxes
        - Recently added mobile devices
        - List all MS Online role members

        This controller script is intended to be ran by an end user. 

        If Inbox rules are fetched, the script will refresh its connection with Office 365 every 150 mailboxes, prompting the end user to log back into Exchange Online.
        This is due to the shell timing out with Exchange Online since the Get-InboxRule cmdlet takes so long to run. 
    
    .NOTES
        Developed in PowerShell version 5.1. Office 365 and Exchange Online modules are required and must be connected to both prior to running controller
        script. Furthermore, you need to be able to query all mailboxes and MSOL Users in your Office 365 tenant; 
        Exchange Administrator and User Management Role at a minimum.

#>

# Global Variables
$today = Get-Date -Format MM-dd-yyyy
[int]$DaysToSearchBack = '90' # This can be changed to suit your needs
$SearchDate = (Get-Date).AddDays(-$DaysToSearchBack)

function New-OutputDirectory
{

    $DirCheck = Get-Item -Path "$env:USERPROFILE\Desktop\$today - Office 365 Investigation" -ErrorAction SilentlyContinue

    If ($DirCheck)
    {

        Write-Warning "Root directory already exists. Data will be appended to previous runs files."

    }

    else
    {
    
        New-Item -Path $env:USERPROFILE\Desktop\ -ItemType Directory -Name "$today - Office 365 Investigation"

        New-Item -Path "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\" -ItemType Directory -Name "Exchange Online Output"
        New-Item -Path "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\" -ItemType Directory -Name "MSOL User Output"
    }


}

function Get-TenantInformation
{
    Function TI-Logwrite
    {
        Param ([string]$logstring)
        $TILogfile = "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\TenantInformation.txt"
        
        Add-content $TILogfile -value $logstring
        
    }
    
    Write-Output "Collecting basic information about the tenant..."
    
    # Company Info
    $CompanyInformation = Get-MsolCompanyInformation

    TI-Logwrite " "
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite "Company Information:"
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite " "
    $String = $CompanyInformation | Out-String
    TI-Logwrite $String

    # Registerd Domains
    $Domains = Get-MsolDomain

    TI-Logwrite " "
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite "Registered Domain with MS Online:"
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite " "
    $string = $Domains | Out-String
    TI-Logwrite $String

    # Subscription info
    $SubInfo = Get-MsolSubscription | ft -AutoSize

    TI-Logwrite " "
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite "Subscription Information:"
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite " "
    $string = $SubInfo | Out-String
    TI-Logwrite $String

    # Exchange Online org config
    $OrgConfig = Get-OrganizationConfig

    TI-Logwrite " "
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite "Exchange Online Organization Configuration:"
    TI-Logwrite "---------------------------------------------------------------------------"
    TI-Logwrite " "
    $string = $OrgConfig| Out-String
    TI-Logwrite $String

    If ($OrgConfig.AuditDisabled -eq $true)
    {

        Write-Warning "Auditing is NOT enabled at the organization level!"
        Start-Sleep -Seconds 3

    }

}

function Get-ExchangeOnlineData
{
    <#
        .SYNOPSIS
            Will gather the following in this function. Each datasource will be in its own function:

                - Mailbox Forwarding Addresses (if not $null)
                - Recently Created Mailboxes
                - Recently Changed Global Mail Flow Rules
                - Recently Added Mobile Devices
    
    #>

    Function Get-MailboxData
    {
        

        $Mailboxes = Get-Mailbox -Filter * -ResultSize Unlimited

        $i = 0
        $Total = $Mailboxes.count

        Foreach ($Mailbox in $Mailboxes)
        {
            # Warm and Fuzzies
            Write-Progress -Activity "Gathering Mailbox Data..." -CurrentOperation $Mailbox -PercentComplete ($i/$Total * 100)
            $i++

            # Getting Mailboxes with forwarding addresses
            If ($Mailbox.ForwardingAddress -or $Mailbox.ForwardingSmtpAddress -ne $null)
            {

                $ForwardAddressProperties = [ordered]@{

                    MailboxAddress        = $mailbox.UserPrincipalName
                    MailboxType           = $mailbox.RecipientTypeDetails
                    WhenChanged           = $mailbox.WhenChanged
                    ForwardingAddress     = $Mailbox.ForwardingAddress
                    ForwardingSmtpAddress = $Mailbox.ForwardingSmtpAddress

                }

                $ForwardAddressesOutput = New-Object -TypeName System.Management.Automation.PSObject -Property $ForwardAddressProperties
                $ForwardAddressesOutput | Export-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\MailboxForwardingAddresses.csv" -Append -Force

            }

            # Getting recently created mailboxes
            If ($mailbox.whenCreated -gt $SearchDate)
            {

                $NewMailboxesProperties = [ordered]@{

                    MailboxAddress        = $Mailbox.UserPrincipalName
                    DisplayName           = $Mailbox.DisplayName
                    HiddenFromAddressBook = $Mailbox.HiddenFromAddressListsEnabled
                    MailboxType           = $Mailbox.RecipientTypeDetails
                    WhenCreated           = $Mailbox.WhenCreated

                }

                $NewMailboxesOutput = New-Object -TypeName System.Management.Automation.PSObject -Property $NewMailboxesProperties
                $NewMailboxesOutput | Export-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\NewMailboxes.csv" -Append -Force

            }

        }

    }

    Function Get-RecentTransportRules
    {

        Function TR-Logwrite
        {
            Param ([string]$logstring)
            $TRLogfile = "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\TransportRules.txt"
            
            Add-content $TRLogfile -value $logstring
            
        }

        $TransportRules = Get-TransportRule
        foreach ($TransportRule in $TransportRules)
        {

            If ($TransportRule.WhenChanged -gt $SearchDate)
            {

                $TransportName = $TransportRule.Name
                Write-Output "Recently altered transport rule discovered: $TransportName"

                # Outputing to a text file rather than a CSV because there is so much important data it makes more sense to capture it all.
                TR-Logwrite " "
                TR-Logwrite "---------------------------------------------------------------------------"
                TR-Logwrite "The Transport Rule $TransportName has been altered within the last $DaysToSearchBack days:"
                TR-Logwrite "---------------------------------------------------------------------------"
                TR-Logwrite " "

                $String = $TransportRule | Format-List | Out-String

                TR-Logwrite $String

            }

            else
            {

                $null

            }
            
        }

    }

    Function Get-RecentMobileDevices
    {

        $MobileDevices = Get-MobileDevice
        foreach ($Device in $MobileDevices)
        {

            If ($Device.WhenCreated -gt $SearchDate)
            {
                
                $MobileDeviceProperties = [ordered]@{

                    UserDisplayName = $Device.UserDisplayName
                    Identity        = $Device.Identity
                    DeviceType      = $Device.DeviceType
                    DeviceUserAgent = $Device.DeviceUserAgent
                    DeviceModel     = $Device.DeviceModel
                    WhenCreated     = $Device.WhenCreated
                    # Last sync time can be gathered via a different cmdlet, can be added upon request

                }

                $MobileDeviceOutput = New-Object -TypeName System.Management.Automation.PSObject -Property $MobileDeviceProperties
                $MobileDeviceOutput | Export-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\RecentMobileDevices.csv" -Append -Force                

            }

        }

    }

    # Start Gathering Exchange Online Data
    Get-MailboxData
    Get-RecentTransportRules
    Get-RecentMobileDevices

}

function Get-InterestingInboxRules
{
    <#
        .SYNOPSIS
            Checking all mailbox rules for the following:
                - Delete Message equal $True
                - Forward To not null
                - Forward as Attachment not null
    
    #>

    $Offset = 0
    $PageSize = 150

    Write-Output "Beginning to gather interesting inbox rules..."

    function New-Office365Connection
{
	Try
	{
		# Close any old remote session
		Get-PSSession | Remove-PSSession -Confirm:$false
		
		# Start a new Exchange Online session
        Connect-EXOPSSession

	}
	
	Catch
	{

		$Errorcode = $Error[0] | Select-Object -Property *
		Write-Error $Error[0]
		
	}
}

    Function IR-Logwrite
    {
        Param ([string]$logstring)
        $IRLogfile = "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\InterestingInboxRules.txt"
        
        Add-content $IRLogfile -value $logstring
        
    }

    $Mailboxes = Get-Mailbox -Filter * -ResultSize Unlimited | Export-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\AllMailboxes.csv" -Append -Force
    
    Do
    {
        
        $MailboxCount = (Import-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\AllMailboxes.csv").count
        $MailboxList = Import-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\AllMailboxes.csv" | Select-Object -Skip $Offset -First $PageSize
        
        Foreach ($Mailbox in $MailboxList)
        {

            $UPN = $Mailbox.UserPrincipalName
            Write-Output "Checking $UPN"

            $InboxRules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName
            foreach ($InboxRule in $InboxRules)
            {
                $ID = $InboxRule.Identity
                # Going to be doing more text output to grab all data

                If ($InboxRule.DeleteMessage -eq $true -and $InboxRule.SubjectOrBodyContainsWords -like "*Mail Delivery*" -or $InboxRule.SubjectOrBodyContainsWords -like "*could not be delivered*")
                {

                    Write-Warning "$ID was flagged for a questionable delete action"
                    IR-Logwrite " "
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite "The Inbox Rule from $ID deletes a message when processed:"
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite " "

                    $String = $InboxRule.Description | Format-List | Out-String

                    IR-Logwrite $String

                }

                elseIf ($InboxRule.DeleteMessage -eq $true -and $InboxRule.SubjectContainsWords -like "*Mail Delivery*" -or $InboxRule.SubjectContainsWords -like "*could not be delivered*")
                {

                    Write-Warning "$ID was flagged for a questionable delete action"
                    IR-Logwrite " "
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite "The Inbox Rule from $ID deletes a message when processed:"
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite " "

                    $String = $InboxRule.Description | Format-List | Out-String

                    IR-Logwrite $String

                }

                # Forward to an outside email with questionable keywords
                elseIf ($InboxRule.ForwardTo -like "*@*" -and $InboxRule.SubjectOrBodyContainsWords -like "*pay*" -or $InboxRule.SubjectOrBodyContainsWords -like "*invoice*" -or $InboxRule.SubjectOrBodyContainsWords -like "*wire*")
                {

                    Write-Warning "$ID was flagged for a questionable forward action"
                    IR-Logwrite " "
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite "The Inbox Rule from $ID forwards a message when processed:"
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite " "

                    $String = $InboxRule.Description | Format-List | Out-String

                    IR-Logwrite $String

                }
                
                # Forward to an outside email with questionable keywords
                elseIf ($InboxRule.ForwardTo -like "*@*" -and $InboxRule.SubjectContainsWords -like "*pay*" -or $InboxRule.SubjectContainsWords -like "*invoice*" -or $InboxRule.SubjectContainsWords -like "*wire*")
                {

                    Write-Warning "$ID was flagged for a questionable forward action"
                    IR-Logwrite " "
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite "The Inbox Rule from $ID forwards a message when processed:"
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite " "

                    $String = $InboxRule.Description | Format-List | Out-String

                    IR-Logwrite $String

                }

                # Forward to an outside email with questionable keywords
                elseIf ($InboxRule.ForwardAsAttachmentTo -like "*@*" -and $InboxRule.SubjectOrBodyContainsWords -like "*pay*" -or $InboxRule.SubjectOrBodyContainsWords -like "*invoice*" -or $InboxRule.SubjectOrBodyContainsWords -like "*wire*")
                {

                    Write-Warning "$ID was flagged"
                    IR-Logwrite " "
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite "The Inbox Rule from $ID forwards a message as an attachment when processed:"
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite " "

                    $String = $InboxRule.Description | Format-List | Out-String

                    IR-Logwrite $String

                }

                # Forward to an outside email with questionable keywords
                elseIf ($InboxRule.ForwardAsAttachmentTo -like "*@*" -and $InboxRule.SubjectContainsWords -like "*pay*" -or $InboxRule.SubjectContainsWords -like "*invoice*" -or $InboxRule.SubjectContainsWords -like "*wire*")
                {

                    Write-Warning "$ID was flagged"
                    IR-Logwrite " "
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite "The Inbox Rule from $ID forwards a message as an attachment when processed:"
                    IR-Logwrite "---------------------------------------------------------------------------"
                    IR-Logwrite " "

                    $String = $InboxRule.Description | Format-List | Out-String

                    IR-Logwrite $String

                }

                else
                {
                
                    $null
                    
                }

            }

        }

        #Increase the start point for the next chunk
        $Offset += $PageSize

        New-Office365Connection

    }


    While ($offset -lt $MailboxCount)

    Get-PSSession | Remove-PSSession

}

function Get-MSOnlineData
{
    <#
        .SYNOPSIS
            Will gather the following data from this function:
                - Recently created MSOL Users
                - Members of all administrative roles
    
    #>

    function Get-RecentMSOLUsers
    {

        $MSOLUsers = Get-Msoluser -All 

        $i = 0
        $Total = $MSOLUsers.count

        ForEach ($MSOLUser in $MSOLUsers)
        {
            # Warm and Fuzzies
            Write-Progress -Activity "Gathering MSOLUser Data..." -CurrentOperation $MSOLUser -PercentComplete ($i/$Total * 100)
            $i++

            If ($MSOLUser.WhenCreated -gt $SearchDate)
            {

                $MSOLUserProperties = [ordered]@{
                    UserPrincipalName = $MSOLUser.UserPrincipalName
                    DisplayName       = $MSOLUser.DisplayName
                    IsLicensed        = $MSOLUser.IsLicensed
                    WhenCreated       = $MSOLUser.WhenCreated
                }

                $MSOLUserOutput = New-Object -TypeName System.Management.Automation.PSObject -Property $MSOLUserProperties
                $MSOLUserOutput | Export-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\MSOL User Output\RecentMSOLUsers.csv" -Append -Force

            }

        }

    }

    function Get-AllMSOLRoleMemberships
    {

        $roles = Get-MsolRole | Sort-Object Name
        Foreach ($role in $roles)
        {
            $ID = $role.objectID
            $name = $role.Name

            $RoleMembers = Get-MsolRoleMember -RoleObjectId $ID -ErrorAction SilentlyContinue
            foreach ($RoleMember in $RoleMembers)
            {

                $RoleProperties = [ordered]@{
                    RoleName           = $name
                    MemberEmailAddress = $RoleMember.EmailAddress
                    MemberDisplayName  = $RoleMember.DisplayName
                }

                $RoleOutput = New-Object -TypeName System.Management.Automation.PSObject -Property $RoleProperties
                $RoleOutput | Export-Csv "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\MSOL User Output\MSOLRoleMembers.csv" -Append -Force

            }
            
        }

    }

    # Start gethering MSOnline Data
    Get-RecentMSOLUsers
    Get-AllMSOLRoleMemberships

}

Function Show-Menu
{

    Write-Output "---------------------------------------------"
    Write-Output "                                             "
    Write-Output "______       _____       _____       _____   "
    Write-Output "| ___ \     |  ___|     /  __ \     /  ___|  "
    Write-Output "| |_/ /     | |__       | /  \/     \ `--.   "
    Write-Output "| ___ \     |  __|      | |          `--. \  "
    Write-Output "| |_/ /  _  | |___   _  | \__/\  _  /\__/ /  "
    Write-Output "\____/  (_) \____/  (_)  \____/ (_) \____/   "
    Write-Output "                                             "
    Write-Output "     'Business Email Compromise Search'      "
    Write-Output "  An Office 365 Information Gathering Tool   "
    Write-Output "                                             "
    Write-Output "---------------------------------------------"
    
    $All = New-Object System.Management.Automation.Host.ChoiceDescription '&All', 'Gather Everything'
    $ExchangeOnlineData = New-Object System.Management.Automation.Host.ChoiceDescription '&ExchangeOnline', 'Exchange Online Data Only'
    $MSOnlineData = New-Object System.Management.Automation.Host.ChoiceDescription '&MSOnline', 'MSOnline Data Only'
    $InterestingInboxRules = New-Object System.Management.Automation.Host.ChoiceDescription '&InboxRules', 'Only Interesting Inbox Rules'
    
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $ExchangeOnlineData, $MSOnlineData, $InterestingInboxRules)
    $title = 'Please Select Run Option:'
    $message = 'What Office 365 Information would you like to gather?'
    $result = $host.ui.PromptForChoice($title, $message, $options, 0)


    # Ended up nesting the selection logic within the show-menu function. I cannot get the results variable to persist outside of this function.

    # Warm and fuzzies
    For ($i=5; $i -gt 1; $i--)
    {  

        Write-Progress -Activity "Searching back $DaysToSearchBack days from today, $today. Starting soon..." -SecondsRemaining $i
        Start-Sleep 1

    }
    Write-Output "Beginning..."

    If ($result -eq '0')
    {
        # Run Everything
        New-OutputDirectory
        Get-TenantInformation
        Get-ExchangeOnlineData
        Get-MSOnlineData
        Get-InterestingInboxRules

    }

    elseif ($result -eq '1')
    {
        # Just Exchange Online Data
        New-OutputDirectory
        Get-TenantInformation
        Get-ExchangeOnlineData
        
    }

    elseif ($result -eq '2')
    {
        # Just MS Online Data
        New-OutputDirectory
        Get-TenantInformation
        Get-MSOnlineData


    }

    elseif ($result -eq '3')
    {
        # Just Interesting Inbox Rules
        New-OutputDirectory
        Get-TenantInformation
        Get-InterestingInboxRules

    }

    else
    {

        Write-Error "No selection or invalid selection was made, exiting..."

    }


}

# Starting actual execution here
Show-Menu
