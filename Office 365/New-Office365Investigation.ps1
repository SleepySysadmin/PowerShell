<#
    .SYNOPSIS
        Script to gather and audit information pretaining to a forensic investigation. 

    .DESCRIPTION
        To assist in Office 365 investigation, this script assists investigators and engineers in finding malicious alterations to an Office 365 environment.
        The following information is gathered from all user mailboxes & MSOL accounts:
        - Mailbox forward addresses
        - Inbox Rules
        - Recent Exchange Online mail flow rules
        - Newly created MSOL Users
        - Newly created mailboxes
        - Recently added mobile devices
        - List all Global Administrators
    
    .NOTES
        Developed in PowerShell version 5.1. Office 365 and Exchange Online modules are required and must be connected to both prior to running controller
        script. Furthermore, you need to be able to query all mailboxes and MSOL Users in your Office 365 tenant; 
        Exchange Administrator and User Management Role at a minimum.

#>

# Global Variables
$today = Get-Date -Format MM-dd-yyyy
[int]$DaysToSearchBack = '90' # Edit this to suit your needs
$SearchDate = (Get-Date).AddDays(-$DaysToSearchBack)

function New-OutputDirectory
{
    # Root
    New-Item -Path $env:USERPROFILE\Desktop\ -ItemType Directory -Name "$today - Office 365 Investigation" -Verbose

    New-Item -Path "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\" -ItemType Directory -Name "Exchange Online Output" -Verbose -OutVariable ExchangeOnlineOutput
    New-Item -Path "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\" -ItemType Directory -Name "MSOL User Output" -Verbose -OutVariable MSOLUserOutput

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

    Function IR-Logwrite
    {
        Param ([string]$logstring)
        $IRLogfile = "$env:USERPROFILE\Desktop\$today - Office 365 Investigation\Exchange Online Output\InterestingInboxRules.txt"
        
        Add-content $IRLogfile -value $logstring
        
    }

    $Mailboxes = Get-Mailbox -Filter * -ResultSize Unlimited

    $i = 0
    $Total = $Mailboxes.count
    
    Foreach ($Mailbox in $Mailboxes)
    {

        Write-Progress -Activity "Checking Mailbox Inbox Rules..." -CurrentOperation $Mailbox -PercentComplete ($i/$Total * 100)
		$i++

        $InboxRules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName
        foreach ($InboxRule in $InboxRules)
        {
            $ID = $InboxRule.Identity
            # Going to be doing more text output to grab all data

            If ($InboxRule.DeleteMessage -eq $true)
            {

                Write-Output $ID
                IR-Logwrite " "
                IR-Logwrite "---------------------------------------------------------------------------"
                IR-Logwrite "The Inbox Rule from $ID deletes a message when processed:"
                IR-Logwrite "---------------------------------------------------------------------------"
                IR-Logwrite " "

                $String = $InboxRule | Format-List | Out-String

                IR-Logwrite $String

            }

            elseIf ($InboxRule.ForwardTo -ne $null)
            {

                Write-Output $ID
                IR-Logwrite " "
                IR-Logwrite "---------------------------------------------------------------------------"
                IR-Logwrite "The Inbox Rule from $ID forwards a message when processed:"
                IR-Logwrite "---------------------------------------------------------------------------"
                IR-Logwrite " "

                $String = $InboxRule | Format-List | Out-String

                IR-Logwrite $String

            }

            elseIf ($InboxRule.ForwardAsAttachment -ne $null)
            {

                Write-Output $ID
                IR-Logwrite " "
                IR-Logwrite "---------------------------------------------------------------------------"
                IR-Logwrite "The Inbox Rule from $ID forwards a message as an attachment when processed:"
                IR-Logwrite "---------------------------------------------------------------------------"
                IR-Logwrite " "

                $String = $InboxRule | Format-List | Out-String

                IR-Logwrite $String

            }

            else
            {
            
                $null
                
            }

        }

    }

}

function Get-MSOnlineData
{
    <#
        .SYNOPSIS
            Will gather the following data from this function:
                - Recently created MSOL Users
                - Members of all groups
    
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

# Start
Try
{
    Get-MsolDomain -ErrorAction Stop > $null
    
}
catch 
{
   write-error "You must call the Connect-MsolService cmdlet before calling any other cmdlets" 

}

# Warm and fuzzies
Write-Output "Beginning"
Write-Warning "Searching back $DaysToSearchBack days from today, $today..."
Start-Sleep -Seconds 5

New-OutputDirectory
#Get-ExchangeOnlineData
# Commenting this function out because it will take a very long time to run and will time out after a while. Uncomment the function if you wish to run it. Also advise running it on its own
Get-InterestingInboxRules
#Get-MSOnlineData

