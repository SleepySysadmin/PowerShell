# B.E.C.S: Business Email Compromise Search tool 
```PowerShell

    ---------------------------------------------
                                                
    ______       _____       _____       _____   
    | ___ \     |  ___|     /  __ \     /  ___|  
    | |_/ /     | |__       | /  \/     \ `--.   
    | ___ \     |  __|      | |          `--. \  
    | |_/ /  _  | |___   _  | \__/\  _  /\__/ /  
    \____/  (_) \____/  (_)  \____/ (_) \____/   
                                                
    'Business Email Compromise Search'      
    An Office 365 Information Gathering Tool   
                                                
    ---------------------------------------------

```

---

## Synopsis
This tool was created with an incident response tech in mind. If you find yourself investigating a breach and you need
to gather any recent changes to an Office 365 tenant, this tool is for you. 



The following data is collected from this tool:
* Basic information about the Office 365 tenant
* Mailbox forward addresses
* Interesting Inbox Rules
    * Forwards to outside emails with interesting keywords
    * Deletes that try to hide non-deliverable notifications 
* Recently changed Exchange Online mail flow rules
* Newly created mailboxes
* Recently added mobile devices
* List all MS Online role members

Anything that was altered/changed in the above data (if applicable) in the last 90 days is pulled and recorded. 

This tool makes no alterations to the Office 365 tenant, nor does it make any
new objects. It collects data and outputs results in a new directory on the users desktop. 

It is recommended that your Office 365 tenant be actively monitored by the native tools, Splunk, Azure Sentinel, or other simular SIEM solutions. However, this tool can come in handy should some auditing or general investigating needs to be done. 

---

## Requirements
Several things are required prior to running this for an investigation:
* Rights to the Office 365/Exchange Online tenant 
* The Exchange Online PowerShell module
* The MSOnline PowerShell module

---

## Links
Links to assist in installing the needed modules:
* [Connecting to Exchange Online](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/connect-to-exchange-online-powershell?view=exchange-ps)

* [Connecting to Exchange Online with MFA](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps)

* [MSOnline PowerShell Module](https://www.powershellgallery.com/packages/MSOnline/1.1.183.57)
