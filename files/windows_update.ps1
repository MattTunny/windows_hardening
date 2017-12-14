Import-Module PSWindowsUpdate
Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot -confirm:$false
