# # encoding: utf-8

# Inspec test for recipe

# The Inspec reference, with examples and extensive documentation, can be
# found at http://inspec.io/docs/reference/resources/

# WinLogon Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon') do
  its('PasswordExpiryWarning') { should eq 14 }
  its('ScreenSaverGracePeriod') { should eq '5' }
  its('AllocateDASD') { should eq '0' }
  its('ScRemoveOption') { should eq '1' }
  its('CachedLogonsCount') { should eq '4' }
  its('ForceUnlockLogon') { should eq 1 }
end

# LSA tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa') do
  its('FullPrivilegeAuditing') { should eq [0o0] }
  its('AuditBaseObjects') { should eq 0 }
  its('scenoapplylegacyauditpolicy') { should eq 1 }
  its('DisableDomainCreds') { should eq 1 }
  its('LimitBlankPasswordUse') { should eq 1 }
  its('CrashOnAuditFail') { should eq 0 }
  its('RestrictAnonymousSAM') { should eq 1 }
  its('RestrictAnonymous') { should eq 1 }
  its('SubmitControl') { should eq 0 }
  its('ForceGuest') { should eq 0 }
  its('EveryoneIncludesAnonymous') { should eq 0 }
  its('NoLMHash') { should eq 1 }
  its('SubmitControl') { should eq 0 }
  its('LmCompatibilityLevel') { should eq 5 }
end

# LSA Pku2 tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u') do
  its('AllowOnlineID') { should eq 0 }
end

# FIPS FIPSAlgorithmPolicy Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy') do
  its('Enabled') { should eq 0 }
end

# Netlogon Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters') do
  its('MaximumPasswordAge') { should eq 30 }
  its('DisablePasswordChange') { should eq 0 }
  its('RefusePasswordChange') { should eq 0 }
  its('SealSecureChannel') { should eq 1 }
  its('RequireSignOrSeal') { should eq 1 }
  its('SignSecureChannel') { should eq 1 }
  its('RequireStrongKey') { should eq 1 }
  its('RestrictNTLMInDomain') { should eq 7 }
  its('AuditNTLMInDomain') { should eq 7 }
end

# TCPIP v4 Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
  its('DisableIPSourceRouting') { should eq 2 }
  its('TcpMaxDataRetransmissions') { should eq 3 }
end

# TCPIP v6 Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
  its('DisableIPSourceRouting') { should eq 2 }
  its('TcpMaxDataRetransmissions') { should eq 3 }
end

# Audit Process Creation
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
  its('ProcessCreationIncludeCmdLine_Enabled') { should eq 0 }
end

# Ensure 'Network Security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1,AES256_HMAC_SHA1, Future encryption types'
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
  its('supportedencryptiontypes') { should eq 2_147_483_644 }
end

# Windows System Policies Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System') do
  its('ConsentPromptBehaviorUser') { should eq 0 }
  its('EnableLUA') { should eq 1 }
  its('PromptOnSecureDesktop') { should eq 1 }
  its('NoConnectedUser') { should eq 3 }
  its('EnableVirtualization') { should eq 1 }
  its('EnableUIADesktopToggle') { should eq 0 }
  its('ConsentPromptBehaviorAdmin') { should eq 2 }
  # its('LocalAccountTokenFilterPolicy') { should eq 1 } #Removed due to breaking Test-Kitchen
  its('EnableSecureUIAPaths') { should eq 1 }
  its('FilterAdministratorToken') { should eq 1 }
  its('MaxDevicePasswordFailedAttempts') { should eq 10 }
  its('DontDisplayLastUserName') { should eq 1 }
  its('DontDisplayLockedUserId') { should eq 3 }
  its('InactivityTimeoutSecs') { should eq 900 }
  its('EnableInstallerDetection') { should eq 1 }
  its('DisableCAD') { should eq 0 }
  its('ShutdownWithoutLogon') { should eq 0 }
  its('legalnoticecaption') { should eq 'Company Logon Warning' }
  its('legalnoticetext') do
    should eq 'Unauthorised access message.'
  end
end

# LanMan Server Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters') do
  its('enablesecuritysignature') { should eq 1 }
  its('requiresecuritysignature') { should eq 1 }
  its('RestrictNullSessAccess') { should eq 1 }
  its('enableforcedlogoff') { should eq 1 }
  its('autodisconnect') { should eq 15 }
  its('SMBServerNameHardeningLevel') { should eq 1 }
end

# Lanman Workstations Tests
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
  its('RequireSecuritySignature') { should eq 1 }
  its('EnableSecuritySignature') { should eq 1 }
  its('EnablePlainTextPassword') { should eq 0 }
end

# LDAP Client Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP') do
  its('LDAPClientIntegrity') { should eq 1 }
end

# LDAP Server Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters') do
  its('LDAPServerIntegrity') { should eq 2 }
end

# Session Manager Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager') do
  its('ProtectionMode') { should eq 1 }
  its('SafeDllSearchMode') { should eq 1 }
end

# EMET (IE)Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
  its('IE') { should eq '*\Internet Explorer\iexplore.exe' }
  its('7z') { should eq '*\7-Zip\7z.exe -EAF' }
  its('7zFM') { should eq '*\7-Zip\7zFM.exe -EAF' }
  its('7zGUI') { should eq '*\7-Zip\7zG.exe -EAF' }
  its('Access') { should eq '*\OFFICE1*\MSACCESS.EXE' }
  its('Acrobat') { should eq '*\Adobe\Acrobat*\Acrobat\Acrobat.exe' }
  its('AcrobatReader') { should eq '*\Adobe\Reader*\Reader\AcroRd32.exe' }
  its('Chrome') { should eq '*\Google\Chrome\Application\chrome.exe -SEHOP' }
  its('Excel') { should eq '*\OFFICE1*\EXCEL.EXE' }
  its('Firefox') { should eq '*\Mozilla Firefox\firefox.exe' }
  its('FirefoxPluginContainer') { should eq '*\Mozilla Firefox\plugin-container.exe' }
  its('FoxitReader') { should eq '*\Foxit Reader\Foxit Reader.exe' }
  its('GoogleTalk') { should eq '*\Google\Google Talk\googletalk.exe -DEP -SEHOP' }
  its('InfoPath') { should eq '*\OFFICE1*\INFOPATH.EXE' }
  its('iTunes') { should eq '*\iTunes\iTunes.exe' }
  its('jre6_java') { should eq '*\Java\jre6\bin\java.exe -HeapSpray' }
  its('jre6_javaw') { should eq '*\Java\jre6\bin\javaw.exe -HeapSpray' }
  its('jre6_javaws') { should eq '*\Java\jre6\bin\javaws.exe -HeapSpray' }
  its('jre7_java') { should eq '*\Java\jre7\bin\java.exe -HeapSpray' }
  its('jre7_javaw') { should eq '*\Java\jre7\bin\javaw.exe -HeapSpray' }
  its('jre7_javaws') { should eq '*\Java\jre7\bin\javaws.exe -HeapSpray' }
  its('jre8_java') { should eq '*\Java\jre1.8*\bin\java.exe -HeapSpray' }
  its('jre8_javaw') { should eq '*\Java\jre1.8*\bin\javaw.exe -HeapSpray' }
  its('jre8_javaws') { should eq '*\Java\jre1.8*\bin\javaws.exe -HeapSpray' }
  its('LiveWriter') { should eq '*\Windows Live\Writer\WindowsLiveWriter.exe' }
  its('Lync') { should eq '*\OFFICE1*\LYNC.EXE' }
  its('LyncCommunicator') { should eq '*\Microsoft Lync\communicator.exe' }
  its('mIRC') { should eq '*\mIRC\mirc.exe' }
  its('Opera') { should eq '*\Opera\opera.exe' }
  its('Outlook') { should eq '*\OFFICE1*\OUTLOOK.EXE' }
  its('PhotoGallery') { should eq '*\Windows Live\Photo Gallery\WLXPhotoGallery.exe' }
  its('Photoshop') { should eq '*\Adobe\Adobe Photoshop CS*\Photoshop.exe' }
  its('Picture Manager') { should eq '*\OFFICE1*\OIS.EXE' }
  its('Pidgin') { should eq '*\Pidgin\pidgin.exe' }
  its('PowerPoint') { should eq '*\OFFICE1*\POWERPNT.EXE' }
  its('PPTViewer') { should eq '*\OFFICE1*\PPTVIEW.EXE' }
  its('Publisher') { should eq '*\OFFICE1*\MSPUB.EXE' }
  its('QuickTimePlayer') { should eq '*\QuickTime\QuickTimePlayer.exe' }
  its('RealConverter') { should eq '*\Real\RealPlayer\realconverter.exe' }
  its('RealPlayer') { should eq '*\Real\RealPlayer\realplay.exe' }
  its('Safari') { should eq '*\Safari\Safari.exe' }
  its('SkyDrive') { should eq '*\SkyDrive\SkyDrive.exe' }
  its('Skype') { should eq '*\Skype\Phone\Skype.exe -EAF' }
  its('Thunderbird') { should eq '*\Mozilla Thunderbird\thunderbird.exe' }
  its('ThunderbirdPluginContainer') { should eq '*\Mozilla Thunderbird\plugin-container.exe' }
  its('UnRAR') { should eq '*\WinRAR\unrar.exe' }
  its('Visio') { should eq '*\OFFICE1*\VISIO.EXE' }
  its('VisioViewer') { should eq '*\OFFICE1*\VPREVIEW.EXE' }
  its('VLC') { should eq '*\VideoLAN\VLC\vlc.exe' }
  its('Winamp') { should eq '*\Winamp\winamp.exe' }
  its('WindowsLiveMail') { should eq '*\Windows Live\Mail\wlmail.exe' }
  its('WindowsMediaPlayer') { should eq '*\Windows Media Player\wmplayer.exe -SEHOP -EAF -MandatoryASLR' }
  its('WinRARConsole') { should eq '*\WinRAR\rar.exe' }
  its('WinRARGUI') { should eq '*\WinRAR\winrar.exe' }
  its('WinZip') { should eq '*\WinZip\winzip32.exe' }
  its('Winzip64') { should eq '*\WinZip\winzip64.exe' }
  its('Word') { should eq '*\OFFICE1*\WINWORD.EXE' }
  its('Wordpad') { should eq '*\Windows NT\Accessories\wordpad.exe' }
end

# EMET (IE)Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings') do
  its('DEP') { should eq 2 }
end

# Session Management Kernal Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel') do
  its('ObCaseInsensitive') { should eq 1 }
end

# WDigest Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest') do
  its('UseLogonCredential') { should eq 0 }
end

# Memory Management Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management') do
  its('ClearPageFileAtShutdown') { should eq 1 }
end

# RecoveryConsole Parameters Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole') do
  its('setcommand') { should eq 0 }
  its('securitylevel') { should eq 0 }
end

# Event Log Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security') do
  its('WarningLevel') { should eq 90 }
end

# Cryptography Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography') do
  its('ForceKeyProtection') { should eq 2 }
end

# Lanman Print Drivers Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers') do
  its('AddPrinterDrivers') { should eq 1 }
end

# CodeIdentifiers Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers') do
  its('authenticodeenabled') { should eq 0 }
end

# rubocop:disable all
# AllowedPaths Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths') do
  its('Machine') { should include /(System\\CurrentControlSet\\Control\\Print\\Printers)/ }
end

# AllowedExactPaths Test
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths') do
  its('Machine') { should include /(System\\CurrentControlSet\\Control\\ProductOptions)/ }
end

# rubocop:enable all
# WinRS Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS') do
  its('AllowRemoteShellAccess') { should eq 1 }
end

# Search Companion prevented from automatically downloading content updates.
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion') do
  its('DisableContentFileUpdates') { should eq 1 }
end

# SQMC Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows') do
  its('CEIPEnable') { should eq 0 }
end

# Disable Microsoft Online Accounts Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount') do
  its('value') { should eq 0 }
end

# Disable Windows Store
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore') do
  its('AutoDownload') { should eq 4 }
  its('DisableOSUpgrade') { should eq 1 }
end

# Disable Network SelectionUI Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System') do
  its('DontDisplayNetworkSelectionUI') { should eq 1 }
  its('DontEnumerateConnectedUsers') { should eq 1 }
  its('EnumerateLocalUsers') { should eq 0 }
  its('DisableLockScreenAppNotifications') { should eq 1 }
  its('AllowDomainPINLogon') { should eq 0 }
  its('EnableSmartScreen') { should eq 2 }
end

# Windows Error Reporting
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting') do
  its('AutoApproveOSDumps') { should eq 0 }
end

# Windows Consent
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent') do
  its('DefaultConsent') { should eq 1 }
end

# UAC Elevation TesT
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer') do
  its('AlwaysInstallElevated') { should eq 0 }
  its('EnableUserControl') { should eq 0 }
end

# Disable SkyDrive
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SkyDrive') do
  its('DisableFileSync') { should eq 1 }
end

# Audit Application Log Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application') do
  its('MaxSize') { should eq 32_768 }
  its('Retention') { should eq '0' }
end

# Audit Security Log Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security') do
  its('MaxSize') { should eq 196_608 }
  its('Retention') { should eq '0' }
end

# Audit System Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System') do
  its('MaxSize') { should eq 32_768 }
  its('Retention') { should eq '0' }
end

# Audit Setup Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup') do
  its('MaxSize') { should eq 32_768 }
  its('Retention') { should eq '0' }
end

# Auto Mount CD Drive Tests
describe registry_key('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
  its('NoDriveTypeAutoRun') { should eq 255 }
  its('NoPublishingWizard') { should eq 1 }
  its('NoAutorun') { should eq 1 }
  its('PreXPSP2ShellProtocolBehavior') { should eq 0 } # 18.9.30.5 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
end

# RDP encryption Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
  its('MinEncryptionLevel') { should eq 3 }
  its('fAllowUnsolicited') { should eq 0 }
  its('DeleteTempDirsOnExit') { should eq 1 }
  its('DisablePasswordSaving') { should eq 1 }
  its('fPromptForPassword') { should eq 1 }
  its('fAllowToGetHelp') { should eq 0 }
  its('fDisableCdm') { should eq 1 }
  its('fEncryptRPCTraffic') { should eq 1 }
  its('PerSessionTempDir') { should eq 1 }
end

# Index of Encryption Files Test
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
  its('AllowIndexingEncryptedStoresOrItems') { should eq 0 }
end

# Personalization Lock screen Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization') do
  its('NoLockScreenSlideshow') { should eq 1 }
  its('NoLockScreenCamera') { should eq 1 }
end

# Personalization Lock screen Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client') do
  its('CEIP') { should eq 2 }
end

# Turn off Windows Update device driver searching Test
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching') do
  its('DontSearchWindowsUpdate') { should eq 1 }
end

# PowerShell Settings
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
  its('EnableScriptBlockLogging') { should eq 0 }
end
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription') do
  its('EnableTranscripting') { should eq 0 }
end

# Credential User Interface # 18.9.13.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'
# 18.9.15.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI') do
  its('DisablePasswordReveal') { should eq 1 }
  its('EnumerateAdministrators') { should eq 0 }
end

# NetBIOS over TCP/IP Parameters
describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters') do
  its('nonamereleaseondemand') { should eq 1 }
end

# Domain User for network path
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections') do
  its('NC_StdDomainUserSetLocation') { should eq 1 }
  its('NC_AllowNetBridge_NLA') { should eq 0 }
end

# Hardening Network Paths
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
  its('\\\*\NETLOGON') { should eq 'RequireMutualAuthentication=1,RequireIntegrity=1' }
  its('\\\*\SYSVOL') { should eq 'RequireMutualAuthentication=1,RequireIntegrity=1' }
end

# Windows Connection Manager - Minimize the number of simultaneousconnections to the Internet
describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
  its('fMinimizeConnections') { should eq 1 }
end

# Disable old protocols TLS 1.0
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.0\Server') do
  its('Enabled') { should eq 0 }
end

# Disable old protocols TLS 1.1
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.1\Server') do
  its('Enabled') { should eq 0 }
end

# Disable old protocols sslv3 client
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Client') do
  its('DisabledByDefault') { should eq 1 }
end

# Disable old protocols sslv3 server
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Server') do
  its('Enabled') { should eq 0 }
end

# Disable old protocols PCT 1.0
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\PCT 1.0\Server') do
  its('Enabled') { should eq 0 }
end

# Disable old protocols SSLv2.0
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 2.0\Server') do
  its('Enabled') { should eq 0 }
end

# Disable Weak Ciphers - DES
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56') do
  its('Enabled') { should eq 0 }
end

# Disable Weak Ciphers - NULL
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL') do
  its('Enabled') { should eq 0 }
end

# Disable Weak Ciphers - RC2 40/128
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128') do
  its('Enabled') { should eq 0 }
end

# Disable Weak Ciphers - RC2 56/128
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128') do
  its('Enabled') { should eq 0 }
end

# Disable Weak Ciphers - RC4 40/128
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128') do
  its('Enabled') { should eq 0 }
end

# Disable Weak Ciphers - RC4 56/128
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128') do
  its('Enabled') { should eq 0 }
end

# Disable Weak Ciphers - RC4 64/128
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128') do
  its('Enabled') { should eq 0 }
end

# Disallow Autoplay for non-volume devices
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
  its('NoAutoplayfornonVolume') { should eq 1 }
  its('NoDataExecutionPrevention') { should eq 0 }
  its('NoHeapTerminationOnCorruption') { should eq 0 }
end

# 18.8.19.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
  its('NoBackgroundPolicy') { should eq 0 }
  its('NoGPOListChanges') { should eq 0 }
end

# Early Launch Antimalware
# 18.8.12.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to'Enabled: Good, unknown and bad but critical'
describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch') do
  its('DriverLoadPolicy') { should eq 1 }
end

# 18.8.32 Remote Procedure Call
# Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
# DO NOT APPLY TO DOMAIN CONTROLLER - Breaks One-way trust
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
  its('EnableAuthEpResolution') { should eq 1 }
end

# 18.9.53 RSS Feeds
# 18.9.53.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
# Internet Explorer
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
  its('DisableEnclosureDownload') { should eq 1 }
end

# 18.9.90.4 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
# Windows Update Force reboot if users are logged on
# Windows Update
describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU') do
  its('NoAutoRebootWithLoggedOnUsers') { should eq 0 }
end

# Local Policy Script
script = <<-EOH
secedit /export /cfg c:\\temp\\tempexport.inf /quiet
Get-content C:\\temp\\tempexport.inf | findstr /B `
/C:"MinimumPasswordAge = 1" `
/C:"MaximumPasswordAge = 42" `
/C:"MinimumPasswordLength = 14" `
/C:"PasswordComplexity = 1" `
/C:"PasswordHistorySize = 24" `
/C:"LockoutBadCount = 10" `
/C:"ResetLockoutCount = 15" `
/C:"LockoutDuration = 15" `
/C:"SeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544" `
/C:"SeServiceLogonRight = *S-1-5-80-0" `
/C:"SeInteractiveLogonRight = *S-1-5-32-544" `
/C:"SeSecurityPrivilege = *S-1-5-32-544" `
/C:"SeSystemEnvironmentPrivilege = *S-1-5-32-544" `
/C:"SeProfileSingleProcessPrivilege = *S-1-5-32-544" `
/C:"SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20" `
/C:"SeRestorePrivilege = *S-1-5-32-544" `
/C:"SeShutdownPrivilege = *S-1-5-32-544" `
/C:"SeTakeOwnershipPrivilege = *S-1-5-32-544" `
/C:"SeDenyNetworkLogonRight = *S-1-5-32-546" `
/C:"SeDenyBatchLogonRight = *S-1-5-32-546" `
/C:"SeDenyServiceLogonRight = *S-1-5-32-546" `
/C:"SeDenyInteractiveLogonRight = *S-1-5-32-546"
del "C:\\temp\\tempexport.inf" -force -ErrorAction SilentlyContinue
EOH

# Local Policy Tester
describe powershell(script) do
  its('stdout') do
    should eq "MinimumPasswordAge = 1\r
MaximumPasswordAge = 42\r
MinimumPasswordLength = 14\r
PasswordComplexity = 1\r
PasswordHistorySize = 24\r
LockoutBadCount = 10\r
ResetLockoutCount = 15\r
LockoutDuration = 15\r
SeNetworkLogonRight = *S-1-5-11,*S-1-5-32-544\r
SeServiceLogonRight = *S-1-5-80-0\r
SeInteractiveLogonRight = *S-1-5-32-544\r
SeSecurityPrivilege = *S-1-5-32-544\r
SeSystemEnvironmentPrivilege = *S-1-5-32-544\r
SeProfileSingleProcessPrivilege = *S-1-5-32-544\r
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20\r
SeRestorePrivilege = *S-1-5-32-544\r
SeShutdownPrivilege = *S-1-5-32-544\r
SeTakeOwnershipPrivilege = *S-1-5-32-544\r
SeDenyNetworkLogonRight = *S-1-5-32-546\r
SeDenyBatchLogonRight = *S-1-5-32-546\r
SeDenyServiceLogonRight = *S-1-5-32-546\r
SeDenyInteractiveLogonRight = *S-1-5-32-546\r\n"
  end
  its('stderr') { should eq '' }
end
