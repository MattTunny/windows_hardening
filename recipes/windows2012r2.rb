# Registry keys for Windows Server2012 R2 hardening GPO

# Winlogon Settings
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{ name: 'PasswordExpiryWarning', type: :dword, data: 14 },
          { name: 'ScreenSaverGracePeriod', type: :string, data: 5 },
          { name: 'AllocateDASD', type: :string, data: 0 },
          { name: 'ScRemoveOption', type: :string, data: 1 },
          { name: 'ForceUnlockLogon', type: :string, data: 0 },
          { name: 'AutoAdminLogon', type: :string, data: 0 }, # This will stop auto login for kitchen tests
          { name: 'CachedLogonsCount', type: :string, data: 4 }]
  action :create
end

# LSA settings
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa' do
  values [{ name: 'FullPrivilegeAuditing', type: :binary, data: 01 },
          { name: 'AuditBaseObjects', type: :dword, data: 1 },
          { name: 'SCENoApplyLegacyAuditPolicy', type: :dword, data: 1 },
          { name: 'DisableDomainCreds', type: :dword, data: 1 },
          { name: 'LimitBlankPasswordUse', type: :dword, data: 1 },
          { name: 'CrashOnAuditFail', type: :dword, data: 0 },
          { name: 'RestrictAnonymousSAM', type: :dword, data: 1 },
          { name: 'RestrictAnonymous', type: :dword, data: 0 },
          { name: 'SubmitControl', type: :dword, data: 0 },
          { name: 'ForceGuest', type: :dword, data: 0 },
          { name: 'EveryoneIncludesAnonymous', type: :dword, data: 0 },
          { name: 'NoLMHash', type: :dword, data: 1 },
          { name: 'LmCompatibilityLevel', type: :dword, data: 5 }]
  action :create
end

# This setting prevents online identities from being used by PKU2U, which is a peer-to-peer authentication protocol. Authentication will be centrally managed with Windows user accounts.
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u' do
  values [{
    name: 'AllowOnlineID',
    type: :dword,
    data: 0
  }]
  action :create
end

if node['NTLM_Harden'] == false
  registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0' do
    values [{ name: 'NTLMMinServerSec', type: :dword, data: 537_395_200 },
            { name: 'allownullsessionfallback', type: :dword, data: 0 },
            # { name: 'RestrictReceivingNTLMTraffic', type: :dword, data: 2 }, # Hashed out due to breaking WinRM
            # { name: 'RestrictSendingNTLMTraffic', type: :dword, data: 2 }, # Hashed out due to breaking WinRM
            { name: 'NTLMMinClientSec', type: :dword, data: 537_395_200 },
            { name: 'AuditReceivingNTLMTraffic', type: :dword, data: 2 }]
    action :create
  end
end

if node['NTLM_Harden'] == true
  registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0' do
    values [{ name: 'NTLMMinServerSec', type: :dword, data: 537_395_200 },
            { name: 'allownullsessionfallback', type: :dword, data: 0 },
            { name: 'RestrictReceivingNTLMTraffic', type: :dword, data: 2 },
            { name: 'RestrictSendingNTLMTraffic', type: :dword, data: 2 },
            { name: 'NTLMMinClientSec', type: :dword, data: 537_395_200 },
            { name: 'AuditReceivingNTLMTraffic', type: :dword, data: 2 }]
    action :create
  end
  # Setting this on breaks test-kitchen - Federal Information Processing Standards.
  registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' do
    values [{
      name: 'Enabled',
      type: :dword,
      data: 0
    }]
    action :create
  end
end

# Netlogon Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters' do
  values [{ name: 'MaximumPasswordAge', type: :dword, data: 30 },
          { name: 'DisablePasswordChange', type: :dword, data: 0 },
          { name: 'RefusePasswordChange', type: :dword, data: 0 },
          { name: 'SealSecureChannel', type: :dword, data: 1 },
          { name: 'RequireSignOrSeal', type: :dword, data: 1 },
          { name: 'SignSecureChannel', type: :dword, data: 1 },
          { name: 'RequireStrongKey', type: :dword, data: 1 },
          { name: 'RestrictNTLMInDomain', type: :dword, data: 7 },
          { name: 'AuditNTLMInDomain', type: :dword, data: 7 }]
  action :create
end

# TCPIP 4 Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 2 },
          { name: 'TcpMaxDataRetransmissions', type: :dword, data: 3 }]
  action :create
end

# TCPIP 6 Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 2 },
          { name: 'TcpMaxDataRetransmissions', type: :dword, data: 3 }]
  action :create
end

# System Policys
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{ name: 'ConsentPromptBehaviorUser', type: :dword, data: 0 },
          { name: 'EnableLUA', type: :dword, data: 1 },
          { name: 'MSAOptional', type: :dword, data: 1 },
          { name: 'NoConnectedUser', type: :dword, data: 1 },
          { name: 'PromptOnSecureDesktop', type: :dword, data: 1 },
          { name: 'EnableVirtualization', type: :dword, data: 1 },
          { name: 'LocalAccountTokenFilterPolicy', type: :dword, data: 0 },
          { name: 'EnableUIADesktopToggle', type: :dword, data: 0 },
          { name: 'ConsentPromptBehaviorAdmin', type: :dword, data: 2 },
          { name: 'EnableSecureUIAPaths', type: :dword, data: 1 },
          { name: 'FilterAdministratorToken', type: :dword, data: 1 },
          { name: 'MaxDevicePasswordFailedAttempts', type: :dword, data: 10 },
          { name: 'DontDisplayLastUserName', type: :dword, data: 1 },
          { name: 'DontDisplayLockedUserId', type: :dword, data: 3 },
          { name: 'InactivityTimeoutSecs', type: :dword, data: 900 },
          { name: 'EnableInstallerDetection', type: :dword, data: 1 },
          { name: 'DisableCAD', type: :dword, data: 0 },
          { name: 'ShutdownWithoutLogon', type: :dword, data: 0 },
          { name: 'legalnoticecaption', type: :string, data: 'Company Logon Warning' },
          { name: 'legalnoticetext', type: :string, data: 'Warning text goes here...' }]
  action :create
end

# Lanman Server Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters' do
  values [{ name: 'enablesecuritysignature', type: :dword, data: 1 },
          { name: 'requiresecuritysignature', type: :dword, data: 1 },
          { name: 'RestrictNullSessAccess', type: :dword, data: 1 },
          { name: 'enableforcedlogoff', type: :dword, data: 1 },
          { name: 'autodisconnect', type: :dword, data: 15 },
          { name: 'SMBServerNameHardeningLevel', type: :dword, data: 0 }]
  action :create
end

# Lanman Workstation Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' do
  values [{ name: 'RequireSecuritySignature', type: :dword, data: 1 },
          { name: 'EnableSecuritySignature', type: :dword, data: 1 },
          { name: 'EnablePlainTextPassword', type: :dword, data: 0 }]
  action :create
end

# Lanman Print Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' do
  values [{
    name: 'AddPrinterDrivers',
    type: :dword,
    data: 1
  }]
  action :create
end

# LDAP Client Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP' do
  values [{
    name: 'LDAPClientIntegrity',
    type: :dword,
    data: 1
  }]
  action :create
end

# LDAP Server Parameters
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Parameters' do
  values [{
    name: 'LDAPServerIntegrity',
    type: :dword,
    data: 2
  }]
  action :create
end

# Session Manager
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager' do
  values [{ name: 'ProtectionMode', type: :dword, data: 1 },
          { name: 'SafeDllSearchMode', type: :dword, data: 1 }]
  action :create
end

# EMET Parameters (IE)
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults' do
  values [{ name: 'IE', type: :string, data: '*\Internet Explorer\iexplore.exe' }]
  recursive true
  action :create
end

# EMET Sys Parameters
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\SysSettings' do
  values [{ name: 'DEP', type: :dword, data: 2 }]
  recursive true
  action :create
end

# Session Management Kernal
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel' do
  values [{
    name: 'ObCaseInsensitive',
    type: :dword,
    data: 1
  }]
  action :create
end

# WDigest Parameters
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' do
  values [{
    name: 'UseLogonCredential',
    type: :dword,
    data: 0
  }]
  action :create
end

# Memory Management
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management' do
  values [{
    name: 'ClearPageFileAtShutdown',
    type: :dword,
    data: 0
  }]
  action :create
end

# RecoveryConsole Parameters
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole' do
  values [{ name: 'setcommand', type: :dword, data: 0 },
          { name: 'securitylevel', type: :dword, data: 0 }]
  action :create
end

# Event Log
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security' do
  values [{
    name: 'WarningLevel',
    type: :dword,
    data: 90
  }]
  action :create
end

# Cryptography Parameters
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Cryptography' do
  values [{
    name: 'ForceKeyProtection',
    type: :dword,
    data: 2
  }]
  action :create
end

# CodeIdentifiers Parameters
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers' do
  values [{
    name: 'authenticodeenabled',
    type: :dword,
    data: 0
  }]
  action :create
end

# AllowedPaths
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' do
  values [{
    name: 'Machine',
    type: :multi_string,
    data: ['System\CurrentControlSet\Control\Print\Printers',
'System\CurrentControlSet\Services\Eventlog',
'Software\Microsoft\OLAP Server',
'Software\Microsoft\Windows NT\CurrentVersion\Print',
'Software\Microsoft\Windows NT\CurrentVersion\Windows',
'System\CurrentControlSet\Control\ContentIndex',
'System\CurrentControlSet\Control\Terminal Server',
'System\CurrentControlSet\Control\Terminal Server\UserConfig',
'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration',
'Software\Microsoft\Windows NT\CurrentVersion\Perflib',
'System\CurrentControlSet\Services\SysmonLog'] }]
  action :create
end

# AllowedExactPaths
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths' do
  values [{
    name: 'Machine',
    type: :multi_string,
    data: ['System\CurrentControlSet\Control\ProductOptions',
'System\CurrentControlSet\Control\Server Applications',
'Software\Microsoft\Windows NT\CurrentVersion'] }]
  action :create
end

# WinRS Parameters
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS' do
  values [{
    name: 'AllowRemoteShellAccess',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

# Search Companion prevented from automatically downloading content updates. #
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SearchCompanion' do
  values [{
    name: 'DisableContentFileUpdates',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

# SQMC
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows' do
  values [{
    name: 'CEIPEnable',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

# Disable Microsoft Online Accounts
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount' do
  values [{
    name: 'value',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

# Disable Network SelectionUI
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{
    name: 'DontDisplayNetworkSelectionUI',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

# UAC Elevation
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{
    name: 'AlwaysInstallElevated',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

# Audit Logs
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application' do
  values [{ name: 'MaxSize', type: :dword, data: 327_68 },
          { name: 'Retention', type: :string, data: 0 }]
  recursive true
  action :create
end
# Audit Logs
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security' do
  values [{ name: 'MaxSize', type: :dword, data: 196_608 },
          { name: 'Retention', type: :string, data: 0 }]
  recursive true
  action :create
end
# Audit Logs
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System' do
  values [{ name: 'MaxSize', type: :dword, data: 327_68 },
          { name: 'Retention', type: :string, data: 0 }]
  recursive true
  action :create
end
# Auto Mount CD Drive
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{ name: 'NoDriveTypeAutoRun', type: :dword, data: 255 },
          { name: 'NoPublishingWizard', type: :dword, data: 1 }]
  action :create
end

# Encryption of RDP
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'MinEncryptionLevel',
    type: :dword,
    data: 3
  }]
  action :create
  recursive true
end

# Index of encrypted files
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search' do
  values [{
    name: 'AllowIndexingEncryptedStoresOrItems',
    type: :dword,
    data: 0
  }]
  action :create
  recursive true
end

# Personalization Lock screen
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization' do
  values [
    { name: 'NoLockScreenSlideshow', type: :dword, data: 1 },
    { name: 'NoLockScreenCamera', type: :dword, data: 1 }]
  action :create
  recursive true
end

# Messenger
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client' do
  values [{
    name: 'CEIP',
    type: :dword,
    data: 2
  }]
  action :create
  recursive true
end

# Turn off Windows Update device driver searching
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching' do
  values [{
    name: 'DontSearchWindowsUpdate',
    type: :dword,
    data: 1
  }]
  action :create
  recursive true
end

directory 'c:/temp' do
  action :create
end

# Local Security Policy
cookbook_file 'c:/temp/localComputer.inf' do
  action :create
end

# Reg Files for save applications
cookbook_file 'c:/temp/EMET_Files.reg' do
  action :create
end

# Reg Files for save applications
cookbook_file 'c:/temp/audit_settings.csv' do
  action :create
end

# Script to apply settings that can't be down in registry'
powershell_script 'import' do
  cwd 'c:/temp'
  code <<-EOH
    secedit /import /db secedit.sdb /cfg localComputer.inf
    secedit /configure /db secedit.sdb
    regedit /s c:\temp\EMET_Files.reg
    auditpol /restore /File:audit_settings.csv
    gpupdate /force
    del "localComputer.inf" -force -ErrorAction SilentlyContinue
    del "secedit.sdb" -force -ErrorAction SilentlyContinue
    del "audit_settings.csv" -force -ErrorAction SilentlyContinue
    del "EMET_Files.reg" -force -ErrorAction SilentlyContinue
    EOH
end
