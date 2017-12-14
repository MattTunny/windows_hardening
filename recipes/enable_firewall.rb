firewall_controls = node['windows_hardening']

if firewall_controls['enable_firewall'] == true
  powershell_script 'firewall' do
    code <<-EOH
  netsh advfirewall set allprofiles state on
  netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" profile=public protocol=tcp localport=5985 remoteip=localsubnet new remoteip=any
  netsh advfirewall firewall set rule name="Windows Remote Desktop(RDP)" profile=public protocol=tcp localport=3389 remoteip=localsubnet new remoteip=any
  netsh advfirewall firewall set rule group="windows management instrumentation (WMI)" new enable=yes
  EOH
  end

  # Firewall Settings Domain Profile
  registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' do
    values [{ name: 'DisableNotifications', type: :dword, data: 1 },
            { name: 'AllowLocalPolicyMerge', type: :dword, data: 1 },
            { name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 1 },
            { name: 'EnableFirewall', type: :dword, data: 1 },
            { name: 'DefaultOutboundAction', type: :dword, data: 0 },
            { name: 'DefaultInboundAction', type: :dword, data: 1 }]
    recursive true
    action :create
  end

  # Firewall Settings Domain Logging
  registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' do
    values [{ name: 'LogFilePath', type: :string, data: '%systemroot%\\system32\\logfiles\\firewall\\domainfw.log' },
            { name: 'LogFileSize', type: :dword, data: 16_384 },
            { name: 'LogDroppedPackets', type: :dword, data: 1 },
            { name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
    recursive true
    action :create
  end

  # Firewall Settings Private Profile
  registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' do
    values [{ name: 'DisableNotifications', type: :dword, data: 1 },
            { name: 'AllowLocalPolicyMerge', type: :dword, data: 1 },
            { name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 1 },
            { name: 'EnableFirewall', type: :dword, data: 1 },
            { name: 'DefaultOutboundAction', type: :dword, data: 0 },
            { name: 'DefaultInboundAction', type: :dword, data: 1 }]
    recursive true
    action :create
  end

  # Firewall Settings Private Logging
  registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' do
    values [{ name: 'LogFilePath', type: :string, data: '%systemroot%\\system32\\logfiles\\firewall\\privatefw.log' },
            { name: 'LogFileSize', type: :dword, data: 16_384 },
            { name: 'LogDroppedPackets', type: :dword, data: 1 },
            { name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
    recursive true
    action :create
  end

  # Firewall Settings Public Profile
  registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' do
    values [{ name: 'DisableNotifications', type: :dword, data: 0 },
            { name: 'AllowLocalPolicyMerge', type: :dword, data: 1 },
            { name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 1 },
            { name: 'EnableFirewall', type: :dword, data: 1 },
            { name: 'DefaultOutboundAction', type: :dword, data: 0 },
            { name: 'DefaultInboundAction', type: :dword, data: 1 }]
    recursive true
    action :create
  end

  # Firewall Settings Public Logging
  registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' do
    values [{ name: 'LogFilePath', type: :string, data: '%systemroot%\\system32\\logfiles\\firewall\\publicfw.log' },
            { name: 'LogFileSize', type: :dword, data: 16_384 },
            { name: 'LogDroppedPackets', type: :dword, data: 1 },
            { name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
    recursive true
    action :create
  end
end
