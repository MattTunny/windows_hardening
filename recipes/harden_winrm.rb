# WinRM Hardening
winrmh_controls = node['windows_hardening']

if winrmh_controls['harden_winrm'] == true
  registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
    values [{ name: 'AllowAutoConfig', type: :dword, data: 2 }, # breaks remotePS, test-kitchen, InSpec and Nexpose Scan
            { name: 'IPv4Filter', type: :dword, data: 2 }, # breaks remotePS, test-kitchen, InSpec and Nexpose Scan
            { name: 'DisableRunAs', type: :dword, data: 2 }, # breaks test-kitchen, InSpec and Nexpose Scan
            { name: 'AllowUnencryptedTraffic', type: :dword, data: 0 }] # 18.9.81.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
    recursive true
    action :create
  end
  registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client' do
    values [{ name: 'AllowDigest', type: :dword, data: 1 }, # 18.9.81.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'
            { name: 'AllowBasic', type: :dword, data: 0 }, # 18.9.81.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
            { name: 'AllowUnencryptedTraffic', type: :dword, data: 0 }] # 18.9.81.2.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
    recursive true
    action :create
  end
end
