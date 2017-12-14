# Windows Update
update_controls = node['windows_hardening']

if update_controls['force_windowsupdate'] == true
  registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' do
    values [{ name: 'NoAutoUpdate', type: :dword, data: 0 },
            { name: 'AUOptions', type: :dword, data: 4 },
            { name: 'ScheduledInstallDay', type: :dword, data: 0 },
            { name: 'ScheduledInstallTime', type: :dword, data: 3 },
            { name: 'NoAutoRebootWithLoggedOnUsers', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end
