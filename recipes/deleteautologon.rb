# Changed autoadminlogin to 0
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{
    name: 'AutoAdminLogon',
    type: :string,
    data: '0'
  }]
  action :create
  recursive true
end

# Delete DefaultUSer
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{
    name: 'DefaultUserName',
    type: :string,
    data: '0'
  }]
  action :delete
end

# Delete AutoLogonSID
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{
    name: 'AutoLogonSID',
    type: :string,
    data: '0'
  }]
  action :delete
end
