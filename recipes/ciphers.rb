cipher_controls = node['windows_hardening']['ciphers']

# Disable old protocols TLS 1.0
if cipher_controls['disable_tls1.0']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.0\Server' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable old protocols TLS 1.1
if cipher_controls['disable_tls1.1']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\TLS 1.1\Server' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable old protocols PCT 1.0
if cipher_controls['disable_pct']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\PCT 1.0\Server' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable old protocols SSLv2.0
if cipher_controls['disable_ssl2']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 2.0\Server' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable old protocols SSLv3.0 Client
if cipher_controls['disable_ssl3']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Client' do
    values [{ name: 'DisabledByDefault', type: :dword, data: 1 }]
    recursive true
    action :create
  end
end

# Disable old protocols SSLv3.0 Server
if cipher_controls['disable_ssl3']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\SSL 3.0\Server' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable Weak Ciphers - DES
if cipher_controls['disable_des']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable Weak Ciphers - NULL
if cipher_controls['disable_null']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable Weak Ciphers - RC2 40/128
if cipher_controls['disable_RC240_128']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable Weak Ciphers - RC2 56/128
if cipher_controls['disable_RC256_128']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable Weak Ciphers - RC4 40/128
if cipher_controls['disable_RC440_128']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable Weak Ciphers - RC4 56/128
if cipher_controls['disable_RC456_128']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end

# Disable Weak Ciphers - RC4 64/128
if cipher_controls['disable_RC464_128']
  registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' do
    values [{ name: 'Enabled', type: :dword, data: 0 }]
    recursive true
    action :create
  end
end
