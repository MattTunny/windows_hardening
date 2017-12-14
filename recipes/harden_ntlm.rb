# NTLM Hardening -- This settings breaks WinRM

# NTLM Hardening
ntlm_controls = node['windows_hardening']

if ntlm_controls['harden_ntlm'] == true
  registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0' do
    values [{ name: 'RestrictReceivingNTLMTraffic', type: :dword, data: 2 },
            { name: 'RestrictSendingNTLMTraffic', type: :dword, data: 2 },
            { name: 'AuditReceivingNTLMTraffic', type: :dword, data: 2 },
            { name: 'allownullsessionfallback', type: :dword, data: 0 },
            { name: 'NTLMMinServerSec', type: :dword, data: 537_395_200 },
            { name: 'NTLMMinClientSec', type: :dword, data: 537_395_200 }]
    action :create
  end
end
