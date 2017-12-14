# Domain Joined script before hardened script can run in domain.

zone = node['zone'].to_s
domain = node[zone]['ad-join']['domain']
join_domain = (node['kernel']['cs_info']['domain_role'].to_i.zero? || node['kernel']['cs_info']['domain_role'].to_i == 2) && (domain != 'WORKGROUP')
puts join_domain

reboot 'initialize domain' do
  action :reboot_now
  reason 'Need to be fully domain-joined before applying harded template.'
  only_if { join_domain }
end
