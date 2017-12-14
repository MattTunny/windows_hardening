#
# Cookbook Name:: windows_hardening
# Attributes:: default
#
# Copyright (c) 2017 The Authors, All Rights Reserved.

default['cb_server_hardening']['enable_firewall'] = false
default['cb_server_hardening']['enable_winrm'] = true
default['cb_server_hardening']['force_windowsupdate'] = false
default['cb_server_hardening']['harden_ntlm'] = false
default['cb_server_hardening']['harden_winrm'] = false

# ciphers
default['cb_server_hardening']['ciphers']['disable_tls1.0'] = true
default['cb_server_hardening']['ciphers']['disable_tls1.1'] = true
default['cb_server_hardening']['ciphers']['disable_pct'] = true
default['cb_server_hardening']['ciphers']['disable_ssl2'] = true
default['cb_server_hardening']['ciphers']['disable_ssl3'] = true
default['cb_server_hardening']['ciphers']['disable_des'] = true
default['cb_server_hardening']['ciphers']['disable_null'] = true
default['cb_server_hardening']['ciphers']['disable_RC240_128'] = true
default['cb_server_hardening']['ciphers']['disable_RC256_128'] = true
default['cb_server_hardening']['ciphers']['disable_RC440_128'] = true
default['cb_server_hardening']['ciphers']['disable_RC456_128'] = true
default['cb_server_hardening']['ciphers']['disable_RC464_128'] = true
