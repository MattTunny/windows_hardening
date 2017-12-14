#
# Cookbook Name:: windows_hardening
# Attributes:: default
#
# Copyright (c) 2017 The Authors, All Rights Reserved.

default['windows_hardening']['enable_firewall'] = false
default['windows_hardening']['enable_winrm'] = true
default['windows_hardening']['force_windowsupdate'] = false
default['windows_hardening']['harden_ntlm'] = false
default['windows_hardening']['harden_winrm'] = false

# ciphers
default['windows_hardening']['ciphers']['disable_tls1.0'] = true
default['windows_hardening']['ciphers']['disable_tls1.1'] = true
default['windows_hardening']['ciphers']['disable_pct'] = true
default['windows_hardening']['ciphers']['disable_ssl2'] = true
default['windows_hardening']['ciphers']['disable_ssl3'] = true
default['windows_hardening']['ciphers']['disable_des'] = true
default['windows_hardening']['ciphers']['disable_null'] = true
default['windows_hardening']['ciphers']['disable_RC240_128'] = true
default['windows_hardening']['ciphers']['disable_RC256_128'] = true
default['windows_hardening']['ciphers']['disable_RC440_128'] = true
default['windows_hardening']['ciphers']['disable_RC456_128'] = true
default['windows_hardening']['ciphers']['disable_RC464_128'] = true
