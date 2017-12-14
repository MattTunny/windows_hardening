windows_task 'foobar' do
  command "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -noprofile -noexit -executionpolicy Bypass -File c:\\windows\\temp\\windows_update.ps1'"
  action [:create, :run]
  notifies :end, 'windows_task[foobar]', :delayed # TODO: This strangely never gets deleted
  # notifies :delete, 'windows_task[foobar]', :delayed #TODO This strangely never gets deleted
  run_level :highest
  force true
end
