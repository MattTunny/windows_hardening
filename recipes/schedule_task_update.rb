# Windows Update script
cookbook_file 'c:/Windows/temp/windows_update.ps1' do
  action :create
end

windows_task 'windows_update' do
  task_name 'WindowsUpdate'
  user 'packer'
  password 'packer'
  force true
  cwd 'C:\\Windows\\temp'
  command 'windows_update.ps1'
  run_level :highest
  frequency :daily
  start_time '03:00'
end

windows_task 'windows_update' do
  action :run
end
