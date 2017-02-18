# windows_hardening

Chef cookbook for IaC hardening Microsoft Windows Servers without relying on group policy.

#### Microsoft Windows Server with the following guides:

#### Center for Internet Security (CIS)
- Windows 2012 
https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_non-R2_Benchmark_v2.0.1.pdf
- Windows 2012R2
https://benchmarks.cisecurity.org/tools2/windows/CIS_Microsoft_Windows_Server_2012_R2_Benchmark_v2.2.1.pdf

#### Group Policy refrences:
- https://msdn.microsoft.com/en-au/library/ms815238.aspx
- https://www.microsoft.com/en-au/download/details.aspx?id=25250
- https://www.stigviewer.com/stig/microsoft_windows_server_2012_member_server/  

#### To run all test locally
```bash
kitchen verify
```

#### To run all tests remote | Password requires '' or ""
```bash
inspec exec test/integration/default/default_spec.rb -t winrm://username@192.168.0.12 --password 'password'
```

