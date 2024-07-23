iwr https://github.com/gangstanthony/Powershell-Testing/raw/main/bittitan_dma_setup_peo.exe -OutFile "$env:temp\BitTitanDMASetup_2AA07D9C3FD9D0D3__.exe"

. "$env:temp\BitTitanDMASetup_2AA07D9C3FD9D0D3__.exe"



############

if (!(test-path c:\temp)) {
  md c:\temp
}

$(
write-output 'reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 /v SystemDefaultTlsVersions'
reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 /v SystemDefaultTlsVersions
write-output ''

write-output 'reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 /v SchUseStrongCrypto'
reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 /v SchUseStrongCrypto
write-output ''

write-output 'reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /v SystemDefaultTlsVersions'
reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /v SystemDefaultTlsVersions
write-output ''

write-output 'reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto'
reg query HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto
write-output ''

write-output 'reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 /v SystemDefaultTlsVersions'
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 /v SystemDefaultTlsVersions
write-output ''

write-output 'reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 /v SchUseStrongCrypto'
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 /v SchUseStrongCrypto
write-output ''

write-output 'reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319 /v SystemDefaultTlsVersions'
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319 /v SystemDefaultTlsVersions
write-output ''

write-output 'reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto'
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto
write-output ''

write-output 'Reg.exe query "HKCU\Software\Microsoft\Exchange" /v "AlwaysUseMSOAuthForAutoDiscover"'
Reg.exe query "HKCU\Software\Microsoft\Exchange" /v "AlwaysUseMSOAuthForAutoDiscover"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "EnableADAL"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "EnableADAL"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "Version"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "Version"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "DisableADALatopWAMOverride"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "DisableADALatopWAMOverride"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "PreferLocalXML"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "PreferLocalXML"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpRedirect"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpRedirect"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpsAutoDiscoverDomain"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpsAutoDiscoverDomain"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpsRootDomain"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpsRootDomain"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeScpLookup"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeScpLookup"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeSrvRecord"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeSrvRecord"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeLastKnownGoodURL"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeLastKnownGoodURL"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeExplicitO365Endpoint"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeExplicitO365Endpoint"
write-output ''

write-output 'Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpRedirect"'
Reg.exe query "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpRedirect"
) | Set-Content c:\temp\regbackup.txt

############

reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 /v SchUseStrongCrypto /t REG_DWORD /d 1 /f

reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto /t REG_DWORD /d 1 /f

reg add HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 /v SchUseStrongCrypto /t REG_DWORD /d 1 /f

reg add HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319 /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto /t REG_DWORD /d 1 /f

Reg.exe add "HKCU\Software\Microsoft\Exchange" /v "AlwaysUseMSOAuthForAutoDiscover" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "EnableADAL" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "Version" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Identity" /v "DisableADALatopWAMOverride" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "PreferLocalXML" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpRedirect" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpsAutoDiscoverDomain" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpsRootDomain" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeScpLookup" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeSrvRecord" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeLastKnownGoodURL" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeExplicitO365Endpoint" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\AutoDiscover" /v "ExcludeHttpRedirect" /t REG_DWORD /d "1" /f

