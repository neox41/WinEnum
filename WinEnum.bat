@echo OFF
::Based on Windows Privilege Escalation Fundamentals http://www.fuzzysecurity.com/tutorials/16.html
echo "Local Windows Enumeration & Privilege Escalation checks by Mattia Reggiani" > report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] System Info >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
systeminfo >> report.txt 2>nul
ver >> report.txt 2>nul
hostname >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Current user >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
whoami >> report.txt 2>nul
echo %username% >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Users >> report.txt 2>nul 
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
net localgroup >> report.txt 2>nul
net localgroup administrators >> report.txt 2>nul
qusers >> report.txt 2>nul
qwinsta >> report.txt 2>nul
net users >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Interesting files 1>> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
more c:\boot.ini >> report.txt 2>nul
more C:\WINDOWS\System32\drivers\etc\hosts >> report.txt 2>nul
more C:\WINDOWS\System32\drivers\etc\networks >> report.txt 2>nul
more C:\Users\username\AppData\Local\Temp >> report.txt 2>nul 
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo "" >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Environment vars 1>> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
path >> report.txt 2>nul
echo %path% >> report.txt 2>nul
set >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Networking >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
ipconfig /all >> report.txt 2>nul
route print >> report.txt 2>nul
arp -A >> report.txt 2>nul
netstat -ano >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo "" >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Firewalling >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
netsh firewall show state >> report.txt 2>nul
netsh firewall show config >> report.txt 2>nul
netsh dump >> report.txt 2>nul
netsh advfirewall firewall show rule name=all verbose >> report.txt 2>nul 
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Domain >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo "Domain" >> report.txt 2>nul
set userdomain >> report.txt 2>nul 
net view /domain >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Scheduled Tasks 1>> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
schtasks /query /fo LIST /v >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Running Tasks >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
tasklist /SVC >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Tasks started >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
net start >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Software installed >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
qprocess >> report.txt 2>nul
driverquery /v >> report.txt 2>nul  
assoc >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Services >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
sc query >> report.txt 2>nul
sc query state= all >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Hardware 1>> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
DRIVERQUERY >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Config files >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt 2>nul
findstr /si password *.xml *.ini *.txt >> report.txt 2>nul
findstr /si pass *.xml *.ini *.txt >> report.txt 2>nul
reg query HKLM /f password /t REG_SZ /s /reg:64 >> report.txt 2>nul
reg query HKCU /f password /t REG_SZ /s /reg:64 >> report.txt 2>nul
type c:\sysprep.inf >> report.txt 2>nul
type c:\sysprep\sysprep.xml >> report.txt 2>nul
type %WINDIR%\Panther\Unattend\Unattended.xml >> report.txt 2>nul
type %WINDIR%\Panther\Unattended.xml >> report.txt 2>nul
type Services\Services.xml >> report.txt 2>nul
type ScheduledTasks\ScheduledTasks.xml >> report.txt 2>nul
type Printers\Printers.xml >> report.txt 2>nul
type Drives\Drives.xml >> report.txt 2>nul
type DataSources\DataSources.xml >> report.txt 2>nul
reg query "HKCU\Software\ORL\WinVNC3\Password" /reg:64 >> report.txt 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64 >> report.txt 2>nul
reg query" HKCU\Software\SimonTatham\PuTTY\Sessions" /reg:64 >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Checking AlwaysInstallElevated >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /reg:64 >> report.txt 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /reg:64 >> report.txt 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /reg:64 >> report.txt 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /reg:64 >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Find weak directories >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
tools\accesschk.exe -uwdqs users c:\ >> report.txt 2>nul
tools\accesschk.exe -uwdqs "Authenticated Users" c:\ >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Find weak files >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
tools\accesschk.exe -uwqs users c:\*.* >> report.txt 2>nul
tools\accesschk.exe -uwqs "Authenticated Users" c:\*.* >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

::cacls "c:\Program Files" /T | findstr Users

:: If WMIC is enabled
echo "Local Windows Enumeration & Privilege Escalation checks by Mattia Reggiani" > wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo [+] WMIC Zone >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
wmic service list brief /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic service list config /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic process get CSName,Description,ExecutablePath,ProcessId /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic USERACCOUNT list full /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic group list full /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic netuse list full /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic qfe get Caption,Description,HotFixID,InstalledOn /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic startup get Caption,Command,Location,User /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
wmic Timezone get DaylightName,Description,StandardName /format:table >> wmic.txt 2>nul
echo --------------------------------------------------------------------------------- >> wmic.txt 2>nul
echo. >> report.txt 2>nul
