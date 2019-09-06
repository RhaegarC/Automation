function Download-NotesData{
	param($NotesDir="C:\Program Files (x86)\IBM\Lotus\Notes")
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager\UserIds\user.id -File "$NotesDir\Data\user.id"
	Read-S3Object -BucketName nmsp-ci-data -KeyPrefix LabManager\TestDatabases -Folder "$NotesDir\Data"
}

function Download-NotesDataNewDir{
	param($NotesDir="C:\Program Files (x86)\IBM\Notes")
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager\UserIds\user.id -File "$NotesDir\Data\user.id"
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager\notes.ini -File "$NotesDir\notes.ini"
	Read-S3Object -BucketName nmsp-ci-data -KeyPrefix LabManager\TestDatabases -Folder "$NotesDir\Data"
}

function Download-Discovery{
	Read-S3Object -BucketName nmsp-ci-data -KeyPrefix LabManager\Discovery -Folder "C:\Program Files (x86)\Quest\Migrator for Notes to SharePoint\PowerShell"
}

function Reset-Options{
invoke-WebRequest "http://fitnesse.at-nmsp.com/files/nmsp/options/Options.config.default.WebServices.ClassicModeAuthentication" -OutFile "C:\ProgramData\Quest\Migrator for Notes to SharePoint\Options.config"
}

function Download-UIAutomation{
	New-Item 'C:\UIAutomation' -type directory
	Read-S3Object -BucketName nmsp-ci-data -Key 'LabManager\UIAutomation.0.8.7B3.NET40.zip' -File C:\msi\UIAutomation.zip
	$shell_app = new-object -com shell.application
	$zip_file = $shell_app.namespace('C:\msi\UIAutomation.zip')
	$destination = $shell_app.namespace('C:\UIAutomation')
	$destination.Copyhere($zip_file.items())
}

function Download-Selenium{
	New-Item 'C:\selenium' -type directory
	Read-S3Object -BucketName nmsp-ci-data -Key 'LabManager\selenium.zip' -File C:\msi\selenium.zip
	$shell_app = new-object -com shell.application
	$zip_file = $shell_app.namespace('C:\msi\selenium.zip')
	$destination = $shell_app.namespace('C:\selenium')
	$destination.Copyhere($zip_file.items())
}


function Install-ReportViewer{
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager\ReportViewer.msi -File c:\msi\ReportViewer.msi
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager\SQLSysClrTypes.msi -File c:\msi\SQLSysClrTypes.msi
	Start-Process c:\msi\SQLSysClrTypes.msi '/qb!' -PassThru | Wait-Process
	Start-Process c:\msi\ReportViewer.msi '/qb!' -PassThru | Wait-Process
}

function Copy-AsposeComponent{
	copy 'C:\Program Files (x86)\Quest\Migrator for Notes to SharePoint\Bin\Aspose.*' c:\msi
}

function Download-AsposeLicense{
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager\Aspose\Aspose.Pdf.lic -File C:\msi\Aspose.Pdf.lic
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager\Aspose\Aspose.Words.lic -File C:\msi\Aspose.Words.lic
}

function Install-SP13ClientSdk{
	Read-S3Object -BucketName nmsp-ci-data -Key 'LabManager\sharepointclientcomponents_x64.msi' -File C:\msi\sharepointclientcomponents_x64.msi
	Start-Process c:\msi\sharepointclientcomponents_x64.msi '/qn /l*v c:\msi\sharepointclientcomponents_setup.log' -PassThru | Wait-Process  
}

function Add-TestUsers{
	  $password = "Qwerty123"
	  $secstr = New-Object -TypeName System.Security.SecureString
	  $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
	  New-ADUser NotSiteOwner -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser uservladimir -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser userkonstantin -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser userkonstantin1 -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser userjsitu -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser testuser1 -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser testuser2 -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser testuser3 -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser testuser4 -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser testuser5 -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  New-ADUser testuser6 -ChangePasswordAtLogon $false -Enabled $true -AccountPassword $secstr -AccountExpirationDate "05/01/2026 5:00:00 PM"
	  Add-ADGroupMember Administrators NotSiteOwner
	  Add-ADGroupMember Administrators uservladimir
	  Add-ADGroupMember Administrators userkonstantin 
	  Add-ADGroupMember Administrators userkonstantin1  
	  Add-ADGroupMember Administrators userjsitu
	  New-ADGroup adgroup1 -GroupScope Global
}

function Install-Git{
	Read-S3Object -BucketName nmsp-ci-data -Key LabManager/git.exe -File c:\msi\git.exe
	cd c:\msi
	do{
	Start-Process git.exe '/silent' -PassThru | Wait-Process
	"wait till find git"
	sleep 5
	}
	while(-not (Test-Path 'C:\Program Files\Git\bin\git.exe'))
}

function Create-PowerSlimTask{
	param($lab_type="general")
	do{
	Start-Process 'C:\Program Files\Git\bin\git.exe' 'clone https://github.com/anbeel/PowerSlim.git c:\PowerSlim' -PassThru | Wait-Process
	"wait till powerslim is downloaded"
	sleep 5
	}
	while(-not (Test-Path "c:\PowerSlim\slim.ps1"))
	
	if($lab_type -eq "2010"){
		schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn "PowerSlim30" /tr ('PowerShell -STA -NonInteractive -ExecutionPolicy bypass -file c:\powerslim\slim.ps1 30 server') /sc weekly /d SAT /IT /RL HIGHEST
		schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn "PowerSlim35" /tr ('PowerShell  -v 2 -STA -WindowStyle Maximized -NonInteractive -ExecutionPolicy bypass -file c:\powerslim\slim.ps1 35 server') /sc weekly /d SAT /IT /RL HIGHEST
	}
	else{
		schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn "PowerSlim35" /tr ('PowerShell -STA -WindowStyle Maximized -NonInteractive -ExecutionPolicy bypass -file c:\powerslim\slim.ps1 35 server') /sc weekly /d SAT /IT /RL HIGHEST
	}
	netsh advfirewall firewall add rule name="PowerSlim" dir=in action=allow protocol=TCP localport=30-86
}

function Run-PowerSlimTask{
	param($ports=@(35))
	foreach($p in $ports){
		do {
			schtasks /Run /TN "PowerSlim$p"
			Sleep 5
			$status = (schtasks /query /tn "PowerSlim$p" /fo csv | ConvertFrom-Csv).Status
			$status | Out-Default
		}while($status -ne 'Running')
	}
}

function Enable-SqlPort{
	netsh advfirewall firewall add rule name="SQL" dir=in action=allow protocol=TCP localport=1433
}

function Download-PowerQuickr{
	Start-Process 'C:\Program Files\Git\bin\git.exe' 'clone https://github.com/anbeel/PowerQuickr.git c:\PowerQuickr' -PassThru | Wait-Process
}

function Download-SPOnlineSupport{
	Read-S3Object -BucketName nmsp-ci-data -Key 'LabManager\GetSharePointOnlinePage.psm1' -File c:\Powershell\GetSharePointOnlinePage.psm1
}

function Change-IeSettings{
New-Item C:\PowerShell -type Directory -Force
@"
`$a = 0
`$b = 26,55,97,89,35,82,53,12,122,95,32,23,47,30,26,25,14,43,1,115,19,55,19,18,20,26,21,42
`$c = 26,55,97,89,35,82,53,12,122,95,32,23,47,30,26,25,14,43,1,115,19,55,19,18,20,26,21,42

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1A10" -Value `$a
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "{AEBA21FA-782A-4A90-978D-B72164C80120}" -Value `$b
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "{A8A88C49-5EB2-4990-A1A2-0876022C854F}" -Value `$c
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
"@ | Out-File C:\PowerShell\ChangeIeSettings.ps1  
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn ChangeIeSettings /tr 'PowerShell -STA -NonInteractive -ExecutionPolicy bypass -file C:\PowerShell\ChangeIeSettings.ps1' /sc weekly /d SAT /RL HIGHEST
schtasks /Run /TN ChangeIeSettings
do { Sleep 10 } while((schtasks /query /tn ChangeIeSettings /fo csv | ConvertFrom-Csv).Status -ne 'Ready')
}

function Register-Image{
	param($Instance_Id,$Image_Name)
	$img=Get-EC2Image -Owner self | ? {$_.Name -eq $Image_Name}
	if($img.length -gt 0 -and $img.length -lt 3){
	Unregister-EC2Image -ImageId $img.ImageId
	}

	do{
	"Wait till image is deregistered..."
	sleep 30
	$img=Get-EC2Image -Owner self | ? {$_.Name -eq $Image_Name}
	}while($img.length -gt 0)

	New-EC2Image -InstanceId $Instance_Id -Name $Image_Name
	do{
	"Wait till image is available..."
	sleep 30
	$img=Get-EC2Image -Owner self | ? {$_.Name -eq $Image_Name}
	}while($img.state -ne "available")
}

function Run-Fitnesse{
	param($base,$filter)
	$port=GetPort
	$slim_port=GetPort
	"Running test at port # $port" | Out-Default
	remove-item "C:\Program Files (x86)\Jenkins\userContent\$base.xml" -force

	$cmd="$base"+$filter+"&SLIM_PORT=$port"
	$result="C:\Program Files (x86)\Jenkins\userContent\$base.xml"
	cd C:\userdata\PowerSlim
	java -DSLIM_PORT=$port -jar fitnesse-standalone.jar -d C:\userdata\fitnesse\nmsp -c $cmd -p $port -v -b $result
	if(-not [bool]((Get-Content $result) -as [xml])){
		"Test result is not in proper format in $result" | Out-Default
		'<?xml version="1.0"?><testResults><finalCounts><right>0</right><wrong>0</wrong><ignores>0</ignores><exceptions>0</exceptions></finalCounts><totalRunTimeInMillis>0</totalRunTimeInMillis></testResults>'|Out-File -filepath $result
	}
	
}

function global:GetPort(){
    $s = new-object System.Net.Sockets.Socket('InterNetwork', 'Stream', 'Tcp')
    $ep = new-object System.Net.IPEndPoint(0, 0)
    $b = $s.Bind($ep)
    $PORT = $s.LocalEndPoint.Port
    $c = $s.Close()
    return $PORT
}

function Install-Client{
  param($version)
  "Install Client: $version"
  Read-S3Object -BucketName NMSP-ZHUHAI -Key "$version/MigratorforNotestoSharePoint-Clients-$version.msi" -File "c:\msi\MigratorforNotestoSharePoint-Clients-$version.msi"
  Start-Process "c:\msi\MigratorforNotestoSharePoint-Clients-$version.msi" '/qn NDPROG="C:\Program Files (x86)\IBM\Lotus\Notes" NDDATA="C:\Program Files (x86)\IBM\Lotus\Notes\Data" /l*v  c:\msi\setup.log' -PassThru | Wait-Process

  Read-S3Object -BucketName nmsp-ci-data -KeyPrefix LabManager\license -Folder "c:\msi\license"
  cd\
  cd 'C:\Program Files (x86)\Quest\Migrator for Notes to SharePoint\bin'
  .\LicenseInstallerCmd.exe -path 'C:\msi\license\license6.dlv'
}

function Install-ClientNewDir{
  param($version)
  "Install Client: $version"
  Read-S3Object -BucketName NMSP-ZHUHAI -Key "$version/MigratorforNotestoSharePoint-Clients-$version.msi" -File "c:\msi\MigratorforNotestoSharePoint-Clients-$version.msi"
  Start-Process "c:\msi\MigratorforNotestoSharePoint-Clients-$version.msi" '/qn NDPROG="C:\Program Files (x86)\IBM\Notes" NDDATA="C:\Program Files (x86)\IBM\Notes\Data" /l*v  c:\msi\setup.log' -PassThru | Wait-Process

  Read-S3Object -BucketName nmsp-ci-data -KeyPrefix LabManager\license -Folder "c:\msi\license"
  cd\
  cd 'C:\Program Files (x86)\Quest\Migrator for Notes to SharePoint\bin'
  .\LicenseInstallerCmd.exe -path 'C:\msi\license\license6.dlv'
}

function Install-Services{
  param($version)
  "Install Services: $version"
  Read-S3Object -BucketName NMSP-ZHUHAI -Key "$version/MigratorforNotestoSharePoint-Services-$version.msi" -File "c:\msi\MigratorforNotestoSharePoint-Services-$version.msi"
  Start-Process "c:\msi\MigratorforNotestoSharePoint-Services-$version.msi" '/qn ISPOOLUSER="velaskec\Administrator" ISPOOLPASSWORD="Qwerty123" /l*v c:\msi\setup.log' -PassThru | Wait-Process
}

function Enable-ImportService{
 param($sp="2010")
 New-Item 'c:\shared' -type directory
 net share shared=c:\shared /GRANT:'Everyone,FULL'
 New-Item C:\PowerShell -type Directory -Force
 $password=@{"2010"='iU2LNL7dQ2tlOvcwgBHnxQ==';"2013"='DwMBaQmEUehkRgKM7Xf3EA==';"2016"='GYm1tBjGWP/Af1b0JE84PA=='}
@"
Add-PSSnapin Microsoft.SharePoint.PowerShell
`$web = (Get-SPSite "http://$(hostname)/sites/test").RootWeb
`$web.AllowUnsafeUpdates = `$true
# Enable import Service
`$web.Properties['proposion.importservice.enabled'] = 'True'
`$web.Properties['proposion.importservice.address'] = "http://$(hostname):8888/ImportSession.svc"
`$web.Properties['proposion.importservice.apppoolidentity'] = 'velaskec\administrator'
`$web.Properties['proposion.importservice.jobgalleryurl'] = "http://$(hostname)/sites/test"
`$web.Properties['proposion.importservice.endpointname'] = 'Secure HTTP (using Web Services Security)'
`$web.Properties['proposion.importservice.clientpathtosharedfolder'] = "\\$(hostname)\shared"
`$web.Properties['proposion.importservice.sharedfolderpath'] = 'c:\shared'
`$web.Properties['proposion.importservice.isconfigured'] = 'True'

# Enable Link Tracking
`$web.Properties['proposion.linktracking.server'] = "nmsp"
`$web.Properties['proposion.linktracking.database'] = 'QuestLinkTracking'
`$web.Properties['proposion.linktracking.isconfigured'] = 'True'
`$web.Properties['proposion.linktracking.windowsauthentication'] = 'False'
`$web.Properties['proposion.linktracking.windowsimpersonation'] = 'true'
`$web.Properties['proposion.linktracking.userid'] = 'velaskec\administrator'
`$web.Properties['proposion.linktracking.encryptedpassword'] = "$($password[$sp])"

`$web.Properties.Update()
`$web.Update()
`$web.AllowUnsafeUpdates = `$false
`$web.Close()
"@ | Out-File C:\PowerShell\EnableImportService.ps1
if($sp -eq "2010"){
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn EnableImportService /tr 'PowerShell -v 2 -STA -NonInteractive -ExecutionPolicy bypass -file C:\PowerShell\EnableImportService.ps1' /sc weekly /d SAT /RL HIGHEST
}
else{
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn EnableImportService /tr 'PowerShell -STA -NonInteractive -ExecutionPolicy bypass -file C:\PowerShell\EnableImportService.ps1' /sc weekly /d SAT /RL HIGHEST
}
schtasks /Run /TN EnableImportService
do { Sleep 10 } while((schtasks /query /tn EnableImportService /fo csv | ConvertFrom-Csv).Status -ne 'Ready')
netsh advfirewall firewall add rule name="ImportService" dir=in action=allow protocol=TCP localport=8888
}

function Create-LinkTrackingDb{
	cd "C:\Program Files (x86)\Quest\Migrator for Notes to SharePoint\Bin"
	Start-Process DBManager.exe '. QuestLinkTracking' -PassThru | Wait-Process 
}

function Create-LinkTrackingDbForUI{
	cd "C:\Program Files (x86)\Quest\Migrator for Notes to SharePoint\Bin"
	Start-Process DBManager.exe '. QuestLinkTrackingForUI' -PassThru | Wait-Process 
}

function Create-Repository{
#Create Quest repository
$command = @"
`$lns = New-Object -ComObject Lotus.NotesSession  
`$lns.Initialize('')
`$template = `$lns.GetDatabase('','QuestRepository.ntf')
`$template.CreateFromTemplate('','QuestRepository',`$true)
"@ 
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -Command "& { $command }"
}

function Create-SiteCollection{
param($sp="2010")
@"
Add-PSSnapin Microsoft.SharePoint.PowerShell
'Test' | % { Remove-SPSite "http://localhost/sites/`$_" -GradualDelete -Confirm:`$False }
'Test' | % { New-SPSite -URL "http://localhost/sites/`$_" -Template 'STS#0' -OwnerAlias VELASKEC\administrator } 
`$web = Get-SPWeb http://localhost/sites/Test
`$user = `$web.EnsureUser("VELASKEC\administrator")
`$user.IsSiteAdmin = `$true
`$user.Update()
'Test' | % { Enable-SPFeature -identity DocumentSet -URL "http://localhost/sites/`$_" }
"@ | Out-File C:\PowerShell\CreateTargetSiteCollections.ps1  

$psversion=""
if($sp -eq "2010"){
	$psversion=" -v 2"
}
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn CreateTargetSiteCollections /tr ('PowerShell'+$psversion+' -STA -NonInteractive -ExecutionPolicy bypass -file C:\PowerShell\CreateTargetSiteCollections.ps1') /sc weekly /d SAT /RL HIGHEST
schtasks /Run /TN CreateTargetSiteCollections

do {
 Sleep 15
 $status = (schtasks /query /tn CreateTargetSiteCollections /fo csv | ConvertFrom-Csv).Status
 $status | Out-Default
} while($status -ne 'Ready')
}

function Add-TermStoreAdministrator{
param($sp="2010")
@"
Add-PSSnapin Microsoft.SharePoint.PowerShell
`$site = Get-SPSite "http://localhost/sites/test"
`$session = new-object Microsoft.SharePoint.Taxonomy.TaxonomySession(`$site)
`$termstore = `$session.TermStores[0]
`$termstore.AddTermStoreAdministrator("VELASKEC\administrator")
`$termstore.CommitAll()
"@ | Out-File C:\PowerShell\AddTermStoreAdministrator.ps1
$psversion=""
if($sp -eq "2010"){
	$psversion=" -v 2"
}
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn AddTermStoreAdministrator /tr ('PowerShell'+$psversion+' -STA -NonInteractive -ExecutionPolicy bypass -file C:\PowerShell\AddTermStoreAdministrator.ps1') /sc weekly /d SAT /RL HIGHEST
schtasks /Run /TN AddTermStoreAdministrator
do {
 Sleep 15
 $status = (schtasks /query /tn AddTermStoreAdministrator /fo csv | ConvertFrom-Csv).Status
 $status | Out-Default
 } while($status -ne 'Ready')
}

function Deploy-Nintex{
param($nintex="2010")
new-item 'C:\NintexForms' -itemtype Directory
Read-S3Object -BucketName nmsp-ci-data -KeyPrefix 'LabManager\Nintex Forms' -Folder 'C:\msi\Nintex Forms'
$shell_app = new-object -com shell.application
$zip_file = $shell_app.namespace("C:\msi\Nintex Forms\NintexForms$nintex.zip")
$destination = $shell_app.namespace("C:\NintexForms")
$destination.Copyhere($zip_file.items())
Start-Service SPAdminV4
set-location "C:\NintexForms\Forms"
if($nintex -eq "2010")
{
PowerShell -v 2 -STA -NonInteractive -ExecutionPolicy bypass -file .\Install.ps1
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn EnableNintexFeature /tr 'PowerShell -v 2 -STA -NonInteractive -ExecutionPolicy bypass -file C:\NintexForms\setup.ps1' /sc weekly /d SAT /RL HIGHEST
}
if($nintex -eq "2013")
{
PowerShell -STA -NonInteractive -ExecutionPolicy bypass -file .\Install.ps1
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn EnableNintexFeature /tr 'PowerShell -STA -NonInteractive -ExecutionPolicy bypass -file C:\NintexForms\setup.ps1' /sc weekly /d SAT /RL HIGHEST
}
schtasks /Run /TN EnableNintexFeature
do { Sleep 10 } while((schtasks /query /tn EnableNintexFeature /fo csv | ConvertFrom-Csv).Status -ne 'Ready')
}

function Download-Watin{
new-item 'c:\WatiN' -itemtype Directory
Read-S3Object -BucketName nmsp-ci-data -Key 'LabManager\WatiN.net40.zip' -File C:\msi\WatiN.net40.zip
$shell_app = new-object -com shell.application
$zip_file = $shell_app.namespace("C:\msi\WatiN.net40.zip")
$destination = $shell_app.namespace("C:\WatiN")
$destination.Copyhere($zip_file.items())
}

function Test-SecureChannel{
$username = "VELASKEC\Administrator"
$password = "Qwerty123"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$AdminCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
while((Test-ComputerSecureChannel -Credential $AdminCred -Server nmsp -Repair -Verbose) -eq $false) { 
Sleep 10
}
}

function Set-Dns{
  param($cname_sp,$spot_id_nmsp)
  $spot = Get-EC2SpotInstanceRequest -SpotInstanceRequestId $spot_id_nmsp
  $instance=(Get-EC2Instance $spot.InstanceId).RunningInstance
  while($true){
			try{
				$NICs = Get-WMIObject Win32_NetworkAdapterConfiguration -ComputerName $cname_sp | ? IPEnabled -eq 'TRUE'
				break
			}
			catch [Exception]{
				$_.Exception.message
			}
			sleep 30
	}
  $NICs | Out-Default 
  foreach($n in $NICs) {
    'foreach' | Out-Default
    $n.DNSDomain = 'velaskec.ec2l.com'
    $n.SetDNSServerSearchOrder($instance.PrivateIpAddress)
    $n.SetDynamicDNSRegistration('TRUE','TRUE')
  }
}

function Map-AlternateAccess{
param($url,$sp="2013")
$ErrorActionPreference = 'SilentlyContinue' 
$command = @"
 Add-PSSnapin Microsoft.SharePoint.PowerShell;
 New-SPAlternateURL $url -Zone Internet -WebApplication 'SharePoint - 80'
"@  
if($sp -eq "2010"){
PowerShell -v 2 -Command "& { $command }"
}
else{
PowerShell -Command "& { $command }"
}

Restart-SpServer
}

function Restart-SpServer(){
    $username = "VELASKEC\Administrator"
    $password = "Qwerty123"
    $secstr = New-Object -TypeName System.Security.SecureString
    $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
    $AdminCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
    $success = $false
    while(!$success){
        try{
            "Try to connect to SP server..."
            $r=Invoke-WebRequest http://localhost/sites/test/SitePages/Home.aspx -Credential $AdminCred -TimeoutSec 120
            $success = $r.StatusCode -eq 200
            if($success){
                "Connected to SP server."
            }
            else{
                "Failed to connect to SP server. Status Code:" + $r.StatusCode
            }
        }
        catch [Exception]{
            $_.Exception.Message
            "Try to reset IIS..."
            try{
                iisreset /RESTART
                sleep 10
            }
            catch [Exception]{
                $_.Exception.Message
            }
        }
    }
}

function Start-Labs{
	param($labs)

	Get-EC2Tag | ? {$_.ResourceType -eq "Instance" -and $_.value -in $labs.values.name} |  % ResourceId | % { Get-EC2Instance $_ } | % { Stop-EC2Instance $_ -Terminate -Force }

	foreach($lab in $labs.values){
		$img=Get-EC2Image -Owner self | ? {$_.Name -eq $lab.image}
		if($img.length -eq 0){
		"No image named $($lab.image) is found..."
		return
		}
		$lab.spot_id = .\Create-Spot.ps1 $img[0].ImageId $lab.instance_type
		$lab.spot_id | .\Set-InstanceName.ps1 "$($lab.name)" "$($lab.team)"
	}

	$labs.values.spot_id | .\Wait-Spot.ps1

	foreach($lab in $labs.values){
		@{Key='team'; Value='NMSP'} |  .\Set-SpotInstanceTags.ps1 $lab.spot_id
		$spot = Get-EC2SpotInstanceRequest -SpotInstanceRequestId $lab.spot_id
		$instance=(Get-EC2Instance $spot.InstanceId).RunningInstance
		$lab.cname=$instance.publicDnsName
	}

	([wmiclass]"\\$($labs.nmsp.cname)\Root\MicrosoftDNS:MicrosoftDNS_Zone").CreateZone("at-nmsp.com",0,$true,$null,$null,$null) 
	$rec = [WmiClass]"\\$($labs.nmsp.cname)\root\MicrosoftDNS:MicrosoftDNS_ResourceRecord"  
	# Register Fitnesse
	$fitnesseIpAddress = (Invoke-WebRequest http://169.254.169.254/latest/meta-data/local-ipv4).Content
	$text = "fitnesse.$domainName IN A $fitnesseIpAddress"  
	$rec.CreateInstanceFromTextRepresentation('.', "at-nmsp.com", $text)
	# Register SharePoint
	if($labs.sharepoint)
	{
		while($true){
			try{
				$name=(Get-WmiObject -Class Win32_ComputerSystem -ComputerName $labs.sharepoint.cname).Name
				break
			}
			catch [Exception]{
				$_.Exception.message
			}
			sleep 30
		}
		$username = "$name\Administrator"
		$password = "Qwerty123"
		$secstr = New-Object -TypeName System.Security.SecureString
		$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
		$AdminCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
		
		  $instance = .\Get-SpotInstance.ps1 $labs.sharepoint.spot_id
		  $text = "$($labs.sharepoint.name) IN A $($instance.PrivateIpAddress)" 
		  $rec.CreateInstanceFromTextRepresentation('.', "at-nmsp.com", $text)
		  Set-Dns $labs.sharepoint.cname $labs.nmsp.spot_id
		  
	  invoke-command -ComputerName $labs.sharepoint.cname -Credential $AdminCred -ScriptBlock {
		$username = "VELASKEC\Administrator"
		$password = "Qwerty123"
		$secstr = New-Object -TypeName System.Security.SecureString
		$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
		$AdminCred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
		Reset-ComputerMachinePassword -Credential $AdminCred -Server nmsp
		while((Test-ComputerSecureChannel -Credential $AdminCred -Server nmsp -Repair -Verbose) -eq $false) { 
		Sleep 10
		}
		#Get-Service NlaSvc |Restart-Service -Force
		ipconfig /registerdns
	  }
	  
	}
	if($labs.quickr)
	{
	  $instance = .\Get-SpotInstance.ps1 $labs.quickr.spot_id
	  $text = "$($labs.quickr.name) IN A $($instance.PrivateIpAddress)" 
	  $rec.CreateInstanceFromTextRepresentation('.', "at-nmsp.com", $text)
	  Set-Dns $labs.quickr.cname $labs.nmsp.spot_id
	  
	}

	$labs.values | %{.\Register-CNAME.ps1 $_.name $_.cname}
	$labs.Keys | ? {$_ -ne "quickr"}|%{Remote-Logon $labs[$_].cname}
}

function Remote-Logon($lab){
cmdkey /generic:TERMSRV/"$lab" /user:"velaskec\administrator" /pass:"Qwerty123"
	  $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
		$Process = New-Object System.Diagnostics.Process
		$ProcessInfo.FileName = "$($env:SystemRoot)\system32\mstsc.exe"
		$ProcessInfo.Arguments = "/admin /v $lab /w 1920 /h 1080"
		$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized
		$Process.StartInfo = $ProcessInfo
		$Process.Start()
		sleep 30
		"connect to remote desktop of $lab"
}

function Get-LastResult($job){
    $result=@{}
    $xml=[xml](invoke-webrequest "http://ci.at-nmsp.com/view/Acceptance Test/job/$job/lastBuild/api/xml")
    $node = $xml.SelectSingleNode("//action[urlName='fitnesseReport']")
	if($node){
		$node.ChildNodes | % {$result[$_.Name]=$_.InnerText} 
	}
    return $result
}

function Test-Environment($computer,$remote=$false,$port=35){
	if($remote){
		"test connection to $computer"
		ipconfig /flushdns
		while(-not (Test-Connection -ComputerName $computer -BufferSize 16 -Count 1 -ErrorAction SilentlyContinue)){
		sleep 30
		"test connection to $computer"
		}
	}
	else{
		"test connection to $computer at port $port"
		while((Test-NetConnection -ComputerName $computer -Port $port).TcpTestSucceeded -ne $true){
		sleep 30
		"test connection to $computer at port $port"
		}
	}
    
}

function First-Visit($hostname){
@"
Add-PSSnapin Microsoft.SharePoint.PowerShell
`$web=Get-SPWeb "http://$hostname/sites/test"
`$subweb=`$web.Webs.Add("subsite")
`$subweb.Lists.add("wiki","wikipage for first visit","WebPageLibrary")
`$wikiPages=`$subweb.Lists["wiki"]
`$wikiPage = [Microsoft.SharePoint.Utilities.SPUtility]::CreateNewWikiPage(`$wikiPages, [System.String]::Format("{0}/{1}", `$wikiPages.RootFolder.ServerRelativeUrl, "TestPage.aspx"))

`$username = "VELASKEC\Administrator"
`$password = "Qwerty123"
`$secstr = New-Object -TypeName System.Security.SecureString
`$password.ToCharArray() | ForEach-Object {`$secstr.AppendChar(`$_)}
`$AdminCred = new-object -typename System.Management.Automation.PSCredential -argumentlist `$username, `$secstr
Invoke-WebRequest -Uri "http://$hostname/sites/Test/subsite/wiki/TestPage.aspx" -Credential `$AdminCred -TimeoutSec 240
"@ | Out-File C:\PowerShell\VisitNewWikipage.ps1
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn VisitNewWikipage /tr 'PowerShell -STA -NonInteractive -ExecutionPolicy bypass -file C:\PowerShell\VisitNewWikipage.ps1' /sc weekly /d SAT /RL HIGHEST
schtasks /Run /TN VisitNewWikipage
do {
 Sleep 15
 $status = (schtasks /query /tn VisitNewWikipage /fo csv | ConvertFrom-Csv).Status
 $status | Out-Default
 } while($status -ne 'Ready')
}

function Set-SiteAdmin($hostname){
@"
Add-PSSnapin Microsoft.SharePoint.PowerShell
`$users=Get-SPUser -web "http://$hostname/sites/Test"
Set-SPSite -Identity "http://$hostname/sites/test" -OwnerAlias `$users[0]
"@ | Out-File C:\PowerShell\SetSiteAdministrator.ps1
schtasks /create /ru VELASKEC\administrator /rp Qwerty123 /tn SetSiteAdministrator /tr 'PowerShell -STA -NonInteractive -ExecutionPolicy bypass -file C:\PowerShell\SetSiteAdministrator.ps1' /sc weekly /d SAT /RL HIGHEST
schtasks /Run /TN SetSiteAdministrator
do {
 Sleep 15
 $status = (schtasks /query /tn SetSiteAdministrator /fo csv | ConvertFrom-Csv).Status
 $status | Out-Default
 } while($status -ne 'Ready')
}

function Restore-QuestLinkTrackingDbForTimeout{
Read-S3Object -BucketName nmsp-ci-data -Key 'LabManager\LinkTracking\QuestLinkTrackingForTimeout.bak' -File "C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\Backup\QuestLinkTrackingForTimeout.bak"
Restore-SqlDatabase -ServerInstance "NMSP" -Database "QuestLinkTrackingForTimeout" -BackupFile "C:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\Backup\QuestLinkTrackingForTimeout.bak"
}

if((Get-Module AwsPowershell) -eq $null){
Import-Module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell"
Set-DefaultAWSRegion us-east-1
}