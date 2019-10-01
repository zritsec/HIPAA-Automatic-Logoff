$Banner = @'
//////////////////////////////////////////////////////////////////////////////////
//              W       A       R       N       I       N       G               //
//////////////////////////////////////////////////////////////////////////////////

Do not forget to lock your PC before you walk away by pressing WINDOWS + L.

    - Information Security 

'@

$Banner | Out-File $env:userprofile/Desktop/lock_your_pc.txt
Start-Process notepad $env:userprofile/Desktop/lock_your_pc.txt -WindowStyle Maximized
Invoke-Command {rundll32.exe user32.dll,LockWorkStation}
