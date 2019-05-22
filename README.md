# RDP2Ban
Count failed RDP sessions (username / password missmatch) by IP-Address.


# Setup
Create an automated Task:

Trigger: Event  
Protocol: RemoteDesktopServices-RdpCoreTS/Operational  
Source: RemoteDesktopServices-RdpCoreTS  
Event-ID: 140  

Start program:  
Script: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
Args: -file "C:\scripts\RDP2Ban.ps1"  
