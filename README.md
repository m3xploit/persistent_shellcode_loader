# Persistent Shellcode Loader #

This shellcode loader is fully written in C and targets Windows systems. It copies itself into
C:\Users<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ for persistency
and hides as MicrosoftService.exe. Incase that file already exists it replaces it with the
shellcode loader. After that the shellcode loader checks if the script is executed from the
startup folder. If not, it starts the MicrosoftService.exe and exits to prevent the user
from stopping the malware from taskmanager by appearing as MicrosoftService.exe. (Stealth)
It downloads a malicious shellcode from your specified HTTP URL, defined in line 8, into
the a file named WindowsInternalSystemMemory.tmp in the temporary path. Then it just
proceeds loading the shellcode and executing it. This happens on every boot up, so you
can actually change the shellcode without actually spreading new malware.

## Disclaimer ##
I am not responsible for any damage. This tool is for educational purposes only!
