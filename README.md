# QueApcProcessInjection

** Visual Studio 2019 Developer Command Prompt v16.10.4
** Copyright (c) 2021 Microsoft Corporation
**********************************************************************

C:\Windows\System32>csc.exe "C:\Users\Andrea\Desktop\QueApcProcessInjection.cs"
Compilatore Microsoft (R) Visual C# versione 3.10.0-4.21329.37 (246ce641)
Copyright (C) Microsoft Corporation. Tutti i diritti sono riservati.

/*QUEUE USER APC PROCESS INJECTION
description: |
	Injects shellcode into a newly spawned remote process using user-mode asynchronous procedure call (APC). 
	Thread execution via ResumeThread.
key win32 API calls:
  - kernel32.dll:
    1: 'CreateProcess'
    2: 'VirtualAllocEx'
    3: 'WriteProcessMemory'
    4: 'OpenThread'
    5: 'VirtualProtectEx'
    6: 'QueueUserAPC'
	7: 'ResumeThread'
*/
