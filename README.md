# modernSLI
Uncertified SLI configurations on latest drivers

Build with 
`cl /nologo /W4 /O2 /MT /D_CRT_SECURE_NO_WARNINGS /Fe:modernSLI.exe modernSLI.c /link advapi32.lib shell32.lib setupapi.lib`

Should run on Windows 7 to Windows 11 on any driver with any config (too few links, no bridge, different cards, unsupported motherboard).
But have more testing to do.

Just double click the exe after installing two cards and drivers, then reboot. If you already had test signing enabled, then go ahead and check
nvidia control panel.