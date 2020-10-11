# Common and otherwise known strings
DICT_KNOWN_STR = {
    "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED.": "Dinkumware maintains the standard C++ libraries that are iincluded in Microsoft Visual C++",
}

# Common DLLs
# Sources:
#   https://en.wikipedia.org/wiki/Microsoft_Windows_library_files
DICT_DLL = {
    "KERNEL32.DLL": "Exposes most of the Win32 base APIs",
    "GDI32.DLL": "Win32 API DLL: Graphics Data Interface functions for basic drawing for output to displays or printers",
    "USER32.DLL": "Win32 API DLL: Creates and manipulates standard elements of UI like the desktop, windows, and menus",
    "COMCTL32.DLL": "Win32 API DLL",
    "COMDLG32.DLL": "Win32 API DLL",
    "WS2_32.DLL": "Win32 API DLL",
    "ADVAPI32.DLL": "Win32 API DLL",
    "NETAPI32.DLL": "Win32 API DLL",
    "OLE32.DLL": "Win32 API DLL",
    "NTDLL.DLL": "Exports the Windows Native API",
}

# Using pipe characters here instead of backslaches to simplify character escaping
# Sources:
#   https://resources.infosecinstitute.com/common-malware-persistence-mechanisms
DICT_REGISTRY = {
    "HKCU|SOFTWARE|MICROSOFT|COMMAND PROCESSOR|AUTORUN": "Possible persistence mechanism. If /D was NOT specified on the command line, then when CMD.EXE starts, it looks for the following REG_SZ/REG_EXPAND_SZ registry variables, and if either or both are present, they are executed first.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUNSERVICESONCE": "Possible persistence mechanism.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUNSERVICES": "Possible persistence mechanism.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINLOGON|SHELL": "Possible persistence mechanism.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|EXPLORER|USER SHELL": "Persistence mechanism. Listings here will be launched furing logon and reboot.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|EXPLORER|SHELL": "Persistence mechanism. Listings here will be launched furing logon and reboot.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUN": "Used to achieve persistence at the user level.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUNONCE": "Used to achieve persistence at the user level.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|POLICIES|EXPLORER|RUN": "Possible persistence mechanism.",
    "HKCU|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINDOWS|LOAD": "Possible persistence mechanism.",
    "HKLM|SOFTWARE|MICROSOFT|COMMAND PROCESSOR|AUTORUN": "Possible persistence mechanism. If /D was NOT specified on the command line, then when CMD.EXE starts, it looks for the following REG_SZ/REG_EXPAND_SZ registry variables, and if either or both are present, they are executed first.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|EXPLORER|USER SHELL": "Persistence mechanism. Listings here will be launched furing logon and reboot.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|EXPLORER|SHELL": "Persistence mechanism. Listings here will be launched furing logon and reboot.",
    "HKLM|SYSTEM|CURRENTCONTROLSET|CONTROL|SESSION MANAGER|BOOTEXECUTE": "Possible persistence mechanism.",
    "HKLM|SYSTEM|CURRENTCONTROLSET|SERVICES": "Start value of 0 indicates kernel drivers, which load before kernel initiation. Start value of 2 indicates auto-start, 3 for manual start via SCM.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUNSERVICESONCE": "Used to start background services. Possible persistence mechanism.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUNSERVICES": "Used to start background services. Possible persistence mechanism.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINLOGON": "Winlogon uses values in this key to launch login scripts. The Userinit key can be changed to point to something other than userinit.exe, which will be launched by Winlogon.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINLOGON|NOTIFY": "Can be edited to launch a DLL whenever Secure Attention Services (ctrl+alt+del) events occur.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINLOGON|USERINIT": "Winlogon uses values in this key to launch login scripts. The Userinit key can be changed to point to something other than userinit.exe, which will be launched by Winlogon.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINLOGON|SHELL": "Should only point to explorer.exe and not the complete path.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|INIFILEMAPPING|SYSTEM.INI|BOOT": "Should only point to location under Winlogon.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|SHELLSERVICEOBJECTDELAYLOAD": "Possible persistence mechanism.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUN": "Used to achieve persistence at the system level.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUNONCE": "Used to achieve persistence at the system level.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|RUNONCEEX": "Used to achieve persistence at the system level.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|POLICIES|EXPLORER|RUN": "Used to achieve persistence at the system level.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINDOWS": "Possible persistence mechanism.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|EXPLORER|SHAREDTASKSCHEDULER": "Possible persistence mechanism.",
    "HKLM|SYSTEM|CURRENTCONTROLSET|CONTROL|HIVELIST": "Persistence mechanism. smss.exe launches prior to Windows subsystem is loaded and calls this hive.",
    "HKLM|SYSTEM|CONTROLSET002|CONTROL|SESSION MANAGER": "Persistence mechanism. smss.exe starts anything present in this key, which should have value of 'autocheck autochk*'. Additional values suggest malware will launch at boot.",
    "HKLM|SYSTEM|CURRENTCONTROLSET|SERVICES": "Windows services required to run at boot. Possible persistence mechanism.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|EXPLORER|BROWSER HELPER OBJECTS": "DLL module loaded when Internet Explorer starts. Possible persistence mechanism.",
    "HKLM|SOFTWARE|MICROSOFT|WINDOWS NT|CURRENTVERSION|WINDOWS|APPINIT_DLLS": "Shows DLLs loaded by User32.dll, which is a good place to check for malware persistence.",
    "HKLM|SYSTEM|CURRENTCONTROLSET|CONTROL|SESSION MANAGER|KNOWNDLLS": "OS checks if a DLL is known. If not loaded and not in KnownDLLs, then OS starts searching directories, which can be abused by DLL search order hijacking.",
    "SOFTWARE|MICROSOFT|WINDOWS|CURRENTVERSION|INTERNET SETTINGS": "Internet settings.",
}
