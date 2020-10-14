# interestring
*interesting things about strings*

Use interestring to add informative annotations to output from static analysis tools like `strings.exe` or `FLOSS`. 

### Usage ###

```
usage: interestring.py [-h] [-a] [strings_input]

Learn more about strings

positional arguments:
  strings_input    A term or file to annotate (or pipe it in via stdin)

optional arguments:
  -h, --help       show this help message and exit
  -a, --annotated  Only show annotated output
 ```
 
 Input can be provided via stdin:
 
 ```$ strings example.exe | interestring```
 
 or as an argument:
 
 ```$ interestring strings.txt```
 
which also allows you to look up individual terms:

```
$ ./interestring.py GetProcAddress
GetProcAddress  > MSDN: Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL). (http://msdn.microsoft.com/en-us/library/ms683212%28VS.85%29.aspx)
```

### Sample ###


Using a snippet of the sample output from the [FLOSS readme](https://github.com/fireeye/flare-floss#sample-output) for demonstration purposes:

```
$ ./interestring.py -a floss.txt 
WS2_32.dll                                              > DLL: Win32 API DLL                    
FreeLibrary                                             > MSDN: Frees the loaded dynamic-link library (DLL) module and, if necessary, decrements its reference count. When the reference count reaches zero, the module is unloaded from the address space of the calling process and the handle is no longer valid. (http://msdn.microsoft.com/en-us/library/ms683152%28VS.85%29.aspx)
GetProcAddress                                          > MSDN: Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL). (http://msdn.microsoft.com/en-us/library/ms683212%28VS.85%29.aspx)
LoadLibraryA                                            > MSDN: Loads the specified  module into the address space of the calling process. The specified module may cause other modules to be loaded. (http://msdn.microsoft.com/en-us/library/ms684175%28VS.85%29.aspx)
GetModuleHandleA                                        > MSDN: Retrieves a module handle for the specified module. The module must have been loaded by the calling process. (http://msdn.microsoft.com/en-us/library/ms683199%28VS.85%29.aspx)
GetVersionExA                                           > MSDN: [GetVersionEx may be altered or unavailable for releases after Windows 8.1. Instead, use the Version Helper functions] With the release of Windows 8.1, the behavior of the GetVersionEx API has changed in the value it will return for the operating system version. The value returned by the GetVersionEx function now depends on how the application is manifested. (http://msdn.microsoft.com/en-us/library/ms724451%28VS.85%29.aspx)
Sleep                                                   > MSDN: Suspends the execution of the current thread until the time-out interval elapses. (http://msdn.microsoft.com/en-us/library/ms686298%28VS.85%29.aspx)
GetLastError                                            > MSDN: Retrieves the calling thread's last-error code value. The last-error code is maintained on a per-thread basis. Multiple threads do not overwrite each other's last-error code. (http://msdn.microsoft.com/en-us/library/ms679360%28VS.85%29.aspx)
DeleteFileA                                             > MSDN: Deletes an existing file. (http://msdn.microsoft.com/en-us/library/aa363915%28VS.85%29.aspx)
WriteFile                                               > MSDN: Writes data to the specified file or input/output (I/O) device. (http://msdn.microsoft.com/en-us/library/aa365747%28VS.85%29.aspx)
Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings > REGISTRY:                             
Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings > REGISTRY:   
```
