This project was created as one of the client applications with reverse engineering protection . 
It has a lot of layers of protection:
You can see in it a obsuficate  - its meaning is that we can confuse the attacker when he tries to disassemble our application.
Searching for and finding a node, as well as a driver that will keep track of our application .

Now I would like to delve into the theory of .
# Obsuficate
Types of obfuscation
There are four types of conversions:

lexical obfuscation;
data conversion;
control transformation;
preventive obfuscation.
Lexical obfuscation is replacement of variable and function names. For example, previously understandable final_cost[positions] turns into soulless f5rq[zlp]. Or here is another way of comparing:
```C++
int counter;
bool alarm;

for (counter = 0; counter < 100; counter++)
{
  if (counter == 99)
  {
    alarm = true;
  }
}
```
```C++
int plf5ojvb; bool jht4hnv; for(plf5ojvb=0; plf5ojvb<100; plf5ojvb++){if(plf5ojvb==99) jht4hnv=true;)
```
But what if there are not two variables, but half a dozen? It's hard to read and understand it. This type of obfuscation is easy to use quickly but has little effect: only method names change, while the overall scheme remains unchanged. Modern IDEs know how to search for method usage in code, which makes analysis of obfuscated code very easy. Bypassing such obfuscation is a matter of time.

Data conversion is a more complex and efficient operation. It involves changing and creating new data types and applying combinatorics to them. For example, the number 9 can be represented as 10000000001 (the number of zeros), 210019 (the binary number between the beginning and the end identifiers), 32 (32) and a huge number of other ways. Or replacing the expression i=1 for a simple enumeration loop with i0=21 followed by a representation through other constants - i=i0/i1-i2, where i1=7, i2=2. As for data types, in the simplest case you can represent 32-bit numeric data by multiplying 16-bit by some variable with the value of 16.

Control conversion is a violation of the natural flow of a program, for which opaque predicates are used. That is, it is a case where the result of executed actions is hard to predict in the course of a given procedure. In the simplest case, it is the creation of additional blocks of code: one in which calculations are performed, another in which inheritance takes place, and some general case in which several false operations are performed, only one of which is valid. In more complex situations, a complex map of substitutions and transformations is created, changing the overall code structure beyond recognition.

Preventive obfuscation protects your code from deobfuscation by special deobfuscator programs. They are based on detecting unused pieces of code, finding the most complex structures (fragments of maximum importance) and analyzing statistical and dynamic data. It is the fight against these operations that is the most complex and efficient obfuscation process. Here it is necessary to approach the analysis of raw data as precisely as possible, to use the maximum provided resources, to take into account the approaches of potential opponents.


# Anti-Debugger

Since not only the x86 architecture is popular now, but also x86-64, many of the old debugger detection tools are obsolete. Others need adjustments because they are hardwired into x86 architecture offsets. In this article I will discuss several debugger detection methods and show code that will work on both x64 and x86.

 
## IsDebuggerPresent() and the PEB structure
It would be incorrect to start talking about anti-debugging without mentioning the IsDebuggerPresent() function. It is universal, works on different architectures, and is very easy to use. You only need one line of code to define debugging:
```C++
if (IsDebuggerPresent()).
```
What is the WinAPI IsDebuggerPresent? This function calls the PEB structure.

## Process Environment Block
The process environment block (PEB) is filled in by the operating system's boot loader, located in the process address space and can be modified from usermode. It contains many fields: for example, from here you can get information about the current module, environment and loaded modules. You can get the PEB structure by accessing it directly at fs:[30h] for x86 and gs:[60h] for x64.

Accordingly, if we load the IsDebuggerPresent() function into the debugger, on the x86 system we see:
```Nasm
mov     eax,dword ptr fs:[30h]
movzx   eax,byte ptr [eax+2]
ret
```

And on x64 the code will be like this:
```Nasm
mov   rax,qword ptr gs:[60h]
movzx eax,byte ptr [rax+2]
ret
```

What does byte ptr [rax+2] mean? At this offset is the BeingDebugged field in the PEB structure, which signals to us that debugging is taking place. How else can we use PEB to detect debugging?
NtGlobalFlag

During debugging, the system flags FLG_HEAP_VALIDATE_PARAMETERS, FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK, in the NtGlobalFlag field, which is in the PEB structure. The debugger uses these flags to control heap destruction through overflow. The bit mask of the flags is 0x70. The NtGlobalFlag offset in the PEB for x86 is 0x68, for x64 it is 0xBC. To show an example of the debugger detection code by NtGlobalFlag we will use intrinsics functions, and to make the code more universal we will use preprocessor directives:

```C++
#ifdef _WIN64

DWORD pNtGlobalFlag = NULL;
PPEB pPeb = (PPEB)__readgsqword(0x60);
pNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);

#else

DWORD pNtGlobalFlag = NULL;
PPEB pPeb = (PPEB)__readfsdword(0x30);
pNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);

#endif

if ((pNtGlobalFlag & 0x70) != 0) std::cout << "Debugger detected!\n";
```

## Flags and ForceFlags
The PEB also contains a pointer to the _HEAP structure, which contains the Flags and ForceFlags fields. When the debugger is connected to the application, the Flags and ForceFlags fields contain debugging indications. ForceFlags should not be zero when debugging, the Flags field should not be 0x00000002:
```C++
#ifdef _WIN64

PINT64 pProcHeap = (PINT64)(__readgsqword(0x60) + 0x30);    \\ Получаем структуру _HEAP через PEB
PUINT32 pFlags = (PUINT32)(*pProcHeap + 0x70);      \\ Получаем Flags внутри _HEAP
PUINT32 pForceFlags = (PUINT32)(*pProcHeap + 0x74);     \\ Получаем ForceFlags внутри _HEAP

#else

PPEB pPeb = (PPEB)(__readfsdword(0x30) + 0x18);
PUINT32 pFlags = (PUINT32)(*pProcessHeap + 0x40);
PUINT32 pForceFlags = (PUINT32)(*pProcessHeap + 0x44);

#endif

if (*pFlags & ~HEAP_GROWABLE || *pForceFlags != 0) 
std::cout << "Debugger detected!\n";
```

## CheckRemoteDebuggerPresent() and NtQueryInformationProcess
The CheckRemoteDebuggerPresent function, like IsDebuggerPresent, is cross-platform and checks for a debugger. Its difference from IsDebuggerPresent is that it is able to check not only its own process, but also others by their handles. The prototype of the function looks like this:
```C++
BOOL WINAPI CheckRemoteDebuggerPresent(
_In_    HANDLE hProcess,
_Inout_ PBOOL  pbDebuggerPresent
);
```
where hProcess is the handle of the process that we are checking for a debugger connection, pbDebuggerPresent is the result of the function (TRUE or FALSE, respectively). But the most important difference in the work of this function is that it doesn't take information from the PEB like IsDebuggerPresent, but uses the WinAPI function NtQueryInformationProcess. The prototype of the function looks like this:
```C++
NTSTATUS WINAPI NtQueryInformationProcess(
_In_      HANDLE           ProcessHandle,
_In_      PROCESSINFOCLASS ProcessInformationClass,
_Out_     PVOID            ProcessInformation,
_In_      ULONG            ProcessInformationLength,
_Out_opt_ PULONG           ReturnLength
);
```
The field that helps us understand how CheckRemoteDebuggerPresent works is ProcessInformationClass, which is a large structure (enum) PROCESSINFOCLASS with parameters. The CheckRemoteDebuggerPresent function passes a value of 7 into this field, which points to the ProcessDebugPort. The point is that when the debugger is connected to a process, the ProcessInformation field in the EPROCESS structure is populated, which is named DebugPort in the code.

The EPROCESS structure, or process block, contains a lot of information about the process, pointers to several data structures, including the PEB. It is filled by the OS runtime system and is located in the system address space (kernelmode), like all related structures except the PEB. All processes have this structure.

If the field is populated and a debug port is assigned, a decision is made that debugging is in progress. Code for CheckRemoteDebuggerPresent:
```C++
BOOL IsDbgPresent = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &IsDbgPresent);
if (IsDbgPresent) std::cout << "Debugger detected!\n";
```

Code for passing the ProcessDebugPort parameter directly to the NtQueryInformationProcess function:
```C++
Status = NtQueryInfoProcess(GetCurrentProcess(),
7,  // ProcessDbgPort
&DbgPort, 
dProcessInformationLength, 
NULL);

if (Status == 0x00000000 && DbgPort != 0) std::cout << "Debugger detected!\n";
```

The Status variable is of NTSTATUS type and signals us the success or failure of the function execution; in DbgPort we check if the port is assigned or the field is null. If the function worked without errors and returned status 0 and DbgPort has a non-zero value, the port is assigned and debugging is going on.

### NtQueryInfoProcess intricacies
The MSDN documentation tells us that you should use NtQueryInfoProcess via dynamic linking by getting its address from ntdll.dll directly through the LoadLibrary and GetProcAddress functions and defining the function prototype manually using typedef
```C++
typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(LoadLibrary(_T("ntdll.dll")), "NtQueryInformationProcess");
```
But the NtQueryInformationProcess function can show several signs of debugging, and ProcessDebugPort is only one of them.

## DebugObject
Debugging an application creates a DebugObject, a debugging object. If you pass value 0x1E to NtQueryInformationProcess in the ProcessInformationClass field, it will point to the ProcessDebugObjectHandle element and the debug object handle will be returned to us when the function runs. The code is similar to the previous one with the difference that the value 0x1E is passed to the ProcessInformationClass field instead of 7 and the check condition is changed:
```C++
if (Status == 0x00000000 && hDebObj) std::cout << "Debugger detected!\n";
```

where hDebObj is the ProcessInformation field with the result. It's the same here: the function worked correctly and returned 0, hDebObj is non-zero. So the debug object is created.

## ProcessDebugFlags
The next debugging sign that the NtQueryInfoProcess function will show us is the ProcessDebugFlags field, which has the number 0x1F. By passing a value of 0x1F, we make the NtQueryInfoProcess function show us the NoDebugInherit field, which is in the EPROCESS structure. If the field is zero, it means that the application is currently debugging. The NtQueryInfoProcess call code is identical, we only change the ProcessInformationClass number and the check:

```C++
if (Status == 0x00000000 && NoDebugInherit == 0) std::cout << "Debugger detected!\n";
```

## Checking the parent process
The essence of this anti-debugging method is that we have to check who exactly is running the application we are protecting: the user or the debugger. This method can be implemented in different ways - to check if the parent process is explorer.exe or if it is ollydbg.exe, x64dbg.exe, x32dbg and so on. If we try to develop the logic of this debugging detection method, another simple method comes to mind: get a snapshot of all the processes on the system and compare the name of each process with a list of known debuggers.

We'll check the parent process with the already known NtQueryInformationProcess function and the PROCESS_BASIC_INFORMATION structure (the InheritedFromUniqueProcessId field), and get a list of all the running processes in the system with CreateToolhelp32Snapshot/Process32First/Process32Next. To avoid writing irrelevant code parsing all the processes in the system, let's write only the basic code to get the ID of the parent process and the basic check:

```C++
PROCESS_BASIC_INFORMATION baseInf;

NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &baseInf, sizeof(baseInf), NULL);
```
So, baseInf.InheritedFromUniqueProcessId contains the ID of the process that spawns ours. You can use it in any way you want: for example, get the filename, the process name from it and compare it with the debugger names or check if it's explorer.exe.

## TLS Callbacks.
This non-trivial anti-debugging method consists of embedding anti-debugging techniques into the TLS Callbacks, which are executed before the program's entry point. Breakpoints can be set within the application itself, and attention will be focused on the main application code, but this technique will complete debugging before it has even begun. Some people think this method is very powerful, but now with a properly configured debugger, the debugging process can stop when you enter the TLS Callbacks. That is, it won't save you against experienced reversers, but it will eliminate a lot of schoolchildren who don't understand what's going on To implement this detection method, you have to tell the compiler to create the TLS section by this code:
```C++
#pragma comment(linker,"/include:__tls_used")
```
The section must be named CRT$XLY:
```C++
#pragma section(".CRT$XLY", long, read)
````
Implementation code itself:
```C++
void WINAPI TlsCallback(PVOID pMod, DWORD Reas, PVOID Con)
{

  if (IsDebuggerPresent()) std::cout << "Debugger detected!\n";

}

__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK CallTSL[] = {CallTSL,NULL};
```

## Debug registers
If the debug registers contain any data, that's another indication. But the thing is that the debug registers are a privileged resource and can only be directly accessed in kernel mode. But we will try to get the context of the thread using the GetThreadContext function and thus read data from the debug registers. The total number of debug registers is eight, DR0-DR7. The first four registers DR0-DR3 contain breakpoint information, registers DR4-DR5 are reserved, register DR6 is filled when the debugger breakpoint is triggered and contains information about that event. Register DR7 contains the debug control bits. So, we're wondering what information is contained in the first four registers.

```C++
CONTEXT context = {};
context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

GetThreadContext(GetCurrentThread(), context);

if (ctx.Dr0 != 0 || 
ctx.Dr1 != 0 || 
ctx.Dr2 != 0 || 
ctx.Dr3 != 0)
std::cout << "Debugger detected!\n";
```

## NtSetInformationThread
Another non-trivial method of anti-debugging is based on passing the HideFromDebugger flag (located in the _ETHREAD structure under number 0x11) to the NtSetInformationThread function. Here is what the prototype of the function looks like:
```C++
NTSTATUS ZwSetInformationThread(
_In_ HANDLE ThreadHandle,
_In_ THREADINFOCLASS ThreadInformationClass,
_In_ PVOID ThreadInformation,
_In_ ULONG ThreadInformationLength
);
```
This technique will hide our thread from the debugger, stopping it from sending debug events, such as breakpoint triggers. The peculiarity of this method is that it is universal and works thanks to the standard features of the OS. Here is the code that implements the disconnection of the main program thread from the debugger:
```C++
NTSTATUS stat = NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);
```
## NtCreateThreadEx
The NtCreateThreadEx function works similarly to the previous one. It has been available in Windows since Vista. It can also be used as a ready-made debugging hindrance tool. The principle of action is similar to NtSetInformationThread - if you pass the THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER parameter into the CreateFlags field the process will not be visible to the debugger. Function prototype:
```C++
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateThreadEx (
_Out_ PHANDLE ThreadHandle,
_In_ ACCESS_MASK DesiredAccess,
_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
_In_ HANDLE ProcessHandle,
_In_ PVOID StartRoutine,
_In_opt_ PVOID Argument,
_In_ ULONG CreateFlags,
_In_opt_ ULONG_PTR ZeroBits,
_In_opt_ SIZE_T StackSize,
_In_opt_ SIZE_T MaximumStackSize,
_In_opt_ PVOID AttributeList
);
```
Code to disable the debugger:

```C++
HANDLE hThr = 0;

NTSTATUS status = NtCreateThreadEx(&hThr, 
THREAD_ALL_ACCESS, 0, NtCurrentProcess, 
(LPTHREAD_START_ROUTINE)next, 0, 
THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0, 0, 0, 0);
```
After that the next() function from WinAPI starts working, which is in a separate trace invisible to the debugger.

## SeDebugPrivilege
One of the signs that an application is debugging is that the application gets SeDebugPrivilege. To find out if our process has this privilege, we can, for example, try to open some system process. Traditionally we will try to open csrss.exe. To do that we use the WinAPI OpenProcess function with the PROCESS_ALL_ACCESS parameter. Here is how this method is implemented (Id_From_csrss has the ID of csrss.exe):
```C++
HANDLE hDebug = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Id_From_csrss);
if hDebug != NULL) std::cout << "Debugger detected!\n";
```

## SetHandleInformation
The SetHandleInformation function is used to set the properties of the object descriptor pointed to by hObject. The prototype of the function looks like this:
```C++
BOOL SetHandleInformation(
  HANDLE hObject,
  DWORD dwMask,
  DWORD dwFlags
);
The types of objects are different, for example it can be a job, a file mapping or a mutex. We can take advantage of that: create a mutex with flag HANDLE_FLAG_PROTECT_FROM_CLOSE and try to close it, trying to catch an exception at the same time. If an exception is caught, the process is debugged.

HANDLE hMyMutex = CreateMutex(NULL, FALSE, _T("MyMutex"));

SetHandleInformation(hMyMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);


__try {
CloseHandle(hMutex);
}

__except (HANDLE_FLAG_PROTECT_FROM_CLOSE) {
    std::cout << "Debugger detected!\n";
}
```


Also do not forget about the professional utilities, you can always use VmProtect which has obsuficate , virtualization and debugger detection 
