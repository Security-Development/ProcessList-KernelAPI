#include <stdio.h>
#include <windows.h>

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;
  
typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG PageDirectoryBase;
    VM_COUNTERS VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS 
{
    SystemProcessInformation = 0x00000005,
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (WINAPI *Query)(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);

HANDLE GetProcessPID(wchar_t *ProcessName) {
	HANDLE pid;
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	HANDLE cmpPid = NULL;
	Query qsi = (Query) GetProcAddress(ntdll, "ZwQuerySystemInformation");
	ULONG length = 0x00000000;
	NTSTATUS ntStat = qsi(SystemProcessInformation, NULL, NULL, &length);
	BYTE *buff = (BYTE *) VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	BYTE *addr = buff;
	ntStat = qsi(SystemProcessInformation, buff, length, &length);
	
	PSYSTEM_PROCESS_INFORMATION SPI = (PSYSTEM_PROCESS_INFORMATION) buff;
	buff += ((PSYSTEM_PROCESS_INFORMATION)SPI)->NextEntryOffset;
	BOOLEAN check = FALSE;
	printf("[*] Getting Process..\n");
	
	
	while(true) {
		SPI = (PSYSTEM_PROCESS_INFORMATION) buff;
		
		buff += ((PSYSTEM_PROCESS_INFORMATION)SPI)->NextEntryOffset;
		printf("[%ws] target Process : %ws\n", SPI->ImageName.Buffer, ProcessName);
		
		if( wcsicmp(SPI->ImageName.Buffer, ProcessName) == 0 ){
			printf("- Find Target Process\n");
			pid = SPI->UniqueProcessId;
			check = TRUE;
			break;
		} 
		
		
		if( SPI->UniqueProcessId == cmpPid)
			break;
		cmpPid = SPI->UniqueProcessId;
		
	}
	
	if( !check) {
		printf("- Not Found TargetProcess...\n");	
		return 0x00000000;
	} else {
		return pid;
	}
}

int main() {
	wchar_t input[32];
	wscanf(L"%s", input);
	printf("- pid : %d\n", GetProcessPID(input));
	
	
	return 0;
}
