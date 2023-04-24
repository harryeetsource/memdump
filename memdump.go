package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

type RTL_BALANCED_NODE struct {
	Children    [2]uintptr
	Red         uintptr
	Balance     uintptr
	ParentValue uintptr
}

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

var (
	modkernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	modntdll                      = windows.NewLazySystemDLL("ntdll.dll")
	modpsapi                      = windows.NewLazySystemDLL("psapi.dll")
	procCreateToolhelp32Snapshot  = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First            = modkernel32.NewProc("Process32FirstW")
	procProcess32Next             = modkernel32.NewProc("Process32NextW")
	procOpenProcess               = modkernel32.NewProc("OpenProcess")
	procReadProcessMemory         = modkernel32.NewProc("ReadProcessMemory")
	procGetProcessMemoryInfo      = modpsapi.NewProc("GetProcessMemoryInfo")
	procVirtualQueryEx            = modkernel32.NewProc("VirtualQueryEx")
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
)

const (
	MEM_COMMIT = 0x1000
)

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint8
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
	EntryInProgress                 uintptr
	ShutdownInProgress              uint8
	ShutdownThreadId                uintptr
}

func readUnicodeString(hProcess uintptr, str UNICODE_STRING) string {
	buffer := make([]uint16, str.Length)
	ret, _, _ := procReadProcessMemory.Call(hProcess, uintptr(str.Buffer), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)*2), 0)
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}
type PEB struct {
	InheritedAddressSpace    byte
	ReadImageFileExecOptions byte
	BeingDebugged            byte
	BitField                 byte
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      *PEB_LDR_DATA
	ProcessParameters        uintptr
	SubSystemData            uintptr
	ProcessHeap              uintptr
	FastPebLock              uintptr
	AtlThunkSListPtr         uintptr
	IFEOKey                  uintptr
	CrossProcessFlags        uintptr
	UserSharedInfoPtr        uintptr
	SystemReserved           uint32
	AtlThunkSListPtr32       uint32
	ApiSetMap                uintptr
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks             LIST_ENTRY
	InMemoryOrderLinks           LIST_ENTRY
	InInitializationOrderLinks   LIST_ENTRY
	DllBase                      uintptr
	EntryPoint                   uintptr
	SizeOfImage                  uint32
	FullDllName                  UNICODE_STRING
	BaseDllName                  UNICODE_STRING
	Flags                        uint32
	LoadCount                    uint16
	TlsIndex                     uint16
	HashLinks                    LIST_ENTRY
	SectionPointer               uintptr
	CheckSum                     uint32
	TimeDateStamp                uint32
	EntryPointActivationContext  uintptr
	PatchInformation             uintptr
	ForwarderLinks               LIST_ENTRY
	ServiceTagLinks              LIST_ENTRY
	StaticLinks                  LIST_ENTRY
	ContextInformation           uintptr
	OriginalBase                 uint32
	LoadTimeOrderLinks           LIST_ENTRY
	BaseAddressIndexNode         RTL_BALANCED_NODE
	MappingInfoIndexNode         RTL_BALANCED_NODE
	OriginalBaseIndexNode        RTL_BALANCED_NODE
	LoadTimeOrderIndexNode       RTL_BALANCED_NODE
	PreorderLibraryPathIndexNode RTL_BALANCED_NODE
	DirectedLinkingTimeStamp     uint64
	GlobalLock                   uintptr
	LoadOwner                    uintptr
	LoadReason                   uint32
	QuotaPagedPoolUsage          uint32
	QuotaNonPagedPoolUsage       uint32
	PagefileUsage                uint32
	PeakPagefileUsage            uint32
	PerProcessSystemDll          uintptr
	PerProcessDebugging          uint32
	PerProcessDebugFlags         uint32
	CreatorProcess               uintptr
	CreatorBackTraceIndex        uint32
	LoaderPrivateData            uintptr
	Reserved3                    [1]uintptr
	FreeTebHint                  uintptr
	Reserved4                    uint32
	Reserved5                    uintptr
	Win32ClientInfo              [62]uintptr
	LoaderThreads                uint32
	AlternativeLoadFlags         uint32
	LoaderPrivateFlags           uint32
	LastRITInitError             uint32
	LoadInProgress               uintptr
	LoaderEntry                  uintptr
	Reserved6                    uintptr
	PendingBindings              uintptr
}

func setMemory(ptr unsafe.Pointer, value byte, size uintptr) {
	bytes := make([]byte, size)
	for i := range bytes {
		bytes[i] = value
	}
	copy((*[1 << 30]byte)(ptr)[:size:size], bytes)
}

func main() {
	logFile, err := os.OpenFile("memory_dumper.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating log file: %v", err)
	}
	defer logFile.Close()

	// Redirect log output to the log file
	log.SetOutput(logFile)
	snapshot, err := createToolhelp32Snapshot()
	if err != nil {
		log.Fatalf("Error creating snapshot: %v", err)
	}
	defer syscall.CloseHandle(snapshot)

	processes, err := getProcessList(snapshot)
	if err != nil {
		log.Fatalf("Error getting process list: %v", err)
	}

	currentProcessID := syscall.Getpid()

	for _, process := range processes {
		if process.th32ProcessID == 0 {
			continue
		}

		// Skip dumping memory of current process
		if process.th32ProcessID == uint32(currentProcessID) {
			continue
		}

		fmt.Printf("Process: %s (PID: %d)\n", syscall.UTF16ToString(process.szExeFile[:]), process.th32ProcessID)

		if err := dumpProcessMemory(process.th32ProcessID, process.szExeFile); err != nil {
			fmt.Printf("Failed to dump memory: %v\n", err)
		}
	}
}

// ProcessEntry32 is a PROCESSENTRY32 structure.
type ProcessEntry32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [syscall.MAX_PATH]uint16
}

func createToolhelp32Snapshot() (syscall.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if ret == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(ret), nil
}

func getProcessList(snapshot syscall.Handle) ([]ProcessEntry32, error) {
	var processes []ProcessEntry32

	var process ProcessEntry32
	process.dwSize = uint32(unsafe.Sizeof(process))

	ret, _, err := procProcess32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&process)))
	if ret == 0 {
		return nil, err
	}

	for {
		processes = append(processes, process)

		process = ProcessEntry32{}
		process.dwSize = uint32(unsafe.Sizeof(process))

		ret, _, err := procProcess32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&process)))
		if ret == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}

	return processes, nil
}

type PROCESS_MEMORY_COUNTERS_EX struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

func protectionFlagsToString(protect uint32) string {
	flags := make([]string, 0)

	read := protect&windows.PAGE_READONLY != 0 || protect&windows.PAGE_READWRITE != 0 || protect&windows.PAGE_WRITECOPY != 0 || protect&windows.PAGE_EXECUTE_READ != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0
	write := protect&windows.PAGE_READWRITE != 0 || protect&windows.PAGE_WRITECOPY != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0
	execute := protect&windows.PAGE_EXECUTE != 0 || protect&windows.PAGE_EXECUTE_READ != 0 || protect&windows.PAGE_EXECUTE_READWRITE != 0 || protect&windows.PAGE_EXECUTE_WRITECOPY != 0

	if read {
		flags = append(flags, "R")
	}
	if write {
		flags = append(flags, "W")
	}
	if execute {
		flags = append(flags, "X")
	}

	return strings.Join(flags, "")
}
func dumpProcessMemory(processID uint32, exeFile [syscall.MAX_PATH]uint16) error {
	exePath := syscall.UTF16ToString(exeFile[:])

	hProcess, _, err := procOpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(0), uintptr(processID))
	if hProcess == 0 {
		return err
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	outputPath := filepath.Join(".", fmt.Sprintf("%s_%d.dmp", exePath, processID))
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	var bytesRead uintptr

	// Get the PEB address
	var processBasicInfo PROCESS_BASIC_INFORMATION
	ret, _, err := procNtQueryInformationProcess.Call(hProcess, 0, uintptr(unsafe.Pointer(&processBasicInfo)), unsafe.Sizeof(processBasicInfo), 0)
	if ret != 0 {
		pebAddress := processBasicInfo.PebBaseAddress

		// Read the PEB
		var peb windows.PEB
		ret, _, err = procReadProcessMemory.Call(hProcess, pebAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&bytesRead)))
		if ret == 0 {
			return fmt.Errorf("Failed to read PEB")
		}

		var pebCustom PEB
		ret, _, err = procReadProcessMemory.Call(hProcess, pebAddress, uintptr(unsafe.Pointer(&pebCustom)), unsafe.Sizeof(pebCustom), uintptr(unsafe.Pointer(&bytesRead)))
		if ret == 0 {
			return fmt.Errorf("Failed to read custom PEB")
		}

		ldrData := pebCustom.Ldr

		// Read LDR_DATA_TABLE_ENTRY
		var ldrEntry LDR_DATA_TABLE_ENTRY
		ldrEntryAddress := ldrData.InLoadOrderModuleList.Flink
		for ldrEntryAddress != 0 {
			ret, _, err = procReadProcessMemory.Call(hProcess, uintptr(ldrEntryAddress), uintptr(unsafe.Pointer(&ldrEntry)), unsafe.Sizeof(ldrEntry), uintptr(unsafe.Pointer(&bytesRead)))
			if ret == 0 {
				break
			}

			baseDllName := readUnicodeString(hProcess, ldrEntry.BaseDllName)
			fmt.Printf("Module: %s Base address: %X Size: %X\n", baseDllName, ldrEntry.DllBase, ldrEntry.SizeOfImage)

			// Write module to the dump file
			moduleBuffer := make([]byte, ldrEntry.SizeOfImage)
			ret, _, err = procReadProcessMemory.Call(hProcess, ldrEntry.DllBase, uintptr(unsafe.Pointer(&moduleBuffer[0])), uintptr(ldrEntry.SizeOfImage), uintptr(unsafe.Pointer(&bytesRead)))
			if ret != 0 {
				outputFile.Write(moduleBuffer[:bytesRead])
			}

			ldrEntryAddress = uintptr(ldrEntry.InLoadOrderLinks.Flink)
		}
	}

	type MemoryRange struct {
		BaseAddress uintptr
		RegionSize  uintptr
		Protect     uint32
	}

	var memoryRanges []MemoryRange

	for baseAddress := uintptr(0); ; {
		baseAddress = (baseAddress + 0xFFFF) & ^uintptr(0xFFFF)
		var memoryBasicInfo MEMORY_BASIC_INFORMATION
		setMemory(unsafe.Pointer(&memoryBasicInfo), 0, unsafe.Sizeof(memoryBasicInfo))
		ret, _, _ := procVirtualQueryEx.Call(hProcess, baseAddress, uintptr(unsafe.Pointer(&memoryBasicInfo)), unsafe.Sizeof(memoryBasicInfo))

		if ret == 0 {
			break
		}

		if memoryBasicInfo.State == MEM_COMMIT {
			buffer := make([]byte, memoryBasicInfo.RegionSize)
			var bytesRead uintptr
			ret, _, err = procReadProcessMemory.Call(hProcess, memoryBasicInfo.BaseAddress, uintptr(unsafe.Pointer(&buffer[0])), uintptr(memoryBasicInfo.RegionSize), uintptr(unsafe.Pointer(&bytesRead)))
			if ret != 0 {
				outputFile.Write(buffer[:bytesRead])
				memoryRanges = append(memoryRanges, MemoryRange{BaseAddress: baseAddress, RegionSize: memoryBasicInfo.RegionSize, Protect: memoryBasicInfo.Protect})
			}
		}

		baseAddress += memoryBasicInfo.RegionSize
	}

	log.Printf("Memory dump for PID %d saved to: %s\n", processID, outputPath)
	log.Printf("Memory ranges for PID %d:\n", processID)
	for _, memRange := range memoryRanges {
		protectionStr := protectionFlagsToString(memRange.Protect)
		log.Printf("Base address: %X, Region size: %X, Protection: %s\n", memRange.BaseAddress, memRange.RegionSize, protectionStr)
	}

	return nil
}
