package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type RTL_BALANCED_NODE struct {
	Children    [2]*RTL_BALANCED_NODE
	ParentValue uintptr
}

type RTL_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type (
	PROCESS_BASIC_INFORMATION struct {
		Reserved1       uintptr
		PebBaseAddress  uintptr
		Reserved2       [2]uintptr
		UniqueProcessId uintptr
		Reserved3       uintptr
	}

	PEB_LDR_DATA struct {
		Reserved1             [8]byte
		InLoadOrderModuleList LIST_ENTRY
	}
	LDR_DATA_TABLE_ENTRY struct {
		InLoadOrderLinks LIST_ENTRY
		Reserved1        [2]LIST_ENTRY
		DllBase          uintptr
		Reserved2        [2]uintptr
		FullDllName      UNICODE_STRING
		Reserved3        [8]byte
		Reserved4        [3]uintptr
	}
)

const (
	ProcessBasicInformation = 0
)

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type PEB struct {
	Reserved1     [2]byte
	BeingDebugged byte
	Reserved2     [1]byte
	Reserved3     [2]uintptr
	LoaderData    *PEB_LDR_DATA
}

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

var (
	modkernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	modpsapi                      = windows.NewLazySystemDLL("psapi.dll")
	procNtQueryInformationProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryInformationProcess")
	procCreateToolhelp32Snapshot  = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First            = modkernel32.NewProc("Process32FirstW")
	procProcess32Next             = modkernel32.NewProc("Process32NextW")
	procOpenProcess               = modkernel32.NewProc("OpenProcess")
	procReadProcessMemory         = modkernel32.NewProc("ReadProcessMemory")
	procGetProcessMemoryInfo      = modpsapi.NewProc("GetProcessMemoryInfo")
	procVirtualQueryEx            = modkernel32.NewProc("VirtualQueryEx")
)

func getPEB(processHandle windows.Handle) (*PEB, error) {
	var processBasicInfo PROCESS_BASIC_INFORMATION
	status, _, _ := procNtQueryInformationProcess.Call(uintptr(processHandle), uintptr(ProcessBasicInformation), uintptr(unsafe.Pointer(&processBasicInfo)), uintptr(unsafe.Sizeof(processBasicInfo)), uintptr(0))
	if status != 0 {
		return nil, fmt.Errorf("failed to get PROCESS_BASIC_INFORMATION: %v", syscall.Errno(status))
	}
	peb := (*PEB)(unsafe.Pointer(processBasicInfo.PebBaseAddress))
	return peb, nil
}

func getLdrData(processHandle windows.Handle, peb *PEB) (*PEB_LDR_DATA, error) {
	var ldrData PEB_LDR_DATA
	var bytesRead uintptr
	ret, _, _ := procReadProcessMemory.Call(uintptr(processHandle), uintptr(unsafe.Pointer(peb.LoaderData)), uintptr(unsafe.Pointer(&ldrData)), uintptr(unsafe.Sizeof(ldrData)), uintptr(unsafe.Pointer(&bytesRead)))
	if ret == 0 {
		errCode := windows.GetLastError()
		return nil, fmt.Errorf("failed to read process memory: %v", errCode.Error())
	}

	return &ldrData, nil
}

func getFirstLdrEntry(processHandle windows.Handle, ldrData *PEB_LDR_DATA) (*LDR_DATA_TABLE_ENTRY, error) {
	var firstEntry LDR_DATA_TABLE_ENTRY
	const maxRetries = 3
	retries := 0

	for retries < maxRetries {
		ret, _, _ := procReadProcessMemory.Call(uintptr(processHandle), uintptr(unsafe.Pointer(ldrData.InLoadOrderModuleList.Flink))-unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InLoadOrderLinks), uintptr(unsafe.Pointer(&firstEntry)), uintptr(unsafe.Sizeof(firstEntry)), uintptr(0))
		if ret == 0 {
			errCode := windows.GetLastError()
			if errCode != nil {
				if errno, ok := errCode.(windows.Errno); ok && errno == 299 { // ERROR_PARTIAL_COPY
					retries++
					continue
				}
				return nil, fmt.Errorf("failed to read first LDR_DATA_TABLE_ENTRY: error code %d", int(errCode.(windows.Errno)))
			}
		}
		break
	}

	if retries >= maxRetries {
		return nil, fmt.Errorf("failed to read first LDR_DATA_TABLE_ENTRY: maximum retries reached")
	}

	return &firstEntry, nil
}

func getModuleName(processHandle windows.Handle, entry *LDR_DATA_TABLE_ENTRY) (string, error) {
	if entry.FullDllName.Length == 0 {
		return "", nil
	}
	nameBuffer := make([]uint16, entry.FullDllName.Length/2)
	var bytesRead uintptr
	ret, _, _ := procReadProcessMemory.Call(uintptr(processHandle), uintptr(unsafe.Pointer(entry.FullDllName.Buffer)), uintptr(unsafe.Pointer(&nameBuffer[0])), uintptr(entry.FullDllName.Length), uintptr(unsafe.Pointer(&bytesRead)))

	if ret == 0 {
		errCode := windows.GetLastError()
		return "", fmt.Errorf("failed to read module name: %v", errCode.Error())
	}

	return string(utf16.Decode(nameBuffer)), nil
}

func getNextLdrEntry(processHandle windows.Handle, ldrEntry *LDR_DATA_TABLE_ENTRY) (*LDR_DATA_TABLE_ENTRY, error) {
	var nextEntry LDR_DATA_TABLE_ENTRY
	var bytesRead uintptr
	ret, _, _ := procReadProcessMemory.Call(uintptr(processHandle), uintptr(unsafe.Pointer(ldrEntry.InLoadOrderLinks.Flink)), uintptr(unsafe.Pointer(&nextEntry)), uintptr(unsafe.Sizeof(nextEntry)), uintptr(unsafe.Pointer(&bytesRead)))

	if ret == 0 || bytesRead < uintptr(unsafe.Sizeof(nextEntry)) {
		errCode := windows.GetLastError()
		return nil, fmt.Errorf("failed to read process memory: %v", errCode)
	}

	return &nextEntry, nil
}

func getModuleBaseAddresses(processHandle windows.Handle) (map[uintptr]string, error) {
	if processHandle == 0 {
		return nil, fmt.Errorf("invalid process handle")
	}
	moduleMap := make(map[uintptr]string)

	pebAddress, err := getPEB(processHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get PEB address: %v", err)
	}

	var peb PEB
	ret, _, _ := procReadProcessMemory.Call(uintptr(processHandle), uintptr(unsafe.Pointer(pebAddress)), uintptr(unsafe.Pointer(&peb)), uintptr(unsafe.Sizeof(peb)), uintptr(0))
	if ret == 0 {
		errCode := windows.GetLastError()
		return nil, fmt.Errorf("failed to read PEB: %v", errCode)
	}

	ldrData, err := getLdrData(processHandle, &peb)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEB_LDR_DATA: %v", err)
	}

	firstEntry, err := getFirstLdrEntry(processHandle, ldrData)
	if err != nil {
		return nil, fmt.Errorf("failed to read first LDR_DATA_TABLE_ENTRY: %v", err)
	}

	currentEntry := firstEntry
	for {
		moduleName, err := getModuleName(processHandle, currentEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to get module name: %v", err)
		}

		moduleBase := currentEntry.DllBase
		moduleMap[moduleBase] = moduleName

		nextEntry, err := getNextLdrEntry(processHandle, currentEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to read next LDR_DATA_TABLE_ENTRY: %v", err)
		}

		if nextEntry.InLoadOrderLinks.Flink == ldrData.InLoadOrderModuleList.Flink {
			break
		}

		currentEntry = nextEntry
	}

	return moduleMap, nil
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
	defer windows.CloseHandle(snapshot)

	processes, err := getProcessList(snapshot)
	if err != nil {
		log.Fatalf("Error getting process list: %v", err)
	}

	for _, process := range processes {
		if process.th32ProcessID == 0 {
			continue
		}
		currentProcessID := syscall.Getpid()
		if process.th32ProcessID == uint32(currentProcessID) {
			continue
		}
		fmt.Printf("Process: %s (PID: %d)\n", syscall.UTF16ToString(process.szExeFile[:]), process.th32ProcessID)

		// Pass the log.Writer() when calling the dumpProcessMemory function
		if err := dumpProcessMemory(log.Writer(), process.th32ProcessID, process.szExeFile); err != nil {
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

func createToolhelp32Snapshot() (windows.Handle, error) {
	ret, _, err := procCreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if ret == uintptr(syscall.InvalidHandle) {
		return windows.InvalidHandle, err
	}
	return windows.Handle(ret), nil
}

func getProcessList(snapshot windows.Handle) ([]ProcessEntry32, error) {
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

func processNameToString(name [260]uint16) string {
	return syscall.UTF16ToString(name[:])
}

const (
	PROCESS_VM_READ = 0x0010
	MEM_COMMIT      = 0x1000
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func dumpProcessMemory(logFile io.Writer, processID uint32, processName [260]uint16) error {
	processHandle, err := windows.OpenProcess(syscall.PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, processID)
	if err != nil {
		return fmt.Errorf("failed to open process: %w", err)
	}
	defer windows.CloseHandle(processHandle)

	var memoryBasicInfo MEMORY_BASIC_INFORMATION
	var bytesRead uintptr
	var baseAddress uintptr

	for {
		ret, _, _ := procVirtualQueryEx.Call(uintptr(processHandle), baseAddress, uintptr(unsafe.Pointer(&memoryBasicInfo)), unsafe.Sizeof(memoryBasicInfo))

		if ret == 0 {
			break
		}

		if memoryBasicInfo.State == MEM_COMMIT {
			buffer := make([]byte, memoryBasicInfo.RegionSize)

			ret, _, err = procReadProcessMemory.Call(uintptr(processHandle), memoryBasicInfo.BaseAddress, uintptr(unsafe.Pointer(&buffer[0])), memoryBasicInfo.RegionSize, uintptr(unsafe.Pointer(&bytesRead)))

			if ret != 0 {
				outputFilePath := fmt.Sprintf("%s_%x.bin", processNameToString(processName), memoryBasicInfo.BaseAddress)
				outputFile, err := os.Create(outputFilePath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}

				_, err = outputFile.Write(buffer[:bytesRead])
				if err != nil {
					outputFile.Close()
					return fmt.Errorf("failed to write memory to file: %w", err)
				}

				outputFile.Close()
			}
		}

		baseAddress = uintptr(memoryBasicInfo.BaseAddress) + uintptr(memoryBasicInfo.RegionSize)
	}

	return nil
}
