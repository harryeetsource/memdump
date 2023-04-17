package main

import (
	"fmt"
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

const (
	MEM_COMMIT = 0x1000
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

func getPEB(processHandle windows.Handle) (*PEB, error) {
	var processBasicInfo PROCESS_BASIC_INFORMATION
	err := windows.NtQueryInformationProcess(processHandle, ProcessBasicInformation, unsafe.Pointer(&processBasicInfo), uint32(unsafe.Sizeof(processBasicInfo)), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get PROCESS_BASIC_INFORMATION: %v", err)
	}
	peb := (*PEB)(unsafe.Pointer(processBasicInfo.PebBaseAddress))
	return peb, nil
}

func getLdrData(processHandle windows.Handle, peb *PEB) (*PEB_LDR_DATA, error) {
	var ldrData PEB_LDR_DATA
	var bytesRead uintptr
	err := windows.ReadProcessMemory(processHandle, uintptr(unsafe.Pointer(peb.LoaderData)), (*byte)(unsafe.Pointer(&ldrData)), unsafe.Sizeof(ldrData), &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("failed to read process memory: %v", err)
	}

	return &ldrData, nil
}

func getFirstLdrEntry(processHandle windows.Handle, ldrData *PEB_LDR_DATA) (*LDR_DATA_TABLE_ENTRY, error) {
	var firstEntry LDR_DATA_TABLE_ENTRY
	err := windows.ReadProcessMemory(processHandle, uintptr(unsafe.Pointer(ldrData.InLoadOrderModuleList.Flink))-unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InLoadOrderLinks), (*byte)(unsafe.Pointer(&firstEntry)), uintptr(unsafe.Sizeof(firstEntry)), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read process memory: %v", err)
	}

	return &firstEntry, nil
}

func getNextLdrEntry(processHandle windows.Handle, ldrEntry *LDR_DATA_TABLE_ENTRY) (*LDR_DATA_TABLE_ENTRY, error) {
	var nextEntry LDR_DATA_TABLE_ENTRY
	var bytesRead uintptr
	err := windows.ReadProcessMemory(processHandle, uintptr(unsafe.Pointer(ldrEntry.InLoadOrderLinks.Flink)), (*byte)(unsafe.Pointer(&nextEntry)), uintptr(unsafe.Sizeof(nextEntry)), &bytesRead)

	if err != nil || bytesRead < uintptr(unsafe.Sizeof(nextEntry)) {
		return nil, fmt.Errorf("failed to read process memory: %v", err)
	}

	return &nextEntry, nil
}

func getModuleName(processHandle windows.Handle, entry *LDR_DATA_TABLE_ENTRY) (string, error) {
	nameBuffer := make([]uint16, entry.FullDllName.Length/2)
	var bytesRead uintptr
	err := windows.ReadProcessMemory(processHandle, uintptr(unsafe.Pointer(&entry.FullDllName.Buffer)), (*byte)(unsafe.Pointer(&nameBuffer[0])), uintptr(entry.FullDllName.Length), &bytesRead)

	if err != nil {
		return "", fmt.Errorf("failed to read module name: %v", err)
	}
	return string(utf16.Decode(nameBuffer)), nil
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
	err = windows.ReadProcessMemory(processHandle, uintptr(unsafe.Pointer(pebAddress)), (*byte)(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get PROCESS_BASIC_INFORMATION: %v", err)
	}

	ldrData, err := getLdrData(processHandle, &peb)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEB_LDR_DATA: %v", err)
	}

	ldrEntry := ldrData.InLoadOrderModuleList.Flink
	for {
		var entry LDR_DATA_TABLE_ENTRY
		if ldrEntry == nil || ldrEntry.Flink == nil {
			break
		}
		err = windows.ReadProcessMemory(processHandle, uintptr(unsafe.Pointer(ldrEntry.Flink)), (*byte)(unsafe.Pointer(&entry)), unsafe.Sizeof(entry), nil)

		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == 299 { // ERROR_PARTIAL_COPY
				ldrEntry = ldrEntry.Flink
				continue
			} else {
				return nil, fmt.Errorf("failed to read LDR_DATA_TABLE_ENTRY: %v", err)
			}
		}

		moduleBase := entry.DllBase
		moduleName, err := getModuleName(processHandle, &entry)
		if err != nil {
			return nil, fmt.Errorf("failed to get module name: %v", err)
		}

		moduleMap[moduleBase] = moduleName

		nextEntry := entry.InLoadOrderLinks.Flink
		if nextEntry == ldrData.InLoadOrderModuleList.Flink {
			break
		}

		ldrEntry = nextEntry
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
		fmt.Printf("Process: %s (PID: %d)\n", syscall.UTF16ToString(process.szExeFile[:]), process.th32ProcessID)

		// Pass the logFile when calling the dumpProcessMemory function
		if err := dumpProcessMemory(logFile, process.th32ProcessID, process.szExeFile); err != nil {
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

func dumpProcessMemory(logFile *os.File, processID uint32, exeFile [syscall.MAX_PATH]uint16) error {
	exePath := syscall.UTF16ToString(exeFile[:])

	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(processID))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hProcess)

	moduleMap, err := getModuleBaseAddresses(hProcess)
	if err != nil {
		return fmt.Errorf("Failed to get module base addresses: %v", err)
	}

	for baseAddress := uintptr(0); ; {
		baseAddress = (baseAddress + 0xFFFF) & ^uintptr(0xFFFF)
		var memoryBasicInfo MEMORY_BASIC_INFORMATION
		setMemory(unsafe.Pointer(&memoryBasicInfo), 0, unsafe.Sizeof(memoryBasicInfo))

		ret, _, _ := procVirtualQueryEx.Call(uintptr(hProcess), baseAddress, uintptr(unsafe.Pointer(&memoryBasicInfo)), unsafe.Sizeof(memoryBasicInfo))

		if ret == 0 {
			break
		}

		if memoryBasicInfo.State == MEM_COMMIT {
			var moduleName string
			for moduleBase, name := range moduleMap {
				if memoryBasicInfo.BaseAddress >= moduleBase && memoryBasicInfo.BaseAddress < moduleBase+uintptr(memoryBasicInfo.RegionSize) {
					moduleName = name
					break
				}
			}

			protectionString := protectionFlagsToString(memoryBasicInfo.Protect)

			if err != nil {
				return err
			}

			if moduleName == "" {
				fmt.Fprintf(logFile, "%s - PID %d - 0x%X - 0x%X - %s\n", exePath, processID, memoryBasicInfo.BaseAddress, memoryBasicInfo.RegionSize, protectionString)
			} else {
				moduleBase := uintptr(0)
				for base, name := range moduleMap {
					if name == moduleName {
						moduleBase = base
						break
					}
				}
				fmt.Fprintf(logFile, "%s - PID %d - %s+0x%X - 0x%X - %s\n", exePath, processID, moduleName, memoryBasicInfo.BaseAddress-moduleBase, memoryBasicInfo.RegionSize, protectionString)
			}

			buffer := make([]byte, memoryBasicInfo.RegionSize)
			var bytesRead uintptr
			ret, _, _ = procReadProcessMemory.Call(uintptr(hProcess), memoryBasicInfo.BaseAddress, uintptr(unsafe.Pointer(&buffer[0])), uintptr(memoryBasicInfo.RegionSize), uintptr(unsafe.Pointer(&bytesRead)))
			if ret == 0 {
				return fmt.Errorf("Failed to read process memory: %v", err)
			}
		}

		baseAddress += memoryBasicInfo.RegionSize
	}

	return nil
}
