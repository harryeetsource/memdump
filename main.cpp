#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <set>
#include <dbghelp.h>
std::set<DWORD> dumpedPids;

int main() {
    // Get the process IDs of all active processes
    DWORD processIds[1024], cbNeeded;
    if (!EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
        std::cerr << "Error: could not enumerate processes" << std::endl;
        return 1;
    }
    DWORD numProcesses = cbNeeded / sizeof(DWORD);
    const std::string dumpPath = "C:\\memdumps\\";
    // Loop through all active processes
    for (DWORD i = 0; i < numProcesses; i++) {
        // Ignore this process
        if (processIds[i] == GetCurrentProcessId()) {
            continue;
        }

        // Open a handle to the process
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
        if (hProcess == NULL) {
            std::cerr << "Error: could not open process " << processIds[i] << std::endl;
            continue;
        }

        // Check if we've already dumped the memory of this process
        if (dumpedPids.count(processIds[i])) {
            std::cout << "Memory of process " << processIds[i] << " already dumped, skipping..." << std::endl;
            CloseHandle(hProcess);
            continue;
        }

        // Get the name of the process
        TCHAR processName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
            std::cerr << "Error: could not get process name for process " << processIds[i] << std::endl;
            CloseHandle(hProcess);
            continue;
        }

        // Dump the memory of the process
        std::string dumpFilePath = std::string(processName) + "_" + std::to_string(processIds[i]) + ".dmp";
        HANDLE hFile = CreateFile(dumpFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "Error: could not create memory dump file for process " << processIds[i] << std::endl;
            CloseHandle(hProcess);
            continue;
        }
        if (MiniDumpWriteDump(hProcess, processIds[i], hFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == FALSE) {
            std::cerr << "Error: could not dump memory for process " << processIds[i] << std::endl;
            CloseHandle(hProcess);
            CloseHandle(hFile);
            DeleteFile(dumpFilePath.c_str());
            continue;
        }

        // Close the file and process handles
        CloseHandle(hFile);
        CloseHandle(hProcess);

        std::cout << "Memory of process " << processIds[i] << " dumped to file " << dumpFilePath << std::endl;
        dumpedPids.insert(processIds[i]);
    }

    return 0;
}
