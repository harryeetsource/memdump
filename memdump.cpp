#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <set>
#include <dbghelp.h>
#include <Shlwapi.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <algorithm>
#pragma comment(lib, "Shlwapi.lib")

std::set<DWORD> dumpedPids;
std::queue<DWORD> dumpQueue;

std::mutex g_mutex;
std::condition_variable g_cv;
int numThreads = 2;

void dumpMemory(DWORD processId) {
    // Open a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Error: could not open process " << processId << std::endl;
        return;
    }

    // Check if we've already dumped the memory of this process
    if (dumpedPids.count(processId)) {
        std::cout << "Memory of process " << processId << " already dumped, skipping..." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    // Get the name of the process
    TCHAR processName[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
        std::cerr << "Error: could not get process name for process " << processId << std::endl;
        CloseHandle(hProcess);
        return;
    }
    PathStripPath(processName);
    std::this_thread::sleep_for(std::chrono::seconds(5));
    // Dump the memory of the process
    std::string dumpFilePath = std::string(processName) + "_" + std::to_string(processId) + ".dmp";
    HANDLE hFile = CreateFile(dumpFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: could not create memory dump file for process " << processId << std::endl;
        CloseHandle(hProcess);
        return;
    }
    if (MiniDumpWriteDump(hProcess, processId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == FALSE) {
        std::cerr << "Error: could not dump memory for process " << processId << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hFile);
        DeleteFile(dumpFilePath.c_str());
        return;
    }

    // Close the file and process handles
    CloseHandle(hFile);
    CloseHandle(hProcess);

    std::cout << "Memory of process " << processId << " dumped to file " << dumpFilePath << std::endl;
    dumpedPids.insert(processId);

    // Notify the waiting thread that a memory dump has completed
    g_cv.notify_one();
}

void worker_thread() {
    while (true) {
        DWORD processId;
        {
            std::unique_lock<std::mutex> lock(g_mutex);
            // Wait for a signal that there is work to be done or that all work is complete
            g_cv.wait(lock, []{ return !dumpQueue.empty() || dumpedPids.size() >= 1024; });
            if (dumpQueue.empty() && dumpedPids.size() >= 1024) {
                // Stop processing new tasks if we've dumped the memory of all processes
                return;
        }
        // Get the next process ID from the queue
        processId = dumpQueue.front();
        dumpQueue.pop();
    }
    dumpMemory(processId);
}
}

int main() {
    // Get the list of process IDs
    std::vector<DWORD> processIds(1024);
    DWORD bytesReturned;
    while (true) {
        if (EnumProcesses(processIds.data(), processIds.size() * sizeof(DWORD), &bytesReturned) == FALSE) {
            std::cerr << "Error: could not enumerate processes" << std::endl;
            return 1;
        }
        if (bytesReturned < processIds.size() * sizeof(DWORD)) {
            processIds.resize(bytesReturned / sizeof(DWORD));
            break;
        }
        processIds.resize(processIds.size() * 2);
    }

    // Remove the system processes from the list
    processIds.erase(std::remove_if(processIds.begin(), processIds.end(), [](DWORD processId) {
        // Open a handle to the process
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            return true;
        }

        // Get the name of the process
        TCHAR processName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
            CloseHandle(hProcess);
            return true;
        }
        CloseHandle(hProcess);

        // Check if the process is a system process
        return PathIsSystemFolderA(processName, FILE_ATTRIBUTE_DIRECTORY) != FALSE;

    }), processIds.end());

    // Dump the memory of the non-system processes
    for (DWORD processId : processIds) {
        dumpQueue.push(processId);
    }

    // Create and start the worker threads
    std::vector<std::thread> workerThreads;
    for (int i = 0; i < numThreads; i++) {
        workerThreads.emplace_back(worker_thread);
    }

    // Wait for the worker threads to finish
    for (std::thread& thread : workerThreads) {
        thread.join();
    }

    return 0;
}
