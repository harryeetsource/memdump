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
int numThreads = std::thread::hardware_concurrency();
int numFinishedThreads = 0;
bool allProcessesDumped = false;

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
            g_cv.wait(lock, []{ return !dumpQueue.empty() || allProcessesDumped; });
            if (dumpQueue.empty() && allProcessesDumped) {
                // Stop processing new tasks if we've dumped the memory of all processes
                numFinishedThreads++;
                std::cout << "Worker thread " << std::this_thread::get_id() << " finished, " << numFinishedThreads << " of " << numThreads << " threads done." << std::endl;
                if (numFinishedThreads == numThreads) {
                    allProcessesDumped = true;
                    g_cv.notify_all();
                    return;
                }
                continue;
            }
            // Get the next process ID from the queue
            processId = dumpQueue.front();
            dumpQueue.pop();
        }
        std::cout << "Worker thread " << std::this_thread::get_id() << " processing process " << processId << std::endl;
        Sleep(3000); // sleep for 5 seconds
        dumpMemory(processId);
    }
    // Print a message when all processes have been dumped
    std::cout << "Memory of all non-system processes dumped, exiting program..." << std::endl;
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
// Get the program's own process ID
DWORD ownProcessId = GetCurrentProcessId();
// Remove the system and own processes from the list
processIds.erase(std::remove_if(processIds.begin(), processIds.end(), [ownProcessId](DWORD processId) {
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

    // Check if the process is a system process or the own process
    return processId == ownProcessId || PathIsSystemFolderA(processName, FILE_ATTRIBUTE_DIRECTORY) != FALSE;

}), processIds.end());

// Dump the memory of the non-system and non-own processes
for (DWORD processId : processIds) {
    dumpQueue.push(processId);
}

// Create and start the worker threads
std::vector<std::thread> workerThreads;
for (int i = 0; i < numThreads; i++) {
    workerThreads.emplace_back(worker_thread);
}

// Wait for the worker threads to finish
{
    std::unique_lock<std::mutex> lock(g_mutex);
    g_cv.wait(lock, []{ return allProcessesDumped; });
}

// Print a message when all processes have been dumped
std::cout << "Memory of all non-system processes dumped, exiting program..." << std::endl;
return 0;
}