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
#include "pe_extractor.h"
#include <atomic>
#pragma comment(lib, "Shlwapi.lib")

std::set<DWORD> dumpedPids;
std::queue<DWORD> dumpQueue;

std::mutex g_mutex;
std::condition_variable g_cv;
int numThreads = std::thread::hardware_concurrency();
int numFinishedThreads = 0;
bool allProcessesDumped = false;

std::string sanitize_name(const std::string& name) {
    std::string sanitized = name;
    for (auto& c : sanitized) {
        if (!std::isalnum(c) && c != '-' && c != '_') {
            c = '_';
        }
    }
    return sanitized;
}




std::string dumpMemory(DWORD processId) {
    // Open a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Error: could not open process " << processId << std::endl;
    }

    // Check if we've already dumped the memory of this process
    if (dumpedPids.count(processId)) {
        std::cout << "Memory of process " << processId << " already dumped, skipping..." << std::endl;
        CloseHandle(hProcess);

    }

    // Get the name of the process
    TCHAR processName[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
        std::cerr << "Error: could not get process name for process " << processId << std::endl;
        CloseHandle(hProcess);
    }
    PathStripPath(processName);

    // Dump the memory of the process
    std::string dumpFilePath = std::string(processName) + "_" + std::to_string(processId) + ".dmp";
    HANDLE hFile = CreateFile(dumpFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: could not create memory dump file for process " << processId << std::endl;
        CloseHandle(hProcess);
    }
    if (MiniDumpWriteDump(hProcess, processId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == FALSE) {
        std::cerr << "Error: could not dump memory for process " << processId << std::endl;
        CloseHandle(hProcess);
        CloseHandle(hFile);
        DeleteFile(dumpFilePath.c_str());
    }

    // Close the file and process handles
    CloseHandle(hFile);
    CloseHandle(hProcess);

    std::cout << "Memory of process " << processId << " dumped to file " << dumpFilePath << std::endl;
    dumpedPids.insert(processId);

    // Notify the waiting thread that a memory dump has completed
    g_cv.notify_one();
    
    // Extract executables from the memory dump
    std::string output_path = "extracted_executables/";
    if (!fs::exists(output_path)) {
        if (!fs::create_directory(output_path)) {
            std::cerr << "Failed to create output directory: " << output_path << std::endl;
            return std::string(processName);
        }
    }
    extract_executables(dumpFilePath, output_path);

    // Notify the waiting thread that a memory dump has completed
    g_cv.notify_one();

    return std::string(processName);
}


void worker_thread() {
    DWORD currentProcessId = GetCurrentProcessId();
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
                    g_cv.notify_all();
                    break;
                }
            }
            // Get the next process ID from the queue
            processId = dumpQueue.front();
            dumpQueue.pop();
        }
        std::cout << "Worker thread " << std::this_thread::get_id() << " processing process " << processId << std::endl;
        Sleep(3000); // sleep for 3 seconds
        std::string process_name = dumpMemory(processId);
std::string sanitized_process_name = sanitize_name(process_name);
std::string output_path = "extracted_executables_" + sanitized_process_name + "_" + std::to_string(processId) + "/";

std::string input_file_path = sanitized_process_name + "_" + std::to_string(processId) + ".dmp";
std::string output_dir_path = "extracted_" + std::to_string(processId) + "/";
fs::create_directory(output_dir_path);
extract_executables(input_file_path, output_dir_path);


}
    }


std::atomic_bool g_exit(false);

int main() {
    DWORD currentProcessId = GetCurrentProcessId();
    // Set up the worker thread to dump memory
    std::thread worker(worker_thread);

    // Enumerate processes in a loop
    while (!g_exit) {
        DWORD processIds[1024];
        DWORD cbNeeded;

        if (!EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
            std::cerr << "Error enumerating processes" << std::endl;
            return 1;
        }

        // Calculate how many process identifiers were returned
        DWORD cProcesses = cbNeeded / sizeof(DWORD);

        for (unsigned int i = 0; i < cProcesses; ++i) {
            if (processIds[i] != 0 && processIds[i] != currentProcessId) {
                // Dump memory and get the process name
                std::string process_name = dumpMemory(processIds[i]);

                if (!process_name.empty()) {
                    std::string sanitized_process_name = sanitize_name(process_name);
                    std::string dumpFilePath = sanitized_process_name + "_" + std::to_string(processIds[i]) + ".dmp";
                    std::string output_path = "extracted_executables_" + sanitized_process_name + "_" + std::to_string(processIds[i]) + "/";

                    // Create output directory
                    if (!fs::exists(output_path)) {
                        if (!fs::create_directory(output_path)) {
                            std::cerr << "Failed to create output directory: " << output_path << std::endl;
                            continue; // Skip to the next process if the directory cannot be created
                        }
                    }

                    // Extract executables from the memory dump
                    extract_executables(dumpFilePath, output_path);
                }
            }
        }

        // Wait for the specified interval
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    // Join the worker thread
    worker.join();

    return 0;
}

