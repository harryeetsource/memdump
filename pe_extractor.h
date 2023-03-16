// pe_extractor.h
#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <cstring>
#include <windows.h>
#include <algorithm>
#include <unordered_set>

namespace fs = std::filesystem;

std::vector<size_t> find_mz_headers(const std::vector<char>& buffer);
void extract_executables(const std::string& input_path, const std::string& output_path);
