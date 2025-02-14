#pragma once
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <cstdint>

std::unordered_set<std::string> extract_mac_addresses(const std::string& line);
std::unordered_map<std::string, int> count_using(std::istream& in);
std::vector<std::pair<std::string, int>> sort_by_count(const std::unordered_map<std::string, int>& mac_count);
