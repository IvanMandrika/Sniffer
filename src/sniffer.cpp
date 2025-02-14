#include "sniffer.h"

using size_t = std::size_t;

std::pair<std::string, size_t> collect_string(const std::string& line, size_t i) {
    const size_t start = i;
    const size_t len = line.length();
    while (i < len && line[i] != ',' && line[i] != '\n' && line[i] != '\r') {
        ++i;
    }
    return {line.substr(start, i - start), i};
}

std::unordered_set<std::string> extract_mac_addresses(const std::string& line) {
    std::unordered_set<std::string> mac_addresses;
    const size_t len = line.length();
    for (size_t i = 0; i < len; ++i) {
        if (std::string part = line.substr(i, 3); part == "RA/" || part == "TA/" || part == "SA/") {
            i+=3;
            while (line[i] != '=') {
                ++i;
            }
            ++i;
            auto [fst, snd] = collect_string(line, i);
            i = snd;
            mac_addresses.insert(fst);
        } else if (part == "RA=" || part == "TA=" || part == "SA=") {
            i+=3;
            auto [fst, snd] = collect_string(line, i);
            i = snd;
            mac_addresses.insert(fst);
        }
    }
    return mac_addresses;
}

std::unordered_map<std::string, int32_t> count_using(std::istream& in) {
    std::unordered_map<std::string, int> mac_count;
    std::string line;
    while (std::getline(in, line)) {
        for (const auto& mac : extract_mac_addresses(line)) {
            mac_count[mac]++;
        }
    }
    return mac_count;
}

std::vector<std::pair<std::string, int>> sort_by_count(const std::unordered_map<std::string, int>& mac_count) {
    const size_t count = mac_count.size();
    std::vector<std::pair<std::string, int>> sorted_macs(count);
    std::uninitialized_move_n(mac_count.begin(), count, sorted_macs.begin()); // SSO can be used when len(str) <= 15 on required compillers
    std::sort(sorted_macs.begin(), sorted_macs.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    return sorted_macs;
}
