#include "sniffer.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Log file expected as argument\n";
    return 1;
  }

  const std::string filename = argv[1];

  std::ifstream file(filename);
  if (!file) {
    std::cerr << "Cannot open file " << filename << "\n";
    return 1;
  }

  const std::unordered_map<std::string, int> mac_count = count_using(file);
  file.close();

  for (const auto& [mac, count] : sort_by_count(mac_count)) {
    std::cout << mac << " " << count << "\n";
  }

  return 0;
}