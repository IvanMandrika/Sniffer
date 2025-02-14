#include <gtest/gtest.h>
#include <sstream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include "../src/sniffer.h"
#include <string>

TEST(MacExtractTest, BasicCase) {
  const std::string line = "RA=00:11:22:33:44:55,TA=AA:BB:CC:DD:EE:FF\n";
  const auto result = extract_mac_addresses(line);
  ASSERT_EQ(result.size(), 2);
  ASSERT_TRUE(result.contains("00:11:22:33:44:55"));
  ASSERT_TRUE(result.contains("AA:BB:CC:DD:EE:FF"));
}

TEST(MacExtractTest, MultiplePrefixes) {
  std::string line = "SA=DE:AD:BE:EF:CA:FE,TA/foo=BA:D0:0B:AB:CD:EF\n";
  auto result = extract_mac_addresses(line);
  ASSERT_EQ(result.size(), 2);
  ASSERT_TRUE(result.contains("DE:AD:BE:EF:CA:FE"));
  ASSERT_TRUE(result.contains("BA:D0:0B:AB:CD:EF"));
}

TEST(CountTest, BasicCounting) {
  std::stringstream ss;
  ss << "RA=MAC1\n TA=MAC2\n RA=MAC1\n";
  const std::unordered_map<std::string, int> expected = {{"MAC1", 2}, {"MAC2", 1}};

  const auto result = count_using(ss);
  ASSERT_EQ(result, expected);
}

TEST(CountTest, EmptyInput) {
  std::stringstream ss;
  auto result = count_using(ss);
  ASSERT_TRUE(result.empty());
}

TEST(SortTest, BasicSorting) {
  std::unordered_map<std::string, int> input = {
    {"MAC3", 3},
    {"MAC1", 5},
    {"MAC2", 5}
  };

  const auto result = sort_by_count(input);

  ASSERT_EQ(result[0].second, 5);
  ASSERT_EQ(result[1].second, 5);
  ASSERT_EQ(result[2].second, 3);

  std::unordered_set<std::string> macs;
  for (const auto &p: result) macs.insert(p.first);
  ASSERT_TRUE(macs.count("MAC1"));
  ASSERT_TRUE(macs.count("MAC2"));
  ASSERT_TRUE(macs.count("MAC3"));
}

TEST(SortTest, EmptyInput) {
  std::unordered_map<std::string, int> input;
  const auto result = sort_by_count(input);
  ASSERT_TRUE(result.empty());
}

TEST(BigTest, FirstHalf) {
  const std::vector<std::pair<std::string, int> > test = {
    {"b8:69:f4:7a:a5:ac", 7673},
    {"34:1c:f0:d3:40:a2", 2978},
    {"34:1c:f0:d2:78:5a", 2638},
    {"00:0c:29:65:08:ee", 1869},
    {"ff:ff:ff:ff:ff:ff", 65},
    {"4a:5f:99:ae:ea:99", 65},
    {"b8:69:f4:7a:a5:93", 62},
    {"84:c5:a6:07:38:66", 47},
    {"6e:52:4e:5f:f9:eb", 32},
    {"52:ff:20:52:16:9a", 6},
    {"70:c9:32:1b:54:e2", 6},
    {"c8:7f:54:28:74:ac", 3},
    {"80:b6:55:60:6f:58", 1}
  };

  if (std::ifstream file("frames_parser_half.log"); !file) {
    std::cerr << "Soooooory test brouken\n";
  } else {
    ASSERT_EQ(sort_by_count(count_using(file)), test);
  }
}

TEST(BigTest, All) {
  const std::vector<std::pair<std::string, int> > test = {
    {"b8:69:f4:7a:a5:ac", 15235}, {"34:1c:f0:d3:40:a2", 5812}, {"34:1c:f0:d2:78:5a", 5307}, {"00:0c:29:65:08:ee", 3713},
    {"84:c5:a6:07:38:66", 124}, {"6e:52:4e:5f:f9:eb", 107}, {"ff:ff:ff:ff:ff:ff", 98}, {"4a:5f:99:ae:ea:99", 98},
    {"b8:69:f4:7a:a5:93", 68}, {"52:ff:20:52:16:9a", 14}, {"70:c9:32:1b:54:e2", 13}, {"80:b6:55:60:6f:58", 4},
    {"c8:7f:54:28:74:ac", 3}
  };

  if (std::ifstream file("frames_parser.log"); !file) {
    std::cerr << "Soooooory test brouken\n";
  } else {
    ASSERT_EQ(sort_by_count(count_using(file)), test);
  }
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
