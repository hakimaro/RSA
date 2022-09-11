#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "ap/ap.hpp"

class MD5 {
private:
	uint8_t s[64] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
				 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
				 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
				 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
	uint32_t K[64];

	uint32_t funF(uint32_t& x, uint32_t& y, uint32_t& z);
	uint32_t funG(uint32_t& x, uint32_t& y, uint32_t& z);
	uint32_t funH(uint32_t& x, uint32_t& y, uint32_t& z);
	uint32_t funI(uint32_t& x, uint32_t& y, uint32_t& z);

	uint32_t rotate_left(uint32_t& x, int n);

	std::vector<uint32_t> transform(std::string data);
public:
	MD5();
	//std::string hash(std::string input);
	ap_uint<128> hash(std::string input);
};
