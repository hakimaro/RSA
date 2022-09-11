#include "MD5.h"
#include <cmath>
#include <sstream>
#include <iomanip>
using namespace std;

uint32_t MD5::funF(uint32_t& x, uint32_t& y, uint32_t& z) {
    return (x & y) | (~x & z);
}

uint32_t MD5::funG(uint32_t& x, uint32_t& y, uint32_t& z) {
    return (x & z) | (y & ~z);
}

uint32_t MD5::funH(uint32_t& x, uint32_t& y, uint32_t& z) {
    return x ^ y ^ z;
}

uint32_t MD5::funI(uint32_t& x, uint32_t& y, uint32_t& z) {
    return y ^ (x | ~z);
}

uint32_t MD5::rotate_left(uint32_t& x, int n)
{
    return (x << n) | (x >> (32 - n));
}

vector<uint32_t> MD5::transform(string data) {
    uint32_t tmp = 0;
    vector<uint32_t> res;
    for (size_t i = 0; i < data.size(); i++) {
        tmp = tmp | (uint32_t(data[i]) << (8 * (i % 4)));
        if ((i + 1) % 4 == 0) {
            res.push_back(tmp);
            tmp = 0;
        }
    }
    if (data.size() % 4 != 0) {
        tmp = tmp | (uint32_t(128) << (8 * (data.size() % 4)));
        res.push_back(tmp);
    }
    else {
        res.push_back(128);
    }
    res.resize(res.size() + (14 - res.size() % 16 + 16) % 16, 0);
    uint64_t s = data.size() * 8;
    res.push_back(uint32_t(s));
    res.push_back(uint32_t(s >> 32));
    return res;
}

MD5::MD5() {
    for (int i = 0; i < 64; i++) {
        K[i] = uint32_t(pow(2, 32) * abs(sin(i + 1)));
    }
}

ap_uint<128> MD5::hash(string in) {
    vector<uint32_t> data = transform(in);

    uint32_t res[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    for (size_t i = 0; i < data.size(); i += 16) {
        uint32_t buf[4] = { res[0], res[1], res[2], res[3] };
        for (int j = 0; j < 64; j++) {
            uint32_t F = 0;
            int g = 0;
            if (j < 16) {
                F = funF(buf[1], buf[2], buf[3]);
                g = j;
            }
            else if (j < 32) {
                F = funG(buf[1], buf[2], buf[3]);
                g = (5 * j + 1) % 16;
            }
            else if (j < 48) {
                F = funH(buf[1], buf[2], buf[3]);
                g = (3 * j + 5) % 16;
            }
            else {
                F = funI(buf[1], buf[2], buf[3]);
                g = (7 * j) % 16;
            }
            F = F + buf[0] + K[j] + data[i + g];
            buf[0] = buf[3];
            buf[3] = buf[2];
            buf[2] = buf[1];
            buf[1] = buf[1] + rotate_left(F, s[j]);
        }
        for (int j = 0; j < 4; j++) {
            res[j] += buf[j];
        }
    }
    vector<uint32_t> l_end_res;
    for (size_t i = 0; i < 4; i++) {
        uint32_t tmp = 0;
        tmp |= (res[i] & 0xff) << 24;
        tmp |= (((res[i] >> 8) & 0xff)) << 16;
        tmp |= (((res[i] >> 16) & 0xff)) << 8;
        tmp |= ((res[i] >> 24) & 0xff);
        l_end_res.push_back(tmp);
    }

    ap_uint<128> h1 = l_end_res[0];
    ap_uint<128> h2 = l_end_res[1];
    ap_uint<128> h3 = l_end_res[2];
    ap_uint<128> h4 = l_end_res[3];
    ap_uint<128> one_num_res = (h4) | (h3 << 32) | (h2 << 64) | (h1 << 96);
    return one_num_res;
}