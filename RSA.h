#pragma once
#include "ap/ap.hpp"
#include <utility>
#include <ctime>
#include "MD5.h"
#include <random>

constexpr auto SIZE = 1024;

using namespace std;

class RSA
{
private:
	ap_uint<SIZE> p;
	ap_uint<SIZE> q;
	ap_uint<4 * SIZE> n;
	ap_uint<4 * SIZE> fi_n;
	pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> openKey;
	pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> secretKey;
public:
	RSA(ap_uint<SIZE> p, ap_uint<SIZE> q) {
		this->p = p;
		this->q = q;
		this->n = mul(q, p);
		this->fi_n = mul(q - 1, p - 1);
		cout << "p = " << p << endl;
		cout << "q = " << q << endl;
		cout << "n = " << n << endl;
		cout << "fi(n) = " << fi_n << endl;
	}
	void working(ap_uint<SIZE> m, bool type, size_t size);
	static ap_uint<SIZE> gen(int size, int i);
	static ap_uint<SIZE> genP(int size, int k, ap_uint<SIZE> p);
	ap_uint<SIZE> genM();
	static bool testFerma(ap_uint<SIZE> p);
	static pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> createOpenKey(ap_uint<4 * SIZE> fi_n, ap_uint<4 * SIZE> n, size_t countOfBits);
	static pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> createSecretKey(ap_uint<4 * SIZE> e, ap_uint<4 * SIZE> n, ap_uint<4 * SIZE> fi_n);
	static ap_uint<4 * SIZE> mul(ap_uint<SIZE> q, ap_uint<SIZE> p);
	static ap_uint<4 * SIZE> CommonEuclidian(ap_uint<4*SIZE> a, ap_uint<4 * SIZE> n);
	static ap_uint<4 * SIZE> ExtendedEuclidian(ap_uint<4*SIZE> e, ap_uint<4 * SIZE> n);
	static ap_uint<4 * SIZE> BinaryPower(ap_uint<4*SIZE> a, ap_uint<4 * SIZE> fi_n, ap_uint<4 * SIZE> n);
	static bool DigitalSignCheck(pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> digitalSign, pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> openKey);
	static void test();
};

