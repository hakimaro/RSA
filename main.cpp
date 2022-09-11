#include <iostream>
#include "ap/ap.hpp"
#include "RSA.h"
#include "MD5.h"

int main()
{
	cout << "--- Vikipedia Test ---" << endl;
	RSA::test();
	ap_uint<SIZE> p = RSA::genP(SIZE, 0, 0);
	ap_uint<SIZE> q = RSA::genP(SIZE, 0, p);
	size_t size;
	cout << "--- Big Integer test ---" << endl;
	cout << "Enter size of key (in bits): ";
	cin >> size;
	cout << "Creating p" << endl;
	srand(time(0));
	while (!RSA::testFerma(p)) {
		p = RSA::genP(SIZE, 0, 0);
	}
	cout << "Creating q" << endl;
	while (!RSA::testFerma(q) || p == q) {
		q = RSA::genP(SIZE, 0, p);
	}
	RSA rsa(p, q);
	bool type = 0;
	ap_uint<SIZE> m;
	if (!type) {
		cout << "Enter message: ";
		string message;
		cin >> message;
		MD5 md5;
		m = md5.hash(message);
	}
	else {
		m = rsa.genM();
	}
	m %= RSA::mul(p, q);
	rsa.working(m, type, size);
}
