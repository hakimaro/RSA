#include "RSA.h"

void RSA::working(ap_uint<SIZE> msg, bool type, size_t size)
{
    ap_uint<SIZE> m = msg;
    if (type) {
        cout << "--- Type 1: Crypting ---" << endl;
        if (CommonEuclidian(m, n) != 1) {
            cout << "Your message is incorrect!" << endl;
            return;
        }
        cout << "Your message: " << m << endl;
        openKey = createOpenKey(fi_n, n, size);
        cout << "Open key: " << openKey.first << " " << openKey.second << endl;
        ap_uint<4 * SIZE> c = BinaryPower(m, openKey.first, openKey.second);
        cout << "Your crypted message: " << c << endl;
        secretKey = createSecretKey(openKey.first, n, fi_n);
        cout << "Secret key: " << secretKey.first << " " << secretKey.second << endl;
        ap_uint<4 * SIZE> n_m = BinaryPower(c, secretKey.first, secretKey.second);
        cout << "You decrypted message: " << n_m << endl;
    }
    else if (!type) {
        cout << "--- Type 2: Diginal signature ---" << endl;
        cout << "Your hashed message: " << hex << m << dec << endl;
        openKey = createOpenKey(fi_n, n, size);
        secretKey = createSecretKey(openKey.first, openKey.second, fi_n);
        ap_uint<4 * SIZE> s = BinaryPower(m, secretKey.first, secretKey.second);
        cout << "Correct digital signature: " << hex << s << dec << endl;
        pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> correctSign = make_pair(m, s);
        cout << (DigitalSignCheck(correctSign, openKey) ? "It's correct signature" : "It's incorrect signature") << endl;
    }
}

ap_uint<SIZE> RSA::gen(int size, int k)
{
    ap_uint<SIZE> res = 1;
    for (int i = 1; i < size; i++) {
        res <<= 1;
        res |= rand() % 2;
    }
    res |= 1;
    return res;
}

ap_uint<SIZE> RSA::genP(int size, int k, ap_uint<SIZE> p) {
    ap_uint<SIZE> res = 1;
    res <<= (size-1);
    res += 1;
    ap_uint<SIZE> tmp = 1;
    for (int i = 1; i < size; i++) {
        tmp = rand() % 2;
        res |= (tmp << i);
        if (tmp == 1 && testFerma(res) && p != res) return res;
    }
    res |= 1;
    return res;
}

ap_uint<SIZE> RSA::genM()
{
    while (true) {
        ap_uint<SIZE> m = gen(20, 0);
        if (testFerma(m) && m != p && m != q) return m;
    }
}

bool RSA::testFerma(ap_uint<SIZE> n)
{
    srand(time(0));
        for (int i = 0; i < 100; i++) {
            ap_uint<SIZE> a = (rand()) % n;
            if (a != 0 && BinaryPower(a, n - 1, n) != 1) return false;
        }
    return true;
}

pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> RSA::createOpenKey(ap_uint<4 * SIZE> fi_n, ap_uint<4 * SIZE> n, size_t size)
{
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> openKey;
    ap_uint<SIZE> r_num = gen(size, 0);
    r_num %= n;
    while (CommonEuclidian(r_num, fi_n) != 1) {
        r_num = gen(size, 0) % n;
    }
    openKey = make_pair(r_num, n);
    return openKey;
}

pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> RSA::createSecretKey(ap_uint<4 * SIZE> e, ap_uint<4 * SIZE> n, ap_uint<4 * SIZE> fi_n)
{
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> secretKey;
    secretKey = make_pair(ExtendedEuclidian(e, fi_n), n);
    return secretKey;
}

ap_uint<4 * SIZE> RSA::mul(ap_uint<SIZE> q, ap_uint<SIZE> p)
{
    ap_uint<4 * SIZE> n = p;
    n *= q;
    return n;
}

ap_uint<4 * SIZE> RSA::CommonEuclidian(ap_uint<4*SIZE> e, ap_uint<4 * SIZE> n)
{
    ap_uint<4 * SIZE> a = (e > n) ? e : n;
    ap_uint<4 * SIZE> b = (e > n) ? n : e;
    if (a % b == 0) return b;
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> r = make_pair(a % b, b % (a % b));
    while (r.second != 0) {
        r = make_pair(r.second, (r.first % r.second));
    }
    //cout << "NOD: " << r.first << endl;
    return r.first;
}

ap_uint<4 * SIZE> RSA::ExtendedEuclidian(ap_uint<4*SIZE> a, ap_uint<4 * SIZE> b)
{
    pair<ap_int<8 * SIZE>, ap_int<8 * SIZE>> x = (a > b) ? make_pair(1, 0) : make_pair(0, 1);
    pair<ap_int<8 * SIZE>, ap_int<8 * SIZE>> y = (a > b) ? make_pair(0, 1) : make_pair(1, 0);
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> r = make_pair((a > b) ? a : b, (a > b) ? b : a);
    while (r.second != 0) {
        ap_uint<4*SIZE> q = r.first / r.second;
        r = make_pair(r.second, (r.first % r.second));
        x = make_pair(x.second, (x.first - q * x.second));
        y = make_pair(y.second, (y.first - q * y.second));
    }
    //cout << a << "*" << x.first << " + " << b << "*" << y.first << " = " << r.first << endl;
    ap_uint<4 * SIZE> res = (ap_uint<4 * SIZE>) ((x.first + b) % b);
    return res;
}

ap_uint<4 * SIZE> RSA::BinaryPower(ap_uint<4*SIZE> a, ap_uint<4 * SIZE> degree, ap_uint<4 * SIZE> mod)
{
    ap_uint<4*SIZE> res = 1;
    while (degree) {
        if (degree % 2 == 1)
            res = (res * a) % mod;
        a = (a * a) % mod;
        degree >>= 1;
    }
    return res % mod;
}

bool RSA::DigitalSignCheck(pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> digitalSign, pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> openKey)
{
    return digitalSign.first == BinaryPower(digitalSign.second, openKey.first, openKey.second);
}

void RSA::test()
{
    ap_uint<SIZE> p = 3557;
    ap_uint<SIZE> q = 2579;
    ap_uint<4 * SIZE> n = mul(p, q);
    ap_uint<4 * SIZE> fi_n = mul(p - 1, q - 1);
    RSA rsa(p, q);
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> openKey = createOpenKey(fi_n, n, 2);
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> secretKey = createSecretKey(openKey.first, openKey.second, fi_n);
    cout << "Open key: " << openKey.first << " == 3, " << openKey.second << " == 9173503" << endl;
    cout << "Secret key: " << secretKey.first << " == 6111579, " << secretKey.second << " == 9173503" << endl;
    ap_uint<4 * SIZE> m = 111111;
    cout << "Message: " << m << endl;
    ap_uint<4 * SIZE> c = BinaryPower(m, openKey.first, openKey.second);
    cout << "Crypting: " << c << " == 4051753" << endl;
    ap_uint<4 * SIZE> n_m1 = BinaryPower(c, secretKey.first, secretKey.second);
    cout << "Decrypting: " << n_m1 << " == 111111" << endl;
    ap_uint<4 * SIZE> s = BinaryPower(m, secretKey.first, secretKey.second);
    cout << "Correct digital signature: " << s << endl;
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> correctSign = make_pair(m, s);
    cout << (DigitalSignCheck(correctSign, openKey) ? "It's correct signature" : "It's incorrect signature") << endl;
    cout << "Incorrect digital signature: " << s-1 << endl;
    pair<ap_uint<4 * SIZE>, ap_uint<4 * SIZE>> incorrectSign = make_pair(m, s-1);
    cout << (DigitalSignCheck(incorrectSign, openKey) ? "It's correct signature" : "It's incorrect signature") << endl;
}
