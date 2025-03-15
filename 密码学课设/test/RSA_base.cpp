#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;
using namespace NTL;

// ���ɴ���������Ϊ����ָ��b
ZZ GeneratePrime(long bitLength) {
    ZZ prime;
    GenPrime(prime, bitLength);  // ʹ��NTL���������������
    return prime;
}

// ���ɼ���ָ��b: gcd(b, ��(n)) = 1
ZZ b_Generation(ZZ phi) {
    //srand(time(0));
    ZZ b;
    while (1) {
        RandomBnd(b, phi);
        if (GCD(b, phi) == 1)
            break;
    }
    return b;
}

// ����RSA��Կ��
void GenerateRSAKeyPair(ZZ& n, ZZ& b, ZZ& p, ZZ& q, ZZ& a, long bitLength) {
    // �������������� p �� q
    p = GeneratePrime(bitLength);
    q = GeneratePrime(bitLength);

    // ���� n = p * q
    n = p * q;

    // ���� ��(n) = (p-1)*(q-1)
    ZZ phi = (p - 1) * (q - 1);

    // gcd(b, ��(n)) = 1
    b = b_Generation(phi);  

    InvMod(a, b, phi);  // a = b^-1 mod phi 
}

// RSA����
ZZ RSAEncrypt(const ZZ& m, const ZZ& n, const ZZ& b) {
    ZZ c;
    PowerMod(c, m, b, n);  // c = m^b mod n
    return c;
}

// RSA����
ZZ RSADecrypt(const ZZ& c, const ZZ& n, const ZZ& a) {
    ZZ m;
    PowerMod(m, c, a, n);  // m = c^a mod n
    return m;
}

// ���ַ���ת��ΪZZ
ZZ StringToZZ(const string& data) {
    ZZ result(0);
    for (char ch : data) {
       
        result<<=8;  // ����256���ڳ��ռ�
        result += conv<ZZ>(static_cast<unsigned char>(ch));  // �����ַ���ASCIIֵ
    }
    return result;
}

// ��ZZת��Ϊ�ַ���
string ZZToString(const ZZ& data) {
    ZZ temp = data;
    string result;
    while (temp !=0) {
        unsigned char ch = static_cast<unsigned char>(conv<long>(temp %ZZ(256)));
        result += ch ;  // ÿ�ν���ǰ�ַ��ӵ�����ַ�������ǰ��
        temp >>=8;
    }
    reverse(result.begin(), result.end());
    return result;
}

void apply_Encrypt() {
    // ѡ����Կ���ȣ�512 �� 1024
    long bitLength = 512;
    cout << "ѡ����Կ����(512��1024): ";
    cin >> bitLength;

    // ����RSA��Կ��
    ZZ n, b, p, q, a;
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);

    // ��ʾ��Կ��˽Կ
    cout << "Public Key (n, b): " << endl;
    cout << "n: " << n << endl;
    cout<<"b: " << b << endl;
    cout << "Private Key (p, q, a): " << endl;
    cout << "p: " << p << endl;
    cout << "q: " << q << endl;
    cout<< "a: "<<a << endl;

    // ������Ҫ���ܵ���Ϣ
    string message;
    cout << "������Ҫ���ܵ���Ϣ: (�ַ�����";
    cin.ignore();
    getline(cin, message);

    // ���ַ���ת��ΪZZ����
    ZZ m = StringToZZ(message);
    cout << "���ַ�����Ϣת��Ϊ����" << m << endl;
    // RSA����
    ZZ c = RSAEncrypt(m, n, b);
    cout << "���ܺ����Ϣ: " << c << endl;
    cout << "�Ƿ������Ϣ��(y/n)" << endl;
    char is_continue;
    cin >> is_continue;
    if (is_continue == 'y') {
        // RSA����
        ZZ decryptedMessage = RSADecrypt(c, n, a);
        cout << "���ܺ����Ϣ: " << decryptedMessage << endl;

        // �����ܺ����Ϣת��Ϊ�ַ�����ʽ
        string decryptedString = ZZToString(decryptedMessage);
        cout << "���ܺ����Ϣ(�ַ�����ʽ): " << decryptedString << endl;
    }
}
void apply_decrypt() {
    ZZ c;
    cout << "��������ܺ����Ϣ��" << endl;
    cin >> c;
   
    ZZ a;
    cout << "������˽Կa��" << endl;
    cin >> a;
    ZZ n;
    cout << "�����빫Կn��" << endl;
    cin >> n;
    ZZ decryptedMessage = RSADecrypt(c, n, a);
    cout << "���ܺ����Ϣ: " << decryptedMessage << endl;

    // �����ܺ����Ϣת��Ϊ�ַ�����ʽ
    string decryptedString = ZZToString(decryptedMessage);
    cout << "���ܺ����Ϣ(�ַ�����ʽ): " << decryptedString << endl;
}
// RSAǩ����ʹ��˽Կ����Ϣ����ǩ��
ZZ RSASign(const string& message, const ZZ& n, const ZZ& a) {
    ZZ m = StringToZZ(message) %n;  // ����Ϣת��Ϊ������
    return RSADecrypt(m, n, a);  // ʹ��˽Կ����Ϣ���м��ܣ�����ǩ��
}

// RSAǩ����֤��ʹ�ù�Կ��֤ǩ��
bool RSAVerify(const string& message, const ZZ& signature, const ZZ& n, const ZZ& b) {
    ZZ m = RSAEncrypt(signature, n, b);  
    return (m == StringToZZ(message)%n);   // �ȽϽ��ܽ����ԭʼ��Ϣ�Ƿ�һ��
}
// RSA ǩ������֤����
void apply_SignAndVerify() {
    // ѡ����Կ���ȣ�512 �� 1024
    long bitLength = 512;
    cout << "ѡ����Կ����(512��1024): ";
    cin >> bitLength;

    // ����RSA��Կ��
    ZZ n, b, p, q, a;
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);

    // ��ʾ��Կ��˽Կ
    cout << "Public Key (n, b): " << endl;
    cout << "n: " << n << endl;
    cout << "b: " << b << endl;
    cout << "Private Key (p, q, a): " << endl;
    cout << "p: " << p << endl;
    cout << "q: " << q << endl;
    cout << "a: " << a << endl;

    // ������Ҫǩ������Ϣ
    string message;
    cout << "������Ҫǩ������Ϣ (�ַ���): ";
    cin.ignore();
    getline(cin, message);

    // ���ַ���ת��ΪZZ����
    ZZ m = StringToZZ(message);
    cout << "���ַ�����Ϣת��Ϊ���� " << m << endl;
    // ����ǩ��
    ZZ signature = RSASign(message, n, a);
    cout << "���ɵ�ǩ��: " << signature << endl;

    // ��֤ǩ��
    cout << "�Ƿ���֤ǩ����(y/n)" << endl;
    char is_continue;
    cin >> is_continue;
    if (is_continue == 'y') {
        bool isValid = RSAVerify(message, signature, n, b);
        cout << "ǩ����֤���: " << (isValid ? "��Ч" : "��Ч") << endl;
    }
}

void apply_Verify() {
    string message;
    cout << "���������֤��Ϣ��" << endl;
    cin.ignore();
    getline(cin, message);
    ZZ signature;
    cout << "������ǩ����" << endl;
    cin >> signature;
    ZZ b;
    cout << "�����빫Կb��" << endl;
    cin >> b;
    ZZ n;
    cout << "�����빫Կn��" << endl;
    cin >> n;
    bool isValid = RSAVerify(message, signature, n, b);
    cout << "ǩ����֤���: " << (isValid ? "��Ч" : "��Ч") << endl;
}

bool Miller_Rabin(ZZ n, int iterations) {
    // �߽�����
    if (n <= 1) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;

    // �� n-1 �ֽ�Ϊ d * 2^s
    ZZ d = n - 1;
    int s = 0;
    while (d % 2 == 0) {
        d /= 2;
        s++;
    }

    // ���ж�β���
    for (int i = 0; i < iterations; i++) {
        ZZ a = RandomBnd( n - 2); // ���ѡ�� a
        ZZ x = PowerMod(a, d, n); // ���� x = a^d % n

        if (x == 1 || x == n - 1) continue; // ��� x �� 1 �� x �� -1���������β���

        bool passed = false;
        for (int r = 1; r < s; r++) {
            x = PowerMod(x, 2, n); // ���� x = x^2 % n
            if (x == n - 1) {
                passed = true;
                break;
            }
        }

        if (!passed) return false; // �������ƽ����ⶼû��ͨ����n �Ǻ���
    }

    return true; // �������в��ԣ�n ����������
}
