#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;
using namespace NTL;

// 生成大素数，作为解密指数b
ZZ GeneratePrime(long bitLength) {
    ZZ prime;
    GenPrime(prime, bitLength);  // 使用NTL库生成随机大素数
    return prime;
}

// 生成加密指数b: gcd(b, φ(n)) = 1
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

// 生成RSA密钥对
void GenerateRSAKeyPair(ZZ& n, ZZ& b, ZZ& p, ZZ& q, ZZ& a, long bitLength) {
    // 生成两个大素数 p 和 q
    p = GeneratePrime(bitLength);
    q = GeneratePrime(bitLength);

    // 计算 n = p * q
    n = p * q;

    // 计算 φ(n) = (p-1)*(q-1)
    ZZ phi = (p - 1) * (q - 1);

    // gcd(b, φ(n)) = 1
    b = b_Generation(phi);  

    InvMod(a, b, phi);  // a = b^-1 mod phi 
}

// RSA加密
ZZ RSAEncrypt(const ZZ& m, const ZZ& n, const ZZ& b) {
    ZZ c;
    PowerMod(c, m, b, n);  // c = m^b mod n
    return c;
}

// RSA解密
ZZ RSADecrypt(const ZZ& c, const ZZ& n, const ZZ& a) {
    ZZ m;
    PowerMod(m, c, a, n);  // m = c^a mod n
    return m;
}

// 将字符串转换为ZZ
ZZ StringToZZ(const string& data) {
    ZZ result(0);
    for (char ch : data) {
       
        result<<=8;  // 乘以256以腾出空间
        result += conv<ZZ>(static_cast<unsigned char>(ch));  // 加入字符的ASCII值
    }
    return result;
}

// 将ZZ转换为字符串
string ZZToString(const ZZ& data) {
    ZZ temp = data;
    string result;
    while (temp !=0) {
        unsigned char ch = static_cast<unsigned char>(conv<long>(temp %ZZ(256)));
        result += ch ;  // 每次将当前字符加到结果字符串的最前面
        temp >>=8;
    }
    reverse(result.begin(), result.end());
    return result;
}

void apply_Encrypt() {
    // 选择密钥长度：512 或 1024
    long bitLength = 512;
    cout << "选择密钥长度(512或1024): ";
    cin >> bitLength;

    // 生成RSA密钥对
    ZZ n, b, p, q, a;
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);

    // 显示公钥和私钥
    cout << "Public Key (n, b): " << endl;
    cout << "n: " << n << endl;
    cout<<"b: " << b << endl;
    cout << "Private Key (p, q, a): " << endl;
    cout << "p: " << p << endl;
    cout << "q: " << q << endl;
    cout<< "a: "<<a << endl;

    // 输入需要加密的消息
    string message;
    cout << "输入需要加密的消息: (字符串）";
    cin.ignore();
    getline(cin, message);

    // 将字符串转换为ZZ类型
    ZZ m = StringToZZ(message);
    cout << "将字符串消息转换为数字" << m << endl;
    // RSA加密
    ZZ c = RSAEncrypt(m, n, b);
    cout << "加密后的消息: " << c << endl;
    cout << "是否解密消息？(y/n)" << endl;
    char is_continue;
    cin >> is_continue;
    if (is_continue == 'y') {
        // RSA解密
        ZZ decryptedMessage = RSADecrypt(c, n, a);
        cout << "解密后的消息: " << decryptedMessage << endl;

        // 将解密后的消息转换为字符串格式
        string decryptedString = ZZToString(decryptedMessage);
        cout << "解密后的消息(字符串格式): " << decryptedString << endl;
    }
}
void apply_decrypt() {
    ZZ c;
    cout << "请输入加密后的消息：" << endl;
    cin >> c;
   
    ZZ a;
    cout << "请输入私钥a：" << endl;
    cin >> a;
    ZZ n;
    cout << "请输入公钥n：" << endl;
    cin >> n;
    ZZ decryptedMessage = RSADecrypt(c, n, a);
    cout << "解密后的消息: " << decryptedMessage << endl;

    // 将解密后的消息转换为字符串格式
    string decryptedString = ZZToString(decryptedMessage);
    cout << "解密后的消息(字符串格式): " << decryptedString << endl;
}
// RSA签名：使用私钥对消息进行签名
ZZ RSASign(const string& message, const ZZ& n, const ZZ& a) {
    ZZ m = StringToZZ(message) %n;  // 将消息转换为大整数
    return RSADecrypt(m, n, a);  // 使用私钥对消息进行加密，生成签名
}

// RSA签名验证：使用公钥验证签名
bool RSAVerify(const string& message, const ZZ& signature, const ZZ& n, const ZZ& b) {
    ZZ m = RSAEncrypt(signature, n, b);  
    return (m == StringToZZ(message)%n);   // 比较解密结果与原始消息是否一致
}
// RSA 签名与验证功能
void apply_SignAndVerify() {
    // 选择密钥长度：512 或 1024
    long bitLength = 512;
    cout << "选择密钥长度(512或1024): ";
    cin >> bitLength;

    // 生成RSA密钥对
    ZZ n, b, p, q, a;
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);

    // 显示公钥和私钥
    cout << "Public Key (n, b): " << endl;
    cout << "n: " << n << endl;
    cout << "b: " << b << endl;
    cout << "Private Key (p, q, a): " << endl;
    cout << "p: " << p << endl;
    cout << "q: " << q << endl;
    cout << "a: " << a << endl;

    // 输入需要签名的消息
    string message;
    cout << "输入需要签名的消息 (字符串): ";
    cin.ignore();
    getline(cin, message);

    // 将字符串转换为ZZ类型
    ZZ m = StringToZZ(message);
    cout << "将字符串消息转换为数字 " << m << endl;
    // 生成签名
    ZZ signature = RSASign(message, n, a);
    cout << "生成的签名: " << signature << endl;

    // 验证签名
    cout << "是否验证签名？(y/n)" << endl;
    char is_continue;
    cin >> is_continue;
    if (is_continue == 'y') {
        bool isValid = RSAVerify(message, signature, n, b);
        cout << "签名验证结果: " << (isValid ? "有效" : "无效") << endl;
    }
}

void apply_Verify() {
    string message;
    cout << "请输入待验证消息：" << endl;
    cin.ignore();
    getline(cin, message);
    ZZ signature;
    cout << "请输入签名：" << endl;
    cin >> signature;
    ZZ b;
    cout << "请输入公钥b：" << endl;
    cin >> b;
    ZZ n;
    cout << "请输入公钥n：" << endl;
    cin >> n;
    bool isValid = RSAVerify(message, signature, n, b);
    cout << "签名验证结果: " << (isValid ? "有效" : "无效") << endl;
}

bool Miller_Rabin(ZZ n, int iterations) {
    // 边界条件
    if (n <= 1) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;

    // 将 n-1 分解为 d * 2^s
    ZZ d = n - 1;
    int s = 0;
    while (d % 2 == 0) {
        d /= 2;
        s++;
    }

    // 进行多次测试
    for (int i = 0; i < iterations; i++) {
        ZZ a = RandomBnd( n - 2); // 随机选择 a
        ZZ x = PowerMod(a, d, n); // 计算 x = a^d % n

        if (x == 1 || x == n - 1) continue; // 如果 x ≡ 1 或 x ≡ -1，跳过本次测试

        bool passed = false;
        for (int r = 1; r < s; r++) {
            x = PowerMod(x, 2, n); // 计算 x = x^2 % n
            if (x == n - 1) {
                passed = true;
                break;
            }
        }

        if (!passed) return false; // 如果所有平方检测都没有通过，n 是合数
    }

    return true; // 经过所有测试，n 可能是素数
}
