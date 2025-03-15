#pragma once
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <string>

using namespace NTL;
using namespace std;

// 生成大素数
ZZ GeneratePrime(long bitLength);

// 生成RSA密钥对
void GenerateRSAKeyPair(ZZ& n, ZZ& b, ZZ& p, ZZ& q, ZZ& a, long bitLength);

// RSA加密
ZZ RSAEncrypt(const ZZ& m, const ZZ& n, const ZZ& b);

// RSA解密
ZZ RSADecrypt(const ZZ& c, const ZZ& n, const ZZ& a);

// string转换为ZZ
ZZ StringToZZ(const string& data);

// ZZ转换为string
string ZZToString(const ZZ& data);
ZZ RSASign(const string& message, const ZZ& n, const ZZ& a);
bool RSAVerify(const string& message, const ZZ& signature, const ZZ& n, const ZZ& b);
void apply_Encrypt();
void apply_decrypt();
void apply_SignAndVerify();
void apply_Verify();