#pragma once
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <string>

using namespace NTL;
using namespace std;

// ���ɴ�����
ZZ GeneratePrime(long bitLength);

// ����RSA��Կ��
void GenerateRSAKeyPair(ZZ& n, ZZ& b, ZZ& p, ZZ& q, ZZ& a, long bitLength);

// RSA����
ZZ RSAEncrypt(const ZZ& m, const ZZ& n, const ZZ& b);

// RSA����
ZZ RSADecrypt(const ZZ& c, const ZZ& n, const ZZ& a);

// stringת��ΪZZ
ZZ StringToZZ(const string& data);

// ZZת��Ϊstring
string ZZToString(const ZZ& data);
ZZ RSASign(const string& message, const ZZ& n, const ZZ& a);
bool RSAVerify(const string& message, const ZZ& signature, const ZZ& n, const ZZ& b);
void apply_Encrypt();
void apply_decrypt();
void apply_SignAndVerify();
void apply_Verify();