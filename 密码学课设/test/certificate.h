#pragma once
#include "RSA_base.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include<string>
#include <iostream>
#include <fstream>
#include <string>
class  Certification {
protected:
    int flag;//标识公钥长度
    string ID;
    ZZ n, b, p, q, a; // RSA 公私钥对
    string ID_ta;
    ZZ s;// s = sigTA的私钥(ID || 公钥)
    string filepath;
public:
    Certification();
    Certification(int bitLength, const string& id);
    Certification(int bitLength, const string& id, const Certification& id_ta);//bitLength为素数p，q长度512或1024
    Certification(const string& filename);
    //验证签名函数
    bool VerifySignature() const;
    //生成txt文件函数
    void GenerateCertFile() const;
    void Display() const; // 显示证书信息

    string GetID() const;
    string GetIssuerID() const;
    ZZ Geta() const;
    ZZ Getn() const;
    ZZ Getb() const;
    ZZ GetSignature() const;
};