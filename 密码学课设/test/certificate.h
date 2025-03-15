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
    int flag;//��ʶ��Կ����
    string ID;
    ZZ n, b, p, q, a; // RSA ��˽Կ��
    string ID_ta;
    ZZ s;// s = sigTA��˽Կ(ID || ��Կ)
    string filepath;
public:
    Certification();
    Certification(int bitLength, const string& id);
    Certification(int bitLength, const string& id, const Certification& id_ta);//bitLengthΪ����p��q����512��1024
    Certification(const string& filename);
    //��֤ǩ������
    bool VerifySignature() const;
    //����txt�ļ�����
    void GenerateCertFile() const;
    void Display() const; // ��ʾ֤����Ϣ

    string GetID() const;
    string GetIssuerID() const;
    ZZ Geta() const;
    ZZ Getn() const;
    ZZ Getb() const;
    ZZ GetSignature() const;
};