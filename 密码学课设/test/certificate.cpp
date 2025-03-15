
#include"certificate.h"
#include <direct.h> // ���� _mkdir
using namespace std;
Certification::Certification(){
    flag = 512;
}
Certification::Certification(int bitLength, const string& id) {
    string folderPath = "Certification";
    // �����ļ���
    if (_mkdir(folderPath.c_str()) == 0 || errno == EEXIST) {
        // ƴ���ļ�·��
        filepath = folderPath + "/" + id  + ".txt";
    }
    else cerr << "�����ļ���ʧ��" << endl;
    flag = bitLength;
    ID = id;
    ID_ta = id;

    // ����RSA��Կ��
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);

    string message = ID + ZZToString(n) + ZZToString(b);//������Щ���ϣһ��
    // cout << message << endl;

    s = RSASign(message, n,a);
    // cout << s<< endl;

 //else {        cerr << "û��˽Կ���޷�ǩ��" << endl;    }
}
Certification::Certification(int bitLength, const string& id, const Certification& id_ta) {
    string folderPath = "Certification";
    // �����ļ���
    if (_mkdir(folderPath.c_str()) == 0 || errno == EEXIST) {
        // ƴ���ļ�·��
        filepath = folderPath + "/" + id  + ".txt";
    }
    else cerr << "�����ļ���ʧ��" << endl;
    flag = bitLength;
    ID = id;
    ID_ta = id_ta.GetID();
   
    // ����RSA��Կ��
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);
  
    string message = ID+ ZZToString(n)+ ZZToString(b);//������Щ���ϣһ��
   // cout << message << endl;
    
        s = RSASign(message, id_ta.Getn(), id_ta.Geta());
       // cout << s<< endl;
    
    //else {        cerr << "û��˽Կ���޷�ǩ��" << endl;    }
}
bool Certification::VerifySignature() const {
    string message = ID + ZZToString(n)+ ZZToString(b);
    Certification TA("Certification/" + ID_ta  + ".txt");
    //TA.Display();
    return RSAVerify(message, s,TA.Getn(), TA.Getb());
}
// ����txt�ļ�����
void Certification::GenerateCertFile()  const {
    

    ofstream outfile(filepath, ios::binary);     // ������ļ�
    if (outfile.is_open()) {
        outfile  << ID <<endl ;
        outfile << n << endl;
        outfile << b << endl;
        outfile <<  s << endl;
        outfile << ID_ta << endl;
        outfile << flag << endl;
        outfile.close();
        cout << "֤���ѱ��浽 " << filepath << " �ļ��С�" << endl;
    }
    else {
        cerr << "�޷����ļ��Ա���֤�顣" << endl;
    }
}

// ��ȡ֤���ļ�����֤����Ч��
Certification::Certification(const string& filename) {
    filepath = filename;
    ifstream infile(filename, ios::binary);  // �Զ�����ģʽ���ļ�
    if (!infile.is_open()) {
        cerr << "�޷���֤���ļ�: " << filename << endl;
        return;
    }
                                     
    // ��ȡ֤���ļ�����
    

    infile >> ID;
    infile >> n;
    infile >> b;
    infile >> s;
    infile >> ID_ta;
    infile >> flag;

    infile.close();
    //˽ԿΪnull
    p = NULL;
    q = NULL;
    a = NULL;
   
}
void Certification::Display() const {
    cout << "ID: " << ID << endl;
    cout << "��Կ n: " << n << endl;
    cout << "��Կ b: " << b << endl;
    
    cout << "ǩ�� s: " << s << endl;
    cout << "�䷢���� ID: " << ID_ta << endl;
    cout << "��Կ���ȱ�ʶ flag: " << flag << endl;
}

// Getter ����ʵ��
string Certification::GetID() const { return ID; }
string Certification::GetIssuerID() const { return ID_ta; }
ZZ Certification::Geta() const { return a; }
ZZ Certification::Getn() const { return n; }
ZZ Certification::Getb() const { return b; }
ZZ Certification::GetSignature() const { return s; }
