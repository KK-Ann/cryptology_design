
#include"certificate.h"
#include <direct.h> // 用于 _mkdir
using namespace std;
Certification::Certification(){
    flag = 512;
}
Certification::Certification(int bitLength, const string& id) {
    string folderPath = "Certification";
    // 创建文件夹
    if (_mkdir(folderPath.c_str()) == 0 || errno == EEXIST) {
        // 拼接文件路径
        filepath = folderPath + "/" + id  + ".txt";
    }
    else cerr << "创建文件夹失败" << endl;
    flag = bitLength;
    ID = id;
    ID_ta = id;

    // 生成RSA密钥对
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);

    string message = ID + ZZToString(n) + ZZToString(b);//加上这些需哈希一次
    // cout << message << endl;

    s = RSASign(message, n,a);
    // cout << s<< endl;

 //else {        cerr << "没有私钥，无法签名" << endl;    }
}
Certification::Certification(int bitLength, const string& id, const Certification& id_ta) {
    string folderPath = "Certification";
    // 创建文件夹
    if (_mkdir(folderPath.c_str()) == 0 || errno == EEXIST) {
        // 拼接文件路径
        filepath = folderPath + "/" + id  + ".txt";
    }
    else cerr << "创建文件夹失败" << endl;
    flag = bitLength;
    ID = id;
    ID_ta = id_ta.GetID();
   
    // 生成RSA密钥对
    GenerateRSAKeyPair(n, b, p, q, a, bitLength);
  
    string message = ID+ ZZToString(n)+ ZZToString(b);//加上这些需哈希一次
   // cout << message << endl;
    
        s = RSASign(message, id_ta.Getn(), id_ta.Geta());
       // cout << s<< endl;
    
    //else {        cerr << "没有私钥，无法签名" << endl;    }
}
bool Certification::VerifySignature() const {
    string message = ID + ZZToString(n)+ ZZToString(b);
    Certification TA("Certification/" + ID_ta  + ".txt");
    //TA.Display();
    return RSAVerify(message, s,TA.Getn(), TA.Getb());
}
// 生成txt文件函数
void Certification::GenerateCertFile()  const {
    

    ofstream outfile(filepath, ios::binary);     // 打开输出文件
    if (outfile.is_open()) {
        outfile  << ID <<endl ;
        outfile << n << endl;
        outfile << b << endl;
        outfile <<  s << endl;
        outfile << ID_ta << endl;
        outfile << flag << endl;
        outfile.close();
        cout << "证书已保存到 " << filepath << " 文件中。" << endl;
    }
    else {
        cerr << "无法打开文件以保存证书。" << endl;
    }
}

// 读取证书文件并验证其有效性
Certification::Certification(const string& filename) {
    filepath = filename;
    ifstream infile(filename, ios::binary);  // 以二进制模式打开文件
    if (!infile.is_open()) {
        cerr << "无法打开证书文件: " << filename << endl;
        return;
    }
                                     
    // 读取证书文件内容
    

    infile >> ID;
    infile >> n;
    infile >> b;
    infile >> s;
    infile >> ID_ta;
    infile >> flag;

    infile.close();
    //私钥为null
    p = NULL;
    q = NULL;
    a = NULL;
   
}
void Certification::Display() const {
    cout << "ID: " << ID << endl;
    cout << "公钥 n: " << n << endl;
    cout << "公钥 b: " << b << endl;
    
    cout << "签名 s: " << s << endl;
    cout << "颁发机构 ID: " << ID_ta << endl;
    cout << "公钥长度标识 flag: " << flag << endl;
}

// Getter 函数实现
string Certification::GetID() const { return ID; }
string Certification::GetIssuerID() const { return ID_ta; }
ZZ Certification::Geta() const { return a; }
ZZ Certification::Getn() const { return n; }
ZZ Certification::Getb() const { return b; }
ZZ Certification::GetSignature() const { return s; }
