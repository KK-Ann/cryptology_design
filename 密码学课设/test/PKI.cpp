#include "Certificate.h"
#include "PKI.h"
#include"menu.h"
#include <fstream>
#include <algorithm>
#include<vector>
#include <direct.h> // 用于 _mkdir
using namespace std;
// User 类成员函数实现

// User 类成员函数实现
User::User(){}
User::User(int bitLength, const string& id, const Certification& id_ta, UserType type)
    : Certification(bitLength, id, id_ta), userType(type) {}
User::User(int bitLength, const string& id, UserType type)
    : Certification(bitLength, id), userType(type) {}
User::User(const string& filename, UserType type)
    : Certification(filename), userType(type) {}

UserType User::GetUserType() const { return userType; }

void User::DisplayUser() const {
    cout << "User Type: ";
    switch (userType) {
    case UserType::ROOT:
        cout << "ROOT" << endl;
        break;
    case UserType::CA:
        cout << "中间 CA" << endl;
        break;
    case UserType::User:
        cout << "User" << endl;
        break;
    }
    Display(); // 调用基类的 Display 函数
    cout << "私钥 a：" << a << endl;
}

// 显示接收消息的函数实现
void User::ChooseReceivedMessages( string& senderID,string & messageFile) const {
    if (messageInfo.empty()) {
        cout << "暂无消息" << endl;
        return;
    }

    cout << "收到的消息:" << endl;
    int  i = 0;
    for (const auto& entry : messageInfo) {
        cout <<i+1<< "  消息文件名: " << entry.first << " | 发送者: " << entry.second << endl;
        i++;
    }
    int choice=cin_num("请选择要详细查看的序号：", 1, messageInfo.size());
    messageFile = messageInfo[choice - 1].first;
    senderID = messageInfo[choice - 1].second;
   
    
}
// PKI 类成员函数实现
void PKI::InsertUser(string & your_ID,int & bitLength,User & CAid) {
    cout << "开始生成证书，请输入你的ID" << endl;
    //string your_ID;
    while (1) {

        cin >> your_ID;
        if (!IsIDInCertStore(your_ID)) break;
        else 	cout << "ID重复，请重新输入" << endl;
    }
    //int bitLength = 512;
    while (1) {
        cout << "选择密钥长度(512或1024): ";
        cin >> bitLength;
        if (bitLength == 512 || bitLength == 1024) break;
        else 	cout << "不符合要求重新输入" << endl;
    }
    cout << "------------------------------" << endl;
    int index=1;
    vector<string> temp;
    for (auto it = certStore.begin(); it != certStore.end(); ++it) {
        User user = (it->second);
        if (user.GetUserType() == UserType::CA) {
            cout << index << ":" << (it->first) << endl; // 将 ID 放入数组
            temp.push_back(it->first);
            index++;
        }
    }

    
    int CAchoice = cin_num("请选择为你颁发机构的CA",1,index-1);
   
    CAid=certStore[temp[CAchoice-1]];
    return;
}
void PKI::StoreCertificate(const User& user) {
    certStore[user.GetID()] = user;
}



void PKI::DisplayCertificatePath(const string& userID) {
    vector<User> certPath;
    string currentID = userID;
    while (1) {
        cout << currentID << "--->";
        if (certStore.find(currentID) == certStore.end()) {
            cout << "证书库中无" << currentID << endl;
            return ;
        }
        User user = certStore[currentID];
        certPath.push_back(user);
        if (user.GetUserType() == UserType::ROOT) break; // 如果是自签名证书（根CA）
        currentID = user.GetIssuerID(); // 继续追溯上一级
    }
    cout << endl;
    for (const auto& cert : certPath) {
        cert.Display();
        cout << "----------------------" << endl;
    }
}

bool PKI::VerifyCertificateChain(const string& userID, bool is_display) {
    vector<User> certPath;
    string currentID = userID;

    while (1) {
        cout  << "--->"<< currentID;
        if (certStore.find(currentID) == certStore.end()) {
            cout << " 证书库中无" << currentID << endl;
            return false;
        }
      
        User user = certStore[currentID];
        certPath.push_back(user);
        if (user.GetUserType() == UserType::ROOT) break; // 如果是自签名证书（根CA）
        currentID = user.GetIssuerID(); // 继续追溯上一级
    }
    cout << endl;
    
    for (const auto& cert : certPath) {
        cert.Display();
        if (!cert.VerifySignature()) {
            cout << "验证失败" << endl;
            return false;
        }
        cout << "验证成功" << endl;
        cout << "----------------------" << endl;
    }
    
    return true;
}

void PKI::GetCAIDs(const char* CA_to_choose[]) {
    int index = 0;
    for (auto it = certStore.begin(); it != certStore.end(); ++it) {
        const User& user = it->second;
        if (user.GetUserType() == UserType::CA) {
            CA_to_choose[index] = (it->first).c_str(); // 将 ID 放入数组
            index++;
        }
    }
    CA_to_choose[index] = NULL;
}

void PKI::GetUserIDs(const char* user_to_choose[]) {
    int index = 0;
    for (auto it = certStore.begin(); it != certStore.end(); ++it) {
        const User& user = it->second;
        if (user.GetUserType() == UserType::User) {
            user_to_choose[index] = (it->first).c_str(); // 将 ID 放入数组
            index++;
        }
    }
    user_to_choose[index] = NULL;
}

void PKI::apply_PKI_inPPT()  {
    //cout << "开始PKI" << endl;
    if (!IsIDInCertStore("CA1")) {
        User ca1(512, "CA1", certStore["CAroot"], UserType::CA);
       

        ca1.GenerateCertFile();
       
       
        StoreCertificate(ca1);
    }
    if (!IsIDInCertStore("CA2")) {
        User ca1(512, "CA2", certStore["CAroot"], UserType::CA);


        ca1.GenerateCertFile();


        StoreCertificate(ca1);
    }

        // 创建 Alice, Bob 和 Eve 的证书
        User alice(512, "Alice", certStore["CA1"], UserType::User);
        User bob(512, "Bob", certStore["CA2"], UserType::User);
        
        alice.GenerateCertFile();
        bob.GenerateCertFile();
       
       StoreCertificate(alice);
        StoreCertificate(bob);
        

        // Alice 发送消息和签名
        string message = "Hello Bob, this is Alice.";
        ZZ aliceSignature = RSASign(message,alice.Getn(), alice.Geta());
        cout << "消息" << message << endl;
        cout << "签名" << aliceSignature << endl;

        // Bob 查询 Alice 的证书路径并验证
        cout << "\nBob 查询 Alice 的证书路径并验证" << endl;
     // DisplayCertificatePath("Alice");

        // 验证 Alice 的证书路径
        if (VerifyCertificateChain("Alice")) {
            cout << "Alice证书链无误." << endl;

            // 验证 Alice 的消息签名
            if (RSAVerify(message, aliceSignature, alice.Getn(), alice.Getb())) {
                cout << "Bob 验证alice消息无误" << endl;
            }
            else {
                cout << "Bob 验证alice消息有误" << endl;
            }
        }
        else {
            cout << "Alice证书链有误" << endl;
        }

        

} 
bool PKI::IsIDInCertStore(const string& id) const {
    // 使用 std::map 的 find 函数查找 ID 是否存在
    auto it = certStore.find(id);
    return it != certStore.end(); // 如果找到了，则说明 ID 存在，返回 true，否则返回 false
}
bool FileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good(); // 如果文件打开成功，返回 true；否则返回 false
}
string PKI:: ChooseUser(const string prmpt) const {
    vector<string> temp;
    int i = 0;
    for (auto it = certStore.begin(); it != certStore.end(); ++it) {
       // if ((it->second).GetUserType() == UserType::User) {
            cout <<char( '1' + i) <<' ' <<it->first << endl;
            temp.push_back(it->first);
            i++;
      //  }
    }
   
    int chice=cin_num(prmpt.c_str(), 1, i + 1);
    return temp[chice-1];

}
void PKI::SendMessage(const string& senderID, const string& message, const string& receiverID) {
    
    // 使用私钥 a 对消息进行签名
    cout << "请输入私钥" << endl;
    ZZ a_temp;
    cin >> a_temp;
    ZZ signature = RSASign(message, certStore[senderID].Getn(), a_temp); // 签名 = msgHash^a mod n

    // 将消息和签名保存到文件中
    string  fileName;
    string folderPath = "Message";
    // 创建文件夹
    if (_mkdir(folderPath.c_str()) == 0 || errno == EEXIST) {
        // 拼接文件路径
        fileName = folderPath + "/" + certStore[senderID].GetID() + "_to_" + certStore[receiverID].GetID() ;
        while (FileExists(fileName + ".txt")) fileName += "()";
        fileName += ".txt";
    }
    else cerr << "创建文件夹失败" << endl;
    
    ofstream outFile(fileName,ios::binary);
    if (!outFile) {
        cerr << "Error creating message file." << endl;
        return;
    }

    outFile <<  message << endl;
    outFile <<  signature << endl;
    outFile.close();
   
    // 将文件名和用户ID添加到 vector 中
    certStore[receiverID].messageInfo.push_back(make_pair(fileName, certStore[senderID].GetID()));

    cout << "消息和消息的签名已保存到" << fileName << endl;
}
bool PKI::VerifyMassage(const string & receiverID) {
     string senderID,  messageFile;
    certStore[receiverID].ChooseReceivedMessages(senderID, messageFile);
    ifstream infile(messageFile,ios::binary);  // 以二进制模式打开文件
    if (!infile.is_open()) {
        cerr << "无法打开证书文件: " << messageFile << endl;
        return false;
    }

    // 读取证书文件内容
    string message;
    ZZ signature;
    getline(infile,message);
    //infile >> message;
    infile >> signature;
    infile.close();
    cout << "信息内容：" << message << endl;
    cout << "签名：" << signature << endl;
    cout << "现开始验证签名..." << endl;
    cout << "查询 发送者" << senderID << " 的证书路径并验证" << endl;
    //DisplayCertificatePath(senderID);

    // 验证 证书路径
    if (VerifyCertificateChain(senderID)) {
        cout << "证书链无误" << endl;
        User sender = certStore[senderID];
        // 验证 消息签名
        if (RSAVerify(message, signature, sender.Getn(), sender.Getb())) {
            cout << "消息验证无误" << endl;
        }
        else {
            cout << "消息签名有误" << endl;
        }
    }
    else {
        cout << "证书链有误" << endl;
    }


}