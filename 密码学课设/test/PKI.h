#pragma once
#include"certificate.h"
#include<map>
#include<vector>
#include<string>

// 定义用户类型的枚举类
enum class UserType {
    ROOT,             // 根 CA
    CA, // 中间 CA
    User            // 普通用户
};

// User 类声明
class User : public Certification {
private:
    UserType userType; // 用户类型：TA, IntermediateCA, User
    
public:
    vector<pair<string, string>> messageInfo; // 用于存储消息文件名和发送用户ID的 vector
    User();
    User(int bitLength, const string& id, const Certification& id_ta, UserType type= UserType::User);
    User(int bitLength, const string& id, UserType type = UserType::ROOT);
    User(const string& filename, UserType type);

    UserType GetUserType() const;
    void DisplayUser() const;
    void ChooseReceivedMessages(string& senderID, string& messageFile) const;

    
};

// PKI 类声明：管理证书库
class PKI {
private:
    map<string, User> certStore; // 证书库，以用户 ID 为键存储证书

public:
    void InsertUser(string& your_ID, int& bitLength, User& CAid);//输入方式得到合法的id名
    void StoreCertificate(const User& user); // 存储证书
 
    void DisplayCertificatePath(const string& userID); // 显示证书路径
    bool VerifyCertificateChain(const string& userID,bool is_display=true); // 验证证书链
    void GetCAIDs(const char* CA_to_choose[]);
    void GetUserIDs(const char* user_to_choose[]);
    bool IsIDInCertStore(const string& id) const;
    void apply_PKI_inPPT() ;
    string ChooseUser(const string prmpt) const;
    void SendMessage(const string& senderID, const string& message, const string& receiverID);
    bool VerifyMassage(const string & receiverID);

};

