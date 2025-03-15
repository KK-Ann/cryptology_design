#pragma once
#include"certificate.h"
#include<map>
#include<vector>
#include<string>

// �����û����͵�ö����
enum class UserType {
    ROOT,             // �� CA
    CA, // �м� CA
    User            // ��ͨ�û�
};

// User ������
class User : public Certification {
private:
    UserType userType; // �û����ͣ�TA, IntermediateCA, User
    
public:
    vector<pair<string, string>> messageInfo; // ���ڴ洢��Ϣ�ļ����ͷ����û�ID�� vector
    User();
    User(int bitLength, const string& id, const Certification& id_ta, UserType type= UserType::User);
    User(int bitLength, const string& id, UserType type = UserType::ROOT);
    User(const string& filename, UserType type);

    UserType GetUserType() const;
    void DisplayUser() const;
    void ChooseReceivedMessages(string& senderID, string& messageFile) const;

    
};

// PKI ������������֤���
class PKI {
private:
    map<string, User> certStore; // ֤��⣬���û� ID Ϊ���洢֤��

public:
    void InsertUser(string& your_ID, int& bitLength, User& CAid);//���뷽ʽ�õ��Ϸ���id��
    void StoreCertificate(const User& user); // �洢֤��
 
    void DisplayCertificatePath(const string& userID); // ��ʾ֤��·��
    bool VerifyCertificateChain(const string& userID,bool is_display=true); // ��֤֤����
    void GetCAIDs(const char* CA_to_choose[]);
    void GetUserIDs(const char* user_to_choose[]);
    bool IsIDInCertStore(const string& id) const;
    void apply_PKI_inPPT() ;
    string ChooseUser(const string prmpt) const;
    void SendMessage(const string& senderID, const string& message, const string& receiverID);
    bool VerifyMassage(const string & receiverID);

};

