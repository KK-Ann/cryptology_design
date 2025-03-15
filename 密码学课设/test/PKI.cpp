#include "Certificate.h"
#include "PKI.h"
#include"menu.h"
#include <fstream>
#include <algorithm>
#include<vector>
#include <direct.h> // ���� _mkdir
using namespace std;
// User ���Ա����ʵ��

// User ���Ա����ʵ��
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
        cout << "�м� CA" << endl;
        break;
    case UserType::User:
        cout << "User" << endl;
        break;
    }
    Display(); // ���û���� Display ����
    cout << "˽Կ a��" << a << endl;
}

// ��ʾ������Ϣ�ĺ���ʵ��
void User::ChooseReceivedMessages( string& senderID,string & messageFile) const {
    if (messageInfo.empty()) {
        cout << "������Ϣ" << endl;
        return;
    }

    cout << "�յ�����Ϣ:" << endl;
    int  i = 0;
    for (const auto& entry : messageInfo) {
        cout <<i+1<< "  ��Ϣ�ļ���: " << entry.first << " | ������: " << entry.second << endl;
        i++;
    }
    int choice=cin_num("��ѡ��Ҫ��ϸ�鿴����ţ�", 1, messageInfo.size());
    messageFile = messageInfo[choice - 1].first;
    senderID = messageInfo[choice - 1].second;
   
    
}
// PKI ���Ա����ʵ��
void PKI::InsertUser(string & your_ID,int & bitLength,User & CAid) {
    cout << "��ʼ����֤�飬���������ID" << endl;
    //string your_ID;
    while (1) {

        cin >> your_ID;
        if (!IsIDInCertStore(your_ID)) break;
        else 	cout << "ID�ظ�������������" << endl;
    }
    //int bitLength = 512;
    while (1) {
        cout << "ѡ����Կ����(512��1024): ";
        cin >> bitLength;
        if (bitLength == 512 || bitLength == 1024) break;
        else 	cout << "������Ҫ����������" << endl;
    }
    cout << "------------------------------" << endl;
    int index=1;
    vector<string> temp;
    for (auto it = certStore.begin(); it != certStore.end(); ++it) {
        User user = (it->second);
        if (user.GetUserType() == UserType::CA) {
            cout << index << ":" << (it->first) << endl; // �� ID ��������
            temp.push_back(it->first);
            index++;
        }
    }

    
    int CAchoice = cin_num("��ѡ��Ϊ��䷢������CA",1,index-1);
   
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
            cout << "֤�������" << currentID << endl;
            return ;
        }
        User user = certStore[currentID];
        certPath.push_back(user);
        if (user.GetUserType() == UserType::ROOT) break; // �������ǩ��֤�飨��CA��
        currentID = user.GetIssuerID(); // ����׷����һ��
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
            cout << " ֤�������" << currentID << endl;
            return false;
        }
      
        User user = certStore[currentID];
        certPath.push_back(user);
        if (user.GetUserType() == UserType::ROOT) break; // �������ǩ��֤�飨��CA��
        currentID = user.GetIssuerID(); // ����׷����һ��
    }
    cout << endl;
    
    for (const auto& cert : certPath) {
        cert.Display();
        if (!cert.VerifySignature()) {
            cout << "��֤ʧ��" << endl;
            return false;
        }
        cout << "��֤�ɹ�" << endl;
        cout << "----------------------" << endl;
    }
    
    return true;
}

void PKI::GetCAIDs(const char* CA_to_choose[]) {
    int index = 0;
    for (auto it = certStore.begin(); it != certStore.end(); ++it) {
        const User& user = it->second;
        if (user.GetUserType() == UserType::CA) {
            CA_to_choose[index] = (it->first).c_str(); // �� ID ��������
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
            user_to_choose[index] = (it->first).c_str(); // �� ID ��������
            index++;
        }
    }
    user_to_choose[index] = NULL;
}

void PKI::apply_PKI_inPPT()  {
    //cout << "��ʼPKI" << endl;
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

        // ���� Alice, Bob �� Eve ��֤��
        User alice(512, "Alice", certStore["CA1"], UserType::User);
        User bob(512, "Bob", certStore["CA2"], UserType::User);
        
        alice.GenerateCertFile();
        bob.GenerateCertFile();
       
       StoreCertificate(alice);
        StoreCertificate(bob);
        

        // Alice ������Ϣ��ǩ��
        string message = "Hello Bob, this is Alice.";
        ZZ aliceSignature = RSASign(message,alice.Getn(), alice.Geta());
        cout << "��Ϣ" << message << endl;
        cout << "ǩ��" << aliceSignature << endl;

        // Bob ��ѯ Alice ��֤��·������֤
        cout << "\nBob ��ѯ Alice ��֤��·������֤" << endl;
     // DisplayCertificatePath("Alice");

        // ��֤ Alice ��֤��·��
        if (VerifyCertificateChain("Alice")) {
            cout << "Alice֤��������." << endl;

            // ��֤ Alice ����Ϣǩ��
            if (RSAVerify(message, aliceSignature, alice.Getn(), alice.Getb())) {
                cout << "Bob ��֤alice��Ϣ����" << endl;
            }
            else {
                cout << "Bob ��֤alice��Ϣ����" << endl;
            }
        }
        else {
            cout << "Alice֤��������" << endl;
        }

        

} 
bool PKI::IsIDInCertStore(const string& id) const {
    // ʹ�� std::map �� find �������� ID �Ƿ����
    auto it = certStore.find(id);
    return it != certStore.end(); // ����ҵ��ˣ���˵�� ID ���ڣ����� true�����򷵻� false
}
bool FileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good(); // ����ļ��򿪳ɹ������� true�����򷵻� false
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
    
    // ʹ��˽Կ a ����Ϣ����ǩ��
    cout << "������˽Կ" << endl;
    ZZ a_temp;
    cin >> a_temp;
    ZZ signature = RSASign(message, certStore[senderID].Getn(), a_temp); // ǩ�� = msgHash^a mod n

    // ����Ϣ��ǩ�����浽�ļ���
    string  fileName;
    string folderPath = "Message";
    // �����ļ���
    if (_mkdir(folderPath.c_str()) == 0 || errno == EEXIST) {
        // ƴ���ļ�·��
        fileName = folderPath + "/" + certStore[senderID].GetID() + "_to_" + certStore[receiverID].GetID() ;
        while (FileExists(fileName + ".txt")) fileName += "()";
        fileName += ".txt";
    }
    else cerr << "�����ļ���ʧ��" << endl;
    
    ofstream outFile(fileName,ios::binary);
    if (!outFile) {
        cerr << "Error creating message file." << endl;
        return;
    }

    outFile <<  message << endl;
    outFile <<  signature << endl;
    outFile.close();
   
    // ���ļ������û�ID��ӵ� vector ��
    certStore[receiverID].messageInfo.push_back(make_pair(fileName, certStore[senderID].GetID()));

    cout << "��Ϣ����Ϣ��ǩ���ѱ��浽" << fileName << endl;
}
bool PKI::VerifyMassage(const string & receiverID) {
     string senderID,  messageFile;
    certStore[receiverID].ChooseReceivedMessages(senderID, messageFile);
    ifstream infile(messageFile,ios::binary);  // �Զ�����ģʽ���ļ�
    if (!infile.is_open()) {
        cerr << "�޷���֤���ļ�: " << messageFile << endl;
        return false;
    }

    // ��ȡ֤���ļ�����
    string message;
    ZZ signature;
    getline(infile,message);
    //infile >> message;
    infile >> signature;
    infile.close();
    cout << "��Ϣ���ݣ�" << message << endl;
    cout << "ǩ����" << signature << endl;
    cout << "�ֿ�ʼ��֤ǩ��..." << endl;
    cout << "��ѯ ������" << senderID << " ��֤��·������֤" << endl;
    //DisplayCertificatePath(senderID);

    // ��֤ ֤��·��
    if (VerifyCertificateChain(senderID)) {
        cout << "֤��������" << endl;
        User sender = certStore[senderID];
        // ��֤ ��Ϣǩ��
        if (RSAVerify(message, signature, sender.Getn(), sender.Getb())) {
            cout << "��Ϣ��֤����" << endl;
        }
        else {
            cout << "��Ϣǩ������" << endl;
        }
    }
    else {
        cout << "֤��������" << endl;
    }


}