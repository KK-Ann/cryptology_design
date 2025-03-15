
//在属性部分加入这个include，不用加入lib到属性直接加入到资源文件中
#include "menu.h"
#include "RSA_base.h"
#include"certificate.h"
#include"PKI.h"
using namespace std;

int main() {
	while (1) {
		const char* Menu[] = {				"RSA加密解密",
														"RSA解密(使用者提供私钥）",
														"RSA签名算法",
														"验证RSA签名（使用者提供公钥）",
														"一个简单的证书方案",
														"严格层次PKI系统的简易版本",
														NULL };
		int choice = menu(Menu);
		if (choice == 0)
			break;
		else if (choice == 1) {
			apply_Encrypt();
		}
		else if (choice == 2) {
			apply_decrypt();
		}
		else if (choice == 3) {
			apply_SignAndVerify();
		}
		else if (choice == 4) {
			apply_Verify();
		}
		else if (choice == 5) {
			const char* Menu3[] = {"生成证书","验证证书",NULL };
			int choice3 = menu(Menu3);
			if (choice3 == 1) {
				cout << "开始生成证书，请输入你的ID" << endl;
				string your_ID;
				cin >> your_ID;
				int bitLength = 512;
				while (1) {
					cout << "选择密钥长度(512或1024): ";
					cin >> bitLength;
					if (bitLength == 512 || bitLength == 1024) break;
					else 	cout << "不符合要求重新输入" << endl;
				}
				cout << "请输入证书颁发机构TA的ID" << endl;
				string ta_ID;
				cin >> ta_ID;
				Certification TA(bitLength, ta_ID);
				Certification cert_gen(bitLength,your_ID, TA);
				cout << "TA证书" << endl;
				TA.Display();
				cout << "用户证书" << endl;
				cert_gen.Display();
				TA.GenerateCertFile();
				cert_gen.GenerateCertFile();

			}
			else if (choice3 == 2) {
				cout << "开始验证证书，请输入证书地址" << endl;
				string cert_path;
				cin >> cert_path;
				Certification cert_verify(cert_path);
				bool is_true = cert_verify.VerifySignature();
				cout << (is_true ? "证书正确" : "证书错误") << endl;
			}

		}
		else if (choice == 6) {
			//初始化
			cout << "正在初始化" << endl;
			// 创建根 CA (TA)
			PKI pkiSystem;
			User rootCA(512, "CAroot", UserType::ROOT);
			rootCA.GenerateCertFile(); // 生成根 CA 的证书文件
			pkiSystem.StoreCertificate(rootCA);
			// 创建中间 CA1 和 CA2
			int num= cin_num("选择中间CA个数",1,10);
			for (int i = 0; i < num; i++) {
				cout << "开始生成证书，请输入CA的ID" << endl;

				string CA_ID;
				while (1) {
					cin >> CA_ID;
					if (!pkiSystem.IsIDInCertStore(CA_ID)) break;
					else 	cout << "ID重复，请重新输入" << endl;
				}
				User ca1(512, CA_ID, rootCA, UserType::CA);
				//User ca2(512, "CA2", "CAroot", UserType::CA);
				ca1.GenerateCertFile();
				//ca2.GenerateCertFile();
				pkiSystem.StoreCertificate(ca1);
				//pkiSystem.StoreCertificate(ca2);
			}
			while (1) {
				const char* Menu_pki[] = { "证书颁发","验证用户","证书显示","消息发送","消息验证","ppt案例示例",NULL };
				int choice6 = menu(Menu_pki);

				switch (choice6) {
				case 1: {
					string user1_name;
					User ca;
					int bit_length;
					pkiSystem.InsertUser(user1_name, bit_length, ca);
					//cout << "test" << user1_name;
					
					User user1(bit_length,user1_name,ca,UserType::User);
					pkiSystem.StoreCertificate(user1);
					user1.DisplayUser();
					user1.GenerateCertFile();
					break;
				}
				case 2: {
					cout << "请选择需要验证的用户" << endl;
					const char* user_to_choose[11];
					pkiSystem.GetUserIDs(user_to_choose);
					int user_choice = menu(user_to_choose);
					if (user_choice == 0) break;
					string user_name = user_to_choose[user_choice - 1];
					pkiSystem.VerifyCertificateChain(user_name);
					break;
				}
				case 3: {
					cout << "请选择需要显示的用户" << endl;
					const char* user_to_choose[11];
					pkiSystem.GetUserIDs(user_to_choose);
					int user_choice = menu(user_to_choose);
					string user_name = user_to_choose[user_choice - 1];
					pkiSystem.DisplayCertificatePath(user_name);
					break;
				}
				case 4: {
					string message;
					cout << "输入需要签名发送的消息: (字符串）";
					cin.ignore();
					getline(cin, message);
					cout << message << endl;
					pkiSystem.SendMessage(pkiSystem.ChooseUser("请选择你是谁（消息发送者）"), message, pkiSystem.ChooseUser("请选择消息接收者"));
					break;
				}
				case 5: {
					pkiSystem.VerifyMassage(pkiSystem.ChooseUser("你要查看谁的消息："));
					break;
				}
				case 6:
					pkiSystem.apply_PKI_inPPT();
					break;
				case 0:
					break;
				}
				
				if (choice6 == 0) break;
				//;
			}
		}
	}
}


