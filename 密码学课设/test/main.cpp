
//�����Բ��ּ������include�����ü���lib������ֱ�Ӽ��뵽��Դ�ļ���
#include "menu.h"
#include "RSA_base.h"
#include"certificate.h"
#include"PKI.h"
using namespace std;

int main() {
	while (1) {
		const char* Menu[] = {				"RSA���ܽ���",
														"RSA����(ʹ�����ṩ˽Կ��",
														"RSAǩ���㷨",
														"��֤RSAǩ����ʹ�����ṩ��Կ��",
														"һ���򵥵�֤�鷽��",
														"�ϸ���PKIϵͳ�ļ��װ汾",
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
			const char* Menu3[] = {"����֤��","��֤֤��",NULL };
			int choice3 = menu(Menu3);
			if (choice3 == 1) {
				cout << "��ʼ����֤�飬���������ID" << endl;
				string your_ID;
				cin >> your_ID;
				int bitLength = 512;
				while (1) {
					cout << "ѡ����Կ����(512��1024): ";
					cin >> bitLength;
					if (bitLength == 512 || bitLength == 1024) break;
					else 	cout << "������Ҫ����������" << endl;
				}
				cout << "������֤��䷢����TA��ID" << endl;
				string ta_ID;
				cin >> ta_ID;
				Certification TA(bitLength, ta_ID);
				Certification cert_gen(bitLength,your_ID, TA);
				cout << "TA֤��" << endl;
				TA.Display();
				cout << "�û�֤��" << endl;
				cert_gen.Display();
				TA.GenerateCertFile();
				cert_gen.GenerateCertFile();

			}
			else if (choice3 == 2) {
				cout << "��ʼ��֤֤�飬������֤���ַ" << endl;
				string cert_path;
				cin >> cert_path;
				Certification cert_verify(cert_path);
				bool is_true = cert_verify.VerifySignature();
				cout << (is_true ? "֤����ȷ" : "֤�����") << endl;
			}

		}
		else if (choice == 6) {
			//��ʼ��
			cout << "���ڳ�ʼ��" << endl;
			// ������ CA (TA)
			PKI pkiSystem;
			User rootCA(512, "CAroot", UserType::ROOT);
			rootCA.GenerateCertFile(); // ���ɸ� CA ��֤���ļ�
			pkiSystem.StoreCertificate(rootCA);
			// �����м� CA1 �� CA2
			int num= cin_num("ѡ���м�CA����",1,10);
			for (int i = 0; i < num; i++) {
				cout << "��ʼ����֤�飬������CA��ID" << endl;

				string CA_ID;
				while (1) {
					cin >> CA_ID;
					if (!pkiSystem.IsIDInCertStore(CA_ID)) break;
					else 	cout << "ID�ظ�������������" << endl;
				}
				User ca1(512, CA_ID, rootCA, UserType::CA);
				//User ca2(512, "CA2", "CAroot", UserType::CA);
				ca1.GenerateCertFile();
				//ca2.GenerateCertFile();
				pkiSystem.StoreCertificate(ca1);
				//pkiSystem.StoreCertificate(ca2);
			}
			while (1) {
				const char* Menu_pki[] = { "֤��䷢","��֤�û�","֤����ʾ","��Ϣ����","��Ϣ��֤","ppt����ʾ��",NULL };
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
					cout << "��ѡ����Ҫ��֤���û�" << endl;
					const char* user_to_choose[11];
					pkiSystem.GetUserIDs(user_to_choose);
					int user_choice = menu(user_to_choose);
					if (user_choice == 0) break;
					string user_name = user_to_choose[user_choice - 1];
					pkiSystem.VerifyCertificateChain(user_name);
					break;
				}
				case 3: {
					cout << "��ѡ����Ҫ��ʾ���û�" << endl;
					const char* user_to_choose[11];
					pkiSystem.GetUserIDs(user_to_choose);
					int user_choice = menu(user_to_choose);
					string user_name = user_to_choose[user_choice - 1];
					pkiSystem.DisplayCertificatePath(user_name);
					break;
				}
				case 4: {
					string message;
					cout << "������Ҫǩ�����͵���Ϣ: (�ַ�����";
					cin.ignore();
					getline(cin, message);
					cout << message << endl;
					pkiSystem.SendMessage(pkiSystem.ChooseUser("��ѡ������˭����Ϣ�����ߣ�"), message, pkiSystem.ChooseUser("��ѡ����Ϣ������"));
					break;
				}
				case 5: {
					pkiSystem.VerifyMassage(pkiSystem.ChooseUser("��Ҫ�鿴˭����Ϣ��"));
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


