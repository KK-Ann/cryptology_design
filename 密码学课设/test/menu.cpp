/*2253553 ������ �Ű�*/
#include <iostream>
#include <conio.h>
#include <Windows.h>
//#include "menu.h"
//#include "cmd_console_tools.h"
using namespace std;
const int letter_menu = 1;
const int num_menu = 0;
/***************************************************************************
  �������ƣ�menu
  ��    �ܣ�����˵�
  ����������ַ�ָ������MENU��ĩβ��NULL����ѡ��˵���ʽletter_menu/num_menu��Ĭ�ϣ�,��ͣʱ��
  �� �� ֵ��ѡ��Ĳ˵���
  ˵    ����
***************************************************************************/
int menu(const char *MENU[], const int choice, const int sleep_time) {
	char ch;
	int n=0 ;
	while (MENU[n] != NULL) {
		n++;
	}//��ȡ�˵�����

	//cout << n << endl;
	cout << "---------------------------------" << endl;
	for (int i = 0; i < n; i++) {
		cout << char(i+'1'+choice * ('A' - '1')) << '.' << MENU[i] << endl;
	}
	cout <<char( '0' + choice * ('Q' - '0')) << '.' << "�˳�" << endl;
	cout << "---------------------------------" << endl;
	cout << "[��ѡ��:]";
	int ret;
	while (1) {
		ch = _getch();//�����л���
		//cout << ch;
		if (choice==letter_menu&&ch >= 'a')
			ch += 'A' - 'a';
		ret = int(ch);
		ret -= '0' + choice * ('A' - '0');
		if ((ret >=0 && ret<= n) || ret == 'Q'-'A') {
			cout << ch << endl;
			Sleep(sleep_time);

			break;
		}
		else
			continue;
	}
	if (choice == num_menu)
		return ret;
	else
		return ch;
}
void enter_to_continue(const char* prompt) {
	//cct_setcolor();
	cout << prompt << endl;//"���س������������������...";
	while (1) {
		char ch = _getch();
		if (ch == '\r')
			break;
	}
}

int cin_num(const char*prompt,int min,int max) {
	int n;
	while (1) {

		cout <<prompt << endl;
		cin >> n;
		if (cin.good() == 1 && (n >= min && n <= max)) {
			cin.clear();
			cin.ignore(65536, '\n');
			break;
		}
		else {
			cin.clear();
			cin.ignore(65536, '\n');
		}
	}
	return n;
}
