/*2253553 况俊安 信安*/
#include <iostream>
#include <conio.h>
#include <Windows.h>
//#include "menu.h"
//#include "cmd_console_tools.h"
using namespace std;
const int letter_menu = 1;
const int num_menu = 0;
/***************************************************************************
  函数名称：menu
  功    能：输出菜单
  输入参数：字符指针数组MENU（末尾放NULL），选择菜单形式letter_menu/num_menu（默认）,暂停时间
  返 回 值：选择的菜单项
  说    明：
***************************************************************************/
int menu(const char *MENU[], const int choice, const int sleep_time) {
	char ch;
	int n=0 ;
	while (MENU[n] != NULL) {
		n++;
	}//获取菜单项数

	//cout << n << endl;
	cout << "---------------------------------" << endl;
	for (int i = 0; i < n; i++) {
		cout << char(i+'1'+choice * ('A' - '1')) << '.' << MENU[i] << endl;
	}
	cout <<char( '0' + choice * ('Q' - '0')) << '.' << "退出" << endl;
	cout << "---------------------------------" << endl;
	cout << "[请选择:]";
	int ret;
	while (1) {
		ch = _getch();//不会有回显
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
	cout << prompt << endl;//"按回车键进行数组下落操作...";
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
