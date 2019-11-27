#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
#include<opencv2/imgproc/imgproc.hpp>
#include<opencv2/highgui/highgui.hpp>
#include<time.h>
#include<stdlib.h>
#include <cstring>
#include <fstream>
#include "sha256.h"
#include<vector>
#include<string.h>
#include<bitset>
#include<ctime>
#include<cstdlib>
#include<vector>
//#include "untrusted.h"

using namespace std;
using namespace cv;

typedef unsigned char uchar_t;


string random_string(size_t length);
string EncKey(string lx, string ly, string rx, string ry);

Mat Encryption_Matrix(Mat src, string* LxKey, string* RxKey, string* LyKey, string* RyKey, int M, int N, int BlockSize);
string* Create_EncKey(int length, string KEY);
string Create_Specific_Location_Key_R(string Msk, int Location, int Length);
string Create_Specific_Location_Key_L(string Msk, int Location);
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N, string Lx_Msk, string Ly_Msk, string Rx_Msk, string Ry_Msk);
Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N);
string HexToASCII(string hex);
string EncKey(string lx, string ly, string rx, string ry);

//TODO
// ��Ʈ���� ũ�� 3�� �ø���


/*
��� ��Ʈ���� : ������ ��ϻ������ ���� ����� ���� ��Ʈ����
ex) 48 x 48 ������ ��ϻ����� 16���� ���� ����� ��� ��Ʈ������ �� ��,
	�� ��, �� ��� ��Ʈ������ ���� ������ M , ���� ������ N
*/

string random_string(size_t length)
{
	auto randchar = []() -> char //generator�� ���� ��
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	string random_str(length, 0);
	std::generate_n(random_str.begin(), length, randchar);//lenght ��ŭ randchar���� �����ϰ� �̾ƿ� random_str�� ����
	return random_str;
}

#pragma region Ű �迭 �����ϴ� ��

//��� Ű�� ���� string*�� ��ȯ�ϴ� �Լ�
// Decryption�Լ����� CropKeyGen�Լ��� ���ؼ� ���� ��°��� ���ؼ� �ʿ��� DecKey���� ����� ��ȯ�ϴ� �Լ�
// ex. ������� �Է��� 0 0 5 6�̸� Lx�� �������� Lx_key[0]~Lx_Key[N]���� ���� ��ȯ��
string* Create_EncKey(int length, string KEY) {
	string* Key = new string[length];
	Key[0] = sha256(KEY);
	for (int i = 1; i < length; i++) Key[i] = sha256(Key[i - 1]);

	return Key;
}
string* Create_EncKey_sub(int length, string KEY) {
	string* Key = new string[length];
	Key[0] = KEY;
	for (int i = 1; i < length; i++) Key[i] = sha256(Key[i - 1]);

	return Key;
}
#pragma endregion

#pragma region Dec Key �迭 ���� �� ���� �Լ�
//Lx , Ly�� �����ؼ� ����ڰ� Dec�ϰ� ���� ���� DecKey �����ϴ� �Լ�
string Create_Specific_Location_Key_L(string Msk, int Location) {
	string Spec_key = sha256(Msk); // Lx_Key[0] , Ly_Key[0]
	for (int i = 0; i < Location; i++) Spec_key = sha256(Spec_key);

	return Spec_key;
}
//Rx�� �����ؼ� ����ڰ� Dec�ϰ� ���� ���� DecKey �����ϴ� �Լ�
string Create_Specific_Location_Key_R(string Msk, int Location, int Length) {
	string Spec_key = sha256(Msk); // Rx_Key[0]
	for (int i = 1; i < Length - Location; i++) 	Spec_key = sha256(Spec_key);

	return Spec_key;
}
#pragma endregion

// Decryption�� ������ �簢������ �������� ��
// �簢�� ���� �� �𼭸��� �ִ� ����� (M,N)�� ���� Left_M , Left_N
// �簢�� ������ �� �𼭸��� �ִ� ����� (M',N')�� ���� Right_M , Right_N
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N, string Lx_Msk, string Ly_Msk, string Rx_Msk, string Ry_Msk) {
	string* DecKeyGroup = new string[4];
	DecKeyGroup[0] = Create_Specific_Location_Key_L(Lx_Msk, Left_N); //  Lx�� �ش�
	DecKeyGroup[1] = Create_Specific_Location_Key_L(Ly_Msk, Left_M); // Ly�� �ش�
	DecKeyGroup[2] = Create_Specific_Location_Key_R(Rx_Msk, Right_N, N); // Rx�� �ش�
	DecKeyGroup[3] = Create_Specific_Location_Key_R(Ry_Msk, Right_M, M); // Ry�� �ش�

	cout << "LX_KEY : " << DecKeyGroup[0] << endl;
	cout << "LY_KEY : " << DecKeyGroup[1] << endl;
	cout << "RX_KEY : " << DecKeyGroup[2] << endl;
	cout << "RY_KEY : " << DecKeyGroup[3] << endl;

	return DecKeyGroup;
}

Mat Decryption(Mat EncSrc, int M, int N, string* DecKeyGroup, int BlockSize, int Left_M, int Left_N, int Right_M, int Right_N) {
	Mat DecSrc = EncSrc.clone();
	string* Dec_LxKey, * Dec_LyKey, * Dec_RxKey, * Dec_RyKey;
	/*
		����
		M : 10 N : 18
		Left_N : 0 , Left_M : 0
		Right_N : 6 , Right_M : 5
	*/
	clock_t start = clock();
	Dec_LxKey = Create_EncKey_sub(Right_N - Left_N + 1, DecKeyGroup[0]); // Dec_LxKey�� ũ�� : 18 - 0 = 18
	Dec_LyKey = Create_EncKey_sub(Right_M - Left_M + 1, DecKeyGroup[1]); // Dec_LxKey�� ũ�� : 10 - 0 = 10
	Dec_RxKey = Create_EncKey_sub(Right_N - Left_N + 1, DecKeyGroup[2]); // Dec_LxKey�� ũ�� :  6
	Dec_RyKey = Create_EncKey_sub(Right_M - Left_M + 1, DecKeyGroup[3]); // Dec_LxKey�� ũ�� :  5
	clock_t end = clock();
	printf("\n........ Create Enckey : %lf  .......\n", (double)(end - start) / CLOCKS_PER_SEC);
	for (int i = 0; i < Right_M - Left_M + 1; i++) { // i�� 0���� 4���� ����
		for (int j = 0; j < Right_N - Left_N + 1; j++) { // j�� 0���� 5���� ����
			int count = 0;
			string EncKeyData = EncKey(Dec_LxKey[j], Dec_LyKey[i], Dec_RxKey[(Right_N - Left_N) - j], Dec_RyKey[(Right_M - Left_M) - i]);
			for (int row = 0; row < BlockSize; row++) {
				for (int col = 0; col < BlockSize; col++) {
					DecSrc.at<uchar>(((BlockSize * (Left_M + i)) + row), ((BlockSize * (Left_N + j)) + col)) ^= EncKeyData[count];
					count++;
				}
			}
			//cout << "ENCKEY �Ķ���͵� LX , LY , RX , RY : " << j << " " << i << " " << (Right_N-Left_N) - j << " " << (Right_M-Left_M) - i << endl;
			//cout << "[M,N] ------------  [" << (Left_M + i) << "," << (Left_N + j) << "]" << endl;
		}
	}
	return DecSrc;
}

//Hex string�� ASCII string���� �ٲٴ� �Լ�
string HexToASCII(string hex)
{
	int len = hex.length();
	std::string newString;
	const char* byte = hex.c_str();
	for (int i = 0; i < len; i += 2)
	{
		string byte = hex.substr(i, 2);//�Է� ���� hex String�� 2���� �ɰ��� ��
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);// ASCII�� ��ȯ�ϴ� �� 
		newString += chr; //newString�� ��ȯ�ϴ� ���� ����
	}
	return newString;
}

//��Ͽ� �´� lx , ly , rx , ry Ű�� �Է����� ����, sha256�� 8�� ������ append �� ���� ��ȯ�ϴ� �Լ�
string EncKey(string lx, string ly, string rx, string ry) {

	std::string key = lx + ly + rx + ry;
	const char* index = "01234567";
	std::string tempKey = "";// sha256(lx + ly + rx + ry);
	for (int i = 0; i < 8; i++)
		tempKey += sha256(key + index[i]);
	//sha256�Լ��� ������ ���� ������� hex string�̾ HexToASCII�Լ��� ����



	//return tempKey; // HexToASCII �� �� ����

	string EncKey = HexToASCII(tempKey);////HexToASCII �� ���� 
	return EncKey; //HexToASCII �� ����
}

// �Է°� : Encryption�� ���� , Lx Ű�迭 , Rx Ű�迭 , Ly Ű�迭 , Ry Ű�迭 , ��� ��Ʈ������ ���� ���� , ��� ��Ʈ������ ���� ����
Mat Encryption_Matrix(Mat src, string* LxKey, string* RxKey, string* LyKey, string* RyKey, int M, int N, int BlockSize) {
	for (int m = 0; m < M; m++) { // ��ϸ�Ʈ������ �ุŭ ����Ǵ� �Լ�
		for (int n = 0; n < N; n++) { //��ϸ�Ʈ������ ����ŭ ����Ǵ� �Լ� ���ݱ��� M*N��
			string EncKeyData = EncKey(LxKey[n], LyKey[m], RxKey[N - n - 1], RyKey[M - m - 1]);//��Ͽ� �´� Encryption Ű �����Ͽ� ����
			int count = 0;
			for (int i = 0; i < BlockSize; i++) {
				for (int j = 0; j < BlockSize; j++)
				{
					src.at<uchar>((BlockSize * m) + i, (BlockSize * n) + j) ^= EncKeyData[count];
					count++;
				}
			}
		}
	}
	return src;
}

int main(int argc, char* argv)
{
	/*if (argc != 3) {
		cout << "error" << endl;
		return -1;
	}*/

	string Lx = random_string(32); 	string Ly = random_string(32);
	string Rx = random_string(32); 	string Ry = random_string(32);

	cout << "Lx : " << Lx << endl;
	cout << "Ly : " << Ly << endl;
	cout << "Rx : " << Rx << endl;
	cout << "Ry : " << Ry << endl << endl;
	cout << "----------------------------- �ʱⰪ ���� �Ϸ�-------------------------------" << endl;

	Mat src, dst, Dec;
	int BlockSize = 16;
	int M, N;
	int Left_N, Left_M, Right_N, Right_M;

	src = imread("dog.jpg", cv::ImreadModes::IMREAD_GRAYSCALE);
	//src = imread("dog.jpg",CV);
	M = src.rows / BlockSize; // ��� ��Ʈ������ ���� ����
	N = src.cols / BlockSize; // ��� ��Ʈ������ ���� ����
	cout << "��� ��Ʈ������ �� - M : " << M << endl << "��� ��Ʈ������ �� - N : " << N << endl;
	cout << "src�� �� - M' : " << src.rows << endl << "src�� �� - N' : " << src.cols << endl << endl;
	if (!src.data)
	{
		return -1;
	}
	// LX, LY, RX , RY�� �´� Ű �迭�� �����ϴ� ��
	string* Lx_key = Create_EncKey(N, Lx);
	string* Ly_key = Create_EncKey(M, Ly);
	string* Rx_key = Create_EncKey(N, Rx);
	string* Ry_key = Create_EncKey(M, Ry);
	cout << "----------------------------- Ű �迭 ���� ----------------------------------" << endl << endl;;

	cout << "Lx Ű �������� ó�� ��(= sha256(Lx) ) : " << Lx_key[0] << endl;
	cout << "Ly Ű �������� ó�� ��(= sha256(Ly) ) : " << Ly_key[0] << endl;
	cout << "Rx Ű �������� ó�� ��(= sha256(Rx) ) : " << Rx_key[0] << endl;
	cout << "Ry Ű �������� ó�� ��(= sha256(Ry) ) : " << Ry_key[0] << endl << endl;

#pragma region Encryption �κ�
	cout << "Encryption ����" << endl << endl;
	dst = Encryption_Matrix(src, Lx_key, Rx_key, Ly_key, Ry_key, M, N, BlockSize);
	imwrite("enc_dog.jpg", dst);

	uchar_t* data = src.data;


	cout << "Encryption ����" << endl << endl;
#pragma endregion

#pragma region Decryption �κ�
	cout << "Decryption" << endl << "Decryption �� BLOCK ���� - M N M* N* ( M* > M , N* > N ) \n�Է� ����(ex. 0 0 5 6 )" << endl << endl;

	cin >> Left_M >> Left_N >> Right_M >> Right_N;

	cout << "CropKeyGen�Լ� ����" << endl;
	string* DecKey = CropKeyGen(M, N, Left_M, Left_N, Right_M, Right_N, Lx, Ly, Rx, Ry);
	cout << "CropKeyGen �Լ� ����" << endl;


	cout << "Decryption �Լ� ����" << endl;
	Dec = Decryption(dst, M, N, DecKey, BlockSize, Left_M, Left_N, Right_M, Right_N);
	cout << "Decryption �Լ� ����" << endl;
	imwrite("Dec_dog.jpeg", Dec);

	imshow("Display Dec", Dec);


	waitKey(0);
	return 0;
}


