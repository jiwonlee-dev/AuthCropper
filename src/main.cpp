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
// 매트릭스 크기 3배 늘리기


/*
블록 매트릭스 : 사진을 블록사이즈로 나눈 결과로 얻은 매트리스
ex) 48 x 48 사진을 블록사이즈 16으로 나눈 결과를 블록 매트릭스라 할 때,
	이 때, 이 블록 매트릭스의 행의 개수를 M , 열의 개수를 N
*/

string random_string(size_t length)
{
	auto randchar = []() -> char //generator를 만든 곳
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	string random_str(length, 0);
	std::generate_n(random_str.begin(), length, randchar);//lenght 만큼 randchar에서 랜덤하게 뽑아와 random_str에 저장
	return random_str;
}

#pragma region 키 배열 생성하는 곳

//모든 키를 만들어서 string*로 반환하는 함수
// Decryption함수에서 CropKeyGen함수를 통해서 나온 출력값을 통해서 필요한 DecKey들을 만들어 반환하는 함수
// ex. 사용자의 입력이 0 0 5 6이면 Lx를 기준으로 Lx_key[0]~Lx_Key[N]까지 만들어서 반환함
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

#pragma region Dec Key 배열 만들 때 만든 함수
//Lx , Ly와 관련해서 사용자가 Dec하고 싶은 범위 DecKey 생성하는 함수
string Create_Specific_Location_Key_L(string Msk, int Location) {
	string Spec_key = sha256(Msk); // Lx_Key[0] , Ly_Key[0]
	for (int i = 0; i < Location; i++) Spec_key = sha256(Spec_key);

	return Spec_key;
}
//Rx와 관련해서 사용자가 Dec하고 싶은 범위 DecKey 생성하는 함수
string Create_Specific_Location_Key_R(string Msk, int Location, int Length) {
	string Spec_key = sha256(Msk); // Rx_Key[0]
	for (int i = 1; i < Length - Location; i++) 	Spec_key = sha256(Spec_key);

	return Spec_key;
}
#pragma endregion

// Decryption할 범위를 사각형으로 생각했을 때
// 사각형 왼쪽 위 모서리에 있는 블락의 (M,N)을 각각 Left_M , Left_N
// 사각형 오른쪽 위 모서리에 있는 블락의 (M',N')을 각각 Right_M , Right_N
string* CropKeyGen(int M, int N, int Left_M, int Left_N, int Right_M, int Right_N, string Lx_Msk, string Ly_Msk, string Rx_Msk, string Ry_Msk) {
	string* DecKeyGroup = new string[4];
	DecKeyGroup[0] = Create_Specific_Location_Key_L(Lx_Msk, Left_N); //  Lx에 해당
	DecKeyGroup[1] = Create_Specific_Location_Key_L(Ly_Msk, Left_M); // Ly에 해당
	DecKeyGroup[2] = Create_Specific_Location_Key_R(Rx_Msk, Right_N, N); // Rx에 해당
	DecKeyGroup[3] = Create_Specific_Location_Key_R(Ry_Msk, Right_M, M); // Ry에 해당

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
		예시
		M : 10 N : 18
		Left_N : 0 , Left_M : 0
		Right_N : 6 , Right_M : 5
	*/
	clock_t start = clock();
	Dec_LxKey = Create_EncKey_sub(Right_N - Left_N + 1, DecKeyGroup[0]); // Dec_LxKey의 크기 : 18 - 0 = 18
	Dec_LyKey = Create_EncKey_sub(Right_M - Left_M + 1, DecKeyGroup[1]); // Dec_LxKey의 크기 : 10 - 0 = 10
	Dec_RxKey = Create_EncKey_sub(Right_N - Left_N + 1, DecKeyGroup[2]); // Dec_LxKey의 크기 :  6
	Dec_RyKey = Create_EncKey_sub(Right_M - Left_M + 1, DecKeyGroup[3]); // Dec_LxKey의 크기 :  5
	clock_t end = clock();
	printf("\n........ Create Enckey : %lf  .......\n", (double)(end - start) / CLOCKS_PER_SEC);
	for (int i = 0; i < Right_M - Left_M + 1; i++) { // i가 0부터 4까지 실행
		for (int j = 0; j < Right_N - Left_N + 1; j++) { // j가 0부터 5까지 실행
			int count = 0;
			string EncKeyData = EncKey(Dec_LxKey[j], Dec_LyKey[i], Dec_RxKey[(Right_N - Left_N) - j], Dec_RyKey[(Right_M - Left_M) - i]);
			for (int row = 0; row < BlockSize; row++) {
				for (int col = 0; col < BlockSize; col++) {
					DecSrc.at<uchar>(((BlockSize * (Left_M + i)) + row), ((BlockSize * (Left_N + j)) + col)) ^= EncKeyData[count];
					count++;
				}
			}
			//cout << "ENCKEY 파라미터들 LX , LY , RX , RY : " << j << " " << i << " " << (Right_N-Left_N) - j << " " << (Right_M-Left_M) - i << endl;
			//cout << "[M,N] ------------  [" << (Left_M + i) << "," << (Left_N + j) << "]" << endl;
		}
	}
	return DecSrc;
}

//Hex string을 ASCII string으로 바꾸는 함수
string HexToASCII(string hex)
{
	int len = hex.length();
	std::string newString;
	const char* byte = hex.c_str();
	for (int i = 0; i < len; i += 2)
	{
		string byte = hex.substr(i, 2);//입력 받은 hex String을 2개씩 쪼개는 곳
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);// ASCII로 변환하는 곳 
		newString += chr; //newString에 변환하는 값을 저장
	}
	return newString;
}

//블록에 맞는 lx , ly , rx , ry 키를 입력으로 갖고, sha256을 8번 돌려서 append 한 것을 반환하는 함수
string EncKey(string lx, string ly, string rx, string ry) {

	std::string key = lx + ly + rx + ry;
	const char* index = "01234567";
	std::string tempKey = "";// sha256(lx + ly + rx + ry);
	for (int i = 0; i < 8; i++)
		tempKey += sha256(key + index[i]);
	//sha256함수를 돌려서 나온 결과물이 hex string이어서 HexToASCII함수를 만듬



	//return tempKey; // HexToASCII 안 쓴 버전

	string EncKey = HexToASCII(tempKey);////HexToASCII 쓴 버전 
	return EncKey; //HexToASCII 쓴 버전
}

// 입력값 : Encryption할 사진 , Lx 키배열 , Rx 키배열 , Ly 키배열 , Ry 키배열 , 블록 매트릭스의 행의 개수 , 블록 매트릭스의 열의 개수
Mat Encryption_Matrix(Mat src, string* LxKey, string* RxKey, string* LyKey, string* RyKey, int M, int N, int BlockSize) {
	for (int m = 0; m < M; m++) { // 블록매트릭스의 행만큼 실행되는 함수
		for (int n = 0; n < N; n++) { //블록매트릭스의 열만큼 실행되는 함수 지금까지 M*N번
			string EncKeyData = EncKey(LxKey[n], LyKey[m], RxKey[N - n - 1], RyKey[M - m - 1]);//블록에 맞는 Encryption 키 생성하여 저장
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
	cout << "----------------------------- 초기값 설정 완료-------------------------------" << endl;

	Mat src, dst, Dec;
	int BlockSize = 16;
	int M, N;
	int Left_N, Left_M, Right_N, Right_M;

	src = imread("dog.jpg", cv::ImreadModes::IMREAD_GRAYSCALE);
	//src = imread("dog.jpg",CV);
	M = src.rows / BlockSize; // 블록 매트릭스의 행의 개수
	N = src.cols / BlockSize; // 블록 매트릭스의 열의 개수
	cout << "블록 매트릭스의 행 - M : " << M << endl << "블록 매트릭스의 열 - N : " << N << endl;
	cout << "src의 행 - M' : " << src.rows << endl << "src의 열 - N' : " << src.cols << endl << endl;
	if (!src.data)
	{
		return -1;
	}
	// LX, LY, RX , RY에 맞는 키 배열을 생성하는 곳
	string* Lx_key = Create_EncKey(N, Lx);
	string* Ly_key = Create_EncKey(M, Ly);
	string* Rx_key = Create_EncKey(N, Rx);
	string* Ry_key = Create_EncKey(M, Ry);
	cout << "----------------------------- 키 배열 생성 ----------------------------------" << endl << endl;;

	cout << "Lx 키 데이터의 처음 값(= sha256(Lx) ) : " << Lx_key[0] << endl;
	cout << "Ly 키 데이터의 처음 값(= sha256(Ly) ) : " << Ly_key[0] << endl;
	cout << "Rx 키 데이터의 처음 값(= sha256(Rx) ) : " << Rx_key[0] << endl;
	cout << "Ry 키 데이터의 처음 값(= sha256(Ry) ) : " << Ry_key[0] << endl << endl;

#pragma region Encryption 부분
	cout << "Encryption 시작" << endl << endl;
	dst = Encryption_Matrix(src, Lx_key, Rx_key, Ly_key, Ry_key, M, N, BlockSize);
	imwrite("enc_dog.jpg", dst);

	uchar_t* data = src.data;


	cout << "Encryption 종료" << endl << endl;
#pragma endregion

#pragma region Decryption 부분
	cout << "Decryption" << endl << "Decryption 할 BLOCK 범위 - M N M* N* ( M* > M , N* > N ) \n입력 예시(ex. 0 0 5 6 )" << endl << endl;

	cin >> Left_M >> Left_N >> Right_M >> Right_N;

	cout << "CropKeyGen함수 실행" << endl;
	string* DecKey = CropKeyGen(M, N, Left_M, Left_N, Right_M, Right_N, Lx, Ly, Rx, Ry);
	cout << "CropKeyGen 함수 종료" << endl;


	cout << "Decryption 함수 실행" << endl;
	Dec = Decryption(dst, M, N, DecKey, BlockSize, Left_M, Left_N, Right_M, Right_N);
	cout << "Decryption 함수 종료" << endl;
	imwrite("Dec_dog.jpeg", Dec);

	imshow("Display Dec", Dec);


	waitKey(0);
	return 0;
}


