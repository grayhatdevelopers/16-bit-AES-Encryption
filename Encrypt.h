#pragma once
//
//
//????????????   ??? ?????????????? ???   ?????????? ???????????? ??????? ????   ???
//?????????????  ??????????????????????? ??????????????????????????????????????  ???
//??????  ?????? ??????     ???????? ??????? ????????   ???   ??????   ????????? ???
//??????  ?????????????     ????????  ?????  ???????    ???   ??????   ?????????????
//??????????? ?????????????????  ???   ???   ???        ???   ??????????????? ??????
//???????????  ????? ??????????  ???   ???   ???        ???   ??? ??????? ???  ?????
//A simple AES Encryption/Decryption implementation, for beginners and computer noobs like myself.
//Implemented by Saad Ahmed Bazaz
//FAST NUCES, Islamabad
//
//



#include<iostream>
#include<math.h>
using namespace std;


//these are the constant mixColumn values defined for 128-bit encryption by the AES
const unsigned char mixMatrix[16] = {
	2, 3, 1, 1,
	1, 2, 3, 1,
	1, 1, 2, 3,
	3, 1, 1, 2
};

//these are the inverse constant mixColumn values defined for 128-bit encryption by the AES
const unsigned char InvmixMatrix[16] = {
14, 11, 13, 9,
9, 14, 11, 13,
13, 9, 14, 11,
11, 13, 9, 14,
};

// substitutes a byte from the sbox
unsigned char substitute(unsigned char byte) {

	static unsigned char sbox[256] = {
	   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
	};

	return sbox[byte];
}

// substitutes a reverse byte from the sbox
unsigned char reverse_substitute(unsigned char byte) {
	static unsigned char rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
	, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
	, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
	, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
	, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
	, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
	, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
	, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
	, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
	, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
	, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
	, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
	, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
	, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
	, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
	, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

	return rsbox[byte];
}

//round constants defined by AES, upto 255 bytes
unsigned char Rcon[255] = {

0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

//retreives the Rcon value for the selected round
unsigned char getRconValue(unsigned char num)
{
	return Rcon[num];
}



//basically you don't have to convert the key to 4x4 rather just work on the 16 bytes you have received in a way that it simulates 4x4


// left shift an array and push the front to the back
unsigned char* rotate_left(unsigned char* byte_array) {
	unsigned char temp = (byte_array[0]);
	for (int i=0; i < 3; i++) {
		byte_array[i] = byte_array[i + 1];
	}
	byte_array[3] = temp;
	return byte_array;
}

// substitutes values of a word with the values from the sbox
void SubWord(unsigned char* state) {
	for (int i = 0; i < 4; i++) {
		state[i] = substitute(state[i]);
	}

}

// substitutes values of a byte with the values from the sbox
void SubBytes(unsigned char* state) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i * 4 + j] = substitute(state[i * 4 + j]);
		}
	}

}

// substitutes values of a word with the values from the reverse_sbox
void InvSubBytes(unsigned char* state) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i * 4 + j] = reverse_substitute(state[i * 4 + j]);
		}
	}
}

// performs exactly opposite function of the shiftRows function
void InvShiftRows(unsigned char* state) {
	char temp;
	int i = 0;

	temp = (state[12]);
	for (; i < 3; i++) {
		state[12 + i] = state[12 + i + 1];
	}
	state[15] = temp;

	swap(state[8], state[10]);
	swap(state[9], state[11]);

	i = 7;
	temp = (state[7]);
	for (; i > 4; i--) {
		state[i] = state[i - 1];
	}
	state[4] = temp;
}

//using loops and swap, performs the requires rowshifts
void ShiftRows(unsigned char* state) {
	char temp;
	int i = 0;

	temp = (state[4]);
	for (; i < 3; i++) {
		state[4 + i] = state[4 + i + 1];
	}
	state[7] = temp;

	swap(state[8], state[10]);
	swap(state[9], state[11]);

	i = 15;
	temp = (state[15]);
	for (; i > 12; i--) {
		state[i] = state[i - 1];
	}
	state[12] = temp;

}

//simply XORs the roundkey with the state argument
void addRoundKey(unsigned char* state, unsigned char* roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}


//generates a key schedule based on existing AES guidelines (currently only works for 16-bit AES)
void KeyExpansion(unsigned char* cipherkey, unsigned char* expandedkey) {
	unsigned char temp[4] = { 0 };
	// here, Nk = 16
	// N = 16 * (10+1) = 176
	int i = 0;
	int rconIteration = 1;

	
	for (; i < 16; i++) {
		expandedkey[i] = cipherkey[i];
	}

	i = 16;
	while (i < 176) {
		for (int j=0; j<4; j++)
			//store the previous key
			temp[j]= expandedkey[i - 4 + j];
		if (i % 16 == 0) {
			//core functionality to create a new key
			rotate_left(temp);
			SubWord(temp);
			temp[0] = temp[0] ^ getRconValue(rconIteration);
					
			rconIteration++;
		}

		for (int l = 0; l < 4; l++) {
			expandedkey[i] = expandedkey[i - 16] ^ temp[l];
			i++;
		}			
		
	}


	


}


//The only function which ended up working after all my research and silly mistakes. This simply performs Rijndael Multiplication assuming b is 2
unsigned char RijndaelMultiplication(unsigned char a, unsigned char b) {
	bool isHigh = false;
		//skipping other steps as they are irrelevant to a constant "2"
		isHigh = ((a >> 7) & 1);
		//step 3
		a = (a << 1);
		//step 4
		if (isHigh) a ^= 0x1b;
		//step 5
	
	return a;
}


//one of my tests
unsigned char RijndaelMultiplication3(unsigned char a, unsigned char b) {
	//unsigned char product = 0;
	bool isHigh = false;

	//for (int j = 0; j < 8; j++) {
		//step 1
		//if (((b >> 0) & 1)) {
			//product ^= a;
		//}
		//step 2
	isHigh = ((a >> 7) & 1);
	//step 3
	a = (a << 1);
	//step 4
	if (isHigh) a ^= 0x1b;
	//step 5
	//a = a >> 1;

	return a;
}

//another one of my test. Logically, this should have worked for all multiplications, but it didn't. Sad.
unsigned char RijndaelMultiplication2(unsigned char a, unsigned char b) {
	unsigned char product = 0;
	bool isHigh = false;
	cout << "a is = " << a << endl;
	for (int j = 0; j < 8; j++) {
		//step 1
		if (((b >> 0) & 1)) {
			product ^= a;
		}
		//step 2
		isHigh = ((a >> 7) & 1);
		//step 3
		a = (a << 1);
		//step 4
		if (isHigh) a ^= 0x1b;
		//step 5
		a = (a >> 1);
	}
	cout << "The product is = " << product << endl;
	return product;
}


//Based on the knowledge of the Rijndael Multiplication of 2, we can find out the multiplication for other numbers using factors
void MixColumn(unsigned char* state) {

	unsigned char* product = new unsigned char [16];

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			product[i*4 + j] = 0;
			for (int k = 0; k < 4; k++)
			{
				if (mixMatrix[i * 4 + k] == 2){
					product[i * 4 + j] ^= RijndaelMultiplication(state[k * 4 + j], 2);

				}
				else if (mixMatrix[i * 4 + k] == 3) {
					product[i * 4 + j] ^= RijndaelMultiplication(state[k * 4 + j], 2);
					product[i * 4 + j] ^= state[k * 4 + j];

				}
				else {
					product[i * 4 + j] ^= state[k * 4 + j];
				}
			}
			cout << product[i * 4 + j] << ", ";
		}
		cout << endl;
	}

	for (int i=0; i<16; i++){
		state[i] = product[i];
	}



}

//the test which should've worked with the other discarded multiplication function. What a shame.
void MixColumn2(unsigned char* state) {
	unsigned char product [16];


	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			product[i * 4 + j] = 0;
			for(int k = 0; k < 4; k++){

					product[i * 4 + j] ^= RijndaelMultiplication(mixMatrix[i * 4 + k], state[k * 4 + j]);

			}
			cout << product[i * 4 + j] << ", ";
		}
		cout << endl;
	}

	for (int i = 0; i < 16; i++) {
			state[i] = product[i];
	}


}

//based on the AES guidelines, this calls the functions in proper order for AES Encryption. However, for proper functionality, transposes must be taken at every corner
void Encrypt(unsigned char* plaintext, unsigned char* cipherkey, unsigned char* ciphertext) {


	cout << "Plain text = ";
	for (int i = 0; i < 16; i++) {
		cout << plaintext[i] << ", ";
	}

	cout << endl;

	unsigned char transroundkey[16];

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			ciphertext[j*4 + i] = plaintext[i*4 + j];
		}
	}

	cout << "Plain text transposed= ";
	for (int i = 0; i < 16; i++) {
		cout << ciphertext[i] << ", ";
	}

	cout << endl;



	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			transroundkey[j * 4 + i] = cipherkey[i * 4 + j];
		}

	}

	addRoundKey(ciphertext, transroundkey);

	unsigned char expandedKey[176];
	KeyExpansion(cipherkey, expandedKey);
	unsigned char roundkey[16];

	for (int i = 1; i < 10; i++) {
		SubBytes(ciphertext);
		ShiftRows(ciphertext);
		MixColumn(ciphertext);

		for (int j = 0; j < 16; j++) {
			roundkey[j] = expandedKey[i * 16 + j];
		}

		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				transroundkey[j * 4 + i] = roundkey[i * 4 + j];
			}

		}

		addRoundKey(ciphertext, transroundkey);
	}

	SubBytes(ciphertext);
	ShiftRows(ciphertext);
	for (int j = 0; j < 16; j++) {
		roundkey[j] = expandedKey[10 * 16 + j];
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			transroundkey[j * 4 + i] = roundkey[i * 4 + j];
		}

	}
	addRoundKey(ciphertext, transroundkey);
	
	cout << "Cipher text = ";
	for (int i = 0; i < 16; i++) {
		cout << ciphertext[i] << ", ";
	}

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			plaintext[j * 4 + i] = ciphertext[i * 4 + j];
		}
	}

	for (int i = 0; i < 16; i++) {
		ciphertext[i] = plaintext[i];
	}



	cout << endl;

	unsigned char expected[16] = {
	0x29, 0xc3, 0x50, 0x5f,
	0x57, 0x14, 0x20, 0xf6,
	0x40, 0x22, 0x99, 0xb3,
	0x1a, 0x02, 0xd7, 0x3a
	};

	cout << "Expected = ";
	for (int i = 0; i < 16; i++) {
		cout << expected[i] << ", ";
	}

	cout << endl;


}


//A wise man once said, 
//"For the MixColumn matrix M, it is true that M4 = I. So, by performing this transformation thrice you get its inverse(M3 = M?1). A little crazy, but it might be practical in certain situations."
void InvMixColumn(unsigned char* state) {
	for (int i = 0; i < 3; ++i)
		MixColumn(state);
}

//based on the AES guidelines, this calls the functions in proper order for AES Decryption. However, for proper functionality, transposes must be taken at every corner
void Decrypt(unsigned char* ciphertext, unsigned char* cipherkey, unsigned char* plaintext) {

	cout << "Cipher text = ";
	for (int i = 0; i < 16; i++) {
		cout << ciphertext[i] << ", ";
	}

	cout << endl;

	unsigned char transroundkey[16];

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			plaintext[i * 4 + j] = ciphertext[j * 4 + i];
		}
	}

	cout << "Cipher text transposed= ";
	for (int i = 0; i < 16; i++) {
		cout << plaintext[i] << ", ";
	}

	cout << endl;

	unsigned char roundkey[16];
	unsigned char expandedKey[176];
	KeyExpansion(cipherkey, expandedKey);

	for (int i = 0; i < 16; i++) {
		roundkey[i] = expandedKey[(10 * 16) + i];
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			transroundkey[i * 4 + j] = roundkey[j * 4 + i];
		}

	}

	addRoundKey(plaintext, transroundkey);





	for (int i = 9; i >0 ; i--) {
		InvShiftRows(plaintext);
		InvSubBytes(plaintext);

	

		for (int j = 0; j < 16; j++) {
			roundkey[j] = expandedKey[i * 16 + j];
		}

		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				transroundkey[i * 4 + j] = roundkey[j * 4 + i];
			}

		}

		addRoundKey(plaintext, transroundkey);	
		InvMixColumn(plaintext);
	}
	InvShiftRows(plaintext);
	InvSubBytes(plaintext);
	for (int j = 0; j < 16; j++) {
		roundkey[j] = expandedKey[(0 * 16) + j];
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			transroundkey[i * 4 + j] = roundkey[j * 4 + i];
		}

	}
	addRoundKey(plaintext, transroundkey);

	cout << "Plain text = ";
	for (int i = 0; i < 16; i++) {
		cout << plaintext[i] << ", ";
	}

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			ciphertext[i * 4 + j] = plaintext[j * 4 + i];
		}
	}

	for (int i = 0; i < 16; i++) {
		plaintext[i] = ciphertext[i];
	}



	cout << endl;

	const char* expectedStr = "Two One Nine Two";

	cout << "Expected = ";
	for (int i = 0; i < 16; i++) {
		cout << expectedStr[i] << ", ";
	}

	cout << endl;


}

//cout << "Cipher text = ";
//for (int i = 0; i < 16; i++) {
//	cout << ciphertext[i] << ", ";
//}
//
//cout << endl;
//
//unsigned char transroundkey[16];
//
//for (int i = 0; i < 4; i++) {
//	for (int j = 0; j < 4; j++) {
//		plaintext[i * 4 + j] = ciphertext[j * 4 + i];
//	}
//}
//
///*for (int i = 0; i <16 ; i++) {
//	plaintext[i] = ciphertext[i];
//}*/
//
//cout << "Cipher text transposed= ";
//for (int i = 0; i < 16; i++) {
//	cout << plaintext[i] << ", ";
//}
//
//cout << endl;
//
//
////for (int i = 0; i < 16; i++) {
////	ciphertext[i] = plaintext[i];
////}	
//unsigned char roundkey[16];
//unsigned char expandedKey[176];
//KeyExpansion(cipherkey, expandedKey);
//
//for (int i = 0; i < 4; i++) {
//	roundkey[i] = expandedKey[(10 * 16) + i];
//}
//for (int i = 0; i < 4; i++) {
//	for (int j = 0; j < 4; j++) {
//		transroundkey[i * 4 + j] = roundkey[j * 4 + i];
//	}
//
//}
//
//addRoundKey(plaintext, transroundkey);
//
//
//
//
//
//for (int i = 9; i > 0; i--) {
//	InvShiftRows(plaintext);
//	InvSubBytes(plaintext);
//
//
//
//	for (int j = 0; j < 16; j++) {
//		roundkey[j] = expandedKey[i * 16 + j];
//	}
//
//	for (int i = 0; i < 4; i++) {
//		for (int j = 0; j < 4; j++) {
//			transroundkey[i * 4 + j] = roundkey[j * 4 + i];
//		}
//
//	}
//
//	addRoundKey(plaintext, transroundkey);
//	InvMixColumn(plaintext);
//}
//InvShiftRows(plaintext);
//InvSubBytes(plaintext);
//for (int j = 0; j < 16; j++) {
//	roundkey[j] = expandedKey[(0 * 16) + j];
//}
//for (int i = 0; i < 4; i++) {
//	for (int j = 0; j < 4; j++) {
//		transroundkey[i * 4 + j] = roundkey[j * 4 + i];
//	}
//
//}
//addRoundKey(plaintext, transroundkey);
//
//cout << "Plain text = ";
//for (int i = 0; i < 16; i++) {
//	cout << plaintext[i] << ", ";
//}
//
//for (int i = 0; i < 4; i++) {
//	for (int j = 0; j < 4; j++) {
//		ciphertext[i * 4 + j] = plaintext[j * 4 + i];
//	}
//}
//
//for (int i = 0; i < 16; i++) {
//	plaintext[i] = ciphertext[i];
//}
//
//
//
//cout << endl;
//
//const char* expectedStr = "Two One Nine Two";
//
//cout << "Expected = ";
//for (int i = 0; i < 16; i++) {
//	cout << expectedStr[i] << ", ";
//}
//
//cout << endl;






//if (InvmixMatrix[i * 4 + k] == 9) {
//	product[i * 4 + j] ^= RijndaelMultiplication(2, RijndaelMultiplication(2, RijndaelMultiplication(2, state[i * 4 + k])));
//	product[i * 4 + j] ^= state[i * 4 + k];
//}
//else if (InvmixMatrix[i * 4 + k] == 11) {
//	product[i * 4 + j] ^= RijndaelMultiplication(2, RijndaelMultiplication(2, RijndaelMultiplication(2, state[i * 4 + k])) ^ state[i * 4 + k]);
//	product[i * 4 + j] ^= state[i * 4 + k];
//
//}
//else if (InvmixMatrix[i * 4 + k] == 13) {
//	product[i * 4 + j] ^= (RijndaelMultiplication(2, RijndaelMultiplication(2, (RijndaelMultiplication(2, state[i * 4 + k]) ^ state[i * 4 + k]))) ^ state[i * 4 + k]);
//	product[i * 4 + j] ^= state[i * 4 + k];
//}
//else if (InvmixMatrix[i * 4 + k] == 14) {
//	product[i * 4 + j] ^= RijndaelMultiplication(2, (RijndaelMultiplication(2, (RijndaelMultiplication(2, state[i * 4 + k]) ^ state[i * 4 + k])) ^ state[i * 4 + k]));
//}


void Display(unsigned char* state) {
	std::cout << std::endl;
	for (int i = 0; i < 16; i++) {
		std::cout << state[i]<<", ";
	}
}