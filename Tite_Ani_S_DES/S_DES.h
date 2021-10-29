//preprocessor directive.
// Tite_Ani_S_DES.cpp : This file contains the 'main' function. Program execution begins and ends there.
/****************************************************************************************************************
*** NAME : 			Tite Divava	& Anirudh Dhoundiyal													  	  ***
*** CLASS : 		CSc 487 																			  	  ***
*** ASSIGNMENT : 	Assignement 1																		  	  ***
*** DUE DATE : 		09/20/2020													   						  	  ***
*** INSTRUCTOR :    Robert Fourney																		  	  ***
*****************************************************************************************************************
*** DESCRIPTION :  	This file contains the class declaration.												  ***
****************************************************************************************************************/

#pragma once
#ifndef S_DES_H
#define S_DES_H

//libraries
#include<string>
#include <fstream>
#include <bitset>           // Library that stores bits (elements with only two possible values: 0 or 1, true or false...)
#include <sstream>
#include <iostream>
//using namespace std
using namespace std;

class S_DES
{
	private:
		// variables
		string cp,			// ciphertext
			pt,				// plaintext 
			key1,			// key 1 
			key2;			// key 2
		bool fk_flag = false;
		bool decrypt_flag = false;
		
		// functions declaration
		string ip();			// T
		string fk(string);	// A
		string e_p(string);			// ep function returns a string of length 8
		string p_4(string, string);	// p4 function gets two strings of length 2 and returns one string of length 4
		string s0_box(string);		// s0 takes a string of length 4 and returns a string of length 2.
		string s1_box(string);		// s1 takes a string of length 4 and returns a string of length 2.
		string sw(string);			//switch function
		string ip_inverse(string);	// T
		string p_10(string);		// T
		string shift(string);	// A
		void left_shift(string&, int); // T takes the string to shift and the number of shift to perform
		string p_8(string,string);	// T
		string x_or(string,string);	// A
		int binary_to_int(string);  // function takes a two bit string and returns an int
		string decimal_to_binary(int); //function takes an int and returns binary.
		void key_gen(string);		// T
		void setkey1(string x) {
			key1 = x;
		}
		void setkey2(string x) {
			key2 = x;
		}
		void setcp(string x) {
			cp = x;
		}

	public:
		bool image_flag = false;
		S_DES();
		~S_DES();

		void readFile(string filename);

		int diffie_Hellman_Exchange();

		void encryptionWrapper(string plaintext, string ten_bit_key7);
		
		void encrypt(string);		// A
		string decrypt();
		void setpt(string x) {
			pt = x;
		}
		string getcp() {
			return cp;
		}
		string charToBinary(char);
		string binaryToChar(string);
		void writeFile(string );
		int fastModExpAlg(string, int, int);
		string decTobin(int);
		void testFastExpo();
};

#endif // !S_DES_H