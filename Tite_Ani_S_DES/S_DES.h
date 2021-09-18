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
		// functions declaration
		void ip(string);			// T
		void fk(string, string);	// A
		void e_p(string);			// A
		void p_4(string, string);	// A
		void s0_box(string);		// A
		void s1_box(string);		// A
		void sw(string);			//switch function	A
		void ip_inverse(string);	// T
		void p_10(string);			// T
		void shift(string, string);	// A
		void ls_1(string);			// T
		void ls_2(string);			// T
		void p_8(string,string);	// T
		void x_or(string,string);	// T
	public:
		S_DES();
		~S_DES();
		void key_gen(string);		// T	
		void encrypt(string);		// A
		void decrypt(string);		// A
};

#endif // !S_DES_H