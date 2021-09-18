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
	string cp, pt, key1, key2;
	// functions
	void ip(string);
	void fk(string, string);
	void e_p(string);
	void p_4(string, string);
	void s0_box(string);
	void s1_box(string);
	void sw(string); //switch function
	void ip_inverse(string);
	void p_10(string);
	void ls_1(string);
	void ls_2(string);
	void p_8(string,string);
	void x_or(string,string);
public:
	S_DES();
	~S_DES();
	void key_gen(string);
	void encrypt(string);
	void decrypt(string);
};

#endif // !S_DES_H