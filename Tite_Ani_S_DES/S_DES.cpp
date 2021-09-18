//including class header file
// Tite_Ani_S_DES.cpp : This file contains the 'main' function. Program execution begins and ends there.
/****************************************************************************************************************
*** NAME : 			Tite Divava	& Anirudh Dhoundiyal													  	  ***
*** CLASS : 		CSc 487 																			  	  ***
*** ASSIGNMENT : 	Assignement 1																		  	  ***
*** DUE DATE : 		09/20/2020													   						  	  ***
*** INSTRUCTOR :    Robert Fourney																		  	  ***
*****************************************************************************************************************
*** DESCRIPTION :  	This file contains the class definition.                		                          ***
****************************************************************************************************************/

#include "S_DES.h"


S_DES::S_DES()
{
}

S_DES::~S_DES()
{
}

void S_DES::key_gen(string)
{
}

/****************************************************************************************
*** FUNCTION < ip >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This function is the initial permutation.  Takws an  >		      ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::ip(string)
{

}       

/****************************************************************************************
*** FUNCTION < fk >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This is the fk function which consists of a combination of        ***
***                 permutation and substitution functions >	        	 		  ***
*** INPUT ARGS :  < String, String>    											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::fk(string, string)
{

}

void S_DES::e_p(string)
{
}

void S_DES::p_4(string, string)
{
}

void S_DES::s0_box(string)
{
}

void S_DES::s1_box(string)
{
}

/****************************************************************************************
*** FUNCTION < sw >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This is the swith function, it interchanges the left and right    ***
***                 4 bits so that the second instance of fK operates on a different  ***
***                 4 bits >                                	        	 		  ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::sw(string)
{

}

/****************************************************************************************
*** FUNCTION < ip_inverse >          											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This is the ip inverse function. It's the second                  ***
***                 permutation and is indeed the reverse of the first                ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::ip_inverse(string)
{

}
void S_DES::p_10(string)
{
}
void S_DES::ls_1(string)
{
}
void S_DES::ls_2(string)
{
}
void S_DES::p_8(string, string)
{
}
void S_DES::x_or(string, string)
{
}
/****************************************************************************************
*** FUNCTION < encrypt >               											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This is encrypt function, it takes an 8 character string and      ***
***                 a 10 character string and produces an 8 character string as       ***
***                 a ciphertext for output                                           ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::encrypt(string)
{
    //  ip(cipher_string);
    //  fk(ip_string, key1);
    //  sw(fk_string);
    //  ip_inverse(sw_string);

}

/****************************************************************************************
*** FUNCTION < decrypt >               											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This is decrypt function. It takes an 8 character string of       ***
***                 ciphertext and the same 10 character string to produce that       ***
***                 ciphertext as input and produces the original 8 character         ***
***                 string of plaintext.                                              ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::decrypt(string)
{

}

