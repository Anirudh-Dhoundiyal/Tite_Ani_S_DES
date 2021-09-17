// Tite_Ani_S_DES.cpp : This file contains the 'main' function. Program execution begins and ends there.
/****************************************************************************************************************
*** NAME : 			Tite Divava	& Anirudh Dhoundiyal													  	  ***
*** CLASS : 		CSc 487 																			  	  ***
*** ASSIGNMENT : 	Assignement 1																		  	  ***
*** DUE DATE : 		09/20/2020													   						  	  ***
*** INSTRUCTOR :    Robert Fourney																		  	  ***
*****************************************************************************************************************
*** DESCRIPTION :  	This file contains the 'main' function. Program execution begins and ends there.		  ***
****************************************************************************************************************/

#include <iostream>
#include <string>
using namespace std;

void ip(string);
void fk(string, string);
void sw(string); //switch function
void ip_inverse(string);
void encrypt();
void decrypt();
int main()
{
    std::cout << "Hello World!\n";
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
void ip(string cipher_text)
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
void fk(string, string)
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
void sw(string) 
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
void ip_inverse(string)
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
void encrypt()
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
void decrypt()
{

}
