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
string S_DES::ip(string cp)
{
    int ip_pos[8] = { 2, 6, 3, 1, 4, 8, 5, 7};
    string cp_ip;           // hold the ciphertext after the initial permutation
    for (int i = 0; i < 8; i++) {
        // assign the cp_ip string at position i to the cipthertext bit located at 
        // the initial permutation position of ith element in the string ip_pos - 1 since 
        // ciphertext string start from 0 to 7 while the ip_pos goes to 8
        cp_ip[i] = cp[ip_pos[i] - 1];
    }
    return cp_ip;
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

string S_DES::e_p(string x)
{
    int arr[8] = { 4,1,2,3,2,3,4,1 };
    string temp = "";

    for (int i = 0; i < 8; i++) {
       temp += x[arr[i] - 1];
    }
    return temp;
}

string S_DES::p_4(string left, string right)
{
    string temp = "";
    temp += left+right;
    return temp;
}

string S_DES::s0_box(string x)
{
    int s0[4][4] = { {1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2} };
    int row, col, result;
    row = 0;
    col = 0;
    result = 0;
    string temp1 = "";
    string temp2 = "";
    temp1 += x.at(0);
    temp1 += x.at(3);
    temp2 += x.at(1);
    temp2 += x.at(2);
    row = binary_to_int(temp1);
    col = binary_to_int(temp2);
    result = s0[row][col];
    return decimal_to_binary(result);
}

string S_DES::s1_box(string x)
{
    int s0[4][4] = { {0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3} };
    int row, col, result;
    row = 0;
    col = 0;
    result = 0;
    string temp1 = "";
    string temp2 = "";
    temp1 += x.at(0);
    temp1 += x.at(3);
    temp2 += x.at(1);
    temp2 += x.at(2);
    row = binary_to_int(temp1);
    col = binary_to_int(temp2);
    result = s0[row][col];
    return decimal_to_binary(result);

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
string S_DES::sw(string x)
{
    string b;
    b = x.substr(4, 4);
    b += x.substr(0, 4);
    return b;
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
string S_DES::ip_inverse(string)
{
    int ip_invers_pos[8] = { 4, 1, 3, 5, 7, 2, 8, 6 };
    string ip_inv;           // hold the ciphertext after the initial permutation
    for (int i = 0; i < 8; i++) {
        // assign the cp_ip string at position i to the cipthertext bit located at 
        // the initial permutation position of ith element in the string ip_pos - 1 since 
        // ciphertext string start from 0 to 7 while the ip_pos goes to 8
        ip_inv[i] = cp[ip_invers_pos[i] - 1];
    }
    return ip_inv;
}

void S_DES::p_10(string)
{
    int bit_key_pos[10] = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };
    string ip_inv;           // hold the ciphertext after the initial permutation
    for (int i = 0; i <10; i++) {
        // assign the cp_ip string at position i to the cipthertext bit located at 
        // the initial permutation position of ith element in the string ip_pos - 1 since 
        // ciphertext string start from 0 to 7 while the ip_pos goes to 8
        ip_inv[i] = cp[bit_key_pos[i] - 1];
    }
    shift(ip_inv.substr(0, 4), ip_inv.substr(5, 9));
}

void S_DES::shift(string left_bit, string right_bit)
{
    left_shift(left_bit, 1);    // LS-1
    left_shift(right_bit,1);    // LS-1
}
void S_DES::left_shift(string bits, int spos)
{
    int n = bits.size();
    string temp;
    // copy strings from spos position to the end of the temp string 
    // by using the total strings remove the amount of shift performed
    temp = bits.substr(spos, n - spos);
    // copy the rest left out from begining to shift position to the end of temp string
    temp += bits.substr(0, spos);

}
void S_DES::p_8(string, string)
{
}
void S_DES::x_or(string, string)
{
}
int S_DES::binary_to_int(string binary)
{
    int decimal =0;
    
    if (binary.at(0) == '0') {
        if (binary.at(1) == '0') {
            decimal = 0;
            return decimal;
        }
        else {
            decimal = 1;
            return decimal;
        }
    }
    else
    {
        if (binary.at(1) == '0') {
            decimal = 2;
            return decimal;
        }
        else {
            decimal = 3;
            return decimal;
        }
    }

    return decimal;
}
string S_DES::decimal_to_binary(int x)
{
    string cmp_arr[4] = { "00","01","10","11" };
    string result = "";
    result = cmp_arr[x];
    return result;
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

