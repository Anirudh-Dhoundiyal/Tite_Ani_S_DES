// Tite_Ani_S_DES.cpp : This file contains the 'main' function. Program execution begins and ends there.
/****************************************************************************************************************
*** NAME : 			Tite Divava	& Anirudh Dhoundiyal													  	  ***
*** CLASS : 		CSc 487 																			  	  ***
*** ASSIGNMENT : 	Assignement 3																		  	  ***
*** DUE DATE : 		11/29/2021													   						  	  ***
*** INSTRUCTOR :    Robert Fourney																		  	  ***
*****************************************************************************************************************
*** DESCRIPTION :  	This file contains the 'main' function. Program execution begins and ends there.		  ***
****************************************************************************************************************/
#pragma warning(disable : 4996)
//libraries 
#include <iostream>
#include <stdio.h>
#pragma warning(suppress : 4996)

using namespace std;

//including class header
#include "CBC.h"
#include "Certificates.h"
//#include "Server.h"
//#include "Client.h"

//main
int main()
{
    Certificates certs;

    string hash, input, ehash;
    while (input != "q") {
        
        cout << "Enter string to hash: ";
        cin >> input;

        hash = certs.cbc_hash(hash);

        cout << "HAsh is now: " << hash << endl;
        ehash = certs.encryptRSA(hash);
        cout << "Encrypting the hash " << hash << " intp --> " << ehash << endl;
        ehash = certs.decryptRSA(ehash);
        cout << "Decrypting the hash " << ehash << " Into --> " << ehash << endl << endl;
    }
  

}
