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

//libraries 
#include <iostream>

//including class header
#include "S_DES.h"


int main()
{
    string temppt;
    string tempkey;
    S_DES cypher;
    cout << "Please enter your plain text: ";
    cin >> temppt;
    cout << " " << endl;
    cypher.setpt(temppt);
    

    cout << "please enter your key: ";
    cin >> tempkey;
    cout << " " << endl;
    cypher.encrypt(tempkey);
    
    cout << "The Cypher Text is: ";
    cout << cypher.getcp() << endl;

    cout << "The plain text is: ";
    cout << cypher.decrypt() << endl;





}   
