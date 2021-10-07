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
//function declarations

string decTobin(int n) {
    // hold the value of the binary string after convertion to be returned 
    string binary = "";

    // do this while n is positive, until the remainder is 0
    while (n > 0) {
        // get the remainder of n divided by 2
        binary += to_string(n % 2);
        // get the new result of n
        n = n / 2;
    }
    return binary;
}

void testFastExpo(S_DES cyph) {
    // a ^ b mod n 
    int a, b, n, result;
    string binary;
    cout << "Enter a --> ";
    cin >> a;
    cout << endl <<"Enter b --> ";
    cin >> b;
    cout << endl << "Enter n --> ";
    cin >> n;
    // convert b to binary then assign to binary string  
    binary = decTobin(b);
    // send binary string, a and n to calculate the fast modular of a to the power of b modular n
    // by using the binary string,  the integer a and the modular number
    // return the result 
    result = cyph.fastModExpAlg(binary, a, n);
    cout << endl << a << " ^ " << b << " mod " << n << " = "<< result << endl;
}
//main
int main()
{
    string fileName = "Plaintext.txt";
    S_DES cypher;
    testFastExpo(cypher);
    //cypher.readFile(fileName);
}
