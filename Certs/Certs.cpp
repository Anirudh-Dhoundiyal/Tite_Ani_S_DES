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
#include "Client.h"
#include "Server.h"


//main
int main()
{
    cout << "Enter 1 for server" << endl;
    cout << "Enter 2 for client"<< endl;
    
    int select = 0;

    cin >> select;
    if(select == 1){
        Server server;
    }
    else if( select = 2){
    Client client;
    }
    
    //Certificates certs;
  
    return 0;
}
