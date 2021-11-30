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

using namespace std;

//including class header
#include "CBC.h"
#include "Certificates.h"
#include "Server.h"
#include "Client.h"

//main
int main()
{
    cout << "press 1 to start client, press 2 to start server" << endl;
    int option = 0;
    cin >> option;
    if(option ==1){
        Client client;
    }
    else{
        Server server;
    }
    //CBC x;
    //x.cbc_menu();
    Certificates certs;
    //certs.va
}
