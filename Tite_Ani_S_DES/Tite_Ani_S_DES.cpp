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
void writeFile(string);
void readFile(string, S_DES);
void encryptionWrapper(string, string, S_DES);
string charToBinary(char);
string BinaryToChar(string);




//main
int main()
{
    string temppt;
    string tempkey;
    string fileName = "Plaintext.txt";
    S_DES cypher;
    readFile(fileName, cypher);



}




void writeFile(string cyphertext) {

    ofstream outFile;
    outFile.open("CipherText.txt", ios_base::app);
    outFile << cyphertext << endl;
    outFile.close();
}

/****************************************************************************************
*** FUNCTION < readFile >          											  	      ***
*****************************************************************************************
*** DESCRIPTION : < This function is the read file function. It reads a txt file which **
***                 contains all the plain text. For each plaintext it encrypts, then ***
***                 diplay cypher text, then decrypt the cypher text and displays it. ***
***                 It takes the file name and the Simple DES class object >          ***                               ***
*** INPUT ARGS :  < String, S_DES >             								  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void readFile(string filename, S_DES cypher) {

    ifstream inFile;
    string plaintext,
        ten_bit_key;
    inFile.open(filename);

    // if file not found display message
    if (!inFile) {
        cerr << "File not found: " << filename << endl;
    }
    else {
        // get 10-bit key from user 
        cout << "Enter 10-bit Key for encryption and decryption : ";
        cin >> ten_bit_key;
        //cypher.setpt(ten_bit_key);
        // if key is too short or too long prompt key one more time
        while (ten_bit_key.size() != 10) {
            cerr << "Error. Key must be a 10 bit key" << endl;
            cin.ignore();
            cin.clear();
            cin >> ten_bit_key;
        }
        // keep getting plaintext from file while not at the end of file
        while (inFile >> plaintext) {

            for (auto i : plaintext) {

                encryptionWrapper(charToBinary(i), ten_bit_key, cypher);
            }


            
        }

    }
}

string charToBinary(char c)
{
    string result = "0";
    string r;
    int n = int(c);
    while (n != 0) { r = (n % 2 == 0 ? "0" : "1") + r; n /= 2; }
    result += r;
    return result;
}
string BinaryToChar(string decrypted_str) {




}


void encryptionWrapper(string plaintext, string ten_bit_key, S_DES cypher)
{
    // process current plaintext being read
    cypher.setpt(plaintext);
    // encrypt the plaintext using the ten_bit_key to create the encryption key
    cypher.encrypt(ten_bit_key);
    // Display the cypher text
    writeFile(cypher.getcp());
    // Decrypt then display the original plaintext
    cout << "The decrypted plain text is: ";

    cout << BinaryToChar(cypher.decrypt()); //added a functiong to send char
}
