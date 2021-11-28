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
#pragma warning(disable : 4996)
//libraries 
#include <iostream>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
#include <math.h>
#include <stdio.h>

using namespace std;

bitset<8> InitialPerm(bitset<8> byte);
bitset<8> Reverse(bitset<8> byte);
char getChar(bitset<8> byte);
bitset<4> functionF(bitset<8> byte, bitset<8> key);
bitset<8> Expansion(bitset<4> byte);
bitset<8> XOR(bitset<8> first, bitset<8> second);
bitset<4> SBoxes(bitset<8> byte);
int conversionToInt(int one, int two);
bitset<2> conversionToBin(int num);
bitset<4> P4(bitset<4> halfByte);
bitset<8> LRSwaped(bitset<8> byte, bitset<4> right);
bitset<4> XOR4(bitset<4> first, bitset<4> second);
bitset<8> FinalPerm(bitset<8> byte);
int binaryToInt(bitset<8> binary);
void printByte(bitset<8> byte);






//including class header
#include "S_DES.h"
//function declarations
void image_function();
string unsignedChartoBinary(unsigned char);
string x_or(string, string);
string sw(string);
string cbc_hash();
ifstream readFile(string filename);
string get_SDES_Key();

bool CBC = false;
bool hashFlag = false;

// SDES Object global 
S_DES cypher;
//main
int main()
{
    string fileName = "Plaintext.txt";

    int option = 0;
    cout << "Enter 1 to encrypt a File, Enter 2 To encrypt a Image, Enter 3 for image CBC, Enter 4 for hash CBS ";
    cin >> option;
    cin.ignore();
    if (option == 1) {
        cypher.readFile(fileName);
    }
    else if (option == 2 )
    {
        image_function();
    }
    else if (option == 3)
    {
        CBC = true;
        image_function();
    }
    else if (option == 4)
    {
        CBC = true;
        hashFlag = true;
        string hash = cbc_hash();
        //image_function();
        cout << "The hash is now " << hash << " " << endl;
    }
}

string cbc_hash() {
    // Initiale value
    int iv = 3;
    bool CBC_firstPass = false;
    string fileName = "Plaintext.txt";
    string plaintext_character,
        initial_vector,
        temp,
        input_block, 
        k;
    // get s-des key for encryption 
    k = get_SDES_Key();

    cypher.image_flag = true;
    // convertion of IV to plaint text block size
    temp += cypher.decTobin(iv);
    int count = 8 - temp.size();
    while (count > 0) {
        initial_vector += '0';
        count--;
    }
    initial_vector += temp ;

    // read the file
    ifstream inFile = readFile(fileName);
    
    // get plain text from it 
    while (inFile >> plaintext_character) {
        // for each plaintext block encrypt every character at a time
        for (int i = 0; i < plaintext_character.size(); i++) {
            if (hashFlag) {
                // after pass one do this
                // Exclusive-or current plaintext block with previous ciphertext block
                // Hi = E (Mi, Hi-1) 
                if (CBC_firstPass) {
                    input_block = "";
                    input_block = cypher.getcp();       // get previous cipher block
                    input_block = x_or(unsignedChartoBinary(plaintext_character[i]), input_block);      // exclusive-or current plain text character with the previous cipher block
                    input_block += "01";        // add padding 
                    cypher.encryptionWrapper(unsignedChartoBinary(plaintext_character[i]), k);      // encrypt output of the exclusive-or 
                }
                else
                {
                    input_block = x_or(unsignedChartoBinary(plaintext_character[i]), initial_vector);      // exclusive-or current plain text character with the previous cipher block
                    // get the initial value h0
                    cypher.encryptionWrapper(input_block, k);
                    CBC_firstPass = true;
                }
            }
        }
    }
    // close file once done 
    inFile.close();
    // get the hash value of the file
    // G = Hn
    string hash = cypher.getcp();

    return hash;
}

string get_SDES_Key()
{
    string ten_bit_key;
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
    return ten_bit_key;
}

ifstream readFile(string filename) {
    ifstream inFile;
    string plaintext,
        ten_bit_key;
    inFile.open(filename);

    // if file not found display message
    if (!inFile) {
        cerr << "File not found: " << filename << endl;
    }
    else {
        return inFile;
    }
}

void image_function() {
    bool CBC_firstPass = false;
    cypher.image_flag = true;
    bool numInput = false;
    bool decrypt = false;
    string temp;
    string fileName = "normal.bmp";
    string outputName = "cypher.bmp";
    string dOrE = "";
    string tempKey = "";
    cout << "Enter 10-bit Key for encryption and decryption : ";
    cin >> tempKey;

    if (decrypt == true)
    {
        cout << endl << "Decrypting " << fileName << endl;
    }
    else
        cout << endl << "Encrypting " << fileName << endl;


    FILE* picture;
    FILE* cypherImg;

    cypherImg = fopen(outputName.c_str(), "wb");

    if (!(picture = fopen(fileName.c_str(), "rb")))
    {
        cout << fileName << " is missing program will now exit" << endl;
        return;

    }

    unsigned char header[54];

    //Reading the header
    fread(header, sizeof(unsigned char), 54, picture);

    //getting picture stats
    int width = *(int*)&header[18];
    int height = *(int*)&header[22];
    //Need this to support multiple BMP types
    short int bitPerPixel = *(short int*)&header[28];
    int multiplier = bitPerPixel / 8;

    int headerSize = *(int*)&header[14];

    //Dealing with Padding Rules
    if (width % 4 != 0)
    {
        width = width + (4 - (width % 4));
    }

    int size = multiplier * width * height;
    unsigned char* pixelData = new unsigned char[size];


    //Reading Pixel Data
    fread(pixelData, sizeof(unsigned char), size, picture);
    fclose(picture);
    fwrite(header, sizeof(unsigned char), 54, cypherImg);
    
    for (int i = 0; i < size; i++) {
        if (CBC) {
            if (CBC_firstPass) {
                string cbc_key = "";
                cbc_key = cypher.getcp();
                cbc_key = x_or(unsignedChartoBinary(pixelData[i]), cbc_key);
                cbc_key += "01";
                cypher.encryptionWrapper(cbc_key, tempKey);
                temp += cypher.binaryToChar(cypher.getcp());
            }
            else
            {
                cypher.encryptionWrapper(unsignedChartoBinary(pixelData[i]), tempKey);
                temp += cypher.binaryToChar(cypher.getcp());
                CBC_firstPass = true;
            }
        }
        else {
            cypher.encryptionWrapper(unsignedChartoBinary(pixelData[i]), tempKey);
            temp += cypher.binaryToChar(cypher.getcp());
        }

        if (hashFlag) {
            // if the hash flag is on keep the last cipher text as the hash value 
            string hash = cypher.getcp();
        }
    }
    unsigned char* cypherData = (unsigned char*)temp.c_str();
    fwrite(cypherData, sizeof(unsigned char), size, cypherImg);

    fclose(cypherImg);
}

//Reference: https://stackoverflow.com/questions/58052458/how-to-convert-unsigned-char-to-binary-representation

string unsignedChartoBinary(unsigned char letter )
{
    string temp;
    int binary[8];
    for (int n = 0; n < 8; n++)
        binary[7 - n] = (letter >> n) & 1;
    
    for (int n = 0; n < 8; n++)
    temp += to_string(binary[n]);


    return temp;
}

string x_or(string value1, string k1)
{
    string result;
    // loop through the value to exclusive-OR
    value1 = sw(value1);
    k1 = sw(k1);
    for (int i = 0; i < value1.size(); i++) {
        if (value1[i] == k1[i])
            result += '0';
        else
            result += '1';
    }
    sw(result);
    return result;
}
string sw(string x)
{
    string b;
    b = x.substr(4, 4);
    b += x.substr(0, 4);
    return b;
}