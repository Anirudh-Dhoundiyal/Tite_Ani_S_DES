#pragma once
#ifndef RSA_H
#define RSA_H
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include<string>
#include <iostream>

using namespace std;

class RSA
{
private:
	int p = 0; //prime number one
	int q = 0; //prime two
	int n = 0; // p*q
	int ntot = 0; //totient of n
	int e = 0; //public key pair (n, e)
	int d = 0; // private key pair (n, d)
	int cnum = 0; // enrypted num
	int pnum = 0; // plain num


public:

#pragma region Function Declarations

	int getInverse(int, int);
	int getRPrime();
	int extendGcd(int, int, int*, int*);
	void Setup();
	void setP(int);
	void setQ(int);
	void setN(int);
	void setNtot(int);
	void setE(int);
	string getE();
	string getD();
	void setD(int);
	void setCNum(int);
	void setPNum(int);
	string encryptRSA(string);
	string decryptRSA(string);
	string dectobinary(int);
	int FastModExpAlgo(int, int, int);
	void print_values();
	string rsa_signature_e(string);
	string rsa_signature_d(string, string);
#pragma endregion

#pragma region Constructor
	RSA() {
		Setup(); // sets up the p and q
		setD(getRPrime()); // sets up d
		print_values();
		//encrypt();
		//decrypt();
	}

#pragma endregion
};

#endif
