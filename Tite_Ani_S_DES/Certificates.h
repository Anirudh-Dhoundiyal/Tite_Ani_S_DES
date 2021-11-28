#pragma once

#ifndef Certificates_H
#define Certificates_H
#include <iostream>
#include<string>
#include "CBC.h"


using namespace std;

struct Ta {
	int not_before,
		not_after;

};
struct subjectPkInfo {
	string algo, 
		parameters,
		key;
};
struct signature_algo_id{
	int algo;
	string parameters;
};

class Certificates :
	public CBC
{
private:
	char version;					// version of the certificate
	string serial_number,			// serial number of the certificate
		issuer_name,				// name of certificate authority
		subject_name,				// name of user A
		signature;
	signature_algo_id signature_algo_id;			// identifier of the algorithm used to sign the certificate
	subjectPkInfo subject_pk_info;			// public key of user A
	Ta period_of_validity;			// period of validity of the certificate
	string trust_level,				// 8 bit field to indicate the trust level of the certificate
			 hash;
	void displayCert();
	void getValues();
public:
	Certificates();
	~Certificates();
	string sign_certificate(string);
	string generate_hash(subjectPkInfo);
	string encrypt();
	string decrypt();
	void compare_hash(string, string);
};


#endif // Certificates_H
