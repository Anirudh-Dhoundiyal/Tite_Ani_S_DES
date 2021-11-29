#pragma once

#ifndef Certificates_H
#define Certificates_H
#include <iostream>
#include<string>
#include "CBC.h"
#include "RSA.h"

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
	string algo,
		parameters;
};
struct signature {
	string algo,
		parameters,
		certificate_signature;
};

struct cert_fields {
	char version;					// version of the certificate
	string serial_number,			// serial number of the certificate
		issuer_name,				// name of certificate authority
		subject_name;				// name of user A
	signature_algo_id signature_algo_id;			// identifier of the algorithm used to sign the certificate
	subjectPkInfo subject_pk_info;			// public key of user A
	Ta period_of_validity;			// period of validity of the certificate
	string trust_level;				// 8 bit field to indicate the trust level of the certificate
};

class Certificates :
	public CBC , public RSA
{
private:
	cert_fields x;
	signature s;
	string hash,
		certificate_file,
		system_time;
	void displayCert();
	void getValues();
public:
	Certificates();
	~Certificates();
	void sign_certificate();
	string generate_hash(cert_fields);
	void compare_hash();
	void verify_validity();
};


#endif // Certificates_H
