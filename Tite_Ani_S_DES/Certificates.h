#pragma once

#ifndef Certificates_H
#define Certificates_H
#include <iostream>
#include<string>
#include "CBC.h"
#include "RSA.h"
#include <vector>
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
	string version,							// version of the certificate
		serial_number,						// serial number of the certificate
		issuer_name,						// name of certificate authority
		subject_name;						// name of user A
	signature_algo_id signature_algo_id;	// identifier of the algorithm used to sign the certificate
	subjectPkInfo subject_pk_info;			// public key of user A
	Ta period_of_validity;					// period of validity of the certificate
	string trust_level;						// 8 bit field to indicate the trust level of the certificate
	signature s;							// signature
};

struct cert_revo_list_fields {
	signature_algo_id sign_algo_id;
	string issuer_name,
		this_data_date,
		next_update_date;
	vector<string>	revoked_certificates;
	signature crl_s;
};

class Certificates :
	public CBC , public RSA
{
private:
	cert_fields x;
	cert_revo_list_fields crl;
	string hash,
		certificate_file,
		system_time;
	void displayCert();
	cert_fields getValues();
public:
	Certificates();
	~Certificates();
	void sign_certificate();
	string generate_hash(cert_fields);
	void compare_hash(string, string);
	void verify_validity();
	void menu();
	cert_fields get_file_data();
};


#endif // Certificates_H
