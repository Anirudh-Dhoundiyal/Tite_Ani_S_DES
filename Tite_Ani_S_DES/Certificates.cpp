#include "Certificates.h"

Certificates::Certificates()
{
	getValues();
}

Certificates::~Certificates()
{
}

void Certificates::getValues()
{
	cout << "Enter certificate version ";
	cin >> version;
	cout << "\n Enter certificate serial number ";
	cin >> serial_number;
	cout << "\n Enter signature algorithm id ";
	cin >> signature_algo_id.algo;
	cout << "\n Enter signature algorithm parameters seperated with a space ";
	cin >> signature_algo_id.parameters;
	cout << "\n Enter name of the CA ";
	cin >> issuer_name;
	cout << "\n Enter period of validity. Not before ";
	cin >> period_of_validity.not_before;
	cout << "\n Enter period of validity. Not after ";
	cin >> period_of_validity.not_after;
	cout << "\n Enter the name of the user ";
	cin >> subject_name;
	// will be change with the algorithm used to make the public key
	cout << "\n Enter public key ";
	cin >> subject_pk_info.key;
	cout << "\n Enter algorithm id";
	cin >> subject_pk_info.algo;
	cout << "\n Enter parameters separated with a space";
	cin >> subject_pk_info.parameters;
	cout << "\n Enter trust in bit value";
	cin >> trust_level;
	cout << endl << endl;
}

void Certificates::displayCert()
{
	cout << "-------------------------------------------------------------------------------------------------------------" << endl;
	cout << "Version : " << version << endl;
	cout << "Certificate Serial Number : "	<< serial_number << endl;
	cout << "Signature Algo Identifier : " << signature_algo_id.algo
		<< endl << "		"
		<< signature_algo_id.parameters<<endl;
	cout << "Issuer Name : " << issuer_name << endl;
	cout << "Period of validity : " << period_of_validity.not_before << " - " << period_of_validity.not_after << endl;
	cout << "Subject Name : " << subject_name << endl;
	cout << "Subject's public key info : " << subject_pk_info.algo << endl
		<< "			" << subject_pk_info.parameters << endl
		<< "			" << subject_pk_info.key << endl;
	cout << "Trust level : " << trust_level << endl;
	cout << "-------------------------------------------------------------------------------------------------------------" << endl;
}
