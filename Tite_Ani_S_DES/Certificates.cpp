#include "Certificates.h"

Certificates::Certificates()
{
	certificate_file = "Certificate.txt";
	getValues();
	hash = generate_hash(x);
	sign_certificate();
	displayCert();
	compare_hash();
}

Certificates::~Certificates()
{
}

void Certificates::sign_certificate()
{
	cout << "\n Enter signature algorithms id: ";
	cin >> s.algo;
	writeFile(s.algo, certificate_file);
	
	cout << "\n Enter signature Parameters: ";
	cin >> s.parameters;
	writeFile(s.parameters, certificate_file);

	// sign the hash using rsa and store the encrypted hash on the signature field of certificate
	int hash_decimal = stoi(hash, 0, 2);									// Convert hash from binary to decimal for encryption
	string signature_decimal = encryptRSA(to_string(hash_decimal));			// Encrypt the hash in decimal and save to convert into binary if needed
	s.certificate_signature = signature_decimal;							// Store decimal sign hash
	writeFile(s.certificate_signature, certificate_file);					// write to file
	
}

string Certificates::generate_hash(cert_fields a)
{
	// adding the CA informations
	string concatinated_info = a.serial_number + a.signature_algo_id.algo + a.signature_algo_id.parameters + a.issuer_name;
	// adding the Rest of user ID information
	concatinated_info += to_string(a.period_of_validity.not_before) + to_string(a.period_of_validity.not_before) + a.subject_name;
	// concatinate the subject's public key information in a string of text
	concatinated_info += a.subject_pk_info.algo + a.subject_pk_info.parameters + a.subject_pk_info.key;
	// send the concatinated string to the function that will hash it
	return cbc_hash(concatinated_info);
}

void Certificates::compare_hash() {
	
	// convert binary unsign hash to decimal for comparison
	int unsigned_hash = stoi(hash, 0, 2), signed_hash;
	// decrypt the decimal sign hash 
	signed_hash = stoi(decryptRSA(s.certificate_signature));
	// compare unsigned hash and decrypted signed hash
	if (unsigned_hash == signed_hash) {
		cout << "Valid Certificate. " << unsigned_hash << "  =  " << signed_hash << endl;
	}
	else {
		cout << "Invalid Certificate. " << unsigned_hash << "  !=  " << signed_hash << endl;
	}
	// hash;
}

void Certificates::getValues()
{
	string certificate_file = "Certificate.txt";
	cout << "Enter certificate version: ";
	cin >> x.version;
	writeFile(x.version + "", certificate_file);

	cout << "\n Enter certificate serial number: ";
	cin >> x.serial_number;
	writeFile(x.serial_number, certificate_file);

	cout << "\n Enter signature algorithm id: ";
	cin >> x.signature_algo_id.algo;
	writeFile(x.signature_algo_id.algo, certificate_file);

	cout << "\n Enter signature algorithm parameters seperated with a space: ";
	cin >> x.signature_algo_id.parameters;
	writeFile(x.signature_algo_id.parameters, certificate_file);

	cout << "\n Enter name of the CA: ";
	cin >> x.issuer_name;
	writeFile(x.issuer_name, certificate_file);

	cout << "\n Enter period of validity. Not before: ";
	cin >> x.period_of_validity.not_before;
	writeFile(to_string(x.period_of_validity.not_before), certificate_file);

	cout << "\n Enter period of validity. Not after: ";
	cin >> x.period_of_validity.not_after;
	writeFile(to_string(x.period_of_validity.not_after), certificate_file);

	cout << "\n Enter the name of the user: ";
	cin >> x.subject_name;
	writeFile(x.subject_name, certificate_file);

	// will be change with the algorithm used to make the public key
	x.subject_pk_info.key = getE();
	cout << "\n Public key is: "<< x.subject_pk_info.key;
	//cin >> subject_pk_info.key;
	writeFile(x.subject_pk_info.key, certificate_file);

	cout << "\n Enter algorithm id: ";
	cin >> x.subject_pk_info.algo;
	writeFile(x.subject_pk_info.algo, certificate_file);

	cout << "\n Enter parameters separated with a space: ";
	cin >> x.subject_pk_info.parameters;
	writeFile(x.subject_pk_info.parameters, certificate_file);

	cout << "\n Enter trust in bit value: ";
	cin >> x.trust_level;
	writeFile(x.trust_level, certificate_file);
	cout << endl << endl;
}

void Certificates::displayCert()
{
	cout << "-----------------------------------------------------------------------------------------------------------------------" << endl;
	cout << "Version : " << x.version << endl;
	cout << "Certificate Serial Number : "	<< x.serial_number << endl;
	cout << "Signature Algo Identifier : " << x.signature_algo_id.algo << "		"<< x.signature_algo_id.parameters<<endl;
	cout << "Issuer Name : " << x.issuer_name << endl;
	cout << "Period of validity : " << x.period_of_validity.not_before << " - " << x.period_of_validity.not_after << endl;
	cout << "Subject Name : " << x.subject_name << endl;
	cout << "Subject's public key info : " << x.subject_pk_info.algo << "			" << x.subject_pk_info.parameters << "			" << x.subject_pk_info.key << endl;
	cout << "Signature : " << s.algo << "		"<<s.parameters<<"		"<< s.certificate_signature<< endl;
	cout << "Trust level : " << x.trust_level << endl;
	cout << "-----------------------------------------------------------------------------------------------------------------------" << endl;
}
