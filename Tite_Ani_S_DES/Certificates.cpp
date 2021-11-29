#include "Certificates.h"

Certificates::Certificates()
{
	certificate_file = "Certificate.txt";
	system_time = "2021";
	menu();
}

Certificates::~Certificates()
{
}

void Certificates::menu() {
	string option;
	//cout << "Press 1 to Read and Verify a Certificate file or Press 2 to enter values for a certificate or Press q to quit: ";
	//cin >> option;
	while (option != "q") {
		cout << "Press 1 to Read and Verify a Certificate file or Press 2 to enter values for a certificate or Press q to quit: ";
		cin >> option;
		if (option == "1")
			verify_validity();
		else if(option == "2")
		{
			getValues();
			displayCert();
			compare_hash(x.s.certificate_signature, hash);
		}
	}
	
}

cert_fields Certificates::get_file_data()
{
	string filename	, filedata;
	ifstream certificate_inFile;
	// get the certificate file name to read
	cout << "Enter file name: ";
	cin >> filename;
	// check if it exist, if yes then read all input in the file
	certificate_inFile = readFile(filename);
	// count for all 14 required fields for a certificate
	for (int i = 0; i <= 14; i++) {
		// read each file input into filedata then later assign to required certificate field
		certificate_inFile >> filedata;
		// read all required values storing each line of the file in a required field 
		if (i == 0)
			x.version = filedata[0];
		if (i == 1)
			x.serial_number = filedata;
		if (i == 2)
			x.signature_algo_id.algo = filedata;
		if (i == 3)
			x.signature_algo_id.parameters = filedata;
		if (i == 4)
			x.issuer_name = filedata;
		if (i == 5)
			x.period_of_validity.not_before = stoi(filedata);
		if (i == 6)
			x.period_of_validity.not_after = stoi(filedata);
		if (i == 7)
			x.subject_name = filedata;
		if (i == 8)
			x.subject_pk_info.algo = filedata;
		if (i == 9)
			x.subject_pk_info.parameters = filedata;
		if (i == 10)
			x.subject_pk_info.key = filedata;
		if (i == 11)
			x.trust_level = filedata;
		if (i == 12)
			x.s.algo = filedata;
		if (i == 13)
			x.s.parameters = filedata;
		if (i == 14)
			x.s.certificate_signature = filedata;
	}
	return x;
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



void Certificates::compare_hash(string encrypted_hash, string unsigned_hash) {
	
	// convert binary unsign hash to decimal for comparison
	int unsigned_hash_int = stoi(unsigned_hash, 0, 2), signed_hash_int;
	// decrypt the decimal sign hash 
	signed_hash_int = stoi(decryptRSA(encrypted_hash));
	// compare unsigned hash and decrypted signed hash
	if (unsigned_hash_int == signed_hash_int) {
		cout << "Valid Certificate. " << unsigned_hash_int << "  =  " << signed_hash_int << endl;
	}
	else {
		cout << "Invalid Certificate. " << unsigned_hash_int << "  !=  " << signed_hash_int << endl;
	}
	// hash;
}

void Certificates::verify_validity()
{
	cert_fields cert_values;
	string unsigned_hash;
	// read all certificate required field
	cert_values = get_file_data();
	// display certificate fields
	displayCert();
	// generate the hash for verification
	unsigned_hash = generate_hash(cert_values);
	// compare the hash
	compare_hash(cert_values.s.certificate_signature, unsigned_hash);
	// check period of validity
	// while system time is between the before and after validity time frame then certificate is validated
	// determine whether vaild or not
	if (stoi(system_time) < cert_values.period_of_validity.not_before)
		cout << "Certificate not valid yet! System time is below the period of validity " << cert_values.period_of_validity.not_before << " - " << cert_values.period_of_validity.not_after << endl;
	else if (stoi(system_time) > cert_values.period_of_validity.not_after)
		cout << "Certificate is expired! System time is above the period of validity " << cert_values.period_of_validity.not_before << " - " << cert_values.period_of_validity.not_after << endl;
	else 
		cout << "Period of validity validated. System time within the period of validity"<< cert_values.period_of_validity.not_before<< " - "<< cert_values.period_of_validity.not_after << endl;
}

void Certificates::sign_certificate()
{
	cout << "\n Enter signature algorithms id: ";
	cin >> x.s.algo;
	writeFile(x.s.algo, certificate_file);

	cout << "\n Enter signature Parameters: ";
	cin >> x.s.parameters;
	writeFile(x.s.parameters, certificate_file);

	// sign the hash using rsa and store the encrypted hash on the signature field of certificate
	int hash_decimal = stoi(hash, 0, 2);									// Convert hash from binary to decimal for encryption
	string signature_decimal = encryptRSA(to_string(hash_decimal));			// Encrypt the hash in decimal and save to convert into binary if needed
	x.s.certificate_signature = signature_decimal;							// Store decimal sign hash
	writeFile(x.s.certificate_signature, certificate_file);					// write to file

}

cert_fields Certificates::getValues()
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

	cout << "\n Enter algorithm id: ";
	cin >> x.subject_pk_info.algo;
	writeFile(x.subject_pk_info.algo, certificate_file);

	cout << "\n Enter parameters separated with a space: ";
	cin >> x.subject_pk_info.parameters;
	writeFile(x.subject_pk_info.parameters, certificate_file);

	// will be change with the algorithm used to make the public key
	x.subject_pk_info.key = getE();
	cout << "\n Public key is: " << x.subject_pk_info.key;
	//cin >> subject_pk_info.key;
	writeFile(x.subject_pk_info.key, certificate_file);

	cout << "\n Enter trust in bit value: ";
	cin >> x.trust_level;
	writeFile(x.trust_level, certificate_file);
	cout << endl << endl;
	// generate to hash to be signed 
	hash = generate_hash(x);
	// sign the hash
	sign_certificate();

	// return the certificate data with the signature
	return x;
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
	cout << "Signature : " << x.s.algo << "		"<<x.s.parameters<<"		"<< x.s.certificate_signature<< endl;
	cout << "Trust level : " << x.trust_level << endl;
	cout << "-----------------------------------------------------------------------------------------------------------------------" << endl;
}
