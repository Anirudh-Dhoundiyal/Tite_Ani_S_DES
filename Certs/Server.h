#pragma once
#ifndef SERVER_H
#define SERVER_H

//#include<arpa/inet.h>	//inet_addr
//#include<unistd.h>		//write
#include<stdlib.h>	
#include <stdio.h>
#include<string.h>	
#include <iostream>
#include "Certificates.h"

using namespace std;

class Server {
private:
	int e,	// RSA public key
		d,
		n,	// RSA n
		g,	// Diffie Parameter (Generator) 
		q;	// DH Parameter
				// Store element of the cert
	cert_fields a;
	char * iencli_message;
public:
	/*Server(char* m) {
		e = 0;
		d = 0;
		n = 0;
		g = -1;
		q = -1;
		iencli_message = (char*)malloc(100 * sizeof(char));
		strcpy (iencli_message,m);
		server();
		strcpy(m, iencli_message);
	}*/
	Server() {
		e = 0;
		d = 0;
		n = 0;
		g = -1;
		q = -1;
		server();
	}


	int modExpo(int x, int y, int p)
	{
		int res = 1;     // Initialize result

		x = x % p; // Update x if it is more than or
					// equal to p

		if (x == 0) return 0; // In case x is divisible by p;

		while (y > 0)
		{
			// If y is odd, multiply x with result
			if (y & 1)
				res = (res * x) % p;

			// y must be even now
			y = y >> 1; // y = y/2
			x = (x * x) % p;
		}
		return res;
	}
	void printFastModTable(int i, char bt, int c, int f)
	{
		printf("%d\t\t %c\t\t %d\t\t %d\t\t\n", i, bt, c, f);

	}

	string decToBin(int decimal)
	{
		// hold the value of the binary string after convertion to be returned 
		string binary = "";

		// do this while n is positive, until the remainder is 0
		while (decimal > 0) {
			// get the remainder of n divided by 2
			binary += to_string(decimal % 2);
			// get the new result of n
			decimal = decimal / 2;
		}

		return binary;
	}

	int fastModExpAlg(int exponent, int a, int n) {

		string binary = decToBin(exponent);
		int c = 0,
			f = 1;
		for (int i = binary.size() - 1; i >= 0; i--) {
			// 
			c = 2 * c;
			f = (f * f) % n;
			// Check that the binary digit at position i is 1 to perform ...
			if (binary[i] == '1') {
				c = c + 1;
				f = (f * a) % n;
			}
		}
		return f;
	}

	string exec_command(char * client_command) {
		char buffer[128];
		string result;
		//std::shared_ptr<FILE> pipe(_popen(client_command, "r"), _pclose);
		FILE* pipe = _popen(client_command, "r");
		if (pipe) {
			while (!feof(pipe)) {
				// use buffer to read and add to result
				if (fgets(buffer, 128, pipe) != NULL)
					result += buffer;
			}
			_pclose(pipe);
		}
		else {
			printf("popen failed!");
		}
		
		memset(client_command, '\0', 100);
		strcpy(client_command, result.c_str());
		
		printf("\n\n");
		return result;
	}
	int server() {
		int socket_desc, new_socket, c, read_size, i, comKey = -1, pKserver, gPKserver, gPKclient, keyReceived, signedKey;
//		struct sockaddr_in server, client;
		char* message, client_message[100], *convert;
		Certificates certs; 
		char *list;
		string input;
		list = (char*)malloc(10 * sizeof(char));
		convert = (char*)malloc(10 * sizeof(char));
		bool authentification = false;
		bool login = false;
		strcpy(list, "ls -l\n");

		char* found, convertS[15] = "\0";
		/******************************************************************************************************************
		//Create socket
		socket_desc = socket(AF_INET, SOCK_STREAM, 0);
		if (socket_desc == -1)
		{
			printf("Could not create socket");
		}// End of if
		
		//Prepare the sockaddr_in structure
		server.sin_family = AF_INET;
		server.sin_addr.s_addr = INADDR_ANY;
		server.sin_port = htons(8421);                 // Random high (assumed unused) port

		//Bind
		if (::bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
		{
			printf(" unable to bind\n");
			return 1;
		}
		printf(" socket bound, ready for and waiting on a client\n");

		//Listen
		listen(socket_desc, 3);

		//Accept incoming connection
		printf(" Waiting for incoming connections... \n");

		c = sizeof(struct sockaddr_in);
		new_socket = accept(socket_desc, (struct sockaddr*)&client, (socklen_t*)&c);
		if (new_socket < 0)
		{
			perror("accept failed");
			return 1;
		}// End of if

		printf("Connection accepted\n");

		//Reply to the client
		message = "You have located Server X at our undisclosed location.  What would you like to say?\n";
		write(new_socket , message , strlen(message));
		******************************************************************************************************************/
		
		//Receive a message from client************************************************
		//while ((read_size = recv(new_socket, client_message, 100, 0)) > 0)
		//*************************************
		// TESTABILITY switched the two while 
		// Assuming the client sent this message, Process it 
		strcpy(client_message, iencli_message);
		read_size = 100;
 
		//while(!strncmp(client_message, "-1", 2))
		//{
			printf("\n Client sent %2i byte message:  %.*s\n", read_size, read_size, client_message);

			
			// Check what instructions have been sent
			//***************************************************************************
			// Receive the Certificate values as a string in client message

			//int init_size = strlen(message);
			// allocate space
			//found = (char*)malloc(strlen(message) + 1);
			found = (char*)malloc(strlen(client_message) + 1);
			// Get the first string in the client message
			found = strtok(client_message, " ");
			//************************TEST**************************//
			cout << "First character in the message is " << found << endl;

			// Case 1 M or m for sending the message to server possibly decrypting before sending then receive encrypted message then decrypt it if instruction is M or m and display the decrypted on the server comparing to original message from client
			// Case 2 K or k for sending the key and requesting key from server
			// Case 3 To process Certificate! 
			if (authentification == true) {
				if (strcmp(found, "P") == 0 || strcmp(found, "p") == 0) {
					found = strtok(NULL, " ");
					string user = found;
					found = strtok(NULL, " ");
					string password = found;	
					fstream inFile;
					inFile.open("client_user.txt");
					string stored_user;
					string stored_pass;
					inFile >> stored_user >> stored_pass;
					stored_pass = certs.cbc_hash(stored_pass, comKey);
					if(user == stored_user && password == stored_pass){
							login = true;
							cout << "Password Validated. User and Password from client" << user << password << " match the ones in file " << stored_pass << " " << stored_pass << endl;
							strcpy(client_message, "L");
					}
					else {
						cout << "User Or Password Incorect." << endl;
					}
					
				}// End of if
				if(login = true){
					
					string result;
					if (strcmp(found, "C") == 0 || strcmp(found, "c") == 0) {
						found = strtok(NULL, " ");

						if (!strncmp(found, "ls", 6))
						{
							printf("\nFiles in this directory: \n");
							result = exec_command(client_message);
						}// End of if
						else if(!strncmp(found, "touch", 5)){
							char *touch ;
							touch = (char*)malloc(strlen(client_message) + 1);
							strcpy(touch, "touch \n");
							found = strtok(NULL, " ");
							strcat(touch, found);
							printf("\n Making new File \n");
							system(touch);
							printf("\n\n");
						}

					}
				}
			}
			else if(!strncmp(found, "-1", 2)) {
			
				if (authentification == false) {
					// while not at the end of the file do this
					found = strtok(NULL, " ");
					a.version = found;
					certs.writeFile(a.version, "client_certs.txt");

					// Get next string
					found = strtok(NULL, " ");
					a.serial_number = found;
					certs.writeFile(a.serial_number, "client_certs.txt");
					//
					found = strtok(NULL, " ");
					a.signature_algo.algo = found;
					certs.writeFile(a.signature_algo.algo, "client_certs.txt");

					found = strtok(NULL, " ");
					a.signature_algo.parameters = found;
					certs.writeFile(a.signature_algo.parameters, "client_certs.txt");

					found = strtok(NULL, " ");
					a.issuer_name = found;
					certs.writeFile(a.issuer_name, "client_certs.txt");

					found = strtok(NULL, " ");
					a.period_of_validity.not_before = stoi(found);
					certs.writeFile(to_string(a.period_of_validity.not_before), "client_certs.txt");

					found = strtok(NULL, " ");
					a.period_of_validity.not_after = stoi(found);
					certs.writeFile(to_string(a.period_of_validity.not_after), "client_certs.txt");

					found = strtok(NULL, " ");
					a.subject_name = found;
					certs.writeFile(a.subject_name, "client_certs.txt");

					found = strtok(NULL, " ");
					a.subject_pk_info.algo = found;
					certs.writeFile(a.subject_pk_info.algo, "client_certs.txt");

					found = strtok(NULL, " ");
					a.subject_pk_info.parameters = found;
					certs.writeFile(a.subject_pk_info.parameters, "client_certs.txt");

					found = strtok(NULL, " ");
					a.subject_pk_info.key = found;
					certs.writeFile(a.subject_pk_info.key, "client_certs.txt");

					found = strtok(NULL, " ");
					a.s.algo = found;
					certs.writeFile(a.s.algo, "client_certs.txt");

					found = strtok(NULL, " ");
					a.s.parameters = found;
					certs.writeFile(a.s.parameters, "client_certs.txt");

					found = strtok(NULL, " ");
					a.s.certificate_signature = found;
					certs.writeFile(a.s.certificate_signature, "client_certs.txt");

					// DH Signed Parameters from client 
					string gS,			// Signed G by client for DH
						qS, 			// Signed Q by client for DH
						nS,				// Signed N by client for RSA Decryption to be used with public key
						gPKS;
					found = strtok(NULL, " ");
					gS = found;
					found = strtok(NULL, " ");
					qS = found;
					found = strtok(NULL, " ");
					nS = found;
					found = strtok(NULL, " ");
					gPKS = found;
					//***************************************************************************
					// Now authenticate the certs
					string unsigned_hash = certs.generate_hash(a),
						signed_hash;
					int	unsigned_hash_dec,
						signed_hash_dec;
					// Convert hash from binray to decimal for comparison
					unsigned_hash_dec = stoi(unsigned_hash, 0, 2);
					// Decrypt the signature then compare to unsigned hash
						// Set the public key found on the certificate
					certs.setE(stoi(a.subject_pk_info.key));
					// Set n
					certs.setN(stoi(nS));

					// get the public key and totient to calculate the private key
					int public_key = stoi(certs.getE()),
						totient = stoi(certs.getNtot());

					// decrypt 
					signed_hash = certs.decryptRSA(a.s.certificate_signature);
					signed_hash_dec = stoi(signed_hash);
					// Display
					if (unsigned_hash_dec == signed_hash_dec) {
						authentification = true;
						cout << "Certificate Hash validated. Decrypted signature: " << signed_hash << " Match Unsigned Hash: " << unsigned_hash_dec << endl;
						//***************************************************************************
						// Decrypt G Q and N using the certs public key for authentification 
						// After authentification Set g and q for DH
						g = stoi(certs.decryptRSA(gS));
						q = stoi(certs.decryptRSA(qS));
						gPKclient = stoi(certs.decryptRSA(gPKS));
						cout << "G Q and GPKClient: " << g << "  " << q << "  " << gPKclient << endl;
						cert_fields temp;				// hold the value for sever certificate

						bool iscorrect = false;
						while (!iscorrect) {
							cout << "Enter 1 to generate a cert or 2 to Read a cert file: ";
							cin >> input;
							if (input == "1") {
								// Generate the server certificate
								temp = certs.generate_cert_sign_request();
								certs.generate_signature();
								temp = certs.getX();
								iscorrect = true;
							}
							else if (input == "2") {
								temp = certs.get_file_data();
								iscorrect = true;
							}
						}

						// get public and private key of cert for RSA Encryption
						certs.get_priv_k(temp.subject_name);
						e = stoi(certs.getE());
						d = stoi(certs.getD());
						n = stoi(certs.getN());

						// Send back to server Certificate in the client message
						// With Certificate add K to request their generated g ^ privateKey mod q
						string data = certs.generate_sendstring(temp);
						//strcat(client_message, data.c_str());
						// Generate G ^ pka mod q
						// Ask user to enter their Diffie-Hellmen private key 
						printf("\nEnter server DH Private key --> ");
						scanf("%d", &pKserver);
						// Generate a key using server private key and g ^ pka mod q		
						gPKserver = modExpo(g, pKserver, q);

						// Display private key and generated private key
						printf("\nYour Private Key is %d and your Generated Key is %d\n\n", pKserver, gPKserver);
						// Generate Shared Secret
						comKey = fastModExpAlg(pKserver, gPKclient, q);
						cout << "After receiving client generated key: " << gPKclient << " Shared Common key to use for S_DES encryption and decryption: " << comKey << endl;

						// Convert to character
						//sprintf(convert, "%d", gPKserver);
						// add the instruction flag to the client message
						strcpy(client_message, "k");
						// add space
						strcat(client_message, " ");
						// copy certificate to be sent over to the server
						strcat(client_message, data.c_str());
						int signedGPK;
						// sign generated key with server RSA private 
						signedGPK = fastModExpAlg(d, gPKserver, n);
						// add the generated key
						sprintf(convert, "%d", signedGPK);
						strcat(client_message, convert);
						// Send the generated key

					}
					else {
						cout << "Certificate Hash not Valid. Decrypted signature: " << signed_hash << " Do no match unsigned hash: " << unsigned_hash << endl;
						strcpy(client_message, "I");
						authentification = false;
					}
				}
				

					//********************TESTABILITY
					strcpy(iencli_message, client_message);


				// wait to receive the generated from client
				//	Use the generated key to create the Shared secret key for DH
				//	Use shared secret key to communicate   

				//  Allow the authenticated remote user to execute a few select commands on the remote server 

				// view the results on the client. 

				// All communication to and from the server are encrypted (using S-DES and either of the keys established in Part 1. 

				// send private key produced 
				// write(new_socket, client_message, read_size);
			}// End of if
			/************************************************************************
			//write(new_socket, client_message , strlen(client_message));
			write(new_socket, client_message, read_size);
			*************************************************************************/
		//}// End of while

		if (read_size == 0)
		{
			printf("client disconnected\n");
			fflush(stdout);
		}// End of if
		else if (read_size == -1)
		{
			perror("receive failed");
		}// End of else

		//Free the socket pointer
		//*************************************close(socket_desc);

		return 0;
	}

};
#endif // !SERVER_H
