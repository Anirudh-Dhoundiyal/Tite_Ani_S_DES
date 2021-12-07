#pragma once
#ifndef SERVER_H
#define SERVER_H

#include<arpa/inet.h>	//inet_addr
#include<unistd.h>		//write
#include<stdlib.h>	
#include <stdio.h>
#include<string.h>	
#include <iostream>
#include "Certificates.h"

using namespace std;

class Server {
private:
	int e,	// RSA public key
		n,	// RSA n
		g,	// Diffie Parameter (Generator) 
		q;	// DH Parameter

public:
Server(){
	 e = 0;
	 n = 0;
	 g = -1;
	 q = -1;
	server();
}
int decrypt(int signedKey){
	int pt = 0;
	pt = fastModExpAlg(decToBin(e), signedKey, n);
	return signedKey;
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
            res = (res*x) % p;
 
        // y must be even now
        y = y>>1; // y = y/2
        x = (x*x) % p;
    }
    return res;
}
void printFastModTable (int i, char bt, int c, int f)
{
  printf ("%d\t\t %c\t\t %d\t\t %d\t\t\n", i, bt, c, f);

}

char * decToBin(int decimal) {
	// hold the value of the binary string after convertion to be returned 
	char *binary = new char[25];
	int i = 0;
	// do this while n is positive, until the remainder is 0
	while (decimal > 0) {
		// get the remainder of n divided by 2
		binary[i] = (decimal % 2) + '0';
		// get the new result of n
		decimal = decimal / 2;
		i++;
	}
	return binary;
}

int fastModExpAlg(char * binary, int a, int n) {
	int c = 0,
		f = 1;
	// Print
	printf("i \t\t b \t\t c \t\t f \t\t\n");
	for (int i = strlen(binary) - 1; i >= 0; i--) {
		// 
		c = 2 * c;
		f = (f * f) % n;
		// Check that the binary digit at position i is 1 to perform ...
		if (binary[i] == '1') {
			c = c + 1;
			f = (f * a) % n;
		}
		printFastModTable(i, binary[i], c, f);
	}
	return f;
}


	int server() {
		int socket_desc , new_socket , c, read_size, i, comKey = -1, pKa, gPKa, gPKb, keyReceived,  signedKey;
	struct sockaddr_in server , client;
	char *message, client_message[100], convert[15];
	Certificates certs;
	char *list;	
	list = "ls -l\n";

	char* found, convertS[15];

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}// End of if
	
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8421 );                 // Random high (assumed unused) port
	
	//Bind
	if( ::bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		printf(" unable to bind\n");
		return 1;
	}
	printf(" socket bound, ready for and waiting on a client\n");
	
	//Listen
	listen(socket_desc , 3);
	
	//Accept incoming connection
	printf(" Waiting for incoming connections... \n");
	
	
	c = sizeof(struct sockaddr_in);
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	if (new_socket<0)
	{
		perror("accept failed");
		return 1;
	}// End of if
	
	printf("Connection accepted\n");
	
	//Reply to the client
	message = "You have located Server X at our undisclosed location.  What would you like to say?\n";
	//write(new_socket , message , strlen(message));
	
	//Receive a message from client
	while( (read_size = recv(new_socket , client_message , 100 , 0)) > 0 )
	{
		printf("\n Client sent %2i byte message:  %.*s\n",read_size, read_size ,client_message);

		if(!strncmp(client_message,"showMe",6)) 
		{
			printf("\nFiles in this directory: \n");
			system(list);
			printf("\n\n");
		}// End of if
		// Check what instructions have been sent
		//***************************************************************************
		// Receive the Certificate values as a string in client message
		// Store element of the cert
		char* found;
		cert_fields a;
		//int init_size = strlen(message);
		// allocate space
		//found = (char*)malloc(strlen(message) + 1);
		found = (char*)malloc(strlen(client_message) + 1);
		// Get the first string in the client message
		found = strtok(client_message, " ");
		// while not at the end of the file do this
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

		string gS,			// Signed G by client for DH
			qS, 				// Signed Q by client for DH
			nS;				// Signed N by client for RSA Decryption to be used with public key

		found = strtok(NULL, " ");
		gS = found;
		found = strtok(NULL, " ");
		qS = found;
		found = strtok(NULL, " ");
		nS = found;
		//***************************************************************************
		// Now authenticate the certs
		string unsigned_hash = certs.generate_hash(a),
			signed_hash;
		int	unsigned_hash_dec,
			signed_hash_dec;
		// Convert hash from binray to decimal for comparison
		unsigned_hash_dec = stoi(unsigned_hash, 0, 2);
		// Decrypt the signature then compare to unsigned hash
		if (a.issuer_name == a.subject_name) {
			// Set the public key found on the certificate
			certs.setE(stoi(a.subject_pk_info.key));
			// Set n
			certs.setN(stoi(nS));

			// get the public key and totient to calculate the private key
			int public_key = stoi(certs.getE()),
				totient = stoi(certs.getNtot());

			// decrypt 
			signed_hash = certs.decryptRSA(a.s.certificate_signature);

			// Display
			if (unsigned_hash == signed_hash)
				cout << "Certificate Hash validated. Decrypted signature: " << signed_hash << " Match Unsigned Hash: " << unsigned_hash << endl;
			else
				cout << "Certificate Hash not Valid. Decrypted signature: " << signed_hash << " Do no match unsigned hash: " << unsigned_hash << endl;
		}
		//***************************************************************************
		// Decrypt G Q and N using the certs public key for authentification 
		// After authentification Set g and q for DH
		g = stoi(certs.decryptRSA(gS));
		q = stoi(certs.decryptRSA(qS));
		cert_fields temp;				// hold the value for sever certificate
		// Generate the server certificate
		temp = certs.generate_cert_sign_request();
		certs.generate_signature();
		// Send back to server Certificate in the client message
		// With Certificate  K to request their generated g ^ privateKey mod q
		
		// Generate G ^ pka mod q
		
		// Send the generated key
		
		// wait to receive the generated from client
		
		//	Use the generated key to create the Shared secret key for DH
		
		//	Use shared secret key to communicate   
		 
		

		//  Allow the authenticated remote user to execute a few select commands on the remote server 
		
		// view the results on the client. 

		// All communication to and from the server are encrypted (using S-DES and either of the keys established in Part 1. 
		 
		
		// Case 1 -1 for setting up g and q 
		// Case 2 K or k for sending the key and requesting key from server
		// Case 3 M or m for sending the message to server possibly decrypting before sending then receive encrypted message then decrypt it if instruction is M or m and display the decrypted on the server comparing to original message from client
		
		
		// Check if g prime and q are defined,
		// If not process with g and q
		if (g >= 0 && q >= 0) {
			found = (char *)malloc(strlen(client_message)+1);
			strcpy(found, client_message);
			// Get the first string in the client message
			found = strtok(found, " ");
			// Case 2: K or k for sending the key and requesting key from server
			if (strcmp(found,"K") == 0 || strcmp(found, "k") == 0) {
				// Ask user to enter their Diffie-Hellmen private key 
				printf("\nEnter server DH Private key --> ");
				scanf("%d", &pKa);
				// Generate a key using server private key and g ^ pka mod q		
				gPKa = modExpo(g, pKa, q);
				// Get the next element after space in the message 
				// Receive g ^ pkb mod q from client then store in found.
				found = strtok(NULL, " ");	
				 
				//Convert variable containing the key to integer
				gPKb = atoi(found);
				// Use key received to find common key
				comKey = fastModExpAlg(decToBin(gPKb), g, q);
				
				// Check for signed key for authentification
				// get signed next to generated key 
				found = strtok(NULL, " ");
				signedKey = atoi(found);
				printf("Your decrypted RSA Key is %d \n", decrypt(signedKey));
				
				// Display private key and generated private key
				printf("\nYour Private Key is %d and your Generated Key is %d\n\n", pKa, gPKa);
				// Display common key generated from client private key
				printf("\nThe common key is %d\n\n", comKey);
			
				// Add flag K to specify that it's a generated key from server
				strcpy(client_message, "k ");
				// Convert the the server private key integer to string of character then copy it to the message back to the client
				sprintf (convert, "%d", gPKa);
				strcat(client_message, convert);
			}
			else if (strcmp(found, "M") == 0 || strcmp(found, "m") == 0) {
				// Check if private key was entered
				if(comKey <= 0){
					printf("Error. Common generated key not found.\n");
				}
				else{
					// Decrypt the message 
					printf("\n Client sent %2i byte message:  %.*s\n",read_size, read_size ,client_message);
				
					// Send the message back to client
					for(i=0;i< read_size;i++)
					{
						if ( i%2)
						client_message[i] = 'z';
					}
				} 
				
			}	
			// send private key produced 
			// write(new_socket, client_message, read_size);
		}// End of if

		// Otherwise if g and q not define
		else{
			found = (char *)malloc(strlen(client_message)+1);
			strcpy(found, client_message);
			// looking for the first string by checking the separator 
			found = strtok(client_message, " ");
			
			// If not included in client message 
			// Send a message back to the user to ask the client to enter them
			// check if client message contain -1 meaning g and q are included in the client message 
			if (strcmp(found,"-1") == 0) {
				// get g and q from client message by parsing them
				// return string found before the seperator " " as long as string is no NULL
				// set g
				found = strtok(NULL, " ");
				g = atoi(found);
				// set q
				found = strtok(NULL, " ");
				q = atoi(found);
				// get key pair d
				found = strtok(NULL, " ");
				e = atoi(found);
				// get key pair n
				found = strtok(NULL, " ");
				n = atoi(found);
				// send confirmation message back
				// copy the message to reply back to the client
				strcpy(client_message, "g and q are set!! Ready to receive generated key\n");
			}// End of if
			else{
				printf("g prime and q prime not found. Try again.\n\n");
				strcpy(client_message, "g prime and q prime not found. Try again.\n\n");
			}// End of else
		}// End of else
		//write(new_socket, client_message , strlen(client_message));
		write(new_socket, client_message , read_size);
	}// End of while
	
	if(read_size == 0)
	{
		printf("client disconnected\n");
		fflush(stdout);
	}// End of if
	else if(read_size == -1)
	{
		perror("receive failed");
	}// End of else
		
	//Free the socket pointer
	close(socket_desc);

	return 0;
	}

};
#endif // !SERVER_H
