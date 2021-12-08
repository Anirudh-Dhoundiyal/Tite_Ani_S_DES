#pragma once
#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdbool.h> 
#include <stdlib.h>
#include<string.h>	
//#include<sys/socket.h>
//#include<arpa/inet.h> 
#include "Certificates.h"
#include "Server.h"

using namespace std;

class Client
{
private:
	Certificates certs;
	int nt, 	// totient of n 
		e,		// public key pair
		d,		// private key pair
		p, q,
		n;
public:

	int extendGcd(int a, int b, int* x, int* y)
	{
		// Base Case 
		if (a == 0)
		{
			*x = 0;
			*y = 1;
			return b;
		}
		int x1, y1;
		int gcd = extendGcd(b % a, a, &x1, &y1);
		*x = y1 - (b / a) * x1;
		*y = x1;

		return gcd;
	}
	/*int getInverse(int a, int m)
	{
		int x, y;
		int result = 0;
		int g = extendGcd(a, m, &x, &y);


		if (g != 1)
		{
			cout << "The Inverse dosent exist" << endl;
		}
		else {
			result = (x % m + m) % m;
			cout << "The Inverse of " << a << " mod " << m << " is: " << result << endl;
		}

		return result;
	}
	void getRPrime()
	{
		char convert[2];

		srand(time(NULL)); //http://www.cplusplus.com/forum/beginner/26611/

		int a[9] = { 73, 79, 83, 107, 109, 113, 283, 293, 307 };
		// get the totient
		//int  nt = (p - 1) * (q - 1);
		nt = (p - 1) * (q - 1);	// get the totient of n
		//int e = 0;
		int RandIndex = rand() % 9; //Gets random index for the array
		e = a[RandIndex]; 		// sets public key
		d = getInverse(e, nt);  	// set private key pair using public key and totient of n
		n = p * q;

		sprintf(convert, "%d", d);
		// add the private key to character of string	
		strcpy(pubKeyPair, convert);
		// add space between key pair 
		strcat(pubKeyPair, " ");
		// convert n
		sprintf(convert, "%d", n);
		// add n converted to the key pair
		strcat(pubKeyPair, convert);

		//setN(p * q);
			//setNtot(nt);
			//setE(e);
	   // return d;
	   // return pubKeyPair;
	}
	int encrypt()
	{
		int pt, signedKey;
		char entry;

		// set the private key pair (n, d) and the public key pair
		//	getRPrime();
		printf("\nEnter your signed key: ");
		while (scanf("%d%c", &pt, &entry) != 2 || entry != '\n') {
			printf("Failure, enter numerical value followed by enter.\nEnter your signed key: ");
			getchar();
		}
		signedKey = fastModExpAlg(e, pt, n);
		printf("encrypted num is: %d\n", signedKey);
		return signedKey;
	}*/


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

	int fastModExpAlg(int exponent, int a, int n)
	{
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

	void reverseStr(string& str)
	{
		int n = str.length();

		// Swap character starting from two
		// corners
		for (int i = 0; i < n / 2; i++)
			swap(str[i], str[n - i - 1]);
	}

	Client() {
	//	certs.generate_cert_sign_request();
	//	certs.generate_signature();
		e = stoi(certs.getE());
		d = stoi(certs.getD());
		cout << " e is " << e << endl;
		cout << " d is " << d << endl;
		n = 7081;
		client();
	}

	int client() {
		int socket_desc;    // file descripter returned by socket command
	//	struct sockaddr_in server;    // in arpa/inet.h
		int read_size = 0, pKclient = 0, g = -1, q = -1, gPKclient = 0, comKey, gPKserver, rsaK;
		char  server_reply[100], client_message[100], entry;
		bool auth = false; bool login = false;
		bool valid = false, validEntry = false;
		char* found, convert[15], * foundS;
		cert_fields temp;
		cert_fields servercert;
		int gE, qE, gPKclientE;
		// //Create socket
	//	socket_desc = socket(AF_INET, SOCK_STREAM, 0);

		printf("Trying to create socket\n");
		/****************************************************************************************
		if (socket_desc == -1)
		{
			printf("Unable to create socket\n");
		}
		
		// *********** This is the line you need to edit ****************
		server.sin_addr.s_addr = inet_addr("169.254.121.170");  // doesn't like localhost?
		server.sin_family = AF_INET;
		server.sin_port = htons(8421);    // random "high"  port number

		//Connect to remote server
		if (connect(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
		{
			printf(" connect error");
			return 1;
		}
		***************************************************************************************/

		//Get data from keyboard and send  to server
		printf("What do you want to send to the server. (b for bye)\n");

		while (strncmp(client_message, "b", 1))      // quit on "b" for "bye"
		{
			printf("Enter -1 to start cert authentication\n");
			printf("Enter M or m for message to server.\n");

			memset(client_message, '\0', 100);
			scanf("%s", client_message);


			while (auth = true)
			{
				if(login == false){
				printf("Enter p or P to send password\n");
				}
				else if(login == true){
				printf("Enter c or C to send command.\n");
				}
			

				memset(client_message, '\0', 100);
				scanf("%s", client_message);
				if (strcmp(client_message, "p") == 0 || strcmp(client_message, "p") == 0){

					printf("\nEnter your user --> ");

					scanf("%s", client_message);
					strcat(client_message, " ");
					printf("\nEnter your Passsword --> ");
					scanf("%s", client_message);
					valid = true;
				}
				else if(strcmp(client_message, "c") == 0 || strcmp(client_message, "C") == 0){
					string temp = "";
					printf("\nEnter the command --> ");
					cin  >> temp;
					strcat(client_message, temp.c_str());
					valid = true;

				}
				if (valid) {
						// Set valid back to false for next menu selection
						valid = false;

						/*************************************************************************
						// Send to server
						if (send(socket_desc, &client_message, strlen(client_message), 0) < 0)
						{
							printf("Send failed");
							return 1;
						}// End of if
						**************************************************************************/

						// Print message client is sending to the client 
						printf("\nSending Message: %.*s\n", (int)strlen(client_message), client_message);

						/*********************************************************************************
						//Receive a reply from the server
						if ((read_size = recv(socket_desc, server_reply, 100, 0)) < 0)
						{
							printf("recv failed");
						}
						*********************************************************************************/
						// Allocate space for server reply instruction check
						
						foundS = (char*)malloc(strlen(server_reply) + 1);
						//sprintf(convert, "%s", "k");
						//strcat(foundS, convert);
						// Copy content of server reply
						strcpy(foundS, server_reply);
						// Get the first string from the server reply
						foundS = strtok(foundS, " ");

						// Print message client is sending to the client 
						printf("\nServer replied with: %.*s\n\n", (int)strlen(client_message), client_message);
						// If server reply's first string is k then reply contains generated key
						// Process server generated private key
						if (strcmp(foundS, "l") == 0 || strcmp(foundS, "L") == 0) {
							login = true;
						}
				}
			
			
			}
			
			// if client input is -1 prompt user for G and Q then send to server
			// Server reply with a confirmation message that G and Q are set
			if (strcmp(client_message, "-1") == 0) {

				strcat(client_message, " ");
				temp = certs.get_file_data();
				// Get public and private key of certificate being sent over to sockets
				certs.get_priv_k(temp.issuer_name);
				e = stoi(certs.getE());
				d = stoi(certs.getD());
				n = stoi(certs.getN());

				string data = certs.generate_sendstring(temp);
				strcat(client_message, data.c_str());
				// Prompt User for g and q prime
				printf("\nEnter g --> ");
				// if entry is not an int and enter input
				while (scanf("%d%c", &g, &entry) != 2 || entry != '\n') {
					printf("Failure, enter numerical value followed by enter.\nEnter g--> ");
					getchar();
					//signing g
				}
				gE = fastModExpAlg(d, g, n);

				printf("\nEnter q --> ");
				while (scanf("%d%c", &q, &entry) != 2 || entry != '\n') {
					printf("Failure, enter numerical value followed by enter.\nEnter q --> ");
					getchar();
					//signing q
				}
				qE = fastModExpAlg(d, q, n);

				// append the integer g and q to client message containing -1 already
				// after converting the integer to character g
				//strcat(client_message, " ");
				sprintf(convert, "%d", gE);
				strcat(client_message, convert);
				// q
				strcat(client_message, " ");
				sprintf(convert, "%d", qE);
				strcat(client_message, convert);

				// adding n to server message
				strcat(client_message, " ");

				cout << n << endl;
				sprintf(convert, "%d", n);
				cout << convert << endl;
				strcat(client_message, convert);

				// Prompt user for message 
				printf("Enter the private key to generate a public key to server.\n");
				cin >>pKclient;
				// Send the client message  
				// generate a key using your private key and g ^ pkb mod q
				gPKclient = modExpo(g, pKclient, q);
				// Sign the generated key 
				gPKclientE = fastModExpAlg(d,gPKclient, n);
				// Display private key and generated private key for debugging
				printf("Your Private Key is %d and your Generated Key is %d\n", pKclient, gPKclient);
				// convert the key to a character
				sprintf(convert, "%d", gPKclientE);
				// adding generated client key to server message
				strcat(client_message, " ");
				// copy key generated to be sent over to the server
				strcat(client_message, convert);

				valid = true;
			}//End of if
			// Before Sending the message make sure(Check) that g and q are set

			if (!(g >= 0 && q >= 0))
				printf("No g prime or q set. Error, set them before to continue. Press -1 no enter them\n");
			else {

				found = (char*)malloc(strlen(client_message) + 1);
				strcpy(found, client_message);
				// Get the first string in the client message
				found = strtok(found, " ");

				//*** Case 1 message containning private key 
					// If first string is not -1 then message contain private key.
					// Produce generated key using then copy generated key to client message to be sent over to the server
				if (strcmp(found, "K") == 0 || strcmp(found, "k") == 0) {

					// Sign the private key using RSA for authentification by server
					//rsaK = encrypt();
					// convert rsa key to string to be appended to the private key for authentification
					//sprintf(convert, "%d", rsaK);
					
					// Append rsa Keyy with flag r or just add a space next to the private key
					strcat(client_message, " ");
					strcat(client_message, convert);

					printf("Wait for server generated private key!! \n");
					valid = true;
				}	// End of if
			//*** Case 2 message containing client message to be encrypted
				// If M is the instruction ask client to enter their message, then encrypt the message using the generated private key if it exist, if not start again 
				else if (strcmp(found, "M") == 0 || strcmp(found, "m") == 0) {

					printf("Enter message to server.\n");
					memset(client_message, '\0', 100);
					scanf("%s", client_message);

					// encrypt the message 
					printf("Message is now %s\n", client_message);

					// add the instruction flag with the client message
					strcat(found, " ");
					strcat(found, client_message);

					// copy message encrypted
					strcpy(client_message, found);

					valid = true;
				}
				else if (strncmp(found, "-1", 2) == 0) {
					Server ser(&*client_message);// (client_message);
					strcpy(server_reply, client_message);
				}

				//*** Case 3 message containing g and q to be sent
					// Do nothing as -1 already included in message just send over to server
					// Send to server only if client message is valid
				if (valid) {
					// Set valid back to false for next menu selection
					valid = false;

					/*************************************************************************
					// Send to server
					if (send(socket_desc, &client_message, strlen(client_message), 0) < 0)
					{
						printf("Send failed");
						return 1;
					}// End of if
					**************************************************************************/

					// Print message client is sending to the client 
					printf("\nSending Message: %.*s\n", (int)strlen(client_message), client_message);

					/*********************************************************************************
					//Receive a reply from the server
					if ((read_size = recv(socket_desc, server_reply, 100, 0)) < 0)
					{
						printf("recv failed");
					}
					*********************************************************************************/
					// Allocate space for server reply instruction check
					
					foundS = (char*)malloc(strlen(server_reply) + 1);
					//sprintf(convert, "%s", "k");
					//strcat(foundS, convert);
					// Copy content of server reply
					strcpy(foundS, server_reply);
					// Get the first string from the server reply
					foundS = strtok(foundS, " ");

					// Print message client is sending to the client 
					printf("\nServer replied with: %.*s\n\n", (int)strlen(client_message), client_message);
					// If server reply's first string is k then reply contains generated key
					// Process server generated private key
					if (strcmp(foundS, "k") == 0 || strcmp(foundS, "K") == 0) {
						foundS = strtok(NULL, " ");
						// found k now read the cert
						servercert.version = foundS;

						// Get next string
						foundS = strtok(NULL, " ");
						servercert.serial_number = foundS;
						//
						foundS = strtok(NULL, " ");
						servercert.signature_algo.algo = foundS;

						foundS = strtok(NULL, " ");
						servercert.signature_algo.parameters = foundS;

						foundS = strtok(NULL, " ");
						servercert.issuer_name = foundS;

						foundS = strtok(NULL, " ");
						servercert.period_of_validity.not_before = stoi(foundS);

						foundS = strtok(NULL, " ");
						servercert.period_of_validity.not_after = stoi(foundS);

						foundS = strtok(NULL, " ");
						servercert.subject_name = foundS;

						foundS = strtok(NULL, " ");
						servercert.subject_pk_info.algo = foundS;

						foundS = strtok(NULL, " ");
						servercert.subject_pk_info.parameters = foundS;

						foundS = strtok(NULL, " ");
						servercert.subject_pk_info.key = foundS;

						foundS = strtok(NULL, " ");
						servercert.s.algo = foundS;

						foundS = strtok(NULL, " ");
						servercert.s.parameters = foundS;

						foundS = strtok(NULL, " ");
						servercert.s.certificate_signature = foundS;

						certs.writeFile(servercert.version, "server_cert.txt");
						certs.writeFile(servercert.serial_number, "server_cert.txt");
						certs.writeFile(servercert.signature_algo.algo, "server_cert.txt");
						certs.writeFile(servercert.signature_algo.parameters, "server_cert.txt");
						certs.writeFile(servercert.issuer_name, "server_cert.txt");
						certs.writeFile(to_string(servercert.period_of_validity.not_before), "server_cert.txt");
						certs.writeFile(to_string(servercert.period_of_validity.not_after), "server_cert.txt");
						certs.writeFile(servercert.subject_pk_info.algo, "server_cert.txt");
						certs.writeFile(servercert.subject_pk_info.parameters, "server_cert.txt");
						certs.writeFile(servercert.s.algo, "server_cert.txt");
						certs.writeFile(servercert.s.parameters, "server_cert.txt");
						certs.writeFile(servercert.s.certificate_signature, "server_cert.txt");
						string unsigned_hash = certs.generate_hash(servercert);

						certs.setE(stoi(servercert.subject_pk_info.key));

						//string comparehash = decToBin(fastModExpAlg(d, stoi(servercert.s.certificate_signature), n));
						string comparehash = decToBin(stoi(certs.decryptRSA(servercert.s.certificate_signature)));
						reverseStr(comparehash);
						if (unsigned_hash == comparehash) {
							cout << "hash is validated" << endl;
							auth = true;
						}
						else {
							cout << "invalid cert" << endl;
						}
						//this is a comment
						printf("Server sent the cert and the signed generated key: %.*s\n\n", read_size, foundS);
						// Decrypt generated key from server 
						//int temp = fastModExpAlg(d, atoi(foundS), n);
						int temp = stoi(certs.decryptRSA(foundS));
						gPKserver = temp;
						printf("Server  Replies: %d.  Generated key decrypted: %d \n\n", read_size, gPKserver);




						// Find common key using the server key received 
						comKey = fastModExpAlg(pKclient, gPKserver, q);

						// display common key
						printf("Shared Common key to use for S_DES encryption and decryption is %d \n", comKey);
					}// End of if

					// if server reply instruction is m send back decrypted message to client
					else if (strcmp(foundS, "m") == 0 || strcmp(foundS, "M") == 0) {
						printf("Server decrypted message is: %.*s\n\n", read_size, server_reply);
						// clear array containing message for next message
						client_message[0] = '\0';
					}
					
					// Otherwise If first string equal to -1 print the message from server 
					// then loop again
					else
						printf("Server  Replies: %.*s\n\n", read_size, server_reply);

				}
			}
		}
		return 0;
	}

};


#endif // !CLIENT_H