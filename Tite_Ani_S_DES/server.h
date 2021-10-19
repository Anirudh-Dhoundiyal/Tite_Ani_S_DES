/****************************************************
*
*    Basic minimal socket server program for use
*    in CSc 487 final projects.  You will have to
*    enhance this for your projects!!
*
*                                  RSF    11/14/20
*
****************************************************/
#include<stdio.h>
#include<string.h>		//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<unistd.h>		//write
#include<stdlib.h>		// for system & others

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
	char *binary = malloc (25);
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


int server(void)
{
	int socket_desc , new_socket , c, read_size, i, comKey, pKa, gPKa, gPKb, keyReceived, g = -1, q = -1;
	struct sockaddr_in server , client;
	char *message, client_message[100], convert[15];
		
	char *list;	
	list = "ls -l\n";

	char* found, convert[15];

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
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		printf(" unable to bind\n");
		return 1;
	}// End of if
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
		
		// Check if g prime and q are defined,
		// If not process with g and q
		if (g >= 0 && q >= 0) {
			// Ask user to enter their key 
			printf("\nEnter server private key --> ");
			scanf("%d", &pKa);
			// Generate a key using server private key and g ^ pka mod q		
			// convert to binary && mod private key
			//gPKa = fastModExpAlg(decToBin(pKa), g, q);
			gPKa = modExpo(g, pKa, q);
			
			// Receive private key from client. Convert message containing the key to integer
			gPKb = atoi(client_message);
			// Use key received to find common key
			comKey = fastModExpAlg(decToBin(gPKb), g, q);
			// Display private key and generated private key
			printf("\nYour Private Key is %d and your Generated Key is %d\n\n", pKa, gPKa);
			// Display common key generated from client private key
			printf("\nThe common key is %d\n\n", comKey);
			
			// Add flag K to specify that it's a generated key from server
			strcpy(client_message, "k ");
			// Convert the the server private key integer to string of character then copy it to the message back to the client
			sprintf (convert, "%d", gPKa);
			strcat(client_message, convert);
			// send private key produced 
			write(new_socket, client_message, read_size);
		}// End of if
		// Otherwise if g and q not define
		else{
			found = (char *)malloc(strlen(client_message)+1);
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
				// send confirmation message back
				// copy the message to reply back to the client
				strcpy(client_message, "g and q are set!! Ready to receive generated key\n");
			}// End of if
			else{
				printf("g prime and q prime not found. Try again.\n\n");
			}// End of else

		}// End of if
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

	return comKey;
}
