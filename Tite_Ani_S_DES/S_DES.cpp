//including class header file
// Tite_Ani_S_DES.cpp : This file contains the 'main' function. Program execution begins and ends there.
/****************************************************************************************************************
*** NAME : 			Tite Divava	& Anirudh Dhoundiyal													  	  ***
*** CLASS : 		CSc 487 																			  	  ***
*** ASSIGNMENT : 	Assignement 1																		  	  ***
*** DUE DATE : 		09/20/2020													   						  	  ***
*** INSTRUCTOR :    Robert Fourney																		  	  ***
*****************************************************************************************************************
*** DESCRIPTION :  	This file contains the class definition.                		                          ***
****************************************************************************************************************/

#include "S_DES.h"


S_DES::S_DES()
{
}

S_DES::~S_DES()
{
}


/****************************************************************************************
*** FUNCTION < readFile >          											  	      ***
*****************************************************************************************
*** DESCRIPTION : < This function is the read file function. It reads a txt file which **
***                 contains all the plain text. For each plaintext it encrypts, then ***
***                 diplay cypher text, then decrypt the cypher text and displays it. ***
***                 It takes the file name and the Simple DES class object >          ***
*** INPUT ARGS :  < String, S_DES >             								  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::readFile(string filename) {

    ifstream inFile;
    string plaintext,
        ten_bit_key;
    inFile.open(filename);

    // if file not found display message
    if (!inFile) {
        cerr << "File not found: " << filename << endl;
    }
    else {
        // get 10-bit key from user 
        cout << "Enter 10-bit Key for encryption and decryption : ";
        cin >> ten_bit_key;
        //cypher.setpt(ten_bit_key);
        // if key is too short or too long prompt key one more time
        while (ten_bit_key.size() != 10) {
            cerr << "Error. Key must be a 10 bit key" << endl;
            cin.ignore();
            cin.clear();
            cin >> ten_bit_key;
        }
        // keep getting plaintext from file while not at the end of file
        while (inFile >> plaintext) {

            for (auto i : plaintext) {

                encryptionWrapper(charToBinary(i), ten_bit_key);
            }

        }

    }
}


void S_DES::encryptionWrapper(string plaintext, string ten_bit_key)
{
    // process current plaintext being read
    setpt(plaintext);
    // encrypt the plaintext using the ten_bit_key to create the encryption key
    encrypt(ten_bit_key);
    // Display the cypher text
    writeFile(getcp());
    // Decrypt then display the original plaintext
    cout << "The decrypted plain text is: ";
    //cout << cypher.decrypt()<<endl; //added a functiong to send char
    cout << binaryToChar(decrypt()) << endl; //added a functiong to send char
}

/****************************************************************************************
*** FUNCTION < key_gen >          											  	      ***
*****************************************************************************************
*** DESCRIPTION : < This function is the key generation function. It takes a 10 bit   ***
***                 key and two string for key passed by reference. It produces two 8 ***
***                 bit subkey returned by reference. >                               ***
*** INPUT ARGS :  < String, String&, String& >    								  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < String&, String& > 	    										  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::key_gen(string ten_bit_key)
{
    // permutate the 10 bit key
    string p10_out = p_10(ten_bit_key);
    //string shift_out = shift(p10_out);

    string left_side, right_side;                   // hold the value of first and second five bit

    // after permutation split bit in two halves
    left_side = p10_out.substr(0, 5);               // get the first five bit
    right_side = p10_out.substr(5, 11);              // get the second five bit
    
    // circular left shift by a on each 5 bit part 
    left_shift(left_side, 1);                       // left LS-1
    left_shift(right_side, 1);                      // right LS-1
    // next we apply p8, the result is subkey 1 K1
    setkey1(p_8(left_side, right_side));

    // then we go back to the pair of 5-bit strings produced by the two LS-1 functions
    // right side and left side. Perform a circular shift of 2 bits on each string 
    left_shift(left_side, 2);
    left_shift(right_side, 2);
    // next we apply p8, the result is subkey 2 K2
    setkey2(p_8(left_side, right_side));
}

/****************************************************************************************
*** FUNCTION < ip >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This function is the initial permutation. Takes an 8 bit block of *** 
***                 plaintext. Permutes it using the IP order of permutation. It then ***
***                 return the 8 bit of plaintext that was mixed up as a string.>     ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < String > 														  ***
****************************************************************************************/
string S_DES::ip()
{
    int ip_pos[8] = { 2, 6, 3, 1, 4, 8, 5, 7};
    string pt_ip;           // hold the plaintext after the initial permutation
    for (int i = 0; i < 8; i++) {
        // assign the pt_ip string at position i to the bit located at 
        // the initial permutation position of ith element in the string ip_pos - 1 since 
        // plainttext string start from 0 to 7 while the ip_pos goes to 8
        if (decrypt_flag == false) {
            pt_ip += pt[ip_pos[i] - 1];
        }
        else
        {
            pt_ip += cp[ip_pos[i] - 1];
        }
    }
    return pt_ip;
}

/****************************************************************************************
*** FUNCTION < fk >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This is the fk function which consists of a combination of        ***
***                 permutation and substitution functions. Input is a 4-bit number   ***
***                 that produce a 4 bit output.    >                                 ***
*** INPUT ARGS :  < String, String>    											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < String >    													  ***
****************************************************************************************/
string S_DES::fk(string eight_bit_num)
{
    string ep_out,
        xor_out1, xor_out2,
        s0_out, s1_out,
        p4_out,
        l,                          //      the leftmost 4 bits
        r;                          //      the rightmost 4 bits

    //  L and R be the leftmost 4 bits and rightmost 4 bits of the 8 - bit input
    l = eight_bit_num.substr(0, 4);
    r = eight_bit_num.substr(4, 8);

    // the first operation is an expansion/permutation operation
    // transforming a 4-bit to an 8-bit number
    ep_out = e_p(r);
    if (decrypt_flag == false) {
    if (fk_flag == false) {
        // The 8-bit subkey K1 is added to this value using exclusive OR
        xor_out1 = x_or(ep_out, key1);
        fk_flag = true;
    }
    else {
        xor_out1 = x_or(ep_out, key2);
    }
    }
    else {
        if (fk_flag == true) {
            // The 8-bit subkey K2 is added to this value using exclusive OR
            xor_out1 = x_or(ep_out, key2);
            fk_flag = false;
        }
        else {
            xor_out1 = x_or(ep_out, key1);
        }
    }
    // the first 4 bits are fed into the S-box S0 to produce a 2 bit output
    s0_out = s0_box(xor_out1.substr(0,4));

    // the remaining 4 bits are fed into S1 to produce another 2-bit output
    s1_out = s1_box(xor_out1.substr(4, 4));
    
    // the 4 bits produced by S0 and S1 undergo a further permutation
    p4_out = p_4(s0_out, s1_out);

    // xor leftmost bit of initial permutation with p4_out
    xor_out2 = x_or(p4_out,l);

    // The output of P4 is the output of the function F
    return xor_out2;
}

/****************************************************************************************
*** FUNCTION < e_p >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This is the e_p function. An expansion/permutation operation is   ***
***                 performed on a 4-bit number >                                     ***
*** INPUT ARGS :  < String >        											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < String >    													  ***
****************************************************************************************/
string S_DES::e_p(string x)
{
    int arr[8] = { 4,1,2,3,2,3,4,1 };
    string temp = "";

    for (int i = 0; i < 8; i++) {
       temp += x[arr[i] - 1];
    }
    return temp;
}

/****************************************************************************************
*** FUNCTION < p_4 >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This is the p_4 function that performs the permutation on a 4-bit > *
*** INPUT ARGS :  < String, String >  											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < String >    													  ***
****************************************************************************************/
string S_DES::p_4(string left, string right)
{
    string temp = "";
    temp += left+right;
    string temp2;
    int arr[8] = { 2,4,3,1 };
    
    for (int i = 0; i < 4; i++) {
        temp2 += temp[arr[i] - 1];
    }
    return temp2;
}

string S_DES::s0_box(string x)
{
    int s0[4][4] = { {1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2} };
    int row, col, result;
    row = 0;
    col = 0;
    result = 0;
    string temp1 = "";
    string temp2 = "";
    temp1 += x.at(0);
    temp1 += x.at(3);
    temp2 += x.at(1);
    temp2 += x.at(2);
    row = binary_to_int(temp1);
    col = binary_to_int(temp2);
    result = s0[row][col];
    return decimal_to_binary(result);
}

string S_DES::s1_box(string x)
{
    int s0[4][4] = { {0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3} };
    int row, col, result;
    row = 0;
    col = 0;
    result = 0;
    string temp1 = "";
    string temp2 = "";
    temp1 += x.at(0);
    temp1 += x.at(3);
    temp2 += x.at(1);
    temp2 += x.at(2);
    row = binary_to_int(temp1);
    col = binary_to_int(temp2);
    result = s0[row][col];
    return decimal_to_binary(result);

}

/****************************************************************************************
*** FUNCTION < sw >          											  			  ***
*****************************************************************************************
*** DESCRIPTION : < This is the swith function, it interchanges the left and right    ***
***                 4 bits so that the second instance of fK operates on a different  ***
***                 4 bits >                                	        	 		  ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
string S_DES::sw(string x)
{
    string b;
    b = x.substr(4, 4);
    b += x.substr(0, 4);
    return b;
}

/****************************************************************************************
*** FUNCTION < ip_inverse >          											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This is the ip inverse function. It's the second                  ***
***                 permutation and is indeed the reverse of the first                ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
string S_DES::ip_inverse(string x)
{
    int ip_invers_pos[8] = { 4, 1, 3, 5, 7, 2, 8, 6 };
    string ip_inv;           // hold the ciphertext after the initial permutation
    for (int i = 0; i < 8; i++) {
        // assign the cp_ip string at position i to the cipthertext bit located at 
        // the initial permutation position of ith element in the string ip_pos - 1 since 
        // ciphertext string start from 0 to 7 while the ip_pos goes to 8
        ip_inv += x[ip_invers_pos[i] - 1];
    }
    return ip_inv;
}

string S_DES::p_10(string key)
{
    int bit_key_pos[10] = { 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 };
    string ip_inv;           // hold the ciphertext after the initial permutation
    for (int i = 0; i <10; i++) {
        // assign the cp_ip string at position i to the cipthertext bit located at 
        // the initial permutation position of ith element in the string ip_pos - 1 since 
        // ciphertext string start from 0 to 7 while the ip_pos goes to 8
        ip_inv += key[bit_key_pos[i] - 1];
    }
    // shift(ip_inv.substr(0, 4), ip_inv.substr(5, 9));
    return ip_inv;
}

string S_DES::shift(string p10_out)
{
    //left_shift(left_bit, 1);    // LS-1
   // left_shift(right_bit,1);    // LS-1


    return "";
}


/****************************************************************************************
*** FUNCTION < left_shift >          											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This is the left shift function. It performs the circular shift   ***
***                 by the spos integer value.                                        ***
*** INPUT ARGS :  < String, int >         											  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < string > 														  ***
****************************************************************************************/
void S_DES::left_shift(string & bits, int spos)
{
    int n = bits.size();
    string temp;
    // copy strings from spos position to the end of the temp string 
    // by using the total strings remove the amount of shift performed
    temp = bits.substr(spos, n - spos);
    // copy the rest left out from begining to shift position to the end of temp string
    temp += bits.substr(0, spos);
    bits = temp;
}

/****************************************************************************************
*** FUNCTION < p_8 >          											  	          ***
*****************************************************************************************
*** DESCRIPTION : < This is the p_8. Picks out and permutes 8 of 10 bits according to ***
***                 the values in the array bit_key_pos into a string to be returned. ***
*** INPUT ARGS :  < String, String >       											  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < String > 														  ***
****************************************************************************************/
string S_DES::p_8(string leftShift_L, string leftShift_R)
{
    int bit_key_pos[8] = { 6, 3, 7, 4, 8, 5, 10, 9};
    string perm = leftShift_L + leftShift_R,
        p8_out;           // hold the bit of string after the permutation p8
    for (int i = 0; i < 8; i++) {
        // assign the p8_out string at position i to the bit located at 
        // the rule's ith positioning in the string bit_key_pos - 1 since 
        // permutation p8_out string starts from 0 to 7 while the ip_pos goes to 8
        p8_out += perm[bit_key_pos[i] - 1];
    }
    return p8_out;
}


/****************************************************************************************
*** FUNCTION < x_or >          											  	          ***
*****************************************************************************************
*** DESCRIPTION : < This is the Exclusive OR                                          ***
*** INPUT ARGS :  < String, String >       											  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < String > 														  ***
****************************************************************************************/
string S_DES::x_or(string value1, string k1)
{
    string result;
    // loop through the value to exclusive-OR
    for (int i = 0; i < value1.size(); i++) {
        if (value1[i] == k1[i])
            result += '0';
        else
            result += '1';
    }
    return result;
}


int S_DES::binary_to_int(string binary)
{
    int decimal =0;
    
    if (binary.at(0) == '0') {
        if (binary.at(1) == '0') {
            decimal = 0;
            return decimal;
        }
        else {
            decimal = 1;
            return decimal;
        }
    }
    else
    {
        if (binary.at(1) == '0') {
            decimal = 2;
            return decimal;
        }
        else {
            decimal = 3;
            return decimal;
        }
    }

    return decimal;
}
string S_DES::decimal_to_binary(int x)
{
    string cmp_arr[4] = { "00","01","10","11" };
    string result = "";
    result = cmp_arr[x];
    return result;
}
/****************************************************************************************
*** FUNCTION < encrypt >               											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This is encrypt function, it takes an 8 character string and      ***
***                 a 10 character string and produces an 8 character string as       ***
***                 a ciphertext for output                                           ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::encrypt(string ten_bit_key)
{
    string  ip_out, cipthertext, 
            fk_out1, fk_out2,
            sw_out1, sw_out2;
    // key generation
    key_gen(ten_bit_key);

    //  initial permutation
    ip_out = ip();

    // F(R,SK) SK is the subkey 
    fk_out1 = fk(ip_out);
    
    // the switch function
    // interchanges the fk output and right 4 bits of initial permutation 
    sw_out1 = sw(fk_out1+(ip_out.substr(4,4)));
    
    // second function fk 
    fk_out2 = fk(sw_out1);

    // inverse initial permutation
    cipthertext = ip_inverse(fk_out2+(sw_out1.substr(4,4)));

    //  ip(cipher_string);
    //  fk(ip_string, key1);
    //  sw(fk_string);
    //  ip_inverse(sw_string);
    setcp(cipthertext);
}

/****************************************************************************************
*** FUNCTION < decrypt >               											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This is decrypt function. It takes an 8 character string of       ***
***                 ciphertext and the same 10 character string to produce that       ***
***                 ciphertext as input and produces the original 8 character         ***
***                 string of plaintext.                                              ***
*** INPUT ARGS :  < String >         											  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None > 															  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
string S_DES::decrypt()
{
    decrypt_flag = true;
    string  ip_out,
        fk_out1, fk_out2,
        sw_out1, sw_out2;
    // key generation

    //  initial permutation
    ip_out = ip();

    // F(R,SK) SK is the subkey 
    fk_out1 = fk(ip_out);

    // the switch function
    // interchanges the fk output and right 4 bits of initial permutation 
    sw_out1 = sw(fk_out1 + (ip_out.substr(4, 4)));

    // second function fk 
    fk_out2 = fk(sw_out1);

    // inverse initial permutation
    string text = ip_inverse(fk_out2 + (sw_out1.substr(4, 4)));

    //  ip(cipher_string);
    //  fk(ip_string, key1);
    //  sw(fk_string);
    //  ip_inverse(sw_string);
    decrypt_flag = false;
    return text;
}



/****************************************************************************************
*** FUNCTION < charToBinary >          											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This function reads a character, converts it to an 8 bit ASCII    ***
***                 then convert that ASCII value to a binary string                  ***
*** INPUT ARGS :  < String >             								  	          ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < String > 														  ***
****************************************************************************************/
string S_DES::charToBinary(char c)
{
    string result = "0";
    string r;
    int n = int(c);
    while (n != 0) { r = (n % 2 == 0 ? "0" : "1") + r; n /= 2; }
    result += r;
    return result;
}

/****************************************************************************************
*** FUNCTION < binaryToChar >          											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This function reads an 8 bit decrypted string, converts it into   ***
***                 ASCII then back to its original value >                           ***
*** INPUT ARGS :  < String >             								  	          ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < String > 														  ***
****************************************************************************************/
string S_DES::binaryToChar(string decrypted_str) {
    // stores the converted 8 bit to original character
    string asciiToCharacter;
    // read from string as if it were a stream like cin
    stringstream sstream(decrypted_str);
    // stores the 8 bit to be converted 
    bitset<8> bits;
    // read from stringstream object 
    sstream >> bits;
    // convert binary to character
    asciiToCharacter = char(bits.to_ullong());

    return asciiToCharacter;

}


/****************************************************************************************
*** FUNCTION < writeFile >          											  	  ***
*****************************************************************************************
*** DESCRIPTION : < This function write strings into a file called Ciphertext >       ***
*** INPUT ARGS :  < String, S_DES >             								  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < None > 															  ***
****************************************************************************************/
void S_DES::writeFile(string cyphertext) {

    ofstream outFile;
    outFile.open("CipherText.txt", ios_base::app);
    outFile << cyphertext << endl;
    outFile.close();
}

void printFastModTable(int i, char bt, int c, int f) {
    cout << i << "\t\t" << bt << "\t\t" << c << "\t\t" << f << "\t\t" << endl;
}
/****************************************************************************************
*** FUNCTION < fastModExpAlg >       											  	  ***
*****************************************************************************************
*** DESCRIPTION : This function performs the Fast Modular Exponentiation calculation  ***
***               of the modulo n of an integer a raised to the power of an integer b ***
***                                     a ^ b mod n                                   *** 
*** INPUT ARGS :  < String, int, int >             								  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < int > 															  ***
****************************************************************************************/
int S_DES::fastModExpAlg(string binary, int a, int n) {
    int c = 0,
        f = 1;
    // Print
    cout << "i\t\t" << "b\t\t" << "c\t\t" << "f\t\t" << endl;
    for (int i = binary.size() - 1; i >= 0; i--) {
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

/****************************************************************************************
*** FUNCTION < decTobin >              											  	  ***
*****************************************************************************************
*** DESCRIPTION : This function converts a decimal value to binary and return result  ***
***               as a string                                                         ***
*** INPUT ARGS :  < int >                        								  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < string >    													  ***
****************************************************************************************/
string S_DES::decTobin(int n) {
    // hold the value of the binary string after convertion to be returned 
    string binary = "";

    // do this while n is positive, until the remainder is 0
    while (n > 0) {
        // get the remainder of n divided by 2
        binary += to_string(n % 2);
        // get the new result of n
        n = n / 2;
    }
    return binary;
}

/****************************************************************************************
*** FUNCTION < testFastExpo >              											  ***
*****************************************************************************************
*** DESCRIPTION : This function test the fast modular exponents algorithm. Prompt the ***
***               the user to enter values to apply the algo on. It prints the results **
***               of the Fast Modular Exponentiation Algorithm for a ^ b mod n        ***
*** INPUT ARGS :  < int >                        								  	  ***
*** OUTPUT ARGS : < None > 															  ***
*** IN/OUT ARGS : < None >          	    										  ***
*** RETURN : 	  < string >    													  ***
****************************************************************************************/
void S_DES::testFastExpo() {
    // a ^ b mod n 
    int a, b, n, result;
    string binary;
    cout << "Enter a --> ";
    cin >> a;
    cout << endl << "Enter b --> ";
    cin >> b;
    cout << endl << "Enter n --> ";
    cin >> n;
    // convert b to binary then assign to binary string  
    binary = decTobin(b);
    // send binary string, a and n to calculate the fast modular of a to the power of b modular n
    // by using the binary string,  the integer a and the modular number
    // return the result 
    result = fastModExpAlg(binary, a, n);
    cout << endl << a << " ^ " << b << " mod " << n << " = " << result << endl;
}