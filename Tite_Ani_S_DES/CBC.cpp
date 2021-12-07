#include "CBC.h"
#pragma warning(suppress : 4996)

CBC::CBC()
{
	CBCFlaG = false;
	hashFlag = false;
    k = "1010101010";
}

CBC::~CBC()
{

}


void CBC::cbc_menu() {

    string fileName = "Plaintext.txt";

    int option = 0;
    cout << "Enter 1 to encrypt a File, Enter 2 To encrypt a Image, Enter 3 for image CBC, Enter 4 for hash CBS ";
    cin >> option;
    cin.ignore();
    if (option == 1) {
        read_file(fileName);
    }
    else if (option == 2)
    {
        image_function();
    }
    else if (option == 3)
    {
        CBCFlaG = true;
        image_function();
    }
    else if (option == 4)
    {
        CBCFlaG = true;
        hashFlag = true;
        string hash = cbc_hash(fileName);
        //image_function();
        cout << "The hash is now " << hash << " " << endl;
    }
}

string CBC::cbc_hash(string fileName) {
    // Initiale value
    int iv = 3, option;
    bool CBC_firstPass = false;
    S_DES block;
    string plaintext_character,
        initial_vector,
        temp,
        input_block;
    // get s-des key for encryption 
    //k = get_SDES_Key();

    image_flag = true;
    // convertion of IV to plaint text block size
    temp += decTobin(iv);
    int count = 8 - temp.size();
    while (count > 0) {
        initial_vector += '0';
        count--;
    }
    initial_vector += temp;

    //cout << "Press 1 to hash a file or 2 to hash a string of text ";
    //cin >> option;
    //if (option == 1) {
        // read the file
    //    ifstream inFile = read_file(fileName);
    //    temp = "";
        // get plain text from it 
    //    while (inFile >> temp) {
    //        plaintext_character += temp;
    //    }
        // close file once done 
    //    inFile.close();
    //}
    //else if (option == 2) {
        plaintext_character = fileName;
        hashFlag = true;
    //}
    writeFile(plaintext_character + "  ---Hash -----\n\n", "cbctest.txt");
    // for each plaintext block encrypt every character at a time
    for (int i = 0; i < plaintext_character.size(); i++) {
        if (hashFlag) {
            
            // after pass one do this
            // Exclusive-or current plaintext block with previous ciphertext block
            // Hi = E (Mi, Hi-1) 
            if (CBC_firstPass) {
                input_block = "";
                input_block = block.getcp();       // get previous cipher block
                input_block = x_or(unsignedChartoBinary(plaintext_character[i]), input_block);      // exclusive-or current plain text character with the previous cipher block
                //input_block += "01";        // add padding 
                block.encryptionWrapper(input_block, k);      // encrypt output of the exclusive-or 
                writeFile(block.getcp(), "cbctest.txt");
            }
            else
            {
                input_block = x_or(unsignedChartoBinary(plaintext_character[i]), initial_vector);      // exclusive-or current plain text character with the previous cipher block
                // get the initial value h0
                block.encryptionWrapper(input_block, k);
                writeFile(block.getcp(), "cbctest.txt");
                CBC_firstPass = true;
            }
        }
    }
    // get the hash value of the file
    // G = Hn
    string hash = block.getcp();
    block.setcp("");
    return hash;
}

string CBC::get_SDES_Key()
{
    string ten_bit_key;
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
    return ten_bit_key;
}

ifstream CBC::read_file(string filename) {
    ifstream inFile;
    string plaintext,
        ten_bit_key;
    inFile.open(filename);

    // if file not found display message
    if (!inFile) {
        cerr << "File not found: " << filename << endl;
    }
    else {
        return inFile;
    }
}

void CBC::image_function() {
    bool CBC_firstPass = false;
    image_flag = true;
    bool numInput = false;
    bool decrypt = false;
    string temp;
    string fileName = "normal.bmp";
    string outputName = "cypher.bmp";
    string dOrE = "";
    string tempKey = "";
    cout << "Enter 10-bit Key for encryption and decryption : ";
    cin >> tempKey;

    if (decrypt == true)
    {
        cout << endl << "Decrypting " << fileName << endl;
    }
    else
        cout << endl << "Encrypting " << fileName << endl;


    FILE* picture;
    FILE* cypherImg;

    cypherImg = fopen(outputName.c_str(), "wb");

    if (!(picture = fopen(fileName.c_str(), "rb")))
    {
        cout << fileName << " is missing program will now exit" << endl;
        return;

    }

    unsigned char header[54];

    //Reading the header
    fread(header, sizeof(unsigned char), 54, picture);

    //getting picture stats
    int width = *(int*)&header[18];
    int height = *(int*)&header[22];
    //Need this to support multiple BMP types
    short int bitPerPixel = *(short int*)&header[28];
    int multiplier = bitPerPixel / 8;

    int headerSize = *(int*)&header[14];

    //Dealing with Padding Rules
    if (width % 4 != 0)
    {
        width = width + (4 - (width % 4));
    }

    int size = multiplier * width * height;
    unsigned char* pixelData = new unsigned char[size];


    //Reading Pixel Data
    fread(pixelData, sizeof(unsigned char), size, picture);
    fclose(picture);
    fwrite(header, sizeof(unsigned char), 54, cypherImg);

    for (int i = 0; i < size; i++) {
        if (CBCFlaG) {
            if (CBC_firstPass) {
                string cbc_key = "";
                cbc_key = getcp();
                cbc_key = x_or(unsignedChartoBinary(pixelData[i]), cbc_key);
                cbc_key += "01";
                encryptionWrapper(cbc_key, tempKey);
                temp += binaryToChar(getcp());
            }
            else
            {
                encryptionWrapper(unsignedChartoBinary(pixelData[i]), tempKey);
                temp += binaryToChar(getcp());
                CBC_firstPass = true;
            }
        }
        else {
            encryptionWrapper(unsignedChartoBinary(pixelData[i]), tempKey);
            temp += binaryToChar(getcp());
        }

        if (hashFlag) {
            // if the hash flag is on keep the last cipher text as the hash value 
            string hash = getcp();
        }
    }
    unsigned char* cypherData = (unsigned char*)temp.c_str();
    fwrite(cypherData, sizeof(unsigned char), size, cypherImg);

    fclose(cypherImg);
}

//Reference: https://stackoverflow.com/questions/58052458/how-to-convert-unsigned-char-to-binary-representation

string dec_to_binary(int x)
{
    string cmp_arr[10] = { "0000","0001","0010","0011", "0100", "0101", "0110", "0111", "1000", "1001" };
    string result = "";
    result = cmp_arr[x];
    return result;
}

string CBC::unsignedChartoBinary(unsigned char letter)
{
    string temp;
    int binary[8] = {'/0'};
    if (letter >= '0' && letter <= '9') {
        temp = letter;
        temp = "0000" + dec_to_binary(stoi(temp));
    }
    else {
        for (int n = 0; n < 8; n++)
            binary[7 - n] = (letter >> n) & 1;

        for (int n = 0; n < 8; n++)
            temp += to_string(binary[n]);
    }
    return temp;
}



string CBC::x_or(string value1, string k1)
{
    string result;
    // loop through the value to exclusive-OR
 //   value1 = sw(value1);
  //  k1 = sw(k1);
    for (int i = 0; i < value1.size(); i++) {
        if (value1[i] == k1[i])
            result += '0';
        else
            result += '1';
    }
  //  sw(result);
    return result;
}

string CBC::sw(string x)
{
    string b;
    b = x.substr(4, 4);
    b += x.substr(0, 4);
    return b;
}