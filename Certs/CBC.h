#pragma once
#include "S_DES.h"

#include <iostream>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <bitset>
#include <math.h>
#include <stdio.h>

class CBC :
    public S_DES
{
private:
    bool CBCFlaG;
    bool hashFlag;
public:
    CBC();
    ~CBC();
    void image_function();
    string unsignedChartoBinary(unsigned char);
    string x_or(string, string);
    string sw(string);
    string cbc_hash(string);
    ifstream read_file(string filename);
    string get_SDES_Key();
    int binaryToInt(bitset<8> binary);
    void printByte(bitset<8> byte);
    void cbc_menu();
};

