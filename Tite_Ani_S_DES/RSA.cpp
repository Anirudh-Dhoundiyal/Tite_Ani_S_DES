#include "RSA.h"

/// <summary>
/// 
/// </summary>
/// <param name="n"></param>
/// <param name="nt"></param>
/// <param name="x"></param>
/// <returns></returns>
int RSA::getInverse(int a, int m)
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
/// <summary>
/// 
/// </summary>
/// <returns></returns>
int RSA::getRPrime()
{
    srand(time(NULL)); //http://www.cplusplus.com/forum/beginner/26611/

    int a[9] = { 73, 79, 83, 107, 109, 113, 283, 293, 307 };
    int  d = 0;
    int  nt = (p - 1) * (q - 1);
    int e = 0;
    int RandIndex = rand() % 9; //Gets random index for the array
    e = a[RandIndex]; // sets e
    d = getInverse(e, nt);
    setN(p * q);
    setNtot(nt);
    setE(e);
    return d;
}




/// <summary>
/// Reference: https://www.geeksforgeeks.org/euclidean-algorithms-basic-and-extended/ 
/// </summary>
/// <param name="a"></param>
/// <param name="b"></param>
/// <param name="x"></param>
/// <param name="y"></param>
/// <returns></returns>
int RSA::extendGcd(int a, int b, int* x, int* y)
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
/// <summary>
/// Set up P and Q for the RSA
/// </summary>
void RSA::Setup()
{
    int p = 73;
    int q = 97;
    setP(p);
    setQ(q);
}

#pragma region Set Functions

void RSA::setP(int setp)
{
    p = setp;
}

void RSA::setQ(int setQ)
{
    q = setQ;
}

void RSA::setN(int setN)
{
    n = setN;
}

void RSA::setNtot(int setNtot)
{
    ntot = setNtot;
}

void RSA::setE(int setE)
{
    e = setE;
}

string RSA::getE()
{
    return to_string(e);
}

string RSA::getD()
{
    return to_string(d);
}

void RSA::setD(int setD)
{
    d = setD;
}

void RSA::setCNum(int setCnum)
{
    cnum = setCnum;
}

void RSA::setPNum(int setPnum)
{
    pnum = setPnum;
}

#pragma endregion

#pragma region Encrypt / Decrypt Functions
string RSA::encryptRSA(string hash)
{
    int pt = stoi(hash);
    cout << "Encrypting Plaintext" << pt << endl;
    setPNum(pt);
    setCNum(FastModExpAlgo(e, pt, n));
    cout << "Ciphertext: " << cnum << endl;
    return to_string(cnum);
}
string RSA::decryptRSA(string cipher)
{
    int pt = 0;
    int ct = stoi(cipher);
    //pt = FastModExpAlgo(d, cnum, n);
    pt = FastModExpAlgo(d, ct, n);
    cout << "decrypted num is: " << pt << endl;
    return to_string(pt);
}


string RSA::dectobinary(int n)
{
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


/// <summary>
/// 
/// </summary>
/// <param name="exponent"></param>
/// <param name="num"></param>
/// <param name="mod"></param>
int RSA::FastModExpAlgo(int exponent, int a, int n)
{
    string binary = dectobinary(exponent);
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
void RSA::print_values()
{
    cout << "P is: " << p << endl;
    cout << "Q is: " << q << endl;
    cout << "n (p*q) is: " << n << endl;
    cout << "Totient of n is: " << ntot << endl;
    cout << "e is: " << e << endl;
    cout << "d is: " << d << endl;
}
#pragma endregion

