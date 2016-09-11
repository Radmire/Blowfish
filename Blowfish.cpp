/////////////////////////////////////////////////////////////////////
//File: Blowfish.cpp                                               //
//Programmer: Ryan Admire                                          //
//Description: A variation of the Blowfish encryption algorithm.   //
//             The program takes in one command line argument,     //
//             a 16 bit hexadecimal key. It then reads the message //
//             to be encrypted from standard input.                //
/////////////////////////////////////////////////////////////////////

#include <iostream>  //for input/output
#include <string>    //for reading from standard input
#include <sstream>   //for getting hex ascii values
#include "blowfish_boxes.c"   //holds the p-arryas and s-boxes


unsigned int F(unsigned int S);                     //bit shifts the input sent to it
void Encrypt(unsigned int *Lin, unsigned int *Rin); //encrypts the split plaintext 
void Decrypt(unsigned int *Lin, unsigned int *Rin); //decrypts the split ciphertext

using namespace std;

//the body of the program. takes the key as a command line argument and reads the plaintext from standard input.
int main(int argc, char* argv[]) {
	
	//VARIABLES
	string key = argv[1];   //store the whole key
	unsigned long long K1 = stoll(key.substr(0,8), NULL, 16);  //stores the leftmost portion of the key as HEX
	//stores the rightmost portion of the key as HEX
	unsigned int long long K2 = stoll(key.substr(8, 8), NULL, 16);

	string in;                  //will store the user input
	string Lin = "", Rin = "";  //Left and Right strings
	unsigned int L;     //stores the left piece of the plaintext
	unsigned int R;     //stores the right piece of the plaintext

	//generate parray for the key
	for (int i = 0; i < 18; i++) {
		
		//if even
		if (i % 2 == 0) {
			parray[i] ^= K1;
		}
		//if odd
		else {
			parray[i] ^= K2;
		}
	}
	string blank = "00000000";
	L = R = stol(blank, NULL, 16); //set L and R to zero. We will need them to finish generating key specific parrys and s-boxes

	//use the encrypt function fully update the parray and s-boxes
	for (int k = 0; k < 18; k+=2) {
		Encrypt(&L, &R); //encrypt the zeros
		parray[k] = L; //L is the new parray value at k
		parray[k + 1] = R; //R is the new parray value at k+1
	}
	//we increment by two above to get past our new P[k] and P[k+1]
	//continue this process for the Sboxes. there are 256 values in each sbox we must do this 4 times
	///this will be slow
	for (int k = 0; k < 256; k += 2) {
		Encrypt(&L, &R); //encrypt the zeros
		sbox0[k] = L; //L is the new parray value at k
		sbox0[k + 1] = R; //R is the new parray value at k+1
	}
	for (int k = 0; k < 256; k += 2) {
		Encrypt(&L, &R); //encrypt the zeros
		sbox1[k] = L; //L is the new parray value at k
		sbox1[k + 1] = R; //R is the new parray value at k+1
	}
	for (int k = 0; k < 256; k += 2) {
		Encrypt(&L, &R); //encrypt the zeros
		sbox2[k] = L; //L is the new parray value at k
		sbox2[k + 1] = R; //R is the new parray value at k+1
	}
	for (int k = 0; k < 256; k += 2) {
		Encrypt(&L, &R); //encrypt the zeros
		sbox3[k] = L; //L is the new parray value at k
		sbox3[k + 1] = R; //R is the new parray value at k+1
	}

	//Begin actual encryption
	cin >> in; //read in from standard input

	stringstream Left, Right;

	for (int l = 0; l < in.length(); l++) {
		if (l < 4) {
			Left << hex << (int) in[l];
		}
		else {
			Right << hex << (int)in[l];
		}
	}

	Lin = Left.str();
	Rin = Right.str();

	L = stol(Lin, NULL, 16); //converts the input into hex
	R = stol(Rin, NULL, 16); //converts the input into hex

	cout << "Pre-encrypted message: " << in << endl;

	Encrypt(&L, &R); //encrypt the message

	cout << "Ciphertext: " << hex << L << R << endl;

	Decrypt(&L, &R);

	cout << "Decrypted ASCII values: " << L << R;


}

//takes in a hex value S and splits it into 4 pieces
//these pieces are used as input into the S-boxes the outputs of the S-boxes
//are added mod 2^32 and XOR with one another to get the final output
unsigned int F(unsigned int S) {
	unsigned int H = sbox0[S >> 24] + sbox1[S >> 16 & 0xff]; //create H by giving 8 bits to sbox0 and combining that with the result of the next 8 bits in sbox1
	H ^= sbox2[S >> 8 & 0xff]; //XOR H and the next result from sbox2. 
	return (H += sbox3[S & 0xff]); //return H + the results of the last s-box. 
//You will see "& 0xff" becuase it performs an AND that essentially ignores all the bits but what we want.
}

//encrypts some ascii values(plaintext) using the given key, s-boxes, and the function "F".
void Encrypt(unsigned int *Lin, unsigned int *Rin) {

	unsigned int hold;  //used to swap L and R

	unsigned int L = *Lin;
	unsigned int R = *Rin;

	//this loop will encrypt the message that was read in
	for (int k = 0; k < 16; k++) {

		L ^= parray[k];   //XOR L with the parray value at k
		R ^= F(L);        //XOR R with the results of F on the new L

						  //swap L and R
		hold = L;
		L = R;
		R = hold;

	}

	//swap back after final round
	hold = L;
	L = R;
	R = hold;

	//XOR once more by the final parray values
	L ^= parray[17];
	R ^= parray[16];

	*Lin = L;
	*Rin = R;
}

//decrypts some ciphertext using the given key, s-boxes, and the function "F".
void Decrypt(unsigned int *Lin, unsigned int *Rin) {

	unsigned int hold;  //used to swap L and R
	unsigned int L = *Lin;
	unsigned int R = *Rin;


	//this loop will encrypt the message that was read in
	for (int k = 16; k > 0; k--) {

		L ^= parray[k + 1];   //XOR L with the parray value at k + 1
		R ^= F(L);            //XOR R with the results of F on the new L

						  //swap L and R
		hold = L;
		L = R;
		R = hold;

	}

	//swap back after final round
	hold = L;
	L = R;
	R = hold;

	//XOR once more by the final parray values
	L ^= parray[0];
	R ^= parray[1];

	*Lin = L;
	*Rin = R;
}
