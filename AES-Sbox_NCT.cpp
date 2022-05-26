#include<stdio.h>
#include<iostream>
#include <iomanip>
using namespace std;
uint8_t sbox[256] = {
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/*
We divide the classical implementation of AES S-box into three parts: denoted by f_1, S_4, f_2, respectively.
	-f_1: the first part, is aimed at generating the intputs of the 4-bit S-box;
	-S_4: the second part, the 4-bit S-box;
	-f_2: the third part, generates the outputs of AES S-box.

	Note that we only transform f_1 and f_2 to be reversible, since the public tool LIGHTER is used to implement S_4.
*/

/*
the first part, i.e., f_1, costs 5 ancilla qubits: t_21, t_22, t_23, t_24, a. 
a should be reset and be reused to construct the in-place implementation of S_4.


#Toffoli gates: 12
#CNOT gates:    50
#Pauli X gates: 0
Toffoli depth:  3
The circuit of f_1 will be applied twice.
*/
void f_1(int *x,int *t)
{
	int a = 0;//ancilla qubit
	////////////////////The NCT-base circuit of f_1 with Toffoli depth 3////////////////////////////////
x[0] = x[0] ^ x[3] ^ x[5] ^ x[6];
x[5] = x[5] ^ x[0] ^ x[4];
x[1] = x[1] ^ x[2] ^ x[3] ^ x[7];
x[3] = x[3] ^ x[5] ^ x[0] ^ x[4];
x[6] = x[6] ^ x[0] ^ x[2];
x[4] = x[4] ^ x[1] ^ x[5] ^ x[6] ^ x[0] ^ x[2];
x[2] = x[2] ^ x[3] ^ x[4] ^ x[5];
	t[21] = t[21] ^ x[0]&x[5];
	t[22] = t[22] ^ x[1]&x[7];
	t[23] = t[23] ^ x[3]&x[6];
	t[24] = t[24] ^ x[4]&x[2];
	t[22] = t[22] ^ t[21];
	t[21] = t[21] ^ t[23];

x[0] = x[0] ^ x[3];
x[5] = x[5] ^ x[6];
x[1] = x[1] ^ x[0] ^ x[3];
x[7] = x[7] ^ x[5] ^ x[6];
x[4] = x[4] ^ x[1] ^ x[0];
x[2] = x[2] ^ x[7] ^ x[5];
x[3] = x[3] ^ x[4];
x[6] = x[6] ^ x[2];
	t[23] = t[23] ^ x[0]&x[5];
	t[21] = t[21] ^ x[1]&x[7];
	t[24] = t[24] ^ x[4]&x[2];
	a = a ^ x[3]&x[6];
	t[21] = t[21] ^ a;
	t[22] = t[22] ^ a;
	t[23] = t[23] ^ a;
	t[24] = t[24] ^ a;

x[1] = x[1] ^ x[4];
x[7] = x[7] ^ x[2];
	t[22] = t[22] ^ x[4]&x[2];
	t[23] = t[23] ^ x[1]&x[7];
	t[24] = t[24] ^ x[0]&x[5];
	a = a ^ x[3]&x[6];
	//cout<<a; //to check that if the ancilla qubit has been reset or not;

x[6] = x[6] ^ x[3];
x[4] = x[4]^ x[2];
x[0] = x[0] ^ x[5];

	t[21] = t[21] ^ x[6];
	t[22] = t[22] ^ x[4];
	t[23] = t[23] ^ x[0];
x[0] = x[0] ^ x[1] ^ x[7];
	t[24] = t[24] ^ x[0];
}

/*
the second part, i.e., S_4, only one ancilla qubit is required, denoted by a.
since f_2 requires no ancilla qubit, it is no need to reset a in S_4.

#Toffoli gates: 6
#CNOT gates:    4
#Pauli X gates: 0
Toffoli depth:  6
The circuit of S_4 will be applied twice.
*/
void S_4(int *t)
{
	t[23] = t[23] ^ (t[22] & t[24]);
	t[24] = t[24] ^ t[23];
	t[22] = t[22] ^ (t[21] & t[24]);
	t[24] = t[24] ^ (t[22] & t[23]);
	t[23] = t[23] ^ t[24];
	t[22] = t[22] ^ t[21];
	t[21] = t[21] ^ (t[22] & t[24]);
	int a = 0;
	a = a ^ (t[23] & t[22]);
	t[24] = t[24] ^ (a & t[21]);
	t[21] = t[21] ^ t[22];
	// t[29] = t[21];
	// t[33] = t[23];
	// t[37] = t[24];
	// t[40] = t[22];
}

/*the third part, i.e., f_2

#Toffoli gates: 21
#CNOT gates:    65
#Pauli X gates: 4
Toffoli depth:  6
	Partial linear operations in the circuit of f_2 will be applied twice, specifically,
the outputs of f_1 and S_4 have been changed by f_2, in order to reuse the operations in 
S_4 and f_1 in inverse order to reset the allocated 5 ancilla qubits, we should recover 
the outputs of S_4 and f_1 from the outputs of f_2, and the following two cases should be
considered:
		1. for the case that the values of S-box's outputs are all 0s,
				the linear operations in f_2 formed as 't_i = t_i ^ t_j ^ ... ^ t_k' and 
				'x_i = x_i ^ x_j ^...^ x_k' should be applied again in inverse order to 
				recover the outputs of S_4 and f_1 from the outputs of f_2.
				in all, 50 CNOT gates are required.
		2. for the case that the values of S-box's outputs are not all 0s,
				except the operations in case 1 should be applied, the operation formed
				as 's_i = s_i ^ s_j' in f_2 should be applied to remove the influence of
				non-zero s_j.
				in all, 50 + 15 CNOT gates are required.
						
*/
void f_2(int *x, int * t, int *s)
{
	for(int i = 0; i < 8; i++)
	{
		s[i] = 0;
	}

/*
//These 15 operations are for the transformation that maps |x>|y>|0> to |x>|y^S(x)>|0>. 
s[1] = s[1] ^ s[0];
s[4] = s[4] ^ s[3]; 
s[6] = s[6] ^ s[7];
s[7] = s[7] ^ s[4];
s[3] = s[3] ^ s[1];
s[0] = s[0] ^ s[3]; 
s[2] = s[2] ^ s[0];
s[5] = s[5] ^ s[2];
s[2] = s[2] ^ s[6];
s[4] = s[4] ^ s[6];
s[3] = s[3] ^ s[5];
s[1] = s[1] ^ s[6];
s[7] = s[7] ^ s[2];
s[6] = s[6] ^ s[0];
s[0] = s[0] ^ s[4];
*/
//////////////////The NCT-based circuit of f_2 with Toffoli depth 6//////////// 
x[4] = x[4] ^ x[1] ^ x[2];
x[6] = x[6] ^ x[5] ^ x[2] ^ x[3]; 
t[22] = t[22] ^ t[21];
t[24] = t[24];
t[23] = t[23] ^ t[24];
t[21] = t[21] ^ t[23] ^ t[24];	
	s[0] = s[0] ^ t[22]&x[5];//1-1
	s[5] = s[5] ^ t[24]&x[4];//1-2
	s[6] = s[6] ^ t[23]&x[6];//1-3
	s[2] = s[2] ^ t[21]&x[3];//1-4

x[5] = x[5] ^ x[0] ^ x[1] ^ x[7]; 
x[4] = x[4] ^ x[3] ^ x[1]; 
//t[22] = t[22];
t[23] = t[23] ^ t[22];
t[24] = t[24] ^ t[21] ^ t[23];
	s[2] = s[2] ^ t[22]&x[5];//2-1
	s[5] = s[5] ^ t[23]&x[4];//2-2
	s[4] = s[4] ^ t[24]&x[7];//2-3
	
	s[0] = s[0] ^ s[4];
	s[6] = s[6] ^ s[0];
	s[7] = s[7] ^ s[2];
	s[1] = s[1] ^ s[6];
	s[3] = s[3] ^ s[5];

x[6] = x[6] ^ x[7] ^ x[2]; 
x[5] = x[5] ^ x[6] ^ x[0] ^ x[1] ^ x[2];
t[21] = t[21] ^ t[24] ^ t[22];
t[22] = t[22] ^ t[21] ^ t[24];
	s[6] = s[6] ^ t[21]&x[6];//3-1
	s[3] = s[3] ^ t[22]&x[3];//3-2
	s[0] = s[0] ^ t[23]&x[5];//3-3
	
	s[4] = s[4] ^ s[6];

x[2] = x[2] ^ x[5];
x[0] = x[0] ^ x[6] ^ x[2];
t[21] = t[21] ^ t[22];
	s[6] = s[6] ^ t[23]&x[5];//4-1
	s[0] = s[0] ^ t[22]&x[2];//4-2
	s[7] = s[7] ^ t[24]&x[1];//4-3
	s[2] = s[2] ^ t[21]&x[0];//4-4

x[5] = x[5] ^ x[2];
x[7] = x[7] ^ x[5]; 
x[6] = x[6] ^ x[2]; 
x[0] = x[0] ^ x[4] ^ x[1]; 
t[22] = t[22] ^ t[23];
t[24] = t[24] ^ t[22]; 

t[23] = t[23] ^ t[21] ^ t[24] ^ t[22];
	s[6] = s[6] ^ t[22]&x[5];//5-1
	s[1] = s[1] ^ t[24]&x[7];//5-2
	s[4] = s[4] ^ t[21]&x[6];//5-3
	s[3] = s[3] ^ t[23]&x[0];//5-4
	
	s[2] = s[2] ^ s[6];
	s[5] = s[5] ^ s[2]; 
	s[2] = s[2] ^ s[0];
	s[0] = s[0] ^ s[3]; 
	s[3] = s[3] ^ s[1]; 
	s[7] = s[7] ^ s[4];

x[4] = x[4] ^ x[3];
x[3] = x[3] ^ x[4]; 
x[1] = x[1] ^ x[0] ^ x[4];
t[23] = t[23] ^ t[21] ^ t[24] ^ t[22];
t[21] = t[21] ^ t[23] ^ t[22]; 
	s[2] = s[2] ^ t[22]&x[4];//6-1 
	s[7] = s[7] ^ t[23]&x[3];//6-2
	s[5] = s[5] ^ t[21]&x[1];//6-3

	s[6] = s[6] ^ s[7]; 
	s[4] = s[4] ^ s[3]; 
	s[1] = s[1] ^ s[0]; 
	s[6] = s[6] ^ 1;
	s[7] = s[7] ^ 1;
	s[1] = s[1] ^ 1;
	s[2] = s[2] ^ 1;
}

void foward_sbox(int *x, int *s)
{
	int y[22] ={0};
	int t[68] ={0};
	f_1(x,t);
	S_4(t);
	f_2(x,t,s);
}
int main()
{
	int in[8] = {0};
	int out[8] = {0};

	for(int i = 0; i < 256; i++)
	{ 
		in[7] = (i & 1);
		in[6] = (i >> 1 & 1);
		in[5] = (i >> 2 & 1);
		in[4] = (i >> 3 & 1);
		in[3] = (i >> 4 & 1);
		in[2] = (i >> 5 & 1);
		in[1] = (i >> 6 & 1);
		in[0] = (i >> 7 & 1);

		foward_sbox(in, out);
		
		int sum = out[7] + out[6] * 2 + out[5] * 4 + out[4] * 8 + out[3] * 16 + out[2] *32 + out[1] *64 + out[0]*128;
		
		if((i != 0) && ((i % 16 == 0)))
		{
			cout<<endl;
		}
		if(sum == sbox[i])
		{
			cout<<"0 ";//match
		}
		else if(sum != sbox[i])
		{
			cout<<"1 ";
		}
		
	}
	cout<<endl;
	return 0;
}