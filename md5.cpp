#include "md5.h"

MD5::MD5()
{
}

MD5::~MD5()
{
}

void MD5::hash(std::string message)
{
const uint32_t S[64] =	{7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
						5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
						4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
						6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};

const uint32_t K[64] =	{0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
						0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
						0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
						0x6b901122,0xfd987193,0xa679438e,0x49b40821,
						0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
						0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
						0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
						0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
						0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
						0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
						0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
						0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
						0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
						0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
						0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
						0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};

	//Since we are going to pad with a 1 in the message, which would be b"10000000" or 0x80 or 128
	//We cannot use signed char (string) because their maximum value is 127
	std::vector<BYTE> byteMsg;
	for(size_t i = 0; i < message.length(); i++)
	{
		byteMsg.push_back(message[i]);
	}
	//Append a 1 after the message. It's fine to use an entire byte since this is all from a string anyway
	byteMsg.push_back((unsigned char) 0x80);
	//Append a lot of zeroes until the message length int bits mod 512 = 448
	while((byteMsg.size() * 8) % 512 != 448)
		byteMsg.push_back((unsigned char) 0x00);

	//Get the original length of the message. In case it is huge (>2^64) we mod it down.
	uint64_t originalLength = (message.length() * 8) % ((uint64_t) pow(2.0, 64));
	//Append the length of the original message to the end.
	for(int i = 0; i < 8; i++)
		byteMsg.push_back(originalLength >> i * 8); //Loss of data intended (guess it's possibly to use memcpy instead)

	//Initialize the registers
	uint32_t a0 = 0x67452301;
	uint32_t b0 = 0xefcdab89;
	uint32_t c0 = 0x98badcfe;
	uint32_t d0 = 0x10325476;

	//for every 512 bit block
	for(size_t i = 0; i < byteMsg.size(); i += 64)
	{
		//Split the 512 bit block into 16 blocks of 32 bits
		//Probably not needed but this is what wikipedia says
		std::vector<uint32_t> M;
		for(int j = 0; j < 64; j += 4)
		{
			uint32_t word =	byteMsg[i+j] ^
							byteMsg[i+j+1] << 8 ^
							byteMsg[i+j+2] << 16 ^
							byteMsg[i+j+3] << 24;
			M.push_back(word);
		}

		//Initialize the registers for this round
		uint32_t A = a0;
		uint32_t B = b0;
		uint32_t C = c0;
		uint32_t D = d0;

		//This is the main loop of MD5
		for(int j = 0; j < 64; j++)
		{
			uint32_t F, g;
			if(0 <= j && j <= 15) //These if statements can be more effective but this is how it's done according to wikipedia
			{
				F = (B & C) | ((~B) & D);
				g = j;
			}
			else if(16 <= j && j <= 31)
			{
				F = (D & B) | ((~D) & C);
				g = (5 * j + 1) % 16;
			}
			else if(32 <= j && j <= 47)
			{
				F = B ^ C ^ D;
				g = (3 * j + 5) % 16;
			}
			else if(48 <= j && j <= 63)
			{
				F = C ^ (B | (~D));
				g = (7 * j) % 16;
			}
			uint32_t tempD = D;
			D = C;
			C = B;
			B = B + rotateLeft32(A + F + K[j] + M[g], S[j]);
			A = tempD;
		}

		//And add up the registers. These WILL overflow, but appearantly that's
		//how MD5 works lol. No need to mod with 2^32
		a0 += A;
		b0 += B;
		c0 += C;
		d0 += D;
	}

	//And print it all
	uint8_t *p=(uint8_t *)&a0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], a0);
    p=(uint8_t *)&b0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], b0);
    p=(uint8_t *)&c0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], c0);
    p=(uint8_t *)&d0;
    printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], d0);

	return;
}

//Rotates bits to the left
uint32_t MD5::rotateLeft32(uint32_t val, int amount)
{
	amount %= 32;
	if(amount == 0)
		return val;
	return (val << amount) | (val >> (32 - amount));
}

//Input with spaces needs to be input like "message with spaces"
int main(int argc, char* argv[])
{
	if(argc < 2 || (strcmp(argv[1], "-h") == 0))
	{
		printf("Input a string value to hash, use quotation marks if it contains spaces like:\n"
				"MessageWithNoSpaces or \"Message With Spaces\"\n");
		return 0;
	}
	std::string message = argv[1];
	MD5 md5 = MD5();
	md5.hash(message);
	return 1;
}