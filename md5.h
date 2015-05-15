#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <cmath>
#include <string>
#include <vector>

typedef unsigned char BYTE;

class MD5
{
private:
	uint32_t rotateLeft32(uint32_t val, int amount);
public:
	MD5();
	~MD5();
	void hash(std::string message);
};

#endif