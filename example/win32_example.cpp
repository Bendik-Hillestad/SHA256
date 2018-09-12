#include "../src/sha256.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#if !defined(EXIT_SUCCESS)
#	define EXIT_SUCCESS 0
#endif

#if !defined(EXIT_FAILURE)
#	define EXIT_FAILURE 1
#endif

DWORD CALLBACK mainCRTStartup()
{
	using namespace bkh;
	
	//The input and expected message digest
    u8 input   []{'a', 'b', 'c'};
	u8 expected[]
	{ 
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
    
	//Compute digest
    u8 dig[sha256::digest_length];
    sha256::compute_hash(input, sizeof(input), dig);
	
	//Check if the digest matches what we expect
	bool eq = true;
	for (int i = 0; i < sha256::digest_length; i++)
	{
		if (dig[i] != expected[i])
		{
			eq = false;
			break;
		}
	}

    return eq ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * The compiler is stupid and replaces some code with its intrinsic memcpy which it can
 * no longer find because the CRT is not included.
 */
extern "C"
{
    #pragma function(memcpy)
    void* memcpy(void* dst, void const* src, unsigned long long size)
    {
        for (unsigned long long i = 0; i < size; i++)
            static_cast<char*>(dst)[i] = static_cast<char const*>(src)[i];

        return dst;
    }
};
