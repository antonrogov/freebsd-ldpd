#include "ldpd.h"


static int _mm_count = 0;


void *mpls_malloc(mpls_size_type size)
{
	void *mem = malloc(size);
	if(mem)
		_mm_count++;
	return mem;
}


void mpls_free(void *mem)
{
	_mm_count--;
	free(mem);
}


void mpls_mm_results()
{
	printf("Info: LDP memory results: %d\n", _mm_count);
}
