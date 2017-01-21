#ifndef ARRAY_H_
#define ARRAY_H_

#include <stdlib.h>
#include <string.h>

inline void realloc_array(size_t sz, void *array, size_t *len)
{
	*(void **)array = realloc(*(void **)array, *len * sz);
}

inline void free_array(size_t sz, void *array, size_t *len)
{
	free(*(void **)array);
	*len = 0;
}

inline void grow_array(size_t sz, void *array, size_t *len)
{
	(*len)++;
	realloc_array(sz, array, len);
}

inline void shrink_array(size_t sz, void *array, size_t *len)
{
	(*len)--;
	realloc_array(sz, array, len);
}

inline void remove_array(size_t sz, void *array, size_t *len, int at)
{
	memmove(*(void **)array + at * sz, *(void **)array + (at + 1) * sz, (*len - at - 1) * sz);
	shrink_array(sz, array, len);
}

#endif
