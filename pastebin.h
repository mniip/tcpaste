#ifndef PASTEBIN_H_
#define PASTEBIN_H_

typedef struct
{
	int desc;
	char *id;
	char *key;
}
paste;

extern void paste_init();
extern void paste_cleanup();
extern paste *new_paste(char const *, char const *);
#endif
