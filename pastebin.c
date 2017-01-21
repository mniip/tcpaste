#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#include <postgresql/libpq-fe.h>

#include "logging.h"
#include "pastebin.h"
#include "config.h"

char const filename_chars[] = {'_','0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
static size_t filename_chars_len = sizeof filename_chars / sizeof *filename_chars;

int approx_pastes = 0;

char const *make_filename()
{
	int exp = (approx_pastes + 1) * 1000;
	int length = 1;
	while(exp /= filename_chars_len)
		length++;
	static char buffer[4096];
	int i;
	for(i = 0; i < length; i++)
		buffer[i] = filename_chars[rand() % filename_chars_len];
	buffer[i] = 0;
	return buffer;
}

char const *unique_filename(char const *prefix)
{
	static char buffer[8192];
	strcpy(buffer, prefix);
	size_t prefix_len = strlen(prefix);
	do
	{
		strcpy(buffer + prefix_len, make_filename());
	}
	while(!access(buffer, F_OK));
	return buffer + prefix_len;
}

char const hexdigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

char const *generate_key()
{
	static char buffer[65];
	int i;
	for(i = 0; i < 64; i++)
		buffer[i] = hexdigits[rand() % 16];
	return buffer;
}

PGconn *conn;

void paste_cleanup()
{
	PQfinish(conn);
}

void paste_init()
{
	srand(time(NULL));
	conn = PQconnectdb(CONFIG_DB);
	if(PQstatus(conn) != CONNECTION_OK)
		panic("Cannot connect to the database: %s", PQerrorMessage(conn));
	PGresult *res = PQexec(conn, "SELECT COUNT(*) FROM pastes WHERE status = 'existing';");
	if(PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		PQclear(res);
		panic("Could not fetch paste amount: %s", PQerrorMessage(conn));
	}
	if(0 >= sscanf(PQgetvalue(res, 0, 0), "%d", &approx_pastes))
	{
		PQclear(res);
		panic("Could not read paste amount: %s", strerrno);
	}
	PQclear(res);
	log_append("Have %d pastes", approx_pastes);
}

paste *new_paste(char const *ip, char const *ext)
{
	char const *id = unique_filename(CONFIG_FS_PREFIX);
	char filename[8192];
	strcpy(filename, CONFIG_FS_PREFIX);
	strcat(filename, id);
	int fd = open(filename, O_WRONLY | O_CREAT, 0644);
	if(fd == -1)
	{
		log_append("Could not open file '%s': %s", filename, strerrno);
		return NULL;
	}
	char const *key = generate_key();
	char const *params[3] = {id, key, ip};
	PGresult *res = PQexecParams(conn, "INSERT INTO pastes (filename, key, created, lifespan, ip, status) VALUES ($1, $2, CURRENT_TIMESTAMP, INTERVAL '30 days', $3, 'existing');", 3, NULL, params, NULL, NULL, 0);
	if(PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		log_append("Could not execute SQL statement: %s", PQerrorMessage(conn));
		close(fd);
		unlink(filename);
		PQclear(res);
		return NULL;
	}
	PQclear(res);
	paste *ret = malloc(sizeof(paste));
	ret->id = strdup(id);
	ret->key = strdup(key);
	ret->desc = fd;
	approx_pastes++;
	return ret;
}
