#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <magic.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "array.h"
#include "logging.h"
#include "pastebin.h"
#include "extensions.h"
#include "config.h"

char const *format_sockaddr(struct sockaddr_storage const *storage)
{
	static char buffer[4096];
	static char ip[4096];
	if(storage->ss_family == AF_INET)
	{
		struct sockaddr_in const *addr = (struct sockaddr_in const *)storage;
		snprintf(buffer, 4096, "%s:%d", inet_ntop(storage->ss_family, &addr->sin_addr, ip, 4096), ntohs(addr->sin_port));
	}
	else if(storage->ss_family == AF_INET6)
	{
		struct sockaddr_in6 const *addr = (struct sockaddr_in6 const *)storage;
		snprintf(buffer, 4096, "[%s]:%d", inet_ntop(storage->ss_family, &addr->sin6_addr, ip, 4096), ntohs(addr->sin6_port));
	}
	return buffer;
}

void parse_sockaddr(struct sockaddr_storage *storage, char const *str, int port)
{
	if(strchr(str, ':'))
	{
		storage->ss_family = AF_INET6;
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
		addr->sin6_port = htons(port);
		inet_pton(AF_INET6, str, &addr->sin6_addr);
	}
	else
	{
		storage->ss_family = AF_INET;
		struct sockaddr_in *addr = (struct sockaddr_in *)storage;
		addr->sin_port = htons(port);
		inet_pton(AF_INET, str, &addr->sin_addr);
	}
}

char const *format_ip(struct sockaddr_storage const *storage)
{
	static char ip[4096];
	if(storage->ss_family == AF_INET)
	{
		struct sockaddr_in *addr = (struct sockaddr_in *)storage;
		inet_ntop(storage->ss_family, &addr->sin_addr, ip, 4096);
	}
	else if(storage->ss_family == AF_INET6)
	{
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
		inet_ntop(storage->ss_family, &addr->sin6_addr, ip, 4096);
	}
	return ip;
}

typedef struct
{
	int desc;
	struct sockaddr_storage addr;
	char const *ext;
	SSL_CTX *ssl;
}
server_fd;

typedef struct
{
	int desc;
	struct sockaddr_storage addr;
	int dead;
	int die_after_write;
	void *write_buffer;
	size_t write_buffer_len;
	struct timespec last_action;
	size_t written;
	paste *paste;
	server_fd *sfd;
	int sent_urls;
	void *header;

	SSL *ssl;
	int operation;
	int ssl_want;
	void *buffer_last;
	size_t buffer_len_last;
}
client_fd;

enum { OP_READ, OP_WRITE, OP_ACCEPT };

server_fd *listeners;
size_t listeners_len;

client_fd *clients;
size_t clients_len;

magic_t magic;

void queue_data(client_fd *fd, void const *data, size_t len)
{
	fd->write_buffer_len += len;
	fd->write_buffer = realloc(fd->write_buffer, fd->write_buffer_len);
	memcpy(fd->write_buffer + fd->write_buffer_len - len, data, len);
}

void queue_urls(client_fd *fd, char const *ext)
{
	char data[4096];
	snprintf(data, 4096, "URL %s%s%s\nADMIN %s%s\n",
			fd->sfd->ssl ? CONFIG_URL_ID_PREFIX_SSL : CONFIG_URL_ID_PREFIX,
			fd->paste->id,
			ext ? ext : "",
			fd->sfd->ssl ? CONFIG_URL_KEY_PREFIX_SSL : CONFIG_URL_KEY_PREFIX,
			fd->paste->key
		);
	queue_data(fd, data, strlen(data));
	fd->sent_urls = 1;
}

void try_check_type(client_fd *fd, int force)
{
	if(fd->sent_urls)
		return;
	if(fd->written < CONFIG_HEADER_SIZE && !force)
		return;
	char const *result = magic_buffer(magic, fd->header, fd->written > CONFIG_HEADER_SIZE ? CONFIG_HEADER_SIZE : fd->written);
	if(!result)
	{
		log_append("Magic autodetection failed for %s: %s", format_sockaddr(&fd->addr), magic_error(magic));
		queue_urls(fd, NULL);
	}
	else
	{
		char const *ext = mime_to_extension(result);
		log_append("Detected %s (%s) for %s", result, ext ? ext : "", format_sockaddr(&fd->addr));
		queue_urls(fd, ext);
	}
}

void add_client(server_fd *sfd)
{
	log_append("Client connecting to %s", format_sockaddr(&sfd->addr));
	struct sockaddr_storage storage;
	socklen_t addrlen = sizeof storage;
	int fd = accept(sfd->desc, (struct sockaddr *)&storage, &addrlen);
	if(fd == -1)
		panic("Could not accept from %s", format_sockaddr(&sfd->addr));
	SSL *ssl = NULL;
	if(sfd->ssl)
	{
		if(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK))
			panic("Could not set nonblocking socket");
		ssl = SSL_new(sfd->ssl);
		SSL_set_fd(ssl, fd);
	}
	grow_array(sizeof(client_fd), &clients, &clients_len);
	size_t c = clients_len - 1;
	clients[c].desc = fd;
	clients[c].sfd = sfd;
	memcpy(&clients[c].addr, &storage, addrlen);
	clients[c].dead = 0;
	clients[c].die_after_write = 0;
	clients[c].write_buffer = NULL;
	clients[c].write_buffer_len = 0;
	clock_gettime(CLOCK_MONOTONIC, &clients[c].last_action);
	clients[c].written = 0;
	clients[c].ssl = ssl;
	clients[c].paste = NULL;
	clients[c].header = NULL;
	clients[c].sent_urls = 0;
	if(ssl)
	{
		clients[c].ssl_want = SSL_ERROR_NONE;
		clients[c].operation = OP_ACCEPT;
		int err = SSL_get_error(clients[c].ssl, SSL_accept(clients[c].ssl));
		if(err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			clients[c].ssl_want = err;
		else
		{
			log_append("Client %s disconnected during accept: %s", format_sockaddr(&clients[c].addr), ERR_error_string(ERR_get_error(), NULL));
			clients[c].dead = 1;
			return;
		}
	}
	log_append("Client %s connected", format_sockaddr(&clients[c].addr));

	clients[c].paste = new_paste(format_ip(&clients[c].addr), sfd->ext);
	if(!clients[c].paste)
	{
		char const *data = "ERROR Could not create a new paste\n";
		queue_data(&clients[c], data, strlen(data));
		clients[c].die_after_write = 1;
	}
	else
	{
		log_append("Assigned id %s to %s", clients[c].paste->id, format_sockaddr(&clients[c].addr));
		if(!sfd->ext || *sfd->ext)
			queue_urls(&clients[c], sfd->ext);
	}
}

void read_data(client_fd *fd)
{
	if(!fd->dead)
	{
		ssize_t sz;
		static char buffer[CONFIG_READ_BUFFER];
		if(fd->ssl)
		{
			fd->operation = OP_READ;
			if(fd->ssl_want == SSL_ERROR_NONE)
			{
				fd->buffer_last = malloc(CONFIG_READ_BUFFER);
				fd->buffer_len_last = CONFIG_READ_BUFFER;
			}
			sz = SSL_read(fd->ssl, fd->buffer_last, fd->buffer_len_last);
			if(sz == -1)
			{
				int err = SSL_get_error(fd->ssl, sz);
				fd->ssl_want = err;
				if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
					return;
				else
				{
					log_append("Client %s read error: %s", format_sockaddr(&fd->addr), ERR_error_string(ERR_get_error(), NULL));
					fd->dead = 1;
					return;
				}
			}
			else
			{
				fd->ssl_want = SSL_ERROR_NONE;
				memcpy(buffer, fd->buffer_last, sz);
				free(fd->buffer_last);
			}
		}
		else
			sz = recv(fd->desc, &buffer, CONFIG_READ_BUFFER, 0);
		if(sz == -1)
		{
			log_append("Error while receiving from %s: %s", format_sockaddr(&fd->addr), strerrno);
			fd->dead = 1;
		}
		else if(sz)
		{
			clock_gettime(CLOCK_MONOTONIC, &fd->last_action);
			if(!fd->die_after_write && fd->paste)
			{
				size_t written = 0;
				do
				{
					size_t ret = write(fd->paste->desc, buffer + written, sz - written);
					if(ret == -1)
					{
						log_append("Error while writing to %s for %s: %s", fd->paste->id, format_sockaddr(&fd->addr), strerrno);
						char const *data = "ERROR Could not write\n";
						queue_data(fd, data, strlen(data));
						fd->die_after_write = 1;
						break;
					}
					written += ret;
				}
				while(written < sz);
				if(!fd->sent_urls && fd->written < CONFIG_HEADER_SIZE)
				{
					size_t newsize = fd->written + written;
					if(newsize > CONFIG_HEADER_SIZE)
						newsize = CONFIG_HEADER_SIZE;
					fd->header = realloc(fd->header, newsize);
					memcpy(fd->header + fd->written, buffer, newsize - fd->written);
				}
				fd->written += written;
				try_check_type(fd, 0);
				if(fd->written > CONFIG_MAX_SIZE)
				{
					log_append("Size limit exceeded for %s", format_sockaddr(&fd->addr));
					char const *data = "ERROR Size limit exceeded\n";
					queue_data(fd, data, strlen(data));
					fd->die_after_write = 1;
				}
			}
		}
		else
			fd->die_after_write = 1;
	}
}

void write_data(client_fd *fd)
{
	if(!fd->dead)
	{
		ssize_t sz;
		if(fd->ssl)
		{
			fd->operation = OP_WRITE;
			if(fd->ssl_want == SSL_ERROR_NONE)
			{
				fd->buffer_last = malloc(fd->write_buffer_len);
				memcpy(fd->buffer_last, fd->write_buffer, fd->write_buffer_len);
				fd->buffer_len_last = fd->write_buffer_len;
			}
			sz = SSL_write(fd->ssl, fd->buffer_last, fd->buffer_len_last);
			if(sz == -1)
			{
				int err = SSL_get_error(fd->ssl, sz);
				fd->ssl_want = err;
				if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
					return;
				else
				{
					log_append("Client %s write error: %s", format_sockaddr(&fd->addr), ERR_error_string(ERR_get_error(), NULL));
					fd->dead = 1;
					return;
				}
			}
			else
			{
				fd->ssl_want = SSL_ERROR_NONE;
				free(fd->buffer_last);
			}
		}
		else
			sz = send(fd->desc, fd->write_buffer, fd->write_buffer_len, 0);
		if(sz == -1)
		{
			log_append("Error while sending to %s: %s", format_sockaddr(&fd->addr), strerrno);
			fd->dead = 1;
		}
		else if(sz)
		{
			clock_gettime(CLOCK_MONOTONIC, &fd->last_action);
			fd->write_buffer_len -= sz;
			memmove(fd->write_buffer, fd->write_buffer + sz, fd->write_buffer_len);
			fd->write_buffer = realloc(fd->write_buffer, fd->write_buffer_len);
		}
		else
			fd->dead = 1;
	}
}

void eventloop()
{
	log_append("Entering event loop");
	fd_set reads, writes;
	struct timeval timeout;
	while(1)
	{
		FD_ZERO(&reads);
		FD_ZERO(&writes);
		size_t i;
		int nfds = 0;
		for(i = 0; i < listeners_len; i++)
		{
			FD_SET(listeners[i].desc, &reads);
			if(listeners[i].desc > nfds)
				nfds = listeners[i].desc;
		}
		for(i = 0; i < clients_len; i++)
		{
			if(clients[i].ssl ? clients[i].ssl_want == SSL_ERROR_WANT_READ || (clients[i].ssl_want == SSL_ERROR_NONE && !clients[i].die_after_write) : !clients[i].die_after_write)
				FD_SET(clients[i].desc, &reads);
			if(clients[i].ssl ? clients[i].ssl_want == SSL_ERROR_WANT_WRITE || (clients[i].ssl_want == SSL_ERROR_NONE && clients[i].write_buffer_len) : clients[i].write_buffer_len)
				FD_SET(clients[i].desc, &writes);
			if(clients[i].desc > nfds)
				nfds = clients[i].desc;
		}
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		int ret;
		do
		{
			errno = 0;
			ret = select(nfds + 1, &reads, &writes, NULL, &timeout);
		}
		while(errno == EINTR);
		if(ret == -1)
			panic("Error in select: %s", strerrno);
		struct timespec tm;
		clock_gettime(CLOCK_MONOTONIC, &tm);
		for(i = 0; i < clients_len; i++)
			if(clients[i].last_action.tv_sec < tm.tv_sec - CONFIG_TIMEOUT && !clients[i].die_after_write)
			{
				log_append("Timed out: %s", format_sockaddr(&clients[i].addr));
				char const *data = "ERROR Timed out\n";
				queue_data(&clients[i], data, strlen(data));
				clients[i].die_after_write = 1;
			}
		for(i = 0; i < listeners_len; i++)
			if(FD_ISSET(listeners[i].desc, &reads))
				add_client(&listeners[i]);
		for(i = 0; i < clients_len; i++)
		{
			if(clients[i].ssl)
			{
				if(clients[i].ssl_want != SSL_ERROR_NONE && (clients[i].ssl_want == SSL_ERROR_WANT_READ ? FD_ISSET(clients[i].desc, &reads) : FD_ISSET(clients[i].desc, &writes)))
				{
					if(clients[i].operation == OP_READ)
						read_data(&clients[i]);
					else if(clients[i].operation == OP_WRITE)
						write_data(&clients[i]);
					else if(clients[i].operation == OP_ACCEPT)
					{
						int err = SSL_get_error(clients[i].ssl, SSL_accept(clients[i].ssl));
						if(err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
							clients[i].ssl_want = err;
						else
						{
							log_append("Client %s disconnected during accept: %s", format_sockaddr(&clients[i].addr), ERR_error_string(ERR_get_error(), NULL));
							clients[i].dead = 1;
						}
					}
				}
				else if(FD_ISSET(clients[i].desc, &writes))
					write_data(&clients[i]);
				else if(FD_ISSET(clients[i].desc, &reads))
					read_data(&clients[i]);
			}
			else
			{
				if(FD_ISSET(clients[i].desc, &reads))
					read_data(&clients[i]);
				if(FD_ISSET(clients[i].desc, &writes))
					write_data(&clients[i]);
			}
		}
		for(i = 0; i < clients_len; )
		{
			if(!clients[i].sent_urls && (tm.tv_sec - clients[i].last_action.tv_sec) * 1000000000 + tm.tv_nsec - clients[i].last_action.tv_nsec > CONFIG_MAGIC_DELAY_NS && !clients[i].die_after_write)
				try_check_type(&clients[i], 1);
			if(clients[i].die_after_write && !clients[i].write_buffer_len)
				clients[i].dead = 1;
			if(clients[i].dead)
			{
				log_append("Client %s disconnected", format_sockaddr(&clients[i].addr));
				free(clients[i].write_buffer);
				free(clients[i].header);
				if(clients[i].ssl)
				{
					SSL_free(clients[i].ssl);
					if(clients[i].ssl_want != SSL_ERROR_NONE && clients[i].operation != OP_ACCEPT)
						free(clients[i].buffer_last);
				}
				shutdown(clients[i].desc, SHUT_RDWR);
				close(clients[i].desc);
				if(clients[i].paste)
				{
					close(clients[i].paste->desc);
					free(clients[i].paste->id);
					free(clients[i].paste->key);
					free(clients[i].paste);
				}
				remove_array(sizeof(client_fd), &clients, &clients_len, i);
			}
			else
				i++;
		}
	}
}

void add_listener(void *addr, size_t addr_size, char const *ext, SSL_CTX *ssl)
{
	log_append("Binding to %s", format_sockaddr(addr));
	int fd = socket(((struct sockaddr_storage *)addr)->ss_family, SOCK_STREAM, 0);
	if(fd == -1)
		panic("Could not create a socket: %s", strerrno);
	int one = 1;
	if(-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one))
		panic("Could not set SO_REUSEADDR: %s", strerrno);
	if(((struct sockaddr_storage *)addr)->ss_family == AF_INET6)
		if(-1 == setsockopt(fd, SOL_IPV6, IPV6_V6ONLY, &one, sizeof one))
			panic("Could not set IPV6_V6ONLY: %s", strerrno);
	if(bind(fd, (struct sockaddr *)addr, addr_size))
		panic("Could not bind: %s", strerrno);
	if(listen(fd, SOMAXCONN))
		panic("Could not listen: %s", strerrno);
	grow_array(sizeof(server_fd), &listeners, &listeners_len);
	size_t l = listeners_len - 1;
	listeners[l].desc = fd;
	listeners[l].ext = ext;
	listeners[l].ssl = ssl;
	memcpy(&listeners[l].addr, addr, addr_size);
	if(ext)
		log_append("Listening on %s (%s)", format_sockaddr(addr), ext);
	else
		log_append("Listening on %s", format_sockaddr(addr));
}

void cleanup()
{
	signal(SIGHUP, SIG_IGN);
	paste_cleanup();
	log_append("Cleaning up");
	size_t i;
	for(i = 0; i < listeners_len; i++)
	{
		close(listeners[i].desc);
		if(listeners[i].ssl)
			SSL_CTX_free(listeners[i].ssl);
	}
	free_array(sizeof(server_fd), &listeners, &listeners_len);
	for(i = 0; i < clients_len; i++)
	{
		close(clients[i].desc);
		free(clients[i].write_buffer);
		if(clients[i].ssl && clients[i].ssl_want != SSL_ERROR_NONE && clients[i].operation != OP_ACCEPT)
			free(clients[i].buffer_last);
	}
	free_array(sizeof(client_fd), &clients, &clients_len);
}

SSL_CTX *new_ctx()
{
	SSL_CTX *ssl = SSL_CTX_new(SSLv23_server_method());
	if(!ssl)
		panic("Could not initialize SSL");
	if(!SSL_CTX_set_cipher_list(ssl, CONFIG_CIPHER_LIST))
		panic("Could not load ciphers");
	SSL_CTX_use_certificate_chain_file(ssl, CONFIG_CERT_FILE);
	SSL_CTX_use_PrivateKey_file(ssl, CONFIG_KEY_FILE, SSL_FILETYPE_PEM);
	if(!SSL_CTX_check_private_key(ssl))
		panic("Could not verify SSL certificate");
	return ssl;
}

void reload_certs()
{
	size_t i;
	for(i = 0; i < listeners_len; i++)
		if(listeners[i].ssl)
		{
			SSL_CTX *old = listeners[i].ssl;
			listeners[i].ssl = new_ctx();
			SSL_CTX_free(old);
		}
}

void sighup(int unused)
{
	paste_cleanup();
	paste_init();
	reload_certs();
}

int main()
{
	paste_init();
	magic = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_APPTYPE | MAGIC_NO_CHECK_CDF | MAGIC_NO_CHECK_COMPRESS | MAGIC_NO_CHECK_ELF | MAGIC_NO_CHECK_ENCODING | MAGIC_NO_CHECK_TAR | MAGIC_NO_CHECK_TOKENS);
	if(!magic)
		panic("Could not initialize libmagic");
	if(magic_load(magic, NULL))
		panic("Could not load magic database: %s", magic_error(magic));
	log_append("TCPaste initializing");
	SSL_library_init();
	SSL_load_error_strings();
	atexit(cleanup);
	int ports[] = CONFIG_PORTS;
	char const *exts[] = CONFIG_EXTS;
	int have_ssl[] = CONFIG_SSL;
	char const *bindhosts[] = CONFIG_BINDHOSTS;
	int i;
	for(i = 0; i < sizeof ports / sizeof *ports; i++)
	{
		struct sockaddr_storage storage;
		parse_sockaddr(&storage, bindhosts[i], ports[i]);
		add_listener(&storage, sizeof(struct sockaddr_storage), exts[i], have_ssl[i] ? new_ctx() : NULL);
	}
	signal(SIGHUP, sighup);
	eventloop();
	return 0;
}
