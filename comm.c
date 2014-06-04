/*
 * comm.c: functions for communicating between a backend and a frontend
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "pgcov.h"

#include "miscadmin.h"
#include "lib/stringinfo.h"
#include "nodes/pg_list.h"
#include "utils/memutils.h"


static MemoryContext pgcov_protocol_parse_mcxt = NULL;


const char* hello_magic = "\x7A\x99\xBC\x01";


static void init_pgcovNetworkConn(pgcovNetworkConn *conn, int sockfd);

static void nw_append_string(pgcovNetworkConn *conn, const char *str);
static void nw_append_binary(pgcovNetworkConn *conn, const char *str, int len);
static void nw_replace_uint32(char *ptr, uint32 value);
static void nw_append_uint32(pgcovNetworkConn *conn, uint32 value);
static void nw_append_int32(pgcovNetworkConn *conn, int32 value);
static void nw_append_byte(pgcovNetworkConn *conn, uint8_t value);
static void nw_append_msg(pgcovNetworkConn *conn, pgcovProtocolMessageType msg);
static void nw_flush_msg(pgcovNetworkConn *conn);
static void nw_flush_buffer(pgcovNetworkConn *conn);
static void nw_shutdown(pgcovNetworkConn *conn);

static uint32 nw_peek_uint32(const char *ptr);
static bool nw_buf_has_message(pgcovNetworkConn *conn);

static void pgcov_nest_accept(pgcovNest *nest);
static void pgcov_nest_read_from_worker(pgcovNest *nest, pgcovWorker *worker);
static void pgcov_nest_shutdown(pgcovNest *nest);


static void
init_pgcovNetworkConn(pgcovNetworkConn *conn, int sockfd)
{
	initStringInfo(&conn->sendbuf);
	enlargeStringInfo(&conn->sendbuf, 1024);
	conn->sockfd = sockfd;
}

static void
nw_append_string(pgcovNetworkConn *conn, const char *str)
{
	if (str != NULL)
	{
		int len = strlen(str);
		nw_append_uint32(conn, (uint32) len);
		nw_append_binary(conn, str, len + 1);
	}
	else
		nw_append_uint32(conn, 0x80000001);
}

static void
nw_append_binary(pgcovNetworkConn *conn, const char *str, int len)
{
	appendBinaryStringInfo(&conn->sendbuf, str, len);
}

static void
nw_replace_uint32(char *ptr, uint32 value)
{
	unsigned char *b = (unsigned char *) ptr;
	b[0] = (value & 0xFF000000) >> 24;
	b[1] = (value & 0x00FF0000) >> 16;
	b[2] = (value & 0x0000FF00) >> 8;
	b[3] = (value & 0x000000FF);
}

static void
nw_append_uint32(pgcovNetworkConn *conn, uint32 value)
{
	char b[4];
	nw_replace_uint32(b, value);
	return nw_append_binary(conn, b, 4);
}

static void
nw_append_int32(pgcovNetworkConn *conn, int32 value)
{
	return nw_append_uint32(conn, (uint32) value);
}

static void
nw_append_byte(pgcovNetworkConn *conn, uint8_t value)
{
	appendStringInfoCharMacro(&conn->sendbuf, value);
}

static void
nw_append_msg(pgcovNetworkConn *conn, pgcovProtocolMessageType msg)
{
	nw_append_byte(conn, (uint8_t) msg);
	/* reserve 4 bytes for the message length */
	nw_append_uint32(conn, 0);
}

static void
nw_flush_msg(pgcovNetworkConn *conn)
{
	Assert(conn->sendbuf.len >= 5);
	nw_replace_uint32(conn->sendbuf.data + 1, conn->sendbuf.len - 1);
	nw_flush_buffer(conn);
}

static void
nw_flush_buffer(pgcovNetworkConn *conn)
{
	int i;
	int sent;
	int ret;

	Assert(conn->sendbuf.len > 0);

	sent = 0;
	for (i = 0; i < 5; i++)
	{
		/* TODO: implement timeout here */
		ret = write(conn->sockfd, conn->sendbuf.data + sent, conn->sendbuf.len - sent);
		if (ret == -1 && errno == EINTR)
			continue;
		else if (ret == -1)
			elog(ERROR, "could not send data to the listener: %s", strerror(errno));
		else if (ret == 0)
			elog(FATAL, "connection closed by the listener");

		sent += ret;
		if (sent == conn->sendbuf.len)
		{
			resetStringInfo(&conn->sendbuf);
			return;
		}
	}

	elog(FATAL, "could not flush %d bytes of data after 5 attempts", conn->sendbuf.len);
}

static void
nw_client_done(pgcovNetworkConn *conn)
{
	Assert(conn->sendbuf.len == 0);

	/*
	 * Send the DONE message and give the "nest" process a chance to close the
	 * connection.  This should ensure that we don't lose messages under normal
	 * operation.
	 */
	nw_append_msg(conn, PGCOV_MSG_DONE);
	nw_flush_msg(conn);

	for (;;)
	{
		int ret;
		struct timeval tv;
		fd_set readfds;
		char buf;

		FD_ZERO(&readfds);
		FD_SET(conn->sockfd, &readfds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		ret = select(conn->sockfd + 1, &readfds, NULL, NULL, &tv);
		if (ret == -1 && errno != EINTR)
			elog(ERROR, "select() failed: %s", strerror(errno));
		else if (ret == -1)
		{
			CHECK_FOR_INTERRUPTS();
			continue;
		}
		else if (ret == 0)
		{
			elog(WARNING, "connection not closed by the server after PGCOV_MSG_DONE");
			break;
		}

		ret = recv(conn->sockfd, &buf, 1, 0);
		if (ret == -1 && errno == EINTR)
		{
			CHECK_FOR_INTERRUPTS();
			continue;
		}
		else if (ret != 0)
		{
			Assert(ret == -1);
			elog(WARNING, "recv() failed: %d, %s", ret, strerror(errno));
		}
		/* closed, we're done */
		break;
	}
	nw_shutdown(conn);
}

static void
nw_shutdown(pgcovNetworkConn *conn)
{
	if (conn->sendbuf.data != NULL)
		pfree(conn->sendbuf.data);
	(void) shutdown(conn->sockfd, SHUT_RDWR);
	close(conn->sockfd);
}


static uint32
nw_peek_uint32(const char *ptr)
{
	unsigned char *b = (unsigned char *) ptr;
	uint32 value;

	value = ((uint32) b[0]) << 24;
	value |= ((uint32) b[1]) << 16;
	value |= ((uint32) b[2]) << 8;
	value |= ((uint32) b[3]);
	return value;
}

static bool
nw_buf_has_message(pgcovNetworkConn *conn)
{
	if (conn->rcvbuf.len < 5)
		return false;
	return conn->rcvbuf.len >= nw_peek_uint32(conn->rcvbuf.data + 1);
}

/*
 * Discards the first message in conn->rcvbuf.  A message must exist.
 */
static void
nw_buf_discard_message(pgcovNetworkConn *conn)
{
	Assert(nw_buf_has_message(conn));
	int32 msglen = (int32) nw_peek_uint32(conn->rcvbuf.data + 1) + 1;
	Assert(conn->rcvbuf.len >= msglen);
	int32 remaining = conn->rcvbuf.len - msglen;
	if (remaining > 0)
	{
		memmove(conn->rcvbuf.data, conn->rcvbuf.data + msglen, remaining);
		conn->rcvbuf.len -= msglen;
	}
	else
		conn->rcvbuf.len = 0;
}

static PGCOV_MESSAGE_PARSE_FUNC(nw_parse_coverage_report);

static void
nw_parse_message(pgcovWorker *worker)
{
	pgcovNetworkConn *conn = &worker->buf;

	while (nw_buf_has_message(conn))
	{
		switch (conn->rcvbuf.data[0])
		{
			case PGCOV_MSG_COVERAGE_REPORT:
				PGCOV_PARSE(nw_parse_coverage_report);
				break;

			case PGCOV_MSG_DONE:
				worker->done = true;
				return;

			default:
				elog(ERROR, "unrecognized message type %d", conn->rcvbuf.data[0]);
		}
	}
}

static
PGCOV_MESSAGE_PARSE_FUNC(nw_parse_coverage_report)
{
	Oid fnoid;
	char *fnsignature;
	int32 ncalls;
	char *prosrc;
	List *lines;
	int32 num_lines;
	int32 i;

	PGCOV_PARSE_UINT32(&fnoid); /* TODO dboid */
	PGCOV_PARSE_STRING(&fnsignature);
	PGCOV_PARSE_INT32(&ncalls);
	PGCOV_PARSE_UINT32(&fnoid);
	PGCOV_PARSE_STRING(&prosrc);
	PGCOV_PARSE_INT32(&num_lines);
	lines = NIL;
	for (i = 0; i < num_lines; i++)
	{
		pgcovFunctionLine *line = (pgcovFunctionLine *) palloc(sizeof(pgcovFunctionLine));
		PGCOV_PARSE_INT32(&line->lineno);
		PGCOV_PARSE_INT32(&line->num_executed);
		lines = lappend(lines, line);
	}
	/* process the results */
	pgcov_function_coverage_sfunc(fnoid, fnsignature, ncalls, prosrc, lines);
	PGCOV_END_PARSE();
}

/*
 * Starts listening for incoming connections.
 */
void
pgcov_start_listener(pgcovNest *nest)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *res;
	int sockfd;
	struct sockaddr_in localaddr;
	socklen_t addrlen = sizeof(localaddr);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;

	if ((ret = getaddrinfo("127.0.0.1", "0", &hints, &res)) != 0)
		elog(FATAL, "getaddrinfo() failed: %s", strerror(ret));

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd < 0)
		elog(FATAL, "could not create a socket: %s", strerror(errno));

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0)
	{
		int bind_error = errno;
		close(sockfd);
		freeaddrinfo(res);
		elog(FATAL, "bind() failed: %s", strerror(bind_error));
	}
	freeaddrinfo(res);

	if (listen(sockfd, 15) < 0)
	{
		int listen_error = errno;
		close(sockfd);
		elog(FATAL, "listen() failed: %s", strerror(listen_error));
	}

	if (getsockname(sockfd, (struct sockaddr *) &localaddr, &addrlen) < 0)
		elog(FATAL, "getsockname() failed: %s", strerror(errno));

	Assert(sizeof(nest->entrance) == MAX_ENTRANCE_SIZE);
	ret = snprintf(nest->entrance, MAX_ENTRANCE_SIZE,
					"%hu", ntohs(localaddr.sin_port));
	if (ret < 0 || ret >= MAX_ENTRANCE_SIZE)
		elog(FATAL, "snprintf() failed: %s", strerror(errno));

	elog(DEBUG1, "nest entrance: %s", nest->entrance);

	nest->lsockfd = sockfd;

	{
		int i;

		nest->max_workers = 15; /* TODO */
		nest->workers = (pgcovWorker *) palloc(sizeof(pgcovWorker) * nest->max_workers);
		nest->nworkers = 0;
		for (i = 0; i < nest->max_workers; i++)
		{
			nest->workers[i].free = true;
			nest->workers[i].buf.sockfd = -1;
		}
		elog(DEBUG1, "allocated space for %d workers", nest->max_workers);
	}

	/*
	 * Init a protocol parse context.  This will be reset after parsing any
	 * single message from a backend.
	 */
	if (!pgcov_protocol_parse_mcxt)
	{
		pgcov_protocol_parse_mcxt =
			AllocSetContextCreate(TopMemoryContext,
				  "pgcov listener aggregated data memory context",
				  ALLOCSET_SMALL_MINSIZE,
				  ALLOCSET_SMALL_INITSIZE,
				  ALLOCSET_SMALL_MAXSIZE);
	}
	else
		MemoryContextReset(pgcov_protocol_parse_mcxt);
}

void
pgcov_stop_listener(pgcovNest *nest)
{
	pgcov_nest_shutdown(nest);
	if (pgcov_protocol_parse_mcxt)
	{
		MemoryContextDelete(pgcov_protocol_parse_mcxt);
		pgcov_protocol_parse_mcxt = NULL;
	}
}

static void
pgcov_nest_accept(pgcovNest *nest)
{
	int i;
	int sockfd;
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	pgcovWorker *worker;

	sockfd = accept(nest->lsockfd, (struct sockaddr *) &their_addr, &addr_size);
	if (sockfd == -1 && errno == EINTR)
		return;
	else if (sockfd == -1)
	{
		/* pgcov_nest_shutdown() will likely overwrite our errno */
		int accept_error = errno;
		pgcov_nest_shutdown(nest);
		elog(ERROR, "could not accept(): %s", strerror(accept_error));
	}

	if (nest->nworkers + 1 >= nest->max_workers)
	{
		elog(WARNING, "no more available worker slots in nest (%d workers, max %d)", nest->nworkers, nest->max_workers);
		close(sockfd);
		return;
	}

	/* find a free slot */
	worker = NULL;
	for (i = 0; i < nest->max_workers; i++)
	{
		if (nest->workers[i].free)
		{
			worker = &nest->workers[i];
			break;
		}
	}
	/* should definitely not happen */
	if (!worker)
		elog(ERROR, "could not find a free worker slot");
	init_pgcovNetworkConn(&worker->buf, sockfd);
	nest->nworkers++;
	worker->free = false;
	worker->done = false;
	initStringInfo(&nest->workers[i].buf.rcvbuf);
}

/*
 * Return false on errors, true otherwise (even if there was not a complete
 * message in the buffer).
 */
static bool
pgcov_parse_worker_data(pgcovWorker *worker)
{
	bool success = true;
	MemoryContext currcxt;

	/* restore the memory context if we get a parse error */
	currcxt = CurrentMemoryContext;
	PG_TRY();
	{
		nw_parse_message(worker);
	}
	PG_CATCH();
	{
		FlushErrorState();

		MemoryContextSwitchTo(currcxt);
		success = false;
	}
	PG_END_TRY();

	return success;
}

static void
pgcov_nest_read_from_worker(pgcovNest *nest, pgcovWorker *worker)
{
	int ret;
	char buf[2048];

	ret = read(worker->buf.sockfd, buf, sizeof(buf));
	if (ret == -1 && errno == EINTR)
		return;
	else if (ret == -1)
	{
		elog(WARNING, "read error: %s", strerror(errno));
		goto done;
	}
	else if (ret == 0)
		goto done;

	appendBinaryStringInfo(&worker->buf.rcvbuf, buf, ret);

	if (!pgcov_parse_worker_data(worker))
		goto done;

	if (worker->done)
		goto done;
	else
		return;

done:
	/* this worker is done, clean up */
	pfree(worker->buf.rcvbuf.data);
	close(worker->buf.sockfd);
	worker->buf.sockfd = -1;
	worker->free = true;
	nest->nworkers--;
}

static void
pgcov_nest_shutdown(pgcovNest *nest)
{
	int i;

	for (i = 0; i < nest->max_workers; i++)
	{
		if (nest->workers[i].free)
			continue;
		shutdown(nest->workers[i].buf.sockfd, SHUT_RDWR);
		close(nest->workers[i].buf.sockfd);

		/*
		 * We don't need to clear the network buffer; that'll go away once the
		 * memory context we're in is cleared.
		 */
	}
	nest->nworkers = 0;
	close(nest->lsockfd);
}

void
pgcov_gather_information(pgcovNest *nest)
{
	for (;;)
	{
		fd_set readfds;
		int i;
		int nworkers;
		int maxsockfd;
		int ret;
		struct timeval tv;

		FD_ZERO(&readfds);
		FD_SET(nest->lsockfd, &readfds);
		maxsockfd = nest->lsockfd;

		nworkers = nest->nworkers;
		for (i = 0; i < nest->max_workers && nworkers > 0; i++)
		{
			int wsockfd;

			if (nest->workers[i].free)
				continue;

			wsockfd = nest->workers[i].buf.sockfd;
			FD_SET(wsockfd, &readfds);
			if (wsockfd > maxsockfd)
				maxsockfd = wsockfd;
		}

		tv.tv_sec = 3;
		tv.tv_usec = 0;
		ret = select(maxsockfd+1, &readfds, NULL, NULL, &tv);
		if (ret == -1 && errno != EINTR)
			elog(FATAL, "select() failed: %s", strerror(errno));
		else if (ret == -1 || ret == 0)
		{
			CHECK_FOR_INTERRUPTS();
			continue;
		}

		if (FD_ISSET(nest->lsockfd, &readfds))
		{
			pgcov_nest_accept(nest);
			ret--;
		}

		/* finally, read from the workers */
		for (i = 0; i < nest->max_workers && ret > 0; i++)
		{
			pgcovWorker *worker = &nest->workers[i];
			if (worker->free)
				continue;
			if (!FD_ISSET(worker->buf.sockfd, &readfds))
				continue;
			pgcov_nest_read_from_worker(nest, worker);
			ret--;
		}
	}
}

void
pgcov_worker_connect(pgcovNetworkConn *conn, const char *nest_entrance)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *ai;
	int sockfd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	if ((ret = getaddrinfo("127.0.0.1", nest_entrance, &hints, &ai)) != 0)
		elog(FATAL, "getaddrinfo() failed: %s", strerror(ret));

	sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sockfd < 0)
		elog(FATAL, "could not create a socket: %s", strerror(errno));

	if (connect(sockfd, ai->ai_addr, ai->ai_addrlen) < 0)
	{
		close(sockfd);
		elog(FATAL, "could not connect to %s: %s", "127.0.0.1", strerror(errno));
	}

	init_pgcovNetworkConn(conn, sockfd);
	//nw_append_binary(conn, hello_magic, strlen(hello_magic));
}

void
pgcov_emit_function_coverage_report(const pgcovStackFrame *fn)
{
	ListCell *lc;
	pgcovNetworkConn conn;
	char nest_entrance[MAX_ENTRANCE_SIZE];

	if (!pgcov_get_active_listener(nest_entrance))
		return;

	conn.sockfd = -1;
	PG_TRY();
	{
		pgcov_worker_connect(&conn, nest_entrance);
		nw_append_msg(&conn, PGCOV_MSG_COVERAGE_REPORT);
		nw_append_uint32(&conn, (uint32) MyDatabaseId);
		nw_append_string(&conn, fn->fnsignature);
		nw_append_uint32(&conn, 1); /* XXX ncalls is always 1 currently */
		nw_append_uint32(&conn, fn->fnoid);
		nw_append_string(&conn, fn->prosrc);
		nw_append_int32(&conn, (int32) list_length(fn->lines));
		foreach(lc, fn->lines)
		{
			pgcovFunctionLine *line = (pgcovFunctionLine *) lfirst(lc);
			nw_append_int32(&conn, line->lineno);
			nw_append_int32(&conn, line->num_executed);
		}
		nw_flush_msg(&conn);
		nw_client_done(&conn);
	}
	PG_CATCH();
	{
		if (conn.sockfd != -1)
			close(conn.sockfd);
		PG_RE_THROW();
	}
	PG_END_TRY();
}
