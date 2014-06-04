#ifndef __PGCOV_MAIN_HEADER__
#define __PGCOV_MAIN_HEADER__

#include "postgres.h"
#include "plpgsql.h"

typedef struct {
	int32 lineno;
	int32 num_executed;
} pgcovFunctionLine;

extern MemoryContext pgcov_listener_mcxt;

typedef struct {
	int32 depth;
	Oid fnoid;
	char *fnsignature;

	/* only populated if we're doing coverage reports */
	char *prosrc;
	List *lines;
} pgcovStackFrame;

/* func_iter.c */
typedef struct fniter_context
{
	bool (*enter_stmt)(PLpgSQL_function *, PLpgSQL_stmt *, void *);
	bool (*exit_stmt)(PLpgSQL_function *, PLpgSQL_stmt *, void *);
	bool (*enter_body)(PLpgSQL_function *, PLpgSQL_stmt *, List *, void *);
	bool (*exit_body)(PLpgSQL_function *, PLpgSQL_stmt *, List *, void *);
	void *auxiliary;
} fniter_context;

extern bool fniter_function_iterate(PLpgSQL_function *func, fniter_context *context);

/* comm.c */

typedef enum {
	PGCOV_MSG_COVERAGE_REPORT	= 'C',
	//PGCOV_MSG_STACK_FRAME = 'F',

	PGCOV_MSG_DONE				= 'E'
} pgcovProtocolMessageType;

typedef struct {
	/* a connection is always only sending or receiving */
	union {
		StringInfoData sendbuf;
		StringInfoData rcvbuf;
	};
	int sockfd;
} pgcovNetworkConn;


#define MAX_ENTRANCE_SIZE 16

typedef struct {
	pgcovNetworkConn buf;
	bool free;
	bool done;
} pgcovWorker;

typedef struct {
	char entrance[MAX_ENTRANCE_SIZE];
	int lsockfd;

	int max_workers;
	pgcovWorker *workers;
	int nworkers;
} pgcovNest;

extern void pgcov_function_coverage_sfunc(Oid fnoid, char *fnsignature, int32 ncalls,
										  char *prosrc, List *lines);

extern bool pgcov_get_active_listener(char entrance[MAX_ENTRANCE_SIZE]);
extern void pgcov_start_listener(pgcovNest *nest);
extern void pgcov_stop_listener(pgcovNest *nest);
extern void pgcov_gather_information(pgcovNest *nest);
extern void pgcov_worker_connect(pgcovNetworkConn *conn, const char *congregation_area);

extern void pgcov_emit_function_coverage_report(const pgcovStackFrame *fn);

/* message parsing */

/* XXX Who wrote this crap? */

#define PGCOV_MESSAGE_PARSE_FUNC(fnname)				\
	int fnname(const char *__pmsgdata, int32 __pmsglen, int32 __pmsgoff, pgcovNetworkConn *conn)

#define PGCOV_PARSE(parsefn)							\
	do {												\
		int32 msglen;									\
		MemoryContext oldcxt;							\
														\
		*((uint32 *) &msglen) = nw_peek_uint32(conn->rcvbuf.data + 1);	\
														\
		/*
		 * Switch to the parse context, and reset after we've parsed a message.
		 * This makes sure we never leak any memory in the parse functions.
		 * Note that any "sfuncs" will have to copy the data they get passed
		 * out of the parse context if they need it to live longer than the
		 * duration of the call.
		 */												\
		oldcxt = MemoryContextSwitchTo(pgcov_protocol_parse_mcxt);	\
		parsefn(conn->rcvbuf.data + 5, msglen, 0, conn);		\
		MemoryContextReset(pgcov_protocol_parse_mcxt);	\
		nw_buf_discard_message(conn);					\
		MemoryContextSwitchTo(oldcxt);					\
	} while(0)

#define _PGCOV_PARSE_NEED(c)							\
	do {												\
		if ((c) > __pmsglen - __pmsgoff)				\
			elog(ERROR, "parse error: expected %d bytes, only %d bytes available", (c), __pmsglen - __pmsgoff); \
	} while(0)

#define _PGCOV_PARSE_ADVANCE(c) do { __pmsgoff += (c); } while(0)

#define PGCOV_PARSE_INT32(pint)							\
	do {												\
		_PGCOV_PARSE_NEED(4);							\
		*((uint32 *) (pint)) = nw_peek_uint32(__pmsgdata + __pmsgoff);	\
		_PGCOV_PARSE_ADVANCE(4);						\
	} while(0)

#define PGCOV_PARSE_UINT32(puint)						\
	do {												\
		_PGCOV_PARSE_NEED(4);							\
		*(puint) = nw_peek_uint32(__pmsgdata + __pmsgoff);	\
		_PGCOV_PARSE_ADVANCE(4);						\
	} while(0)


#define PGCOV_PARSE_STRING(pstr)						\
	do {												\
		uint32 __pstrlen;								\
		PGCOV_PARSE_INT32((int32 *) &__pstrlen);		\
		if (__pstrlen == 0x80000001)					\
			*(pstr) = NULL;								\
		else {											\
			_PGCOV_PARSE_NEED(__pstrlen + 1);			\
			*(pstr) = palloc(__pstrlen + 1);			\
			memcpy(*(pstr),								\
				   __pmsgdata + __pmsgoff,				\
				   __pstrlen + 1);						\
			_PGCOV_PARSE_ADVANCE((int32) __pstrlen + 1);\
		}												\
	} while(0)

#define PGCOV_END_PARSE()								\
	return __pmsgoff

#endif
