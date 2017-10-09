#include "postgres.h"

#include "plpgsql.h"
#include "funcapi.h"
#include "fmgr.h"
#include "access/hash.h"
#include "catalog/pg_type.h"
#include "catalog/pg_proc.h"
#include "utils/syscache.h"
#include "utils/builtins.h"
#include "executor/executor.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#include "storage/ipc.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "miscadmin.h"

#if PG_VERSION_NUM >= 90300
#include "access/htup_details.h"
#endif


#include "pgcov.h"


PG_MODULE_MAGIC;


/* ************* *
 * shared memory *
 * ************* */

static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

typedef struct {
	LWLockId	lock;
	char		nest_entrance[MAX_ENTRANCE_SIZE];
} pgcovSharedState;

static pgcovSharedState *pgcov = NULL;


/* ******* *
 * testing *
 * ******* */

static bool pgcov_test_function_line_info = false;


/* ****************** *
 * backend-local data *
 * ****************** */

static List *pgcov_call_stack = NIL;

/*
 * All memory in the call stack should be allocated in this memory context.  We
 * reset the context every time the stack is completely unwound in order to
 * avoid leaking any memory.
 */
static MemoryContext pgcov_call_stack_mctx = NULL;


/* *********************************** *
 * backend-local data for the listener *
 * *********************************** */

typedef struct {
	Oid dbid;
	char *fnsignature;
} pgcovFcHashKey;

typedef struct {
	pgcovFcHashKey key;

	Oid fnoid;

	int32 ncalls;

	char *prosrc;
	List *lines;		/* list of pgcovFunctionLine */
} pgcovFunctionCoverage;

static uint32 pgcov_function_coverage_hashfn(const void *key, Size keysize);
static int pgcov_function_coverage_matchfn(const void *key1, const void *key2, Size keysize);

/*
 * All data gathered by the listener should be kept in this memory context.
 * It is created when we start listening and destroyed once we're ready to
 * abandon the data, either by listening again or by an explicit call to reset.
 */
MemoryContext pgcov_listener_mcxt = NULL;
static HTAB *pgcov_function_coverage = NULL;

static void pgcov_init_listener(void);


/* ************************* *
 * PL/PgSQL plugin callbacks *
 * ************************* */

static void pgcov_plpgsql_func_beg(PLpgSQL_execstate *estate,
								   PLpgSQL_function *func);
static void pgcov_plpgsql_stmt_beg(PLpgSQL_execstate *estate,
								   PLpgSQL_stmt *stmt);

static PLpgSQL_plugin pgcov_plpgsql_plugin_struct = {
	NULL, /* func_setup */
	pgcov_plpgsql_func_beg,
	NULL, /* func_end */
	pgcov_plpgsql_stmt_beg,
	NULL, /* stmt_end */
};


/* fmgr hooks */
static bool pgcov_needs_fmgr_hook(Oid fnoid);
static void pgcov_fmgr_hook(FmgrHookEventType event, FmgrInfo *flinfo, Datum *args);

static needs_fmgr_hook_type prev_needs_fmgr_hook = NULL;
static fmgr_hook_type prev_fmgr_hook = NULL;


/* shared memory manipulation routines */
#define pgcov_require_shmem()													\
	do {																		\
		if (!pgcov)																\
			ereport(ERROR,														\
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),			\
					 errmsg("shared memory not initialized"),					\
					 errhint("pgcov must be in shared_preload_libraries")));	\
	} while (0)

static void pgcov_shmem_startup(void);
static void pgcov_shmem_set_listener(const pgcovNest *nest);
static void pgcov_shmem_clear_listener(const pgcovNest *nest);

void _PG_init(void);
void _PG_fini(void);


/* local functions for fetching information about functions */
static bool pgcov_get_function_line_info_enter_stmt(PLpgSQL_function *func,
										PLpgSQL_stmt *stmt,
										void *aux);
static void pgcov_get_function_line_info(pgcovStackFrame *fn,
							 PLpgSQL_function *func,
							 const char *prosrc);
static char *get_function_signature(HeapTuple proctup, Form_pg_proc procform,
									const char *proname);
static void pgcov_record_stmt_enter(PLpgSQL_execstate *estate, PLpgSQL_stmt *stmt);


/*
 * Module load callback
 */
void
_PG_init(void)
{
	PLpgSQL_plugin **plpgsql_plugin;

	/* must be loaded via shared_preload_libraries */
	if (!process_shared_preload_libraries_in_progress)
		return;

	pgcov_call_stack_mctx =
		AllocSetContextCreate(TopMemoryContext,
							  "pgcov call stack memory context",
							  ALLOCSET_SMALL_MINSIZE,
							  ALLOCSET_SMALL_INITSIZE,
							  ALLOCSET_SMALL_MAXSIZE);

	plpgsql_plugin = (PLpgSQL_plugin **) find_rendezvous_variable("PLpgSQL_plugin");
	*plpgsql_plugin = &pgcov_plpgsql_plugin_struct;

	prev_needs_fmgr_hook = needs_fmgr_hook;
	needs_fmgr_hook = pgcov_needs_fmgr_hook;
	prev_fmgr_hook = fmgr_hook;
	fmgr_hook = pgcov_fmgr_hook;

	/* shared memory init */
	RequestAddinShmemSpace(1024);
#if PG_VERSION_NUM >= 90600
	RequestNamedLWLockTranche("pgcov", 1);
#else
	RequestAddinLWLocks(1);
#endif

	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pgcov_shmem_startup;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	PLpgSQL_plugin **plpgsql_plugin;

	plpgsql_plugin = (PLpgSQL_plugin **) find_rendezvous_variable("PLpgSQL_plugin");
	*plpgsql_plugin = NULL;

	needs_fmgr_hook = prev_needs_fmgr_hook;
	fmgr_hook = prev_fmgr_hook;
}

static void
pgcov_shmem_startup(void)
{
	bool found;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/*
	 * Create or attach to the shared memory state, including hash table
	 */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
	pgcov = ShmemInitStruct("pgcov",
							sizeof(pgcovSharedState),
							&found);

	if (!found)
	{
		/* First time through ... */
#if PG_VERSION_NUM >= 90600
		pgcov->lock = &(GetNamedLWLockTranche("pgcov"))->lock;
#else
		pgcov->lock = LWLockAssign();
#endif

		pgcov->nest_entrance[0] = '\0';
	}

	LWLockRelease(AddinShmemInitLock);
}

static void
pgcov_shmem_set_listener(const pgcovNest *nest)
{
	volatile pgcovSharedState *shmem;
	pgcov_require_shmem();

	LWLockAcquire(pgcov->lock, LW_EXCLUSIVE);
	shmem = pgcov;
	if (shmem->nest_entrance[0] != '\0')
		elog(ERROR, "an active listener already exists");
	memcpy(pgcov->nest_entrance, nest->entrance, MAX_ENTRANCE_SIZE);
	LWLockRelease(pgcov->lock);
}

static void
pgcov_shmem_clear_listener(const pgcovNest *nest)
{
	pgcov_require_shmem();

	LWLockAcquire(pgcov->lock, LW_EXCLUSIVE);
	if (memcmp(pgcov->nest_entrance, nest->entrance, MAX_ENTRANCE_SIZE) != 0)
		elog(ERROR, "unexpected entrance %s, was expecting %s", pgcov->nest_entrance, nest->entrance);
	pgcov->nest_entrance[0] = '\0';
	LWLockRelease(pgcov->lock);
}

/*
 * Init all the data structures required to track stuff. XXX
 */
static void
pgcov_init_listener(void)
{
	HASHCTL ctl;
	int flags;

	pgcov_listener_mcxt =
		AllocSetContextCreate(TopMemoryContext,
							  "pgcov listener aggregated data memory context",
							  ALLOCSET_SMALL_MINSIZE,
							  ALLOCSET_SMALL_INITSIZE,
							  ALLOCSET_SMALL_MAXSIZE);

	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(pgcovFcHashKey);
	ctl.entrysize = sizeof(pgcovFunctionCoverage);
	ctl.hash = pgcov_function_coverage_hashfn;
	ctl.match = pgcov_function_coverage_matchfn;
	/* use our memory context for the hash table */
	ctl.hcxt = pgcov_listener_mcxt;

	flags = HASH_ELEM | HASH_FUNCTION | HASH_COMPARE | HASH_CONTEXT;

	pgcov_function_coverage =
			hash_create("pgcov_function_coverage_hash_table", 64, &ctl, flags);
}

static uint32
pgcov_function_coverage_hashfn(const void *ptr, Size keysize)
{
	pgcovFcHashKey *key = (pgcovFcHashKey *) ptr;

	Assert(keysize == sizeof(pgcovFcHashKey));
	return DatumGetUInt32(hash_any((void *) key->fnsignature, strlen(key->fnsignature)));
}

static int
pgcov_function_coverage_matchfn(const void *ptr1, const void *ptr2, Size keysize)
{
	pgcovFcHashKey *key1 = (pgcovFcHashKey *) ptr1;
	pgcovFcHashKey *key2 = (pgcovFcHashKey *) ptr2;

	Assert(keysize == sizeof(pgcovFcHashKey));
	if (key1->dbid < key2->dbid)
		return -1;
	else if (key1->dbid > key2->dbid)
		return 1;
	else
		return strcmp(key1->fnsignature, key2->fnsignature);
}


Datum pgcov_called_functions(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgcov_called_functions);

Datum
pgcov_called_functions(PG_FUNCTION_ARGS)
{
	MemoryContext oldcxt;
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Tuplestorestate *tupstore;
	TupleDesc tupdesc;

	if (!pgcov_function_coverage)
		elog(ERROR, "record some data first (see pgcov_listen())");

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* switch to long-lived memory context */
	oldcxt = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);

	/* get the requested return tuple description */
	tupdesc = CreateTupleDescCopy(rsinfo->expectedDesc);
	if (tupdesc->natts != 4)
		elog(ERROR, "unexpected natts %d", tupdesc->natts);

	tupstore =
		tuplestore_begin_heap(rsinfo->allowedModes & SFRM_Materialize_Random,
							  false, work_mem);

	/* walk over the hash table */
	{
		HASH_SEQ_STATUS hseq;
		pgcovFunctionCoverage *fn;
		Datum values[4];
		bool isnull[4] = { false, false, false, true };

		hash_seq_init(&hseq, pgcov_function_coverage);
		while ((fn = (pgcovFunctionCoverage *) hash_seq_search(&hseq)) != NULL)
		{
			values[0] = CStringGetTextDatum(fn->key.fnsignature);
			values[1] = ObjectIdGetDatum(fn->fnoid);
			values[2] = Int32GetDatum(fn->ncalls);
			tuplestore_putvalues(tupstore, tupdesc, values, isnull);
		}
	}

	MemoryContextSwitchTo(oldcxt);

	/* let the caller know we're sending back a tuplestore */
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	return (Datum) 0;
}

Datum pgcov_fn_line_coverage(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgcov_fn_line_coverage);

Datum
pgcov_fn_line_coverage(PG_FUNCTION_ARGS)
{
	MemoryContext oldcxt;
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Tuplestorestate *tupstore;
	TupleDesc tupdesc;
	char *fnsignature;

	if (!pgcov_function_coverage)
		elog(ERROR, "record some data first (see pgcov_listen())");

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* get a cstring of the argument in the short-lived context */
	fnsignature = TextDatumGetCString(PG_GETARG_DATUM(0));

	/* .. and then switch to long-lived memory context */
	oldcxt = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);

	/* get the requested return tuple description */
	tupdesc = CreateTupleDescCopy(rsinfo->expectedDesc);
	if (tupdesc->natts != 3)
		elog(ERROR, "unexpected natts %d", tupdesc->natts);

	tupstore =
		tuplestore_begin_heap(rsinfo->allowedModes & SFRM_Materialize_Random,
							  false, work_mem);

	{
		pgcovFunctionCoverage *fn;
		bool found;
		Datum values[3];
		bool isnull[3] = { false, false, true };
		const pgcovFcHashKey key = { 0, fnsignature };
		ListCell *lc;

		fn = hash_search(pgcov_function_coverage, (void *) &key, HASH_FIND, &found);
		if (!found)
			elog(ERROR, "could not find function %s", fnsignature);

		foreach(lc, fn->lines)
		{
			pgcovFunctionLine *line = (pgcovFunctionLine *) lfirst(lc);
			values[0] = Int32GetDatum(line->lineno);
			values[1] = Int32GetDatum(line->num_executed);
			tuplestore_putvalues(tupstore, tupdesc, values, isnull);
		}
	}

	MemoryContextSwitchTo(oldcxt);

	/* let the caller know we're sending back a tuplestore */
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	return (Datum) 0;
}

Datum pgcov_fn_line_coverage_src(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgcov_fn_line_coverage_src);

Datum
pgcov_fn_line_coverage_src(PG_FUNCTION_ARGS)
{
	pgcovFunctionCoverage *fn;
	bool found;
	pgcovFcHashKey key = { 0, NULL };

	if (!pgcov_function_coverage)
		elog(ERROR, "record some data first (see pgcov_listen())");

	key.fnsignature = TextDatumGetCString(PG_GETARG_DATUM(0));

	fn = hash_search(pgcov_function_coverage, (void *) &key, HASH_FIND, &found);
	if (!found)
		elog(ERROR, "could not find function %s", key.fnsignature);

	if (!fn->prosrc)
		PG_RETURN_NULL();

	PG_RETURN_DATUM(CStringGetTextDatum(fn->prosrc));
}


/*
 * Takes a newly received function coverage report and incorporates its data
 * into the data we've gathered so far.
 */
void
pgcov_function_coverage_sfunc(Oid fnoid, char *fnsignature, int32 ncalls,
							  char *prosrc, List *lines)
{
	const pgcovFcHashKey key = { 0, fnsignature };
	bool found;
	pgcovFunctionCoverage *fn;
	MemoryContext oldcxt;
	ListCell *lc;

	fn = hash_search(pgcov_function_coverage, (const void *) &key, HASH_ENTER, &found);
	if (!found)
	{
		/* we need to copy the signature out of the parse context */
		fn->key.fnsignature = MemoryContextStrdup(pgcov_listener_mcxt, key.fnsignature);

		fn->prosrc = NULL;
		fn->lines = NIL;
		goto replace;
	}

	/*
	 * See if the function's source code is still the same.  If it's not,
	 * forget everything we thought we knew about the function and replace it.
	 * This allows us to still somewhat function if e.g. a test suite replaces
	 * a function with a mocked version.  N.B. we specifically do *not* look at
	 * the oid of the function.  This way we still keep track of a function
	 * even if it gets replaced via DROP/CREATE function instead of CREATE OR
	 * REPLACE.
	 */
	if ((prosrc == NULL && fn->prosrc == NULL) ||
		(prosrc != NULL && fn->prosrc != NULL &&
			strcmp(fn->prosrc, prosrc) == 0))
	{
		ListCell *lc1, *lc2;

		fn->ncalls += ncalls;

		if (list_length(fn->lines) != list_length(lines))
			elog(ERROR, "line list_length oops");

		forboth(lc1, fn->lines, lc2, lines)
		{
			pgcovFunctionLine *old = lfirst(lc1);
			pgcovFunctionLine *new = lfirst(lc2);

			if (old->lineno != new->lineno)
				elog(ERROR, "lineno oops");
			old->num_executed += new->num_executed;
		}

		return;
	}

replace:
	/*
	 * This is either a function we haven't seen before, or the function with
	 * this signature got replaced with a new definition.  Copy all items out
	 * of the parse context into ours.  Also remember to free the previous ones
	 * if we're replacing or repeatedly redefining functions would result in
	 * memory leaks.
	 */

	oldcxt = MemoryContextSwitchTo(pgcov_listener_mcxt);
	fn->fnoid = fnoid;
	fn->ncalls = ncalls;

	if (fn->prosrc)
		pfree(fn->prosrc);

	if (prosrc)
		fn->prosrc = pstrdup(prosrc);
	else
		fn->prosrc = NULL;

	if (fn->lines)
	{
		list_free(fn->lines);
		fn->lines = NIL;
	}

	foreach(lc, lines)
	{
		pgcovFunctionLine *line = (pgcovFunctionLine *) palloc(sizeof(pgcovFunctionLine));
		memcpy(line, lfirst(lc), sizeof(pgcovFunctionLine));
		fn->lines = lappend(fn->lines, line);
	}
	MemoryContextSwitchTo(oldcxt);
}

/*
 * Returns true if an active listener exists, false otherwise.  If the return
 * value is true, "entrance" is populated with information about the entrance.
 */
bool
pgcov_get_active_listener(char entrance[MAX_ENTRANCE_SIZE])
{
	bool active;
	volatile pgcovSharedState *shmem;

	if (!pgcov)
		return false;

	LWLockAcquire(pgcov->lock, LW_SHARED);
	shmem = pgcov;
	active = (shmem->nest_entrance[0] != '\0');
	if (active && entrance != NULL)
		memcpy(entrance, pgcov->nest_entrance, MAX_ENTRANCE_SIZE);
	LWLockRelease(pgcov->lock);
	return active;
}

Datum pgcov_reset(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgcov_reset);

Datum
pgcov_reset(PG_FUNCTION_ARGS)
{
	if (pgcov_listener_mcxt == NULL)
	{
		/* nothing to do */
		PG_RETURN_VOID();
	}

	hash_destroy(pgcov_function_coverage); /* XXX any reason to do this? (any reason not to?) */
	pgcov_function_coverage = NULL;

	MemoryContextDelete(pgcov_listener_mcxt);
	pgcov_listener_mcxt = NULL;

	PG_RETURN_VOID();
}


Datum pgcov_listen(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgcov_listen);

Datum
pgcov_listen(PG_FUNCTION_ARGS)
{
	pgcovNest nest;

	/*
	 * See if there's already an active listener.  There's a race between us
	 * checking for one and registering ourselves into the shared memory (since
	 * we don't hold the lock while creating the socket), but that's all right;
	 * pgcov_shmem_set_listener will raise an exception in that case.
	 */
	if (pgcov_get_active_listener(NULL))
		elog(ERROR, "an active listener already exists");

	/* make sure we don't have any previous crap left */
	//DirectFunctionCall0(pgcov_reset);
	pgcov_reset(NULL); // XXX WTF

	pgcov_init_listener();
	pgcov_start_listener(&nest);
	PG_TRY();
	{
		pgcov_shmem_set_listener(&nest);
		/* now gather information until we're cancelled */
		pgcov_gather_information(&nest);
	}
	PG_CATCH();
	{
		pgcov_shmem_clear_listener(&nest);
		pgcov_stop_listener(&nest);
		PG_RE_THROW();
	}
	PG_END_TRY();

	pgcov_shmem_clear_listener(&nest);
	pgcov_stop_listener(&nest);

	PG_RETURN_NULL();
}

/*
 * Enables the tester for pgcov_get_function_line_info().
 */
Datum pgcov_enable_test_function_line_info(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(pgcov_enable_test_function_line_info);

Datum
pgcov_enable_test_function_line_info(PG_FUNCTION_ARGS)
{
	pgcov_test_function_line_info = true;
	return (Datum) 0;
}

/*
 * Fetches the function's signature.  None of the types in pg_catalog are
 * schema-qualified, other types always are.
 * TODO actually implement that :-D
 */
static char *
get_function_signature(HeapTuple proctup, Form_pg_proc procform, const char *proname)
{
	StringInfoData str;
	int nargs;
	int i;
	int input_argno;
	Oid *argtypes;
	char **argnames;
	char *argmodes;

	initStringInfo(&str);

	appendStringInfo(&str, "%s(", proname);
	nargs = get_func_arg_info(proctup, &argtypes, &argnames, &argmodes);
	input_argno = 0;
	for (i = 0; i < nargs; ++i)
	{
		Oid argtype = argtypes[i];

		if (argmodes &&
			argmodes[i] != PROARGMODE_IN &&
			argmodes[i] != PROARGMODE_INOUT)
			continue;

		if (input_argno++ > 0)
			appendStringInfoString(&str, ", ");

		appendStringInfoString(&str, format_type_be(argtype));
	}
	appendStringInfoChar(&str, ')');

	return str.data;
}

static bool
pgcov_get_function_line_info_enter_stmt(PLpgSQL_function *func,
										PLpgSQL_stmt *stmt,
										void *aux)
{
	Bitmapset **bms = (Bitmapset **) aux;
	if (stmt->lineno > 0)
		*bms = bms_add_member(*bms, stmt->lineno);
	return false;
}


/*
 * Finds all lines in a function which contain (the first line of) a PL/PgSQL
 * statement.
 *
 * The caller must make sure we're in pgcov_call_stack_mctx.
 */
static void
pgcov_get_function_line_info(pgcovStackFrame *fn,
							 PLpgSQL_function *func,
							 const char *prosrc)
{
	fniter_context ctx;
	Bitmapset *linebms = NULL;

	Assert(fn->lines == NIL);

	memset(&ctx, 0, sizeof(fniter_context));
	ctx.enter_stmt = pgcov_get_function_line_info_enter_stmt;
	ctx.auxiliary = (void *) &linebms;
	fniter_function_iterate(func, &ctx);

	if (linebms)
	{
		int lineno;

		while ((lineno = bms_first_member(linebms)) >= 0)
		{
			pgcovFunctionLine *line =
				(pgcovFunctionLine *) palloc(sizeof(pgcovFunctionLine));
			line->lineno = (int32) lineno;
			line->num_executed = 0;
			fn->lines = lappend(fn->lines, line);
		}
		pfree(linebms);
	}

	if (pgcov_test_function_line_info)
	{
		ListCell *lc;
		pgcovFunctionLine *line;

		elog(INFO, "%d lines:", list_length(fn->lines));
		foreach(lc, fn->lines)
		{
			line = (pgcovFunctionLine *) lfirst(lc);
			elog(INFO, "  %d", line->lineno);
		}
	}
}

static void
pgcov_plpgsql_func_beg(PLpgSQL_execstate *estate,
					   PLpgSQL_function *func)
{
	MemoryContext oldctx;
	HeapTuple proctup;
	pgcovStackFrame *fn;
	Datum prosrc;
	bool isnull;

	if (estate->func->fn_oid == InvalidOid)
		return;

	Assert(pgcov_call_stack != NIL);

	fn = (pgcovStackFrame *) linitial(pgcov_call_stack);
	if (fn->fnoid != func->fn_oid)
		elog(ERROR, "PL/PgSQL function oid %u does not match stack frame %u",
			 func->fn_oid, fn->fnoid);

	oldctx = MemoryContextSwitchTo(fn->mcxt);

	/* look up prosrc */
	proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(fn->fnoid));
	if (!HeapTupleIsValid(proctup))
		elog(ERROR, "cache lookup failed for function %u", fn->fnoid);

	prosrc = SysCacheGetAttr(PROCOID, proctup, Anum_pg_proc_prosrc, &isnull);
	if (isnull)
		elog(ERROR, "unexpected null prosrc for function %u", fn->fnoid);

	fn->prosrc = TextDatumGetCString(prosrc);
	ReleaseSysCache(proctup);

	/* .. and information about the statements in this function */
	pgcov_get_function_line_info(fn, func, fn->prosrc);

	pgcov_record_stmt_enter(estate, (PLpgSQL_stmt *) func->action);

	MemoryContextSwitchTo(oldctx);
}

static void
pgcov_plpgsql_stmt_beg(PLpgSQL_execstate *estate,
					   PLpgSQL_stmt *stmt)
{
	if (estate->func->fn_oid == InvalidOid)
		return;

	Assert(pgcov_call_stack != NIL);

	/* skip dummy returns; see pl_comp.c */
	if (stmt->cmd_type == PLPGSQL_STMT_RETURN &&
		stmt->lineno == 0)
		return;

	pgcov_record_stmt_enter(estate, stmt);
}

static void
pgcov_record_stmt_enter(PLpgSQL_execstate *estate, PLpgSQL_stmt *stmt)
{
	pgcovStackFrame *fn;
	ListCell *lc;

	if (estate->func->fn_oid == InvalidOid)
		return;

	Assert(pgcov_call_stack != NIL);
	fn = (pgcovStackFrame *) linitial(pgcov_call_stack);
	Assert(fn->fnoid == estate->func->fn_oid);
	foreach(lc, fn->lines)
	{
		pgcovFunctionLine *line = (pgcovFunctionLine *) lfirst(lc);
		if (line->lineno == (int32) stmt->lineno)
		{
			line->num_executed++;
			return;
		}
	}

	/* XXX this probably shouldn't happen? */
	elog(WARNING, "could not find lineno %d of function %u, stmt %d",
		 stmt->lineno, fn->fnoid, stmt->cmd_type);
}

static bool
pgcov_needs_fmgr_hook(Oid fnoid)
{
	/* always need */
	return true;
}

static void
pgcov_enter_func_guts(Oid fnoid)
{
	MemoryContext oldctx;
	pgcovStackFrame *newfn;

	oldctx = MemoryContextSwitchTo(pgcov_call_stack_mctx);

	newfn = (pgcovStackFrame *) palloc(sizeof(pgcovStackFrame));
	newfn->mcxt = AllocSetContextCreate(TopMemoryContext,
										"pgcov stack frame memory context",
										ALLOCSET_SMALL_MINSIZE,
										ALLOCSET_SMALL_INITSIZE,
										ALLOCSET_SMALL_MAXSIZE);
	(void) MemoryContextSwitchTo(newfn->mcxt);

	newfn->fnoid = fnoid;
	newfn->lines = NIL;

	{
		HeapTuple proctup;
		Form_pg_proc procform;
		const char *proname;

		proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(fnoid));
		if (!HeapTupleIsValid(proctup))
			elog(ERROR, "cache lookup failed for function %d", fnoid);

		procform = (Form_pg_proc) GETSTRUCT(proctup);
		proname = NameStr(procform->proname);

		newfn->fnsignature = get_function_signature(proctup, procform, proname);

		ReleaseSysCache(proctup);
	}
	/*
	 * If it's a PL/PgSQL function, pgcov_plpgsql_func_beg will fetch the
	 * actual prosrc for the function.
	 */
	newfn->prosrc = NULL;
	pgcov_call_stack = lcons(newfn, pgcov_call_stack);

	MemoryContextSwitchTo(oldctx);
}


static void
pgcov_exit_func_guts(Oid fnoid)
{
	pgcovStackFrame *fn;

	Assert(pgcov_call_stack != NIL);

	fn = (pgcovStackFrame *) linitial(pgcov_call_stack);
	if (fn->fnoid != fnoid)
		elog(FATAL, "XXX %d != %d", fn->fnoid, fnoid);

	pgcov_emit_function_coverage_report(fn);

	MemoryContextDelete(fn->mcxt);
	pfree(fn);

	pgcov_call_stack = list_delete_first(pgcov_call_stack);
	if (pgcov_call_stack == NIL)
	{
		/* last frame, clean up */
		MemoryContextReset(pgcov_call_stack_mctx);
	}
}

static void
pgcov_fmgr_hook(FmgrHookEventType event, FmgrInfo *flinfo, Datum *args)
{
	switch (event)
	{
		case FHET_START:
			pgcov_enter_func_guts(flinfo->fn_oid);
			break;

		case FHET_END:
		case FHET_ABORT:
			// TODO
			pgcov_exit_func_guts(flinfo->fn_oid);
			break;

		default:
			elog(ERROR, "unknown FmgrHookEventType %d", event);
	}

	if (prev_fmgr_hook)
		(*prev_fmgr_hook)(event, flinfo, args);
}

