/*
 * func_iter.c:
 *   iterate over all statements of a PL/PgSQL function
 */
#include "postgres.h"
#include "plpgsql.h"

#include "pgcov.h"


static bool fniter_stmt_iterate(PLpgSQL_function *func,
								PLpgSQL_stmt *stmt,
								fniter_context *context);
static bool fniter_body_iterate(PLpgSQL_function *func,
								PLpgSQL_stmt *stmt,
								List *body,
								fniter_context *context);

bool
fniter_function_iterate(PLpgSQL_function *func, fniter_context *context)
{
	return fniter_stmt_iterate(func, (PLpgSQL_stmt *) func->action, context);
}

static bool
fniter_body_iterate(PLpgSQL_function *func, PLpgSQL_stmt *stmt,
					List *body, fniter_context *context)
{
	ListCell *lc;

	if (!body)
		return false;

	if (context->enter_body &&
		context->enter_body(func, stmt, body, context->auxiliary))
		return true;

	foreach(lc, body)
	{
		if (fniter_stmt_iterate(func, (PLpgSQL_stmt *) lfirst(lc), context))
			return true;
	}

	if (context->exit_body)
		return context->exit_body(func, stmt, body, context->auxiliary);
	return false;
}

static bool
fniter_stmt_iterate(PLpgSQL_function *func, PLpgSQL_stmt *stmt, fniter_context *context)
{
	if (context->enter_stmt &&
		context->enter_stmt(func, stmt, context->auxiliary))
		return true;

	switch (stmt->cmd_type)
	{
		case PLPGSQL_STMT_BLOCK:
			{
				PLpgSQL_stmt_block *stmtblock = (PLpgSQL_stmt_block *) stmt;
				if (fniter_body_iterate(func, stmt, stmtblock->body, context))
					return true;
				if (stmtblock->exceptions)
				{
					ListCell *lc;

					foreach(lc, stmtblock->exceptions->exc_list)
					{
						if (fniter_body_iterate(func, stmt, ((PLpgSQL_exception *) lfirst(lc))->action, context))
							return true;
					}
				}
			}
			break;
		case PLPGSQL_STMT_IF:
			{
				PLpgSQL_stmt_if *ifstmt = (PLpgSQL_stmt_if *) stmt;
#if PG_VERSION_NUM < 90200
				if (fniter_body_iterate(func, stmt, ifstmt->true_body, context))
					return true;
				if (fniter_body_iterate(func, stmt, ifstmt->false_body, context))
					return true;
#else
                if (fniter_body_iterate(func, stmt, ifstmt->then_body, context))
					return true;
                if (ifstmt->elsif_list)
                {
                    ListCell *lc;

                    foreach(lc, ifstmt->elsif_list)
					{
                        if (fniter_body_iterate(func, stmt, ((PLpgSQL_if_elsif *) lfirst(lc))->stmts, context))
							return true;
					}
                }
                if (fniter_body_iterate(func, stmt, ifstmt->else_body, context))
					return true;
#endif
			}
			break;
		case PLPGSQL_STMT_LOOP:
			if (fniter_body_iterate(func, stmt, ((PLpgSQL_stmt_loop *) stmt)->body, context))
				return true;
			break;
		case PLPGSQL_STMT_FOREACH_A:
			if (fniter_body_iterate(func, stmt, ((PLpgSQL_stmt_foreach_a *) stmt)->body, context))
				return true;
			break;
		case PLPGSQL_STMT_FORI:
			if (fniter_body_iterate(func, stmt, ((PLpgSQL_stmt_fori *) stmt)->body, context))
				return true;
			break;
		case PLPGSQL_STMT_FORS:
		case PLPGSQL_STMT_FORC:
		case PLPGSQL_STMT_DYNFORS:
			if (fniter_body_iterate(func, stmt, ((PLpgSQL_stmt_forq *) stmt)->body, context))
				return true;
			break;
		case PLPGSQL_STMT_WHILE:
			if (fniter_body_iterate(func, stmt, ((PLpgSQL_stmt_while *) stmt)->body, context))
				return true;
			break;

		case PLPGSQL_STMT_ASSIGN:
		case PLPGSQL_STMT_EXIT:
		case PLPGSQL_STMT_RETURN:
		case PLPGSQL_STMT_RETURN_NEXT:
		case PLPGSQL_STMT_RETURN_QUERY:
		case PLPGSQL_STMT_RAISE:
		case PLPGSQL_STMT_EXECSQL:
		case PLPGSQL_STMT_DYNEXECUTE:
		case PLPGSQL_STMT_GETDIAG:
		case PLPGSQL_STMT_OPEN:
		case PLPGSQL_STMT_FETCH:
		case PLPGSQL_STMT_CLOSE:
		case PLPGSQL_STMT_PERFORM:
			/* nothing to do */
			break;

		default:
			elog(ERROR, "unknown cmd_type %d", stmt->cmd_type);
			break;
	}

	if (context->exit_stmt)
		return context->exit_stmt(func, stmt, context->auxiliary);
	return false;
}
