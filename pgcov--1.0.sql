-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgcov" to load this file. \quit

CREATE FUNCTION pgcov_listen() RETURNS VOID
	AS 'pgcov', 'pgcov_listen' LANGUAGE c;

CREATE FUNCTION pgcov_called_functions()
	RETURNS TABLE (fnsignature text, fnoid oid, ncalls int4, coverage double precision)
	AS 'pgcov', 'pgcov_called_functions' LANGUAGE c;

CREATE FUNCTION pgcov_fn_line_coverage(fnsignature text)
	RETURNS TABLE (lineno int4, ncalls int4, src text)
	AS 'pgcov', 'pgcov_fn_line_coverage' LANGUAGE c;

CREATE FUNCTION pgcov_fn_line_coverage_src(fnsignature text)
	RETURNS text
	AS 'pgcov', 'pgcov_fn_line_coverage_src' LANGUAGE c;
