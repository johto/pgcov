pgcov
=====

This is a project for tracking test coverage in PL/PgSQL functions.  Very much
a work in progress, so things will probably break and/or won't work correctly.

To run, you need to add "pgcov" to shared\_preload\_libraries.  To build on
9.1, you need to do an in-tree build with NO\_PGXS=1.

Requires PostgreSQL 9.1 or newer.

If you want a frontend, you could look at https://github.com/johto/pgcov-html
