MODULE_big = pgcov
OBJS = comm.o pgcov.o func_iter.o

EXTENSION = pgcov
DATA = pgcov--1.0.sql

REGRESS = gcov_guts function_line_info gcov

ifdef NO_PGXS
# Needed to locate plpgsql.h pre-9.2
PG_CPPFLAGS += -I\$(top_srcdir)/src/pl/plpgsql/src/
subdir = contrib/pgcov
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
else
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
endif
