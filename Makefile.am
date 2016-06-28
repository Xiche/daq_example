AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = daq_example.la
daq_example_la_SOURCES = daq_example.c
daq_example_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
