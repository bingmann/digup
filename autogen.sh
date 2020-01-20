#!/bin/sh

mkdir -p acscripts

aclocal \
&& automake --add-missing \
&& autoconf
