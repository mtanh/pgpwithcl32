#!/bin/sh
# Get a (non-cryptographic) random seed for compilation

# Try and determine whether we need to output a 32- or 64-bit value.  This
# is somewhat crude since it gives the kernel architecture and we could be
# building an arch-a application on an arch-b kernel (typically x86 on x64).
# In addition this assumes that the hardware name has some indicator of
# 64-bit-ness in it, which is usually the case.  In general this check errs
# on the side of caution, leaving the value at 32 bits if we're not sure.

IS64BIT=0
if [ $(uname -m | grep '64') != "" ]; then
	IS64BIT=1 ;
fi

if [ -e /dev/urandom ] ; then
	printf -- "-DFIXED_SEED=0x" ;
	if [ $IS64BIT -gt 0 ] ; then
		printf "%X\n" `od -An -N8 -tu8 < /dev/urandom` ;
	else
		printf "%X\n" `od -An -N4 -tu4 < /dev/urandom` ;
	fi ;
	exit 1 ;
fi

if [ $(which last) ] ; then
	SOURCE="last -50" ;
else
	SOURCE="uptime" ;
fi
if [ $(which md5sum) ] ; then
	printf -- "-DFIXED_SEED=0x" ;
	if [ $IS64BIT -gt 0 ] ; then
		echo $($SOURCE | md5sum | cut -c1-16) ;
	else
		echo $($SOURCE | md5sum | cut -c1-8) ;
	fi ;
	exit 1 ;
fi
