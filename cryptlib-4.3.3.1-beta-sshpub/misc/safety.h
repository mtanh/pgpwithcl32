/****************************************************************************
*																			*
*					  cryptlib Correctness/Safety Header File 				*
*						Copyright Peter Gutmann 1994-2016					*
*																			*
****************************************************************************/

#ifndef _SAFETY_DEFINED

#define _SAFETY_DEFINED

/****************************************************************************
*																			*
*							Design-by-Contract Predicates					*
*																			*
****************************************************************************/

/* Symbolic defines to handle design-by-contract predicates.  If we're 
   really short of code space, we can save a little extra by turning the 
   predicates into no-ops */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES( x )		if( !( x ) ) retIntError()
#define REQUIRES_N( x )		if( !( x ) ) retIntError_Null()
#define REQUIRES_B( x )		if( !( x ) ) retIntError_Boolean()
#define REQUIRES_V( x )		if( !( x ) ) retIntError_Void()
#define REQUIRES_EXT( x, y )	if( !( x ) ) retIntError_Ext( y )
#define REQUIRES_S( x )		if( !( x ) ) retIntError_Stream( stream )

#else

#define REQUIRES( x )
#define REQUIRES_N( x )
#define REQUIRES_B( x )
#define REQUIRES_V( x )
#define REQUIRES_EXT( x, y )
#define REQUIRES_S( x )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES				REQUIRES
#define ENSURES_N			REQUIRES_N
#define ENSURES_B			REQUIRES_B
#define ENSURES_V			REQUIRES_V
#define ENSURES_EXT			REQUIRES_EXT
#define ENSURES_S			REQUIRES_S

/* A special-case form of the REQUIRES() predicate that's used in functions 
   that acquire a mutex.  There are two versions of this, one for cryptlib
   kernel mutexes, denoted by KRNLMUTEX, and one for native mutexes that are
   only visible inside the kernel, denoted by MUTEX */

#ifndef CONFIG_CONSERVE_MEMORY_EXTRA

#define REQUIRES_KRNLMUTEX( x, mutex ) \
		if( !( x ) ) \
			{ \
			krnlExitMutex( mutex ); \
			retIntError(); \
			}
#define REQUIRES_KRNLMUTEX_V( x, mutex ) \
		if( !( x ) ) \
			{ \
			krnlExitMutex( mutex ); \
			retIntError_Void(); \
			}

#define REQUIRES_MUTEX( x, mutex ) \
		if( !( x ) ) \
			{ \
			MUTEX_UNLOCK( mutex ); \
			retIntError(); \
			}
#else

#define REQUIRES_KRNLMUTEX( x, mutex )
#define REQUIRES_KRNLMUTEX_V( x, mutex )
#define REQUIRES_MUTEX( x, mutex )

#endif /* CONFIG_CONSERVE_MEMORY_EXTRA */

#define ENSURES_KRNLMUTEX	REQUIRES_KRNLMUTEX
#define ENSURES_KRNLMUTEX_V	REQUIRES_KRNLMUTEX_V

#define ENSURES_MUTEX		REQUIRES_MUTEX

/****************************************************************************
*																			*
*							Pointer Validity Checks							*
*																			*
****************************************************************************/

/* Check the validity of a pointer passed to a cryptlib function.  Usually
   the best that we can do is check that it's not NULL, but some OSes allow
   for better checking than this, for example that it points to a block of
   readable or writeable memory.  Under Windows IsBadReadPtr() will always
   succeed if the size is 0, so we have to add a separate check to make sure
   that it's non-NULL.

   For any OS, we check not just for the specific value NULL but for anything
   that appears to be pointing into an unlikely memory range.  This is used
   to catch invalid pointers to elements inside structures, for example:

	struct foo_struct *fooPtr; 
	
	function( &fooPtr->element ); 
	
   where fooPtr is NULL, which will pass in a small integer value as the 
   pointer.  While it won't catch most invalid pointers, it's at least a bit 
   more useful than just checking for NULL.

   There are additional caveats with the use of the Windows memory-checking
   functions.  In theory these would be implemented via VirtualQuery(),
   however this is quite slow, requiring a kernel transition and poking
   around with the page protection mechanisms.  Instead, they try and read
   or write the memory, with an exception handler wrapped around the access.
   If the exception is thrown, they fail.  The problem with this way of
   doing things is that if the memory address is a stack guard page used to
   grow the stack (when the system-level exception handler sees an access to
   the bottom-of-stack guard page, it knows that it has to grow the stack)
   *and* the guard page is owned by another thread, IsBadXxxPtr() will catch 
   the exception and the system will never see it, so it can't grow the 
   stack past the current limit (note that this only occurs if the guard 
   page that we hit is owned by a different thread; if we own in then the
   kernel will catch the STATUS_GUARD_PAGE_VIOLATION exception and grow the
   stack as required).  In addition if it's the last guard page then instead 
   of getting an "out of stack" exception, it's turned into a no-op.  The 
   second time the last guard page is hit, the application is terminated by 
   the system, since it's passed its first-chance exception.

   A variation of this is that the calling app could be deliberately passing
   a pointer to a guard page and catching the guard page exception in order
   to dynamically generate the data that would fill the page (this can 
   happen for example when simulating a large address space with pointer 
   swizzling), but this is a pretty weird programming technique that's 
   unlikely to be used with a crypto library.

   A lesser problem is that there's a race condition in the checking in 
   which the memory can be unmapped between the IsBadXxxPtr() check and the 
   actual access, but you'd pretty much have to be trying to actively 
   subvert the checks to do something like this.

   For these reasons we use these functions mostly for debugging, wrapping
   them up in assert()s in most cases where they're used.  Under Windows 
   Vista they've actually been turned into no-ops because of the above 
   problems, although it's probable that they'll be replaced by code to 
   check for NULL pointers, since Microsoft's docs indicate that this much 
   checking will still be done.  In addition the type of checking seems to
   be a function of the Visual C++ libraries used rather than the OS, since
   VC++ 6 applications still perform the full readability check even under
   Windows 7 and 8.
   
   If necessary we could also replace the no-op'd out versions with the 
   equivalent code:

	inline BOOL IsBadReadPtr( const VOID *lp, UINT_PTR ucb )
		{
		__try { memcmp( p, p, cb ); }
		__except( EXCEPTION_EXECUTE_HANDLER ) { return( FALSE ); }
		return( TRUE );
		}

	inline BOOL IsBadWritePtr( LPVOID lp, UINT_PTR ucb )
		{
		__try { memset( p, 0, cb ); }
		__except( EXCEPTION_EXECUTE_HANDLER ) { return( FALSE ); }
		return( TRUE );
		} 

   In a number of cases the code is called as 
   isXXXPtr( ptr, sizeof( ptrObject ) ), which causes warnings about 
   constant expressions, to avoid this we define a separate version 
   isXXXPtrConst() that avoids the size check.
   
   Under Unix we could in theory check against _etext but this is too 
   unreliable to use, with shared libraries the single shared image can be 
   mapped pretty much anywhere into the process' address space and there can 
   be multiple _etext's present, one per shared library, it fails with 
   SELinux (which is something you'd expect to see used in combination with 
   code that's been carefully written to do things like perform pointer 
   checking), and who knows what it'll do in combination with different 
   approaches to ASLR.  Because of its high level of nonportability (even on 
   the same system it can break depending on whether something like SELinux 
   is enabled or not) it's too dangerous to enable its use */

#define isValidPointer( ptr )	( ( uintptr_t ) ( ptr ) > 0x0FFFF )

#if defined( __WIN32__ ) || defined( __WINCE__ )
  /* The use of code analysis complicates the pointer-checking macros
	 because they read memory that's uninitialised at that point.  This is
	 fine because we're only checking for readability/writeability, but the
	 analyser doesn't know this and flags it as an error.  To avoid this,
	 we remove the read/write calls when running the analyser */
  #ifdef _PREFAST_
	#define isReadPtr( ptr, size )	( isValidPointer( ptr ) )
	#define isWritePtr( ptr, size )	( isValidPointer( ptr ) )
	#define isReadPtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
	#define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
  #else
	#define isReadPtr( ptr, size )	( isValidPointer( ptr ) && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
	#define isWritePtr( ptr, size )	( isValidPointer( ptr ) && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
	#define isReadPtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 && \
									  !IsBadReadPtr( ( ptr ), ( size ) ) )
	#define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 && \
									  !IsBadWritePtr( ( ptr ), ( size ) ) )
  #endif /* _PREFAST_ */
#elif defined( __UNIX__ ) && 0		/* See comment above */
  extern int _etext;

  #define isReadPtr( ptr, size )	( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext )
  #define isWritePtr( ptr, size )	( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext )
  #define isReadPtrDynamic( ptr, size )	\
									( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext && \
									  ( size ) > 0 )
  #define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && \
									  ( void * ) ( ptr ) > ( void * ) &_etext && \
									  ( size ) > 0 )
#else
  #define isReadPtr( ptr, type )	( isValidPointer( ptr ) )
  #define isWritePtr( ptr, type )	( isValidPointer( ptr ) )
  #define isReadPtrDynamic( ptr, size )	\
									( isValidPointer( ptr ) && ( size ) > 0 )
  #define isWritePtrDynamic( ptr, size ) \
									( isValidPointer( ptr ) && ( size ) > 0 )
#endif /* Pointer check macros */

/****************************************************************************
*																			*
*								Loop Bounds Checks							*
*																			*
****************************************************************************/

/* Loop bounds used when a more specific constant upper bound isn't 
   available.  The following bounds on loop iterations apply:

	FAILSAFE_SMALL: Expect 1 but can have a few more.
	FAILSAFE_MED: Expect 10-20 but can have a few more.
	FAILSAFE_LARGE: Expect many, but not too many.

  In addition to these values there's a special value 
  FAILSAFE_ITERATIONS_MAX which is equivalent to the ASN.1 (1...MAX) 
  construct in setting an upper bound on loop iterations without necessarily 
  setting any specific limit:

	FAILSAFE_MAX: A value that's unlikely to be reached during normal 
				  operation, but that also won't result in an excessive 
				  stall if it's exceeded */

#define FAILSAFE_ITERATIONS_SMALL	10
#define FAILSAFE_ITERATIONS_MED		50
#define FAILSAFE_ITERATIONS_LARGE	1000
#define FAILSAFE_ITERATIONS_MAX		min( INT_MAX, 100000L )

/* Pseudo-constants used for array bounds-checking.  These provide a more
   precise limit than the FAILSAFE_ITERATIONS_xxx values above.  We subtract
   one from the total count because static arrays are always overallocated 
   with two extra dummy elements at the end */

#define FAILSAFE_ARRAYSIZE( array, elementType ) \
		( ( sizeof( array ) / sizeof( elementType ) ) - 1 )

/* In order to provide its availability guarantees, all loops in cryptlib 
   are statically bounded and double-indexed in case of a fault in the
   primary loop index.  In addition the loops are indexed in opposite
   directions to prevent compilers from combining the two loop index 
   variables into one.  So instead of:

	for( i = 0; i < max; i++ )

   the loop construct used is:

	for( i = 0,		_iterationCount = FAILSAFE_ITERATIONS_MED;
		 i < max && _iterationCount > 0;
		 i++,		_iterationCount-- )

   (in practice the static bounds check is performed before the dynamic one).

   In order to hide the resulting complexity and to ensure consistent
   implementation, the overall construct is manged through macros so that
   the above becomes:

	LOOP_MED( i = 0, i < max, i++ )
		{
		<loop body>;
		}
	ENSURES( LOOP_BOUND_OK );

   First we define the loop variables and conditions that we need.  Since we
   can have nested loops, we also define alternative values for a total of 
   up to three levels of nesting */

#define LOOP_ITERATOR				_iterationCount
#define LOOP_BOUND_INIT( value )	_iterationCount = ( value )
#define LOOP_BOUND_CHECK			( _iterationCount > 0 )
#define LOOP_BOUND_INC				_iterationCount--
#define LOOP_BOUND_OK				LOOP_BOUND_CHECK

#define LOOP_ITERATOR_ALT			_innerIterationCount
#define LOOP_BOUND_INIT_ALT( value ) _innerIterationCount = ( value )
#define LOOP_BOUND_CHECK_ALT		( _innerIterationCount > 0 )
#define LOOP_BOUND_INC_ALT			_innerIterationCount--
#define LOOP_BOUND_OK_ALT			LOOP_BOUND_CHECK_ALT

#define LOOP_ITERATOR_ALT2			_innerInnerIterationCount
#define LOOP_BOUND_INIT_ALT2( value ) _innerInnerIterationCount = ( value )
#define LOOP_BOUND_CHECK_ALT2		( _innerInnerIterationCount > 0 )
#define LOOP_BOUND_INC_ALT2			_innerInnerIterationCount--
#define LOOP_BOUND_OK_ALT2			LOOP_BOUND_CHECK_ALT2

/* With the above we can now create the building blocks for the loops, the
   basic universal form and then more specific forms built on top of that */

#define LOOP_EXT( a, b, c, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC, ( c ) )
#define LOOP_EXT_ALT( a, b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT, ( c ) )
#define LOOP_EXT_ALT2( a, b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT2( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT2 && ( b ); \
			 LOOP_BOUND_INC_ALT2, ( c ) )

#define LOOP_SMALL( a, b, c )	LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED( a, b, c )		LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE( a, b, c )	LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX( a, b, c )		LOOP_EXT( a, b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_SMALL_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_ALT( a, b, c ) \
								LOOP_EXT_ALT( a, b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_LARGE_ALT2( a, b, c ) \
								LOOP_EXT_ALT2( a, b, c, FAILSAFE_ITERATIONS_LARGE )

/* Finally, we need a few specialised subtypes to handle constructs like:

	for( ; i < max ; i++ )

   or even:

	for( ; i < max ; )

   (used when the loop variable is initialised dynamically and the increment
   is part of a conditional in the loop body) */

#define LOOP_EXT_INITCHECK( a, b, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC )
#define LOOP_EXT_INITINC( a, c, bound ) \
		for( LOOP_BOUND_INIT( bound ), ( a ); \
			 LOOP_BOUND_CHECK; \
			 LOOP_BOUND_INC, ( c ) )
#define LOOP_EXT_CHECK( b, bound ) \
		for( LOOP_BOUND_INIT( bound ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC )
#define LOOP_EXT_CHECKINC( b, c, bound ) \
		for( LOOP_BOUND_INIT( bound ); \
			 LOOP_BOUND_CHECK && ( b ); \
			 LOOP_BOUND_INC, ( c ) )

#define LOOP_EXT_INITCHECK_ALT( a, b, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ), ( a ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT )
#define LOOP_EXT_CHECK_ALT( b, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT )
#define LOOP_EXT_CHECKINC_ALT( b, c, bound ) \
		for( LOOP_BOUND_INIT_ALT( bound ); \
			 LOOP_BOUND_CHECK_ALT && ( b ); \
			 LOOP_BOUND_INC_ALT, ( c ) )

#define LOOP_SMALL_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_SMALL ) 
#define LOOP_MED_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_LARGE_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_LARGE ) 
#define LOOP_MAX_INITCHECK( a, b ) \
								LOOP_EXT_INITCHECK( a, b, FAILSAFE_ITERATIONS_MAX ) 

#define LOOP_MED_INITINC( a, c ) \
								LOOP_EXT_INITINC( a, c, FAILSAFE_ITERATIONS_MED )

#define LOOP_SMALL_CHECK( b )	LOOP_EXT_CHECK( b, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_CHECK( b )		LOOP_EXT_CHECK( b, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECK( b )	LOOP_EXT_CHECK( b, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECK( b )		LOOP_EXT_CHECK( b, FAILSAFE_ITERATIONS_MAX )

#define LOOP_SMALL_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_SMALL )
#define LOOP_MED_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECKINC( b, c ) \
								LOOP_EXT_CHECKINC( b, c, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_CHECK_ALT( b ) \
								LOOP_EXT_CHECK_ALT( b, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECK_ALT( b ) \
								LOOP_EXT_CHECK_ALT( b, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECK_ALT( b )	LOOP_EXT_CHECK_ALT( b, FAILSAFE_ITERATIONS_MAX )

#define LOOP_MED_INITCHECK_ALT( a, b ) \
								LOOP_EXT_INITCHECK_ALT( a, b, FAILSAFE_ITERATIONS_MED ) 
#define LOOP_MAX_INITCHECK_ALT( a, b ) \
								LOOP_EXT_INITCHECK_ALT( a, b, FAILSAFE_ITERATIONS_LARGE ) 

#define LOOP_MED_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MED )
#define LOOP_LARGE_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_LARGE )
#define LOOP_MAX_CHECKINC_ALT( b, c ) \
								LOOP_EXT_CHECKINC_ALT( b, c, FAILSAFE_ITERATIONS_MAX )

/****************************************************************************
*																			*
*								Safe Pointers								*
*																			*
****************************************************************************/

/* Error-detecting function and data pointers.  We store two copies of the 
   pointer, the value itself and its bitwise inverse.  If on retrieving them 
   their XOR isn't all-ones then one of the values has been corrupted and 
   the pointer isn't safe to dereference.  The macros are used as:

	FNPTR_DECLARE( PTR_TYPE, ptrStorage );
	DATAPTR_DECLARE( PTR_TYPE, ptrStorage );

	FNPTR_SET( ptrStorage, functionAddress );
	DATAPTR_SET( ptrStorage, dataAddress );

	const PTR_TYPE functionPtr = FNPTR_GET( ptrStorage );
	REQUIRES( functionPtr != NULL );
	PTR_TYPE dataPtr = DATAPTR_GET( ptrStorage );
	REQUIRES( dataPtr != NULL );

   We also require two additional macros for use with the above ones, one 
   that checks whether a pointer is valid and a second one that replaces 
   the standard check for a pointer being NULL:

	FNPTR_ISVALID( ptrStorage );
	DATAPTR_ISVALID( ptrStorage );

	FNPTR_ISSET( ptrStorage );
	DATAPTR_ISSET( ptrStorage );

   The latter is required because pointers are now tri-state, valid and 
   non-NULL, valid and NULL, and invalid, which is reported as NULL but
   FN/DATAPTR_GET() and so would be indistinguishable from valid and NULL.

   In terms of what to store and how, we could store two copies of the 
   same value but that wouldn't detect identical corruption on both 
   values.  We could also mask the value with a secret seed generated at
   runtime, but that's more useful for preventing pointer-overwriting 
   attacks than detecting corruption, and it's not clear whether that's
   a real threat.  Finally, we could actually store a triple modular-
   redundant copy, but if we're trying to deal with that level of 
   corruption then there are likely to be all sorts of other problems as 
   well that we'd need to handle */

#define FNPTR_TYPE				uintptr_t
#define DATAPTR_TYPE			uintptr_t

#define FNPTR_DECLARE( type, name ) \
		type name##1; \
		FNPTR_TYPE name##2
#define DATAPTR_DECLARE( type, name ) \
		type name##1; \
		DATAPTR_TYPE name##2

#define FNPTR_INIT				NULL, ( FNPTR_TYPE ) ~0
#define DATAPTR_INIT			NULL, ( DATAPTR_TYPE ) ~0

#define FNPTR_SET( name, value ) \
			{ \
			name##1 = value; \
			name##2 = ( ( FNPTR_TYPE ) ( value ) ) ^ ~0; \
			}
#define DATAPTR_SET( name, value ) \
			{ \
			name##1 = value; \
			name##2 = ( ( DATAPTR_TYPE ) ( value ) ) ^ ~0; \
			}

#define FNPTR_ISSET( name ) \
		( FNPTR_ISVALID( name ) && ( name##1 ) != NULL )
#define DATAPTR_ISSET( name ) \
		( DATAPTR_ISVALID( name ) && ( name##1 ) != NULL )

#define FNPTR_ISVALID( name ) \
		( ( ( ( FNPTR_TYPE ) ( name##1 ) ) ^ ( name##2 ) ) == ~0 ) 
#define DATAPTR_ISVALID( name ) \
		( ( ( ( DATAPTR_TYPE ) ( name##1 ) ) ^ ( name##2 ) ) == ~0 )

#define FNPTR_GET( name ) \
		( FNPTR_ISVALID( name ) ? ( name##1 ) : NULL )
#define DATAPTR_GET( name ) \
		( DATAPTR_ISVALID( name ) ? ( name##1 ) : NULL )

/****************************************************************************
*																			*
*								Safe Booleans								*
*																			*
****************************************************************************/

/* Boolean constants.  Since the traditional TRUE = 1, FALSE = 0 only has a 
   single-bit difference between the two and it's going to be used to decide
   things like "access authorised" or "cryptographic verification succeeded",
   we define our own value for TRUE that minimises the chances of a simple
   fault converting one value to another.  In addition we explicitly check
   for equality to TRUE rather than just "is non-zero".

   The bit pattern in the TRUE value is chosen to minimise the chances of an
   SEU or similar fault flipping the value into something else that looks 
   valid.  The bit pattern is:

	0000 0000 1111 1111 0011 0011 1100 1100 || \
	  0	   0	F	 F	  3	   3	C	 C

	0000 1111 0011 1100 0101 0110 1001 1111
	  0	   F	3	 C	  5	   6	9	 F

   with the more important patterns at the LSB end, so we use the best
   subset of patterns no matter what the word size is */

#ifdef TRUE
  #undef TRUE
#endif /* TRUE */
#if INT_MAX > 0xFFFFFFFFL
  #define TRUE			0x00FF33CC0F3C569F
#elif INT_MAX > 0xFFFF
  #define TRUE			0x0F3C569F
#else
  #define TRUE			0x569F
#endif /* System-specific word size */
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  /* VC warns about #if FALSE vs. #ifdef FALSE, since FALSE == 0 */
  #pragma warning( push )
  #pragma warning( disable : 4574 )
#endif /* VS 2010 and above */
#ifdef FALSE
  #if FALSE != 0
	#error Value of FALSE is nonzero, this isnt a boolean FALSE value.
  #endif /* FALSE sanity check */
#else
  #define FALSE			0
#endif /* FALSE */
#if defined( _MSC_VER ) && VC_GE_2010( _MSC_VER )
  #pragma warning( pop )
#endif /* VS 2010 and above */

/* The fault-detecting value of TRUE is OK for internal use, but for 
   external use we still have to use TRUE = 1, for which we define an
   alternative constant to make it explicit that this is the external-
   use TRUE */

#define TRUE_ALT		1

/* Error-detecting boolean variables, used for critical values where we 
   don't want to risk a single bit-flip converting a value from one to the
   other.  In this case we also define HA_FALSE to an SEU-immune data value
   rather than allowing it to be all zeroes.
   
   We also mix in an additional value, currently just set to the constant
   HA_CONST, to deal with data-injection attacks in which an attacker tries
   to set a boolean flag to a particular value.   In practice this should
   be some unpredictable value set at runtime, but for now it's just a 
   no-op placeholder */

#define HA_TRUE			TRUE
#if INT_MAX > 0xFFFFFFFFL
  #define HA_FALSE		0x3300CCFF0FC3F596
#elif INT_MAX > 0xFFFF
  #define HA_FALSE		0x0FC3F596
#else
  #define HA_FALSE		0xF596
#endif /* System-specific word size */
#define HA_CONST		0

typedef struct {
		int value1, value2;
		} HA_BOOLEAN;

#define BOOL_SET( name ) \
		{ \
		( name )->value1 = HA_TRUE; \
		( name )->value2 = HA_TRUE ^ HA_CONST; \
		}
#define BOOL_CLEAR( name ) \
		{ \
		( name )->value1 = HA_FALSE; \
		( name )->value2 = ~HA_FALSE ^ HA_CONST; \
		}

#define BOOL_ISSET( name )		( ( ( name )->value1 ^ \
									( name )->value2 ^ HA_CONST ) == 0 )
#define BOOL_ISCLEAR( name )	( ( ( name )->value1 ^ \
									( name )->value2 ^ HA_CONST ) == ~0 )
#define BOOL_ISVALID( name )	( BOOL_ISSET( name ) || BOOL_ISCLEAR( name ) )

#endif /* _SAFETY_DEFINED */
