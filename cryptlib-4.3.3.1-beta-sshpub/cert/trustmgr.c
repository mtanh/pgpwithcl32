/****************************************************************************
*																			*
*					  Certificate Trust Management Routines					*
*						Copyright Peter Gutmann 1998-2008					*
*																			*
****************************************************************************/

/* The following code is actually part of the user rather than certificate
   routines but it pertains to certificates so we include it here.  Trust
   information mutex handling is done in the user object so there are no 
   mutexes required here.

   The interpretation of what represents a "trusted certificate" is somewhat 
   complex and open-ended, it's not clear whether what's being trusted is 
   the key in the certificate, the certificate, or the owner of the 
   certificate (corresponding to subjectKeyIdentifier, issuerAndSerialNumber/
   certHash, or subject DN).  The generally accepted form is to trust the 
   subject so we check for this in the certificate.  The modification for 
   trusting the key is fairly simple to make if required */

#if defined( INC_ALL )
  #include "cert.h"
  #include "trustmgr_int.h"
  #include "trustmgr.h"
#else
  #include "cert/cert.h"
  #include "cert/trustmgr_int.h"
  #include "cert/trustmgr.h"
#endif /* Compiler-specific includes */

#ifdef USE_CERTIFICATES

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Extract ID fields from an encoded certificate.  Since this isn't a
   certificate object we have to parse the encoded data to locate the fields
   that we're interested in */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 3, 4 ) ) \
static int getCertIdInfo( IN_BUFFER( certObjectLength ) const void *certObject, 
						  IN_LENGTH_SHORT_MIN( MIN_CRYPT_OBJECTSIZE ) \
								const int certObjectLength,
						  OUT_PTR_COND void **subjectDNptrPtr,
						  OUT_LENGTH_SHORT_Z int *subjectDNsizePtr )
	{
	STREAM stream;
	void *subjectDNptr DUMMY_INIT_PTR;
	int subjectDNsize DUMMY_INIT, status;

	assert( isReadPtrDynamic( certObject, certObjectLength ) );
	assert( isWritePtr( subjectDNptrPtr, sizeof( void * ) ) );
	assert( isWritePtr( subjectDNsizePtr, sizeof( int ) ) );

	REQUIRES( certObjectLength >= MIN_CRYPT_OBJECTSIZE && \
			  certObjectLength < MAX_INTLENGTH_SHORT );

	/* Clear return values */
	*subjectDNptrPtr = NULL;
	*subjectDNsizePtr = 0;

	/* Parse the certificate to locate the start of the encoded subject DN 
	   and certificate extensions (if present) */
	sMemConnect( &stream, certObject, certObjectLength );
	readSequence( &stream, NULL );			/* Outer wrapper */
	readSequence( &stream, NULL );			/* Inner wrapper */
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) )
		readUniversal( &stream );			/* Version */
	readUniversal( &stream );				/* Serial number */
	readUniversal( &stream );				/* Signature algo */
	readUniversal( &stream );				/* Issuer DN */
	status = readUniversal( &stream );		/* Validity */
	if( cryptStatusOK( status ) )
		status = getStreamObjectLength( &stream, &subjectDNsize );
	if( cryptStatusOK( status ) )
		status = sMemGetDataBlock( &stream, &subjectDNptr, subjectDNsize );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	*subjectDNptrPtr = subjectDNptr;
	*subjectDNsizePtr = subjectDNsize;
	status = sSkip( &stream, subjectDNsize, MAX_INTLENGTH_SHORT );/* Subject DN */
#if 0	/* sKID lookup isn't used at present.  Also this code should use the 
		   parsing mechanism from dbx_rd.c to provide better checking */
	const BYTE *extensionPtr;
	int extensionSize = 0;
	status = readUniversal( &stream );		/* Public key */
	if( checkStatusPeekTag( stream, status, tag ) && \
		tag == MAKE_CTAG( 3 ) )
		{
		status = readConstructed( &stream, &extensionSize, 3 );
		if( cryptStatusOK( status ) )
			{
			extensionPtr = sMemBufPtr( &stream );
			sSkip( &stream, extensionSize, MAX_INTLENGTH_SHORT );
			}
		}
	if( !cryptStatusError( status ) )		/* Signature */
		status = readUniversal( &stream );
#endif /* 0 */
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

#if 0	/* sKID lookup isn't used at present.  Also this code should use the 
		   parsing mechanism from dbx_rd.c to provide better checking */
	/* Look for the subjectKeyID in the extensions.  It's easier to do a 
	   pattern match than to try and parse the extensions */
	subjectKeyIDptr = NULL;
	subjectKeyIDsize = 0;
	LOOP_LARGE( i = 0, i < extensionSize - 64, i++ )
		{
		/* Look for the OID.  This potentially skips two bytes at a time, 
		   but this is safe since the preceding bytes can never contain 
		   either of these two values (they're 0x30, len) */
		if( extensionPtr[ i++ ] != BER_OBJECT_IDENTIFIER || \
			extensionPtr[ i++ ] != 3 )
			continue;
		if( memcmp( extensionPtr + i, "\x55\x1D\x0E", 3 ) )
			continue;
		i += 3;

		/* We've found the OID (with 1.1e-12 error probability), skip the 
		   critical flag if necessary */
		if( extensionPtr[ i ] == BER_BOOLEAN )
			i += 3;

		/* Check for the OCTET STRING and a reasonable length */
		if( extensionPtr[ i++ ] != BER_OCTETSTRING || \
			extensionPtr[ i ] & 0x80 )
			continue;

		/* Extract the key ID */
		if( i + extensionPtr[ i ] <= extensionSize )
			{
			subjectKeyIDsize = extensionPtr[ i++ ];
			subjectKeyIDptr = extensionPtr + i;
			}
		}
	ENSURES( LOOP_BOUND_OK );
#endif /* 0 */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Retrieve Trusted Certificate Information				*
*																			*
****************************************************************************/

/* Find the trust information entry for a given certificate.  Since this 
   function is called from external code that doesn't know about trust 
   information internals the pointer is a void *, as it is for all other 
   externally-accessible trust management functions */

CHECK_RETVAL_PTR STDC_NONNULL_ARG( ( 1 ) ) \
void *findTrustEntry( INOUT TYPECAST( TRUST_INFO ** ) void *trustInfoPtrPtr, 
					  IN_HANDLE const CRYPT_CERTIFICATE iCryptCert,
					  const BOOLEAN getIssuerEntry )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtrPtr;
	const TRUST_INFO *trustInfoCursor;
	DYNBUF nameDB;
	BYTE sHash[ HASH_DATA_SIZE + 8 ];
	BOOLEAN nameHashed = FALSE;
	int sCheck, trustInfoEntry, status, LOOP_ITERATOR;

	assert( isWritePtr( trustInfoPtrPtr, \
						sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE ) );

	REQUIRES_N( isHandleRangeValid( iCryptCert ) );
	REQUIRES_N( getIssuerEntry == TRUE || getIssuerEntry == FALSE );

	/* If we're trying to get a trusted issuer certificate and we're already 
	   at a self-signed (CA root) certificate, don't return it.  This check 
	   is necessary because self-signed certificates have issuer name == 
	   subject name so once we get to a self-signed certificate's subject DN 
	   an attempt to fetch its issuer would just repeatedly fetch the same 
	   certificate */
	if( getIssuerEntry )
		{
		int value;

		status = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CERTINFO_SELFSIGNED );
		if( cryptStatusError( status ) || value )
			return( NULL );
		}

	/* Set up the information needed to find the trusted certificate */
	status = dynCreate( &nameDB, iCryptCert, getIssuerEntry ? \
						CRYPT_IATTRIBUTE_ISSUER : CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusError( status ) )
		return( NULL );
	sCheck = checksumData( dynData( nameDB ), dynLength( nameDB ) );
	trustInfoEntry = sCheck & ( TRUSTINFO_SIZE - 1 );
	ENSURES_N( trustInfoEntry >= 0 && trustInfoEntry < TRUSTINFO_SIZE );

	/* Check to see whether something with the requested DN is present */
	LOOP_MED( trustInfoCursor = trustInfoIndex[ trustInfoEntry ], 
			  trustInfoCursor != NULL,
			  trustInfoCursor = trustInfoCursor->next )
		{
		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( trustInfoCursor->sCheck == sCheck )
			{
			if( !nameHashed )
				{
				hashData( sHash, HASH_DATA_SIZE, dynData( nameDB ), 
						  dynLength( nameDB ) );
				nameHashed = TRUE;
				}
			if( !memcmp( trustInfoCursor->sHash, sHash, HASH_DATA_SIZE ) )
				{
				dynDestroy( &nameDB );
				return( ( TRUST_INFO * ) trustInfoCursor );
				}
			}
		}
	ENSURES_N( LOOP_BOUND_OK );
	dynDestroy( &nameDB );

	return( NULL );
	}

/* Retrieve trusted certificates */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
int getTrustedCert( INOUT TYPECAST( TRUST_INFO ** ) void *trustInfoPtrPtr,
					OUT_HANDLE_OPT CRYPT_CERTIFICATE *iCertificate )
	{
	TRUST_INFO *trustInfo = trustInfoPtrPtr;
	int status;

	assert( isWritePtr( trustInfoPtrPtr, sizeof( TRUST_INFO ) ) );

	/* Clear return value */
	*iCertificate = CRYPT_ERROR;

	/* If the certificate hasn't already been instantiated yet, do so now */
	if( trustInfo->iCryptCert == CRYPT_ERROR )
		{
		MESSAGE_CREATEOBJECT_INFO createInfo;

		/* Instantiate the certificate */
		setMessageCreateObjectIndirectInfo( &createInfo, trustInfo->certObject,
											trustInfo->certObjectLength,
											CRYPT_CERTTYPE_CERTIFICATE );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			{
			/* If we couldn't instantiate the certificate and it's due to a
			   problem with the certificate rather than circumstances beyond
			   our control, warn about the issue since a (supposedly) known-
			   good certificate shouldn't cause problems on import */
			if( status != CRYPT_ERROR_MEMORY )
				{
				DEBUG_DIAG(( "Couldn't instantiate trusted certificate" ));
				assert( DEBUG_WARN );
				}
			return( status );
			}

		/* The certificate was successfully instantiated, free its stored 
		   encoded form */
		zeroise( trustInfo->certObject, trustInfo->certObjectLength );
		clFree( "getTrustedCert", trustInfo->certObject );
		trustInfo->certObject = NULL;
		trustInfo->certObjectLength = 0;
		trustInfo->iCryptCert = createInfo.cryptHandle;
		}

	/* Return the trusted certificate */
	*iCertificate = trustInfo->iCryptCert;

	return( CRYPT_OK );
	}

CHECK_RETVAL_BOOL STDC_NONNULL_ARG( ( 1 ) ) \
BOOLEAN trustedCertsPresent( TYPECAST( TRUST_INFO ** ) const void *trustInfoPtrPtr )
	{
	const TRUST_INFO **trustInfoIndex = ( const TRUST_INFO ** ) trustInfoPtrPtr;
	int i, LOOP_ITERATOR;

	assert( isReadPtr( trustInfoPtrPtr, \
					   sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE ) );

	LOOP_EXT( i = 0, i < TRUSTINFO_SIZE, i++, TRUSTINFO_SIZE + 1 )
		{
		if( trustInfoIndex[ i ] != NULL )
			return( TRUE );
		}
	ENSURES_B( LOOP_BOUND_OK );

	return( FALSE );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int enumTrustedCerts( INOUT TYPECAST( TRUST_INFO ** ) void *trustInfoPtrPtr, 
					  IN_HANDLE_OPT const CRYPT_CERTIFICATE iCryptCtl,
					  IN_HANDLE_OPT const CRYPT_KEYSET iCryptKeyset )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtrPtr;
	int i, LOOP_ITERATOR;

	assert( isWritePtr( trustInfoPtrPtr, \
						sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE ) );

	REQUIRES( ( iCryptCtl == CRYPT_UNUSED && \
				isHandleRangeValid( iCryptKeyset ) ) || \
			  ( isHandleRangeValid( iCryptCtl ) && \
				iCryptKeyset == CRYPT_UNUSED ) );

	/* Send each trusted certificate to the given object, either a 
	   certificate trust list or a keyset */
	LOOP_EXT( i = 0, i < TRUSTINFO_SIZE, i++, TRUSTINFO_SIZE + 1 )
		{
		TRUST_INFO *trustInfoCursor;
		int LOOP_ITERATOR_ALT;

		LOOP_MED_ALT( trustInfoCursor = trustInfoIndex[ i ], 
					  trustInfoCursor != NULL,
					  trustInfoCursor = trustInfoCursor->next )	
			{
			CRYPT_CERTIFICATE iCryptCert;
			int status;

			status = getTrustedCert( trustInfoCursor, &iCryptCert );
			if( cryptStatusError( status ) )
				return( status );
			if( iCryptCtl != CRYPT_UNUSED )
				{
				/* We're sending trusted certificates to a certificate trust 
				   list */
				status = krnlSendMessage( iCryptCtl, IMESSAGE_SETATTRIBUTE,
										  ( MESSAGE_CAST ) &iCryptCert,
										  CRYPT_IATTRIBUTE_CERTCOLLECTION );
				}
			else
				{
				MESSAGE_KEYMGMT_INFO setkeyInfo;

				/* We're sending trusted certificates to a keyset */
				setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0,
									   NULL, 0, KEYMGMT_FLAG_NONE );
				setkeyInfo.cryptHandle = iCryptCert;
				status = krnlSendMessage( iCryptKeyset, IMESSAGE_KEY_SETKEY, 
										  &setkeyInfo, 
										  KEYMGMT_ITEM_PUBLICKEY );
				}
			if( cryptStatusError( status ) )
				return( status );
			}
		ENSURES( LOOP_BOUND_OK_ALT );
		}
	ENSURES( LOOP_BOUND_OK );
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Add/Update Trusted Certificate Information				*
*																			*
****************************************************************************/

/* Add and delete a trust entry */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int addEntry( INOUT TYPECAST( TRUST_INFO ** ) void *trustInfoPtrPtr, 
					 IN_HANDLE_OPT const CRYPT_CERTIFICATE iCryptCert, 
					 IN_BUFFER_OPT( certObjectLength ) const void *certObject, 
					 IN_LENGTH_SHORT_Z const int certObjectLength )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtrPtr;
	TRUST_INFO *newElement, *trustInfoCursor, *trustInfoLast;
	BYTE sHash[ HASH_DATA_SIZE + 8 ];
	BOOLEAN recreateCert = FALSE;
	int sCheck, trustInfoEntry, status, LOOP_ITERATOR;

	assert( isWritePtr( trustInfoPtrPtr, \
						sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE ) );
	assert( ( certObject == NULL && certObjectLength == 0 && \
			  isHandleRangeValid( iCryptCert ) ) || \
			( isReadPtrDynamic( certObject, certObjectLength ) && \
			  iCryptCert == CRYPT_UNUSED ) );

	REQUIRES( ( certObject == NULL && certObjectLength == 0 && \
				isHandleRangeValid( iCryptCert ) ) || \
			  ( certObject != NULL && \
			    certObjectLength >= MIN_CRYPT_OBJECTSIZE && \
				certObjectLength < MAX_INTLENGTH_SHORT && \
				iCryptCert == CRYPT_UNUSED ) );

	/* If we're adding a certificate, check whether it has a context 
	   attached and if it does, whether it's a public-key context.  If 
	   there's no context attached (it's a data-only certificate) or the 
	   attached context is a private-key context (which we don't want to 
	   leave hanging around in memory, or which could be in a removable 
	   crypto device) we don't try and use the certificate but instead add 
	   the certificate data and then later re-instantiate a new certificate 
	   with attached public-key context if required */
	if( certObject == NULL )
		{
		CRYPT_CONTEXT iCryptContext;

		status = krnlSendMessage( iCryptCert, IMESSAGE_GETDEPENDENT,
								  &iCryptContext, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			{
			/* There's no context associated with this certificate, we'll 
			   have to recreate it later */
			recreateCert = TRUE;
			}
		else
			{
			status = krnlSendMessage( iCryptContext, IMESSAGE_CHECK, NULL,
									  MESSAGE_CHECK_PKC_PRIVATE );
			if( cryptStatusOK( status ) )
				{
				/* The context associated with the certificate is a private-
				   key context, recreate it later as a public-key context */
				recreateCert = TRUE;
				}
			}
		}

	/* Get the ID information for the certificate */
	if( certObject == NULL )
		{
		DYNBUF subjectDB;

		/* Generate the checksum and hash of the certificate object's 
		   subject name and key ID */
		status = dynCreate( &subjectDB, iCryptCert, 
							CRYPT_IATTRIBUTE_SUBJECT );
		if( cryptStatusError( status ) )
			return( status );
		sCheck = checksumData( dynData( subjectDB ), 
							   dynLength( subjectDB ) );
		hashData( sHash, HASH_DATA_SIZE, dynData( subjectDB ), 
				  dynLength( subjectDB ) );
#if 0	/* sKID lookup isn't used at present */
		DYNBUF subjectKeyDB;
		status = dynCreate( &subjectKeyDB, iCryptCert, 
							CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
		if( cryptStatusOK( status ) )
			{
			kCheck = checksumData( dynData( subjectKeyDB ), 
								   dynLength( subjectKeyDB ) );
			hashData( kHash, HASH_DATA_SIZE, dynData( subjectKeyDB ), 
					  dynLength( subjectKeyDB ) );
			dynDestroy( &subjectKeyDB );
			}
#endif /* 0 */
		dynDestroy( &subjectDB );
		}
	else
		{
		void *subjectDNptr;
		int subjectDNsize;

		/* Get the ID information from the encoded certificate */
		status = getCertIdInfo( certObject, certObjectLength, 
								&subjectDNptr, &subjectDNsize );
		ENSURES( cryptStatusOK( status ) );
		ANALYSER_HINT( subjectDNptr != NULL );

		/* Generate the checksum and hash of the encoded certificate's 
		   subject name and key ID */
		sCheck = checksumData( subjectDNptr, subjectDNsize );
		hashData( sHash, HASH_DATA_SIZE, subjectDNptr, subjectDNsize );
#if 0	/* sKID lookup isn't used at present */
		kCheck = checksumData( subjectKeyIDptr, subjectKeyIDsize );
		hashData( kHash, HASH_DATA_SIZE, subjectKeyIDptr, subjectKeyIDsize );
#endif /* 0 */
		}

	/* Find the insertion point and make sure that this entry isn't already 
	   present */
	trustInfoEntry = sCheck & ( TRUSTINFO_SIZE - 1 );
	ENSURES( trustInfoEntry >= 0 && trustInfoEntry < TRUSTINFO_SIZE );
	LOOP_MED( trustInfoCursor = trustInfoLast = \
					trustInfoIndex[ trustInfoEntry ], 
			  trustInfoCursor != NULL,
			  trustInfoCursor = trustInfoCursor->next )
		{
		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( trustInfoCursor->sCheck == sCheck && \
			!memcmp( trustInfoCursor->sHash, sHash, HASH_DATA_SIZE ) )
			return( CRYPT_ERROR_DUPLICATE );
		trustInfoLast = trustInfoCursor;
		}
	ENSURES( LOOP_BOUND_OK );
	trustInfoCursor = trustInfoLast;

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement  = ( TRUST_INFO * ) \
				clAlloc( "addEntry", sizeof( TRUST_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( TRUST_INFO ) );
	newElement->sCheck = sCheck;
	memcpy( newElement->sHash, sHash, HASH_DATA_SIZE );
	if( certObject != NULL || recreateCert )
		{
		DYNBUF certDB;
		int objectLength = certObjectLength;

		/* If we're using the data from an existing certificate object we 
		   need to extract the encoded data */
		if( recreateCert )
			{
			/* Get the encoded certificate */
			status = dynCreateCert( &certDB, iCryptCert, 
									CRYPT_CERTFORMAT_CERTIFICATE );
			if( cryptStatusError( status ) )
				{
				clFree( "addEntry", newElement );
				return( status );
				}
			certObject = dynData( certDB );
			objectLength = dynLength( certDB );
			}

		/* Remember the trusted certificate data for later use */
		if( ( newElement->certObject = clAlloc( "addEntry", 
												objectLength ) ) == NULL )
			{
			clFree( "addEntry", newElement );
			if( recreateCert )
				dynDestroy( &certDB );
			return( CRYPT_ERROR_MEMORY );
			}
		memcpy( newElement->certObject, certObject, objectLength );
		newElement->certObjectLength = objectLength;
		newElement->iCryptCert = CRYPT_ERROR;

		/* Clean up */
		if( recreateCert )
			dynDestroy( &certDB );
		}
	else
		{
		/* The trusted key exists as a standard certificate with a public-
		   key context attached, remember it for later */
		krnlSendNotifier( iCryptCert, IMESSAGE_INCREFCOUNT );
		newElement->iCryptCert = iCryptCert;
		}

	/* Add the new entry to the list */
	if( trustInfoCursor == NULL )
		trustInfoIndex[ trustInfoEntry ] = newElement;
	else
		trustInfoCursor->next = newElement;

	return( CRYPT_OK );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int addTrustEntry( INOUT TYPECAST( TRUST_INFO ** ) void *trustInfoPtrPtr, 
				   IN_HANDLE_OPT const CRYPT_CERTIFICATE iCryptCert,
				   IN_BUFFER_OPT( certObjectLength ) const void *certObject, 
				   IN_LENGTH_SHORT_Z const int certObjectLength,
				   const BOOLEAN addSingleCert )
	{
	BOOLEAN itemAdded = FALSE;
	int status;

	assert( isWritePtr( trustInfoPtrPtr, \
						sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE ) );
	assert( ( certObject == NULL && certObjectLength == 0 && \
			  isHandleRangeValid( iCryptCert ) ) || \
			( isReadPtrDynamic( certObject, certObjectLength ) && \
			  iCryptCert == CRYPT_UNUSED ) );

	REQUIRES( ( certObject == NULL && certObjectLength == 0 && \
				isHandleRangeValid( iCryptCert ) ) || \
			  ( certObject != NULL && \
			    certObjectLength >= MIN_CRYPT_OBJECTSIZE && \
				certObjectLength < MAX_INTLENGTH_SHORT && \
				iCryptCert == CRYPT_UNUSED ) );
	REQUIRES( addSingleCert == TRUE || addSingleCert == FALSE );

	/* If we're adding encoded certificate data we can add it directly */
	if( certObject != NULL )
		{
		return( addEntry( trustInfoPtrPtr, CRYPT_UNUSED, certObject, 
						  certObjectLength ) );
		}

	/* Add the certificate/each certificate in the trust list */
	status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	if( addSingleCert )
		{
		status = addEntry( trustInfoPtrPtr, iCryptCert, NULL, 0 );
		if( cryptStatusOK( status ) )
			itemAdded = TRUE;
		}
	else
		{
		int loopStatus, LOOP_ITERATOR;

		/* It's a trust list, move to the start of the list and add each
		   certificate in it */
		status = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								  MESSAGE_VALUE_CURSORFIRST,
								  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
		if( cryptStatusError( status ) )
			{
			( void ) krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
									  MESSAGE_VALUE_FALSE, 
									  CRYPT_IATTRIBUTE_LOCKED );
			return( status );
			}
		LOOP_MED( loopStatus = CRYPT_OK, cryptStatusOK( loopStatus ),
				  loopStatus = krnlSendMessage( iCryptCert, 
									IMESSAGE_SETATTRIBUTE,
									MESSAGE_VALUE_CURSORNEXT,
									CRYPT_CERTINFO_CURRENT_CERTIFICATE ) )
			{
			/* An item being added may already be present, however we can't 
			   fail immediately because what's being added may be a chain 
			   containing further certificates so we keep track of whether 
			   we've successfully added at least one item and clear data 
			   duplicate errors */
			status = addEntry( trustInfoPtrPtr, iCryptCert, NULL, 0 );
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_ERROR_DUPLICATE )
					break;
				status = CRYPT_OK;
				}
			else
				itemAdded = TRUE;
			}
		ENSURES( LOOP_BOUND_OK );
		}
	( void ) krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( status ) )
		return( status );
	if( !itemAdded )
		{
		/* We reached the end of the certificate chain without finding 
		   anything that we could add, return a data duplicate error */
		return( CRYPT_ERROR_DUPLICATE ); 
		}

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1, 2 ) ) \
void deleteTrustEntry( INOUT TYPECAST( TRUST_INFO ** ) void *trustInfoPtrPtr, 
					   IN TYPECAST( TRUST_INFO * ) void *entryToDeletePtr )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtrPtr;
	TRUST_INFO *entryToDelete = ( TRUST_INFO * ) entryToDeletePtr, *prevInfoPtr;
	const int trustInfoEntry = entryToDelete->sCheck & ( TRUSTINFO_SIZE - 1 );

	assert( isWritePtr( trustInfoPtrPtr, \
						sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE ) );
	assert( isWritePtr( entryToDeletePtr, sizeof( TRUST_INFO ) ) );

	REQUIRES_V( trustInfoEntry >= 0 && trustInfoEntry < TRUSTINFO_SIZE );

	/* Unlink the trust information index */
	prevInfoPtr = trustInfoIndex[ trustInfoEntry ];
	ENSURES_V( prevInfoPtr != NULL );
	if( prevInfoPtr == entryToDelete )
		{
		/* Unlink from the start of the list */
		trustInfoIndex[ trustInfoEntry ] = entryToDelete->next;
		}
	else
		{
		int LOOP_ITERATOR;

		/* Unlink from the middle/end of the list */
		LOOP_MED_CHECKINC( prevInfoPtr->next != entryToDelete,
						   prevInfoPtr = prevInfoPtr->next )
			{
			ENSURES_V( prevInfoPtr != NULL );
			}
		ENSURES_V( LOOP_BOUND_OK );
		prevInfoPtr->next = entryToDelete->next;
		}

	/* Free the trust information entry */
	if( entryToDelete->iCryptCert != CRYPT_ERROR )
		krnlSendNotifier( entryToDelete->iCryptCert, IMESSAGE_DECREFCOUNT );
	if( entryToDelete->certObject != NULL )
		{
		zeroise( entryToDelete->certObject, entryToDelete->certObjectLength );
		clFree( "deleteTrustEntry", entryToDelete->certObject );
		}
	memset( entryToDelete, 0, sizeof( TRUST_INFO ) );
	clFree( "deleteTrustEntry", entryToDelete );
	}

/****************************************************************************
*																			*
*				Init/Shut down Trusted Certificate Information				*
*																			*
****************************************************************************/

/* Initialise and shut down the trust information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int initTrustInfo( OUT_PTR_COND TYPECAST( TRUST_INFO ** ) \
						void **trustInfoPtrPtr )
	{
	TRUST_INFO **trustInfoIndex;

	assert( isWritePtr( trustInfoPtrPtr, sizeof( void * ) ) );

	/* Clear return value */
	*trustInfoPtrPtr = NULL;

	/* Initialise the trust information table */
	trustInfoIndex = getTrustMgrStorage();
	memset( trustInfoIndex, 0, sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE );
	*trustInfoPtrPtr = trustInfoIndex;

	return( CRYPT_OK );
	}

STDC_NONNULL_ARG( ( 1 ) ) \
void endTrustInfo( IN TYPECAST( TRUST_INFO ** ) void *trustInfoPtrPtr )
	{
	TRUST_INFO **trustInfoIndex = ( TRUST_INFO ** ) trustInfoPtrPtr;
	int i, LOOP_ITERATOR;

	assert( isWritePtr( trustInfoPtrPtr, \
						sizeof( TRUST_INFO * ) * TRUSTINFO_SIZE ) );

	/* Destroy the chain of items at each table position */
	LOOP_EXT( i = 0, i < TRUSTINFO_SIZE, i++, TRUSTINFO_SIZE + 1 )
		{
		TRUST_INFO *trustInfoCursor;

		/* Destroy any items in the list */
		LOOP_MED_INITCHECK( trustInfoCursor = trustInfoIndex[ i ], 
							trustInfoCursor != NULL )
			{
			TRUST_INFO *itemToFree = trustInfoCursor;

			trustInfoCursor = trustInfoCursor->next;
			deleteTrustEntry( trustInfoIndex, itemToFree );
			}
		ENSURES_V( LOOP_BOUND_OK );
		}
	ENSURES_V( LOOP_BOUND_OK );
	memset( trustInfoIndex, 0, TRUSTINFO_SIZE * sizeof( TRUST_INFO * ) );
	}
#endif /* USE_CERTIFICATES */
