/****************************************************************************
*																			*
*					  cryptlib List Manipulation Header File 				*
*						Copyright Peter Gutmann 1996-2016					*
*																			*
****************************************************************************/

/* The following functions handle the insertion and deletion of elements to 
   and from singly-linked and doubly-linked lists.  This is the sort of 
   thing that we'd really need templates for, but in their absence we have 
   to use unfortunately rather complex macros.  Where possible these macros 
   are invoked through wrapper functions, limiting the macro code expansion 
   to a small number of locations */

#ifndef _LIST_DEFINED

#define _LIST_DEFINED

/****************************************************************************
*																			*
*						Standard List Manipulation Functions				*
*																			*
****************************************************************************/

/* Insert and delete elements to/from single- and double-linked lists */

#define insertSingleListElement( listHead, insertPoint, newElement ) \
		{ \
		/* Make sure that the element to be added is consistent */ \
		REQUIRES( newElement != NULL ); \
		REQUIRES( ( newElement )->next == NULL ); \
		\
		if( *( listHead ) == NULL ) \
			{ \
			/* It's an empty list, make this the new list */ \
			*( listHead ) = ( newElement ); \
			} \
		else \
			{ \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newElement )->next = *( listHead ); \
				*( listHead ) = ( newElement ); \
				} \
			else \
				{ \
				/* Insert the element in the middle or the end of the list */ \
				( newElement )->next = ( insertPoint )->next; \
				( insertPoint )->next = ( newElement ); \
				} \
			} \
		}

#define insertDoubleListElements( listHead, insertPoint, newStartElement, newEndElement ) \
		{ \
		/* Make sure that the elements to be added are consistent */ \
		REQUIRES( newStartElement != NULL && newEndElement != NULL ); \
		REQUIRES( insertPoint != newStartElement && insertPoint != newEndElement ); \
		REQUIRES( ( newStartElement )->prev == NULL && \
				  ( newEndElement )->next == NULL ); \
		\
		if( *( listHead ) == NULL ) \
			{ \
			/* If it's an empty list, make this the new list */ \
			*( listHead ) = ( newStartElement ); \
			} \
		else \
			{ \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newEndElement )->next = *( listHead ); \
				( *( listHead ) )->prev = ( newEndElement ); \
				*( listHead ) = ( newStartElement ); \
				} \
			else \
				{ \
				/* Make sure that the links are consistent */ \
				ENSURES( ( insertPoint )->next == NULL || \
						 ( insertPoint )->next->prev == ( insertPoint ) ); \
				\
				/* Insert the element in the middle or the end of the list */ \
				( newEndElement )->next = ( insertPoint )->next; \
				( newStartElement )->prev = ( insertPoint ); \
				\
				/* Update the links for the next and previous elements */ \
				if( ( insertPoint )->next != NULL ) \
					( insertPoint )->next->prev = ( newEndElement ); \
				( insertPoint )->next = ( newStartElement ); \
				} \
			} \
		}

#define insertDoubleListElement( listHead, insertPoint, newElement ) \
		{ \
		/* Make sure that the elements to be added are consistent */ \
		REQUIRES( insertPoint != newElement ); \
		REQUIRES( ( newElement )->prev == NULL && \
				  ( newElement )->next == NULL ); \
		\
		if( *( listHead ) == NULL ) \
			{ \
			/* If it's an empty list, make this the new list */ \
			*( listHead ) = ( newElement ); \
			} \
		else \
			{ \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				( newElement )->next = *( listHead ); \
				( *( listHead ) )->prev = ( newElement ); \
				*( listHead ) = ( newElement ); \
				} \
			else \
				{ \
				/* Make sure that the links are consistent */ \
				ENSURES( ( insertPoint )->next == NULL || \
						 ( insertPoint )->next->prev == ( insertPoint ) ); \
				\
				/* Insert the element in the middle or the end of the list */ \
				( newElement )->next = ( insertPoint )->next; \
				( newElement )->prev = ( insertPoint ); \
				\
				/* Update the links for the next and previous elements */ \
				if( ( insertPoint )->next != NULL ) \
					( insertPoint )->next->prev = ( newElement ); \
				( insertPoint )->next = ( newElement ); \
				} \
			} \
		}

#define deleteDoubleListElement( listHead, element ) \
		{ \
		/* Make sure that the preconditions for safe delection are met */ \
		REQUIRES( listHead != NULL && element != NULL ); \
		\
		/* Make sure that the links are consistent */ \
		REQUIRES( ( element )->next == NULL || \
				  ( element )->next->prev == ( element ) ); \
		REQUIRES( ( element )->prev == NULL || \
				  ( element )->prev->next == ( element ) ); \
		\
		/* Unlink the element from the list */ \
		if( element == *( listHead ) ) \
			{ \
			/* Further consistency check */ \
			REQUIRES( ( element )->prev == NULL ); \
			\
			/* Special case for first item */ \
			*( listHead ) = ( element )->next; \
			} \
		else \
			{ \
			/* Further consistency check */ \
			REQUIRES( ( element )->prev != NULL ); \
			\
			/* Delete from the middle or the end of the list */ \
			( element )->prev->next = ( element )->next; \
			} \
		if( ( element )->next != NULL ) \
			( element )->next->prev = ( element )->prev; \
		( element )->prev = ( element )->next = NULL; \
		}

/****************************************************************************
*																			*
*					Safe-pointer List Manipulation Functions				*
*																			*
****************************************************************************/

/* Insert and delete elements to/from single- and double-linked lists with 
   safe pointers */

#define insertSingleListElementSafe( listHead, insertPoint, newElement, ELEMENT_TYPE ) \
		{ \
		ELEMENT_TYPE *listHeadPtr = DATAPTR_GET( listHead ); \
		\
		/* Make sure that the element being added is consistent */ \
		REQUIRES( newElement != NULL ); \
		REQUIRES( DATAPTR_GET( ( newElement )->next ) == NULL ); \
		\
		if( listHeadPtr == NULL ) \
			{ \
			/* Further consistency check */ \
			REQUIRES( ( insertPoint ) == NULL ); \
			\
			/* It's an empty list, make this the new list */ \
			DATAPTR_SET( listHead, ( newElement ) ); \
			} \
		else \
			{ \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				DATAPTR_SET( ( newElement )->next, listHeadPtr ); \
				DATAPTR_SET( listHead, ( newElement ) ); \
				} \
			else \
				{ \
				ELEMENT_TYPE *insertPointNext = DATAPTR_GET( ( insertPoint )->next ); \
				\
				/* Insert the element in the middle or the end of the list */ \
				DATAPTR_SET( ( newElement )->next, insertPointNext ); \
				DATAPTR_SET( ( insertPoint )->next, ( newElement ) ); \
				} \
			} \
		}

#define insertDoubleListElementsSafe( listHead, insertPoint, newStartElement, newEndElement, ELEMENT_TYPE ) \
		{ \
		ELEMENT_TYPE *listHeadPtr = DATAPTR_GET( listHead ); \
		\
		/* Make sure that the elements being added are consistent */ \
		REQUIRES( newStartElement != NULL && newEndElement != NULL ); \
		REQUIRES( insertPoint != newStartElement && insertPoint != newEndElement ); \
		REQUIRES( DATAPTR_GET( ( newStartElement )->prev ) == NULL && \
				  DATAPTR_GET( ( newEndElement )->next ) == NULL ); \
		\
		if( listHeadPtr == NULL ) \
			{ \
			/* Further consistency check */ \
			REQUIRES( ( insertPoint ) == NULL ); \
			\
			/* If it's an empty list, make this the new list */ \
			DATAPTR_SET( listHead, ( newStartElement ) ); \
			} \
		else \
			{ \
			if( ( insertPoint ) == NULL ) \
				{ \
				/* We're inserting at the start of the list, make this the \
				   new first element */ \
				DATAPTR_SET( ( newEndElement )->next, listHeadPtr ); \
				DATAPTR_SET( listHeadPtr->prev, ( newEndElement ) ); \
				DATAPTR_SET( listHead, ( newStartElement ) ); \
				} \
			else \
				{ \
				ELEMENT_TYPE *insertPointNext = DATAPTR_GET( ( insertPoint )->next ); \
				\
				/* Make sure that the links are consistent */ \
				ENSURES( insertPointNext == NULL || \
						 DATAPTR_GET( insertPointNext->prev ) == ( insertPoint ) ); \
				\
				/* Insert the element in the middle or the end of the list */ \
				DATAPTR_SET( ( newEndElement )->next, insertPointNext ); \
				DATAPTR_SET( ( newStartElement )->prev, ( insertPoint ) ); \
				\
				/* Update the links for the next and previous elements */ \
				if( insertPointNext != NULL ) \
					DATAPTR_SET( insertPointNext->prev, ( newEndElement ) ); \
				DATAPTR_SET( ( insertPoint )->next, ( newStartElement ) ); \
				} \
			} \
		}

#define deleteSingleListElementSafe( listHead, listPrev, element, ELEMENT_TYPE ) \
		{ \
		ELEMENT_TYPE *listHeadPtr = DATAPTR_GET( listHead ); \
		\
		/* Make sure that the preconditions for safe delection are met */ \
		REQUIRES( listHeadPtr != NULL && element != NULL ); \
		REQUIRES( element == listHeadPtr || listPrev != NULL ); \
		\
		if( element == listHeadPtr ) \
			{ \
			/* Special case for the first item */ \
			DATAPTR_SET( listHead, DATAPTR_GET( element->next ) ); \
			} \
		else \
			{ \
			ANALYSER_HINT( listPrev != NULL ); \
			\
			/* Delete from middle or end of the list */ \
			DATAPTR_SET( listPrev->next, DATAPTR_GET( element->next ) ); \
			} \
		DATAPTR_SET( ( element )->next, NULL ); \
		}

#define deleteDoubleListElementSafe( listHead, element, ELEMENT_TYPE ) \
		{ \
		ELEMENT_TYPE *elementPrev, *elementNext; \
		\
		/* Make sure that the preconditions for safe delection are met */ \
		REQUIRES( DATAPTR_GET( listHead ) != NULL && element != NULL ); \
		\
		elementPrev = DATAPTR_GET( element->prev ); \
		elementNext = DATAPTR_GET( element->next ); \
		\
		/* Make sure that the links are consistent */ \
		REQUIRES( elementNext == NULL || \
				  DATAPTR_GET( elementNext->prev ) == ( element ) ); \
		REQUIRES( elementPrev == NULL || \
				  DATAPTR_GET( elementPrev->next ) == ( element ) ); \
		\
		/* Unlink the element from the list */ \
		if( element == DATAPTR_GET( listHead ) ) \
			{ \
			/* Further consistency check */ \
			REQUIRES( elementPrev == NULL ); \
			\
			/* Special case for the first item */ \
			DATAPTR_SET( listHead, elementNext ); \
			} \
		else \
			{ \
			/* Further consistency check */ \
			REQUIRES( elementPrev != NULL ); \
			\
			/* Delete from the middle or the end of the list */ \
			DATAPTR_SET( elementPrev->next, elementNext ); \
			} \
		if( elementNext != NULL ) \
			DATAPTR_SET( elementNext->prev, elementPrev ); \
		DATAPTR_SET( element->prev, NULL ); \
		DATAPTR_SET( element->next, NULL ); \
		}

#endif /* _LIST_DEFINED */
