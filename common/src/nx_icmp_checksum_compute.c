/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   Internet Control Message Protocol (ICMP)                            */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_icmp.h"

#if (!defined(NX_DISABLE_ICMP_TX_CHECKSUM) || !defined(NX_DISABLE_ICMP_RX_CHECKSUM))
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_icmp_checksum_compute                           PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function computes the ICMP checksum from the supplied packet   */
/*    pointer.                                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to packet             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    ICMP routines                                                       */
/*                                                                        */
/*  RELEASE HISTORY                                                       */
/*                                                                        */
/*    DATE              NAME                      DESCRIPTION             */
/*                                                                        */
/*  05-19-2020     Yuxin Zhou               Initial Version 6.0           */
/*  09-30-2020     Yuxin Zhou               Modified comment(s),          */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
ULONG  _nx_icmp_checksum_compute(NX_PACKET *packet_ptr)
{

ULONG      checksum =  0;
ULONG      long_temp;
USHORT     short_temp;
ULONG      length;
UCHAR     *word_ptr;
NX_PACKET *current_packet;


    /* Setup the length of the packet checksum.  */
    length =  packet_ptr -> nx_packet_length;

    /* Determine if we need to add a padding byte.  */
    if (((length / sizeof(USHORT)) * sizeof(USHORT)) != length)
    {

        /* We have single byte alignment and we need two byte alignment.  */
        length++;

        /* Determine if there is a last packet pointer.  */
        if (packet_ptr -> nx_packet_last)
        {

            /* Multi-packet message, add a zero byte at the end.  */
            *((packet_ptr -> nx_packet_last) -> nx_packet_append_ptr) =  0;
        }
        else
        {

            /* Write a zero byte at the end of the first and only packet.  */
            *(packet_ptr -> nx_packet_append_ptr) =  0;
        }
    }

    /* Setup the pointer to the start of the packet.  */
    word_ptr =  (UCHAR *)packet_ptr -> nx_packet_prepend_ptr;

    /* Initialize the current packet to the input packet pointer.  */
    current_packet =  packet_ptr;

    /* Loop to calculate the packet's checksum.  */
    while (length)
    {

        /* Determine if there is at least one ULONG left.  */
        if ((UINT)(current_packet -> nx_packet_append_ptr - word_ptr) >= sizeof(ULONG))
        {

            /* Pickup a whole ULONG.  */
            long_temp =  *((ULONG *)word_ptr);

            /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
               swap the endian of the ICMP word.  */
            NX_CHANGE_ULONG_ENDIAN(long_temp);

            /* Add upper 16-bits into checksum.  */
            checksum =  checksum + (long_temp >> NX_SHIFT_BY_16);

            /* Add lower 16-bits into checksum.  */
            checksum =  checksum + (long_temp & NX_LOWER_16_MASK);

            /* Move the word pointer and decrease the length.  */
            word_ptr =  word_ptr + sizeof(ULONG);
            length = length - sizeof(ULONG);
        }
        else
        {

            /* Pickup the 16-bit word.  */
            short_temp =  *((USHORT *)word_ptr);

            /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
               swap the endian of the ICMP word.  */
            NX_CHANGE_USHORT_ENDIAN(short_temp);

            /* Add next 16-bit word into checksum.  */
            checksum =  checksum + short_temp;

            /* Move the word pointer and decrease the length.  */
            word_ptr =  word_ptr + sizeof(USHORT);
            length = length - sizeof(USHORT);
        }

        /* Determine if we are at the end of the current packet.  */
        if ((word_ptr >= (UCHAR *)current_packet -> nx_packet_append_ptr) &&
            (current_packet -> nx_packet_next))
        {

            /* We have crossed the packet boundary.  Move to the next packet
               structure.  */
            current_packet =  current_packet -> nx_packet_next;

            /* Setup the new word pointer.  */
            word_ptr =  (UCHAR *)current_packet -> nx_packet_prepend_ptr;
        }
    }

    /* Add in the carry bits into the checksum.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Do it again in case previous operation generates an overflow.  */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Mask off the upper 16-bits.  */
    checksum =  checksum & NX_LOWER_16_MASK;

    /* Return the computed checksum.  */
    return(checksum);
}
#endif

