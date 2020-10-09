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
/**   Transmission Control Protocol (TCP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_tcp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_checksum                                    PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function computes the checksum of a TCP packet.  It is used    */
/*    for calculating new TCP packets as well as verifying that new       */
/*    packets are okay.                                                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to TCP packet         */
/*    source_ip                             Source IP address             */
/*    destination_ip                        Destination IP address        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    checksum                              Computed checksum             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_packet_process                Packet receive processing     */
/*    _nx_tcp_packet_send_ack               Send ACK message              */
/*    _nx_tcp_packet_send_fin               Send FIN message              */
/*    _nx_tcp_packet_send_syn               Send SYN message              */
/*    _nx_tcp_socket_send                   Socket send packet            */
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
ULONG  _nx_tcp_checksum(NX_PACKET *packet_ptr, ULONG source_address, ULONG destination_address)
{

ULONG      checksum;
NX_PACKET *current_packet;
ULONG      temp;
ULONG      length;
ULONG      packet_length;
ULONG      adjusted_packet_length;
UCHAR     *word_ptr;
UCHAR     *pad_ptr;


    /* First calculate the checksum of the pseudo TCP header that includes the source IP
       address, destination IP address, protocol word, and the TCP length.  */
    checksum =  (source_address >> NX_SHIFT_BY_16);
    checksum += (source_address & NX_LOWER_16_MASK);
    checksum += (destination_address >> NX_SHIFT_BY_16);
    checksum += (destination_address & NX_LOWER_16_MASK);
    checksum += (NX_IP_TCP >> NX_SHIFT_BY_16);
    checksum += packet_ptr -> nx_packet_length;

    /* Setup the length of the packet checksum.  */
    length =  packet_ptr -> nx_packet_length;

    /* Initialize the current packet to the input packet pointer.  */
    current_packet =  packet_ptr;

    /* Loop to calculate the packet's checksum.  */
    while (length)
    {

        /* Calculate the current packet length.  */
        packet_length =  (ULONG)(current_packet -> nx_packet_append_ptr - current_packet -> nx_packet_prepend_ptr);

        /* Make the adjusted packet length evenly divisible by sizeof(ULONG).  */
        adjusted_packet_length =  ((packet_length + (sizeof(ULONG) - 1)) / sizeof(ULONG)) * sizeof(ULONG);

        /* Determine if we need to add padding bytes.  */
        if (packet_length < adjusted_packet_length)
        {

            /* Calculate how many bytes we need to zero at the end of the packet.  */
            temp =  adjusted_packet_length - packet_length;

            /* Setup temporary pointer to the current packet's append pointer.  */
            pad_ptr =  current_packet -> nx_packet_append_ptr;

            /* Loop to pad current packet with 0s so we don't have to worry about a partial last word.  */
            while (temp)
            {

                /* Check for the end of the packet.  */
                if (pad_ptr >= current_packet -> nx_packet_data_end)
                {
                    break;
                }

                /* Write a 0. */
                *pad_ptr++ =  0;

                /* Decrease the pad count.  */
                temp--;
            }
        }

        /* Setup the pointer to the start of the packet.  */
        word_ptr =  (UCHAR *)current_packet -> nx_packet_prepend_ptr;

        /* Now loop through the current packet to compute the checksum on this packet.  */
        while (adjusted_packet_length)
        {

            /* Pickup a whole ULONG.  */
            temp =  *((ULONG *)word_ptr);

            /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
               swap the endian of the long word in the message.  */
            NX_CHANGE_ULONG_ENDIAN(temp);

            /* Add upper 16-bits into checksum.  */
            checksum =  checksum + (temp >> NX_SHIFT_BY_16);

            /* Add lower 16-bits into checksum.  */
            checksum =  checksum + (temp & NX_LOWER_16_MASK);

            /* Move the word pointer and decrease the length.  */
            word_ptr =  word_ptr + sizeof(ULONG);
            adjusted_packet_length =  adjusted_packet_length - sizeof(ULONG);
        }

        /* Adjust the checksum length.  */
        length =  length - packet_length;

        /* Determine if we are at the end of the current packet.  */
        if ((length) && (word_ptr >= (UCHAR *)current_packet -> nx_packet_append_ptr) &&
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

    /* Do it again in case previous operation generates an overflow */
    checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

    /* Perform the one's complement operation on the checksum.  */
    checksum =  NX_LOWER_16_MASK & ~checksum;

    /* Return the checksum.  */
    return(checksum);
}

