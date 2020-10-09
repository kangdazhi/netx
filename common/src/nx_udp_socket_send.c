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
/**   User Datagram Protocol (UDP)                                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_udp.h"
#include "nx_ip.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_socket_send                                 PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends the supplied UDP packet through the supplied    */
/*    socket to the supplied IP address and port.                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to UDP socket         */
/*    packet_ptr                            Pointer to UDP packet         */
/*    ip_address                            IP address                    */
/*    port                                  16-bit UDP port number        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_packet_send                    Send the UDP packet over IP   */
/*    nx_ip_route_find                      Find a suitable outgoing      */
/*                                            interface.                  */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
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
UINT  _nx_udp_socket_send(NX_UDP_SOCKET *socket_ptr, NX_PACKET *packet_ptr,
                          ULONG ip_address, UINT port)
{
TX_INTERRUPT_SAVE_AREA

#ifndef NX_DISABLE_UDP_TX_CHECKSUM
ULONG          checksum;
ULONG          length;
ULONG          temp;
UCHAR         *word_ptr;
ULONG          packet_length;
ULONG          adjusted_packet_length;
NX_PACKET     *current_packet;
UCHAR         *pad_ptr;
#endif
NX_IP         *ip_ptr;
NX_UDP_HEADER *udp_header_ptr;

    /* Lockout interrupts.  */
    TX_DISABLE

    /* Determine if the socket is currently bound.  */
    if (!socket_ptr ->  nx_udp_socket_bound_next)
    {

        /* Restore interrupts.  */
        TX_RESTORE

        /* Socket is not bound, return an error message.  */
        return(NX_NOT_BOUND);
    }

    /* Pickup the important information from the socket.  */

    /* Setup the pointer to the associated IP instance.  */
    ip_ptr =  socket_ptr -> nx_udp_socket_ip_ptr;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_UDP_SOCKET_SEND, socket_ptr, packet_ptr, packet_ptr -> nx_packet_length, ip_address, NX_TRACE_UDP_EVENTS, 0, 0)

    /* Restore interrupts.  */
    TX_RESTORE

    /* If the packet does not have outgoing interface defined, pick up the outgoing interface from the socket structure. */
    if (packet_ptr -> nx_packet_ip_interface == NX_NULL)
    {
        packet_ptr -> nx_packet_ip_interface = socket_ptr -> nx_udp_socket_ip_interface;
    }

    /* Call IP routing service to find the best interface for transmitting this packet. */
    if (_nx_ip_route_find(ip_ptr, ip_address, &packet_ptr -> nx_packet_ip_interface, &packet_ptr -> nx_packet_next_hop_address) != NX_SUCCESS)
    {
        return(NX_IP_ADDRESS_ERROR);
    }

    /* Prepend the UDP header to the packet.  First, make room for the UDP header.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - sizeof(NX_UDP_HEADER);

#ifndef NX_DISABLE_UDP_INFO
    /* Increment the total UDP packets sent count.  */
    ip_ptr -> nx_ip_udp_packets_sent++;

    /* Increment the total UDP bytes sent.  */
    ip_ptr -> nx_ip_udp_bytes_sent +=  packet_ptr -> nx_packet_length;

    /* Increment the total UDP packets sent count for this socket.  */
    socket_ptr -> nx_udp_socket_packets_sent++;


    /* Increment the total UDP bytes sent for this socket.  */
    socket_ptr -> nx_udp_socket_bytes_sent +=  packet_ptr -> nx_packet_length;
#endif

    /* Increase the packet length.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + sizeof(NX_UDP_HEADER);

    /* Setup the UDP header pointer.  */
    udp_header_ptr =  (NX_UDP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Build the first 32-bit word of the UDP header.  */
    udp_header_ptr -> nx_udp_header_word_0 =  (((ULONG)socket_ptr -> nx_udp_socket_port) << NX_SHIFT_BY_16) | (ULONG)port;

    /* Build the second 32-bit word of the UDP header.  */
    udp_header_ptr -> nx_udp_header_word_1 =  (packet_ptr -> nx_packet_length << NX_SHIFT_BY_16);

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_UDP_SEND, ip_ptr, socket_ptr, packet_ptr, udp_header_ptr -> nx_udp_header_word_0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the UDP header.  */
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);

#ifndef NX_DISABLE_UDP_TX_CHECKSUM

    /* Determine if we need to compute the UDP checksum.  */
    if (!socket_ptr -> nx_udp_socket_disable_checksum)
    {

        /* Yes, we need to compute the UDP checksum.  */

        /* First calculate the checksum of the pseudo UDP header that includes the source IP
           address, destination IP address, protocol word, and the UDP length.  */
        temp =  packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address;
        checksum =  (temp >> NX_SHIFT_BY_16);
        checksum += (temp & NX_LOWER_16_MASK);
        checksum += (ip_address >> NX_SHIFT_BY_16);
        checksum += (ip_address & NX_LOWER_16_MASK);
        checksum += (NX_IP_UDP >> NX_SHIFT_BY_16);
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
                adjusted_packet_length = adjusted_packet_length - sizeof(ULONG);
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

        /* Do it again in case previous operation generates an overflow.  */
        checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

        /* Place the packet in the second word of the UDP header.  */
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
        udp_header_ptr -> nx_udp_header_word_1 =  udp_header_ptr -> nx_udp_header_word_1 |
            (~checksum & NX_LOWER_16_MASK);
        NX_CHANGE_ULONG_ENDIAN(udp_header_ptr -> nx_udp_header_word_1);
    }
#endif

    /* Get mutex protection.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Send the UDP packet to the IP component.  */
    _nx_ip_packet_send(ip_ptr, packet_ptr, ip_address,
                       socket_ptr -> nx_udp_socket_type_of_service, socket_ptr -> nx_udp_socket_time_to_live, NX_IP_UDP, socket_ptr -> nx_udp_socket_fragment_enable);

    /* Release mutex protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return a successful status.  */
    return(NX_SUCCESS);
}

