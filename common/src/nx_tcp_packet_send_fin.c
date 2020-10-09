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
#include "nx_ip.h"
#include "nx_packet.h"
#include "nx_tcp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_packet_send_fin                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a FIN from the specified socket.                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to socket             */
/*    tx_sequence                           Transmit sequence number      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_allocate                   Allocate a packet             */
/*    _nx_tcp_checksum                      Calculate TCP checksum        */
/*    _nx_ip_packet_send                    Send IP packet                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_socket_disconnect             Socket disconnect processing  */
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
VOID  _nx_tcp_packet_send_fin(NX_TCP_SOCKET *socket_ptr, ULONG tx_sequence)
{

NX_IP         *ip_ptr;
NX_PACKET     *packet_ptr;
NX_TCP_HEADER *tcp_header_ptr;
ULONG          checksum;


    /* Setup the IP pointer.  */
    ip_ptr =  socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Allocate a packet for the FIN message.  */
    if (_nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool,
                            &packet_ptr, NX_TCP_PACKET, NX_NO_WAIT) != NX_SUCCESS)
    {

        /* Just give up and return.  */
        return;
    }

    /* The outgoing interface should have been stored in the socket structure. */
    packet_ptr -> nx_packet_ip_interface = socket_ptr -> nx_tcp_socket_connect_interface;
    packet_ptr -> nx_packet_next_hop_address = socket_ptr -> nx_tcp_socket_next_hop_address;

    /* Setup the packet payload pointers and length for a basic TCP packet.  */
    packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_TCP_HEADER);

    /* Setup the packet length.  */
    packet_ptr -> nx_packet_length =  sizeof(NX_TCP_HEADER);

    /* Pickup the pointer to the head of the TCP packet.  */
    tcp_header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Build the FIN request in the TCP header.  */
    tcp_header_ptr -> nx_tcp_header_word_0 =        (((ULONG)(socket_ptr -> nx_tcp_socket_port)) << NX_SHIFT_BY_16) | (ULONG)socket_ptr -> nx_tcp_socket_connect_port;
    tcp_header_ptr -> nx_tcp_sequence_number =      tx_sequence;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = socket_ptr -> nx_tcp_socket_rx_sequence;
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_FIN_BIT | NX_TCP_ACK_BIT | (socket_ptr -> nx_tcp_socket_rx_window_current >> socket_ptr -> nx_tcp_rcv_win_scale_value);
#else /* NX_ENABLE_TCP_WINDOW_SCALING */
    tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_FIN_BIT | NX_TCP_ACK_BIT | (socket_ptr -> nx_tcp_socket_rx_window_current);
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
    tcp_header_ptr -> nx_tcp_header_word_4 =        0;

    /* Remember the last ACKed sequence and the last reported window size.  */
    socket_ptr -> nx_tcp_socket_rx_sequence_acked =    socket_ptr -> nx_tcp_socket_rx_sequence;
    socket_ptr -> nx_tcp_socket_rx_window_last_sent =  socket_ptr -> nx_tcp_socket_rx_window_current;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_FIN_SEND, ip_ptr, socket_ptr, packet_ptr, tx_sequence, NX_TRACE_INTERNAL_EVENTS, 0, 0)

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the TCP header.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Calculate the TCP checksum.  */
#ifndef NX_DISABLE_TCP_TX_CHECKSUM
    checksum =  _nx_tcp_checksum(packet_ptr, packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address, socket_ptr -> nx_tcp_socket_connect_ip);
#else
    checksum = 0;
#endif


    /* Move the checksum into header.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    tcp_header_ptr -> nx_tcp_header_word_4 =  (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Send the TCP packet to the IP component.  */
    _nx_ip_packet_send(ip_ptr, packet_ptr, socket_ptr -> nx_tcp_socket_connect_ip,
                       socket_ptr -> nx_tcp_socket_type_of_service, socket_ptr -> nx_tcp_socket_time_to_live, NX_IP_TCP, socket_ptr -> nx_tcp_socket_fragment_enable);
}

