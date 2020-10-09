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
#include "nx_tcp.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_packet_send_syn                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a SYN from the specified socket.                */
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
/*    _nx_tcp_client_socket_connect         Client connect processing     */
/*    _nx_tcp_periodic_processing           Connection retry processing   */
/*    _nx_tcp_packet_process                Server connect response       */
/*                                            processing                  */
/*    _nx_tcp_server_socket_accept          Server socket accept          */
/*                                            processing                  */
/*    _nx_tcp_socket_state_syn_sent         Socket SYN sent processing    */
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
VOID  _nx_tcp_packet_send_syn(NX_TCP_SOCKET *socket_ptr, ULONG tx_sequence)
{

NX_IP      *ip_ptr;
NX_PACKET  *packet_ptr;
NX_TCP_SYN *tcp_header_ptr;
ULONG       checksum;
ULONG       option_word2 = NX_TCP_OPTION_END;
ULONG       mss;
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
UINT        include_window_scaling = NX_FALSE;
UINT        scale_factor;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

    /* Setup the IP pointer.  */
    ip_ptr =  socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Allocate a packet for the SYN message.  */
    if (_nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool,
                            &packet_ptr, (ULONG)(NX_IP_PACKET + sizeof(NX_TCP_SYN)), NX_NO_WAIT) != NX_SUCCESS)
    {

        /* Just give up and return.  */
        return;
    }

    /* The outgoing interface should have been stored in the socket structure. */
    packet_ptr -> nx_packet_ip_interface = socket_ptr -> nx_tcp_socket_connect_interface;
    packet_ptr -> nx_packet_next_hop_address = socket_ptr -> nx_tcp_socket_next_hop_address;

    /* Setup the packet payload pointers and length for a basic TCP packet.  */
    packet_ptr -> nx_packet_prepend_ptr -= sizeof(NX_TCP_SYN);

    /* Setup the packet length.  */
    packet_ptr -> nx_packet_length =  sizeof(NX_TCP_SYN);

    /* Pickup the pointer to the head of the TCP packet.  */
    tcp_header_ptr =  (NX_TCP_SYN *)packet_ptr -> nx_packet_prepend_ptr;

    /* Build the SYN request in the TCP header.  */
    tcp_header_ptr -> nx_tcp_header_word_0 =        (((ULONG)(socket_ptr -> nx_tcp_socket_port)) << NX_SHIFT_BY_16) | (ULONG)socket_ptr -> nx_tcp_socket_connect_port;
    tcp_header_ptr -> nx_tcp_sequence_number =      tx_sequence;

    if (socket_ptr -> nx_tcp_socket_rx_window_current > 65535)
    {
        tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_SYN_HEADER | NX_TCP_SYN_BIT | 65535;
    }
    else
    {
        tcp_header_ptr -> nx_tcp_header_word_3 =        NX_TCP_SYN_HEADER | NX_TCP_SYN_BIT | (socket_ptr -> nx_tcp_socket_rx_window_current);
    }
    /* Determine if we are responding to a SYN or sending the initial SYN.  */
    if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT)
    {

        /* This is the initial SYN.  Set just the SYN bit and make the acknowledgement field zero.  */
        tcp_header_ptr -> nx_tcp_acknowledgment_number =  0;
    }
    else
    {

        /* This is the SYN in response to a client SYN... so it has a valid acknowledgment field.  */
        tcp_header_ptr -> nx_tcp_acknowledgment_number =   socket_ptr -> nx_tcp_socket_rx_sequence;
        tcp_header_ptr -> nx_tcp_header_word_3 |=          NX_TCP_ACK_BIT;
    }

#ifdef NX_ENABLE_TCP_WINDOW_SCALING

    /* Include window scaling option if we initiates the SYN, or the peer supports Window Scaling. */
    if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT)
    {
        include_window_scaling = NX_TRUE;
    }
    else if (socket_ptr -> nx_tcp_snd_win_scale_value != 0xFF)
    {
        include_window_scaling = NX_TRUE;
    }

    if (include_window_scaling)
    {

        /* Sets the window scaling option. */
        option_word2 = NX_TCP_RWIN_OPTION;

        /* Compute the window scaling factor */
        for (scale_factor = 0; scale_factor < 15; scale_factor++)
        {

            if ((socket_ptr -> nx_tcp_socket_rx_window_current >> scale_factor) < 65536)
            {
                break;
            }
        }

        if (scale_factor == 15)
        {
            scale_factor = 14;
        }

        option_word2 |= scale_factor << 8;

        socket_ptr -> nx_tcp_rcv_win_scale_value = scale_factor;
    }

#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

    mss = socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_ip_mtu_size - sizeof(NX_IP_HEADER) - sizeof(NX_TCP_HEADER);

    mss &= 0x0000FFFFUL;

    if ((socket_ptr -> nx_tcp_socket_mss < mss) && socket_ptr -> nx_tcp_socket_mss)
    {

        /* Use the custom MSS. */
        mss = socket_ptr -> nx_tcp_socket_mss;
    }

    if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED)
    {

        /* Update the connect MSS for TCP server socket. */
        if (mss < socket_ptr -> nx_tcp_socket_peer_mss)
        {
            socket_ptr -> nx_tcp_socket_connect_mss  = mss;
        }
        else
        {
            socket_ptr -> nx_tcp_socket_connect_mss =  socket_ptr -> nx_tcp_socket_peer_mss;
        }

        /* Compute the SMSS * SMSS value, so later TCP module doesn't need to redo the multiplication. */
        socket_ptr -> nx_tcp_socket_connect_mss2 =
            socket_ptr -> nx_tcp_socket_connect_mss * socket_ptr -> nx_tcp_socket_connect_mss;
    }

    /* Build the remainder of the TCP header.  */
    tcp_header_ptr -> nx_tcp_header_word_4 =        0;
    tcp_header_ptr -> nx_tcp_option_word_1 =        NX_TCP_MSS_OPTION | mss;
    tcp_header_ptr -> nx_tcp_option_word_2 =        option_word2;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_SYN_SEND, ip_ptr, socket_ptr, packet_ptr, tx_sequence, NX_TRACE_INTERNAL_EVENTS, 0, 0)

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the TCP header.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_option_word_1);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_option_word_2);

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

    /* Initialize recover sequence and previous cumulative acknowledgment. */
    socket_ptr -> nx_tcp_socket_tx_sequence_recover = tx_sequence;
    socket_ptr -> nx_tcp_socket_previous_highest_ack = tx_sequence;

    /* Reset duplicated ack received. */
    socket_ptr -> nx_tcp_socket_duplicated_ack_received = 0;

    /* Reset fast recovery stage. */
    socket_ptr -> nx_tcp_socket_fast_recovery = NX_FALSE;
}

