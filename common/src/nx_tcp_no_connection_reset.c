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
#include "nx_packet.h"
#include "nx_ip.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_no_connection_reset                         PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a reset when there is no connection present,    */
/*    which avoids the timeout processing on the other side of the        */
/*    connection.                                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*    tcp_header_ptr                        TCP header                    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_route_find                     Find a suitable outgoing      */
/*                                            interface.                  */
/*    _nx_tcp_packet_send_rst               Send RST on no connection     */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_packet_process                TCP packet processing         */
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
VOID  _nx_tcp_no_connection_reset(NX_IP *ip_ptr, NX_PACKET *packet_ptr, NX_TCP_HEADER *tcp_header_ptr)
{

NX_TCP_SOCKET fake_socket;
ULONG        *ip_header_ptr;
ULONG         header_length;


    /* Clear the fake socket first.  */
    memset((void *)&fake_socket, 0, sizeof(NX_TCP_SOCKET));

    /* Build a fake socket so we can send a reset TCP requests that are not valid.  */
    fake_socket.nx_tcp_socket_ip_ptr =           ip_ptr;

    /* Set the connection IP address.  */
    ip_header_ptr = (ULONG *)packet_ptr -> nx_packet_prepend_ptr;
    fake_socket.nx_tcp_socket_connect_ip = *(ip_header_ptr - 2);

    /* Set the time to live.  */
    fake_socket.nx_tcp_socket_time_to_live =     NX_IP_TIME_TO_LIVE;

    /* Assume the interface that receives the incoming packet is the best interface for sending responses. */
    fake_socket.nx_tcp_socket_connect_interface = packet_ptr -> nx_packet_ip_interface;

    /* Set the source port and destination port.  */
    fake_socket.nx_tcp_socket_port  = (UINT)(tcp_header_ptr -> nx_tcp_header_word_0 & NX_LOWER_16_MASK);
    fake_socket.nx_tcp_socket_connect_port = (UINT)(tcp_header_ptr -> nx_tcp_header_word_0 >> NX_SHIFT_BY_16);

    /* Update the sequence number.  */
    /* Get the header length.  */
    header_length = (tcp_header_ptr -> nx_tcp_header_word_3 >> NX_TCP_HEADER_SHIFT) * sizeof(ULONG);

    /* Update sequence number to set the reset acknowledge number.  */
    tcp_header_ptr -> nx_tcp_sequence_number += (packet_ptr -> nx_packet_length - header_length);

    /* Check the SYN bit.  */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
    {

        /* Update sequence number to set the reset acknowledge number.  */
        tcp_header_ptr -> nx_tcp_sequence_number++;
    }

    /* Find outgoing interface and next hop info. */
    if (_nx_ip_route_find(ip_ptr, fake_socket.nx_tcp_socket_connect_ip, &fake_socket.nx_tcp_socket_connect_interface,
                          &fake_socket.nx_tcp_socket_next_hop_address) != NX_SUCCESS)
    {
        return;
    }

    /* Send a RST to indicate the connection was not available.  */
    _nx_tcp_packet_send_rst(&fake_socket, tcp_header_ptr);
}

