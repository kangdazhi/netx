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
/*    _nx_tcp_packet_process                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes an incoming TCP packet, which includes      */
/*    matching the packet to an existing connection and dispatching to    */
/*    the socket specific processing routine.  If no connection is        */
/*    found, this routine checks for a new connection request and if      */
/*    found, processes it accordingly. If a reset packet is received, it  */
/*    checks the queue for a previous connection request which needs to be*/
/*    removed.                                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Packet release function       */
/*    _nx_tcp_checksum                      Calculate TCP packet checksum */
/*    _nx_tcp_mss_option_get                Get peer MSS option           */
/*    _nx_tcp_no_connection_reset           Reset on no connection        */
/*    _nx_tcp_packet_send_syn               Send SYN message              */
/*    _nx_tcp_socket_packet_process         Socket specific packet        */
/*                                            processing routine          */
/*    (nx_tcp_listen_callback)              Application listen callback   */
/*                                            function                    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_queue_process                 Process TCP packet queue      */
/*    _nx_tcp_packet_receive                Receive packet processing     */
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
VOID  _nx_tcp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

UINT                         index;
UINT                         port;
ULONG                       *ip_header_ptr;
ULONG                        source_ip;
UINT                         source_port;
NX_TCP_SOCKET               *socket_ptr;
NX_TCP_HEADER               *tcp_header_ptr;
struct NX_TCP_LISTEN_STRUCT *listen_ptr;
VOID                         (*listen_callback)(NX_TCP_SOCKET *socket_ptr, UINT port);
ULONG                        option_words;
ULONG                        mss = 536;
ULONG                        queued_count;
NX_PACKET                   *queued_ptr;
ULONG                        queued_source_ip;
UINT                         queued_source_port;
UINT                         is_connection_packet_flag;
UINT                         is_valid_option_flag = NX_TRUE;
UINT                         status;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
ULONG                        rwin_scale = 0xFF;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */


    /* Pickup the source IP address.  */
    ip_header_ptr =  (ULONG *)packet_ptr -> nx_packet_prepend_ptr;
    source_ip =  *(ip_header_ptr - 2);

#ifndef NX_DISABLE_TCP_RX_CHECKSUM

    /* Calculate the checksum.  */
    if (_nx_tcp_checksum(packet_ptr, source_ip, packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address))
    {

#ifndef NX_DISABLE_TCP_INFO

        /* Increment the TCP invalid packet error count.  */
        ip_ptr -> nx_ip_tcp_invalid_packets++;

        /* Increment the TCP packet checksum error count.  */
        ip_ptr -> nx_ip_tcp_checksum_errors++;
#endif

        /* Checksum error, just release the packet.  */
        _nx_packet_release(packet_ptr);
        return;
    }
#endif

    /* Pickup the pointer to the head of the TCP packet.  */
    tcp_header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the TCP header.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Determine if there are any option words...  Note there are always 5 words in a TCP header.  */
    option_words =  (tcp_header_ptr -> nx_tcp_header_word_3 >> 28) - 5;

#ifndef NX_DISABLE_RX_SIZE_CHECKING
    /* Check for valid packet length.  */
    if (((INT)option_words < 0) || (packet_ptr -> nx_packet_length < (option_words << 2)))
    {

#ifndef NX_DISABLE_TCP_INFO
        /* Increment the TCP invalid packet error.  */
        ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif

        /* Invalid packet length, just release it.  */
        _nx_packet_release(packet_ptr);

        /* The function is complete, just return!  */
        return;
    }
#endif

    if (option_words)
    {

        /* Yes, there are one or more option words.  */

        /* Derive the Maximum Segment Size (MSS) in the option words.  */
        status = _nx_tcp_mss_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)), option_words * sizeof(ULONG), &mss);

        /* Check the status. if status is NX_FALSE, means Option Length is invalid.  */
        if (status == NX_FALSE)
        {

            /* The option is invalid.  */
            is_valid_option_flag = NX_FALSE;
        }
        else
        {

            /* Set the default MSS if the MSS value was not found.  */
            if (mss == 0)
            {
                mss = 536;
            }
        }

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
        status = _nx_tcp_window_scaling_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)), option_words * sizeof(ULONG), &rwin_scale);

        /* Check the status. if status is NX_FALSE, means Option Length is invalid.  */
        if (status == NX_FALSE)
        {
            is_valid_option_flag = NX_FALSE;
        }
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
    }

    /* Pickup the destination TCP port.  */
    port =  (UINT)(tcp_header_ptr -> nx_tcp_header_word_0 & NX_LOWER_16_MASK);

    /* Pickup the source TCP port.  */
    source_port =  (UINT)(tcp_header_ptr -> nx_tcp_header_word_0 >> NX_SHIFT_BY_16);

    /* Calculate the hash index in the TCP port array of the associated IP instance.  */
    index =  (UINT)((port + (port >> 8)) & NX_TCP_PORT_TABLE_MASK);

    /* Search the bound sockets in this index for the particular port.  */
    socket_ptr =  ip_ptr -> nx_ip_tcp_port_table[index];

    /* Determine if there are any sockets bound on this port index.  */
    if (socket_ptr)
    {

        /*  Yes, loop to examine the list of bound ports on this index.  */
        do
        {

            /* Determine if the port has been found.  */
            if ((socket_ptr -> nx_tcp_socket_port == port) &&
                (socket_ptr -> nx_tcp_socket_connect_ip == source_ip) &&
                (socket_ptr -> nx_tcp_socket_connect_port == source_port))
            {

                /* Yes, we have a match!  */

                /* Determine if we need to update the tcp port head pointer.  This should
                   only be done if the found socket pointer is not the head pointer and
                   the mutex for this IP instance is available.  */
                if (socket_ptr != ip_ptr -> nx_ip_tcp_port_table[index])
                {

                    /* Move the port head pointer to this socket.  */
                    ip_ptr -> nx_ip_tcp_port_table[index] =  socket_ptr;
                }

                /* If this packet contains SYN */
                if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
                {
                    /* Record the MSS value if it is present and the   Otherwise use 536, as
                       outlined in RFC 1122 section 4.2.2.6. */

                    /* Yes, MSS was found store it!  */
                    socket_ptr -> nx_tcp_socket_peer_mss =  mss;

                    /* Compute the local MSS size based on the interface MTU size. */
                    mss = packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_mtu_size - sizeof(NX_TCP_HEADER) - sizeof(NX_IP_HEADER);

                    /* Calculate sender MSS. */
                    if (mss > socket_ptr -> nx_tcp_socket_peer_mss)
                    {

                        /* Local MSS is larger than peer MSS. */
                        mss = socket_ptr -> nx_tcp_socket_peer_mss;
                    }

                    if ((mss > socket_ptr -> nx_tcp_socket_mss) && socket_ptr -> nx_tcp_socket_mss)
                    {
                        socket_ptr -> nx_tcp_socket_connect_mss  = socket_ptr -> nx_tcp_socket_mss;
                    }
                    else
                    {
                        socket_ptr -> nx_tcp_socket_connect_mss  = mss;
                    }

                    /* Compute the SMSS * SMSS value, so later TCP module doesn't need to redo the multiplication. */
                    socket_ptr -> nx_tcp_socket_connect_mss2 =
                        socket_ptr -> nx_tcp_socket_connect_mss * socket_ptr -> nx_tcp_socket_connect_mss;



#ifdef NX_ENABLE_TCP_WINDOW_SCALING
                    /*
                       Simply record the peer's window scale value. When we move to the
                       ESTABLISHED state, we will set the peer window scale to 0 if the
                       peer does not support this feature.
                     */
                    socket_ptr -> nx_tcp_snd_win_scale_value = rwin_scale;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
                }


                /* Process the packet within an existing TCP connection.  */
                _nx_tcp_socket_packet_process(socket_ptr, packet_ptr);

                /* Get out of the search loop and this function!  */
                return;
            }
            else
            {

                /* Move to the next entry in the bound index.  */
                socket_ptr =  socket_ptr -> nx_tcp_socket_bound_next;
            }
        } while ((socket_ptr) && (socket_ptr != ip_ptr -> nx_ip_tcp_port_table[index]));
    }

    /* At this point, we know there is not an existing TCP connection.  */

    /* If this packet contains the valid option.  */
    if (is_valid_option_flag == NX_FALSE)
    {

        /* Send RST message.
           TCP MUST be prepared to handle an illegal option length (e.g., zero) without crashing;
           a suggested procedure is to reset the connection and log the reason, outlined in RFC 1122, Section 4.2.2.5, Page85. */
        _nx_tcp_no_connection_reset(ip_ptr, packet_ptr, tcp_header_ptr);

        /* Not a connection request, just release the packet.  */
        _nx_packet_release(packet_ptr);

        return;
    }

#ifdef NX_ENABLE_TCP_MSS_CHECKING
    /* Optionally check for a user specified minimum MSS. The user application may choose to
       define a minimum MSS value, and reject a TCP connection if peer MSS value does not
       meet the minimum. */
    if (mss < NX_TCP_MSS_MINIMUM)
    {
        /* Handle this as an invalid connection request. */
        _nx_packet_release(packet_ptr);

        return;
    }
#endif

    /* Determine if the packet is an initial connection request (only SYN bit set)
       and that we have resources to handle a new client connection request.  */

    /* Initialize a check for connection related request to false. */
    is_connection_packet_flag = NX_FALSE;

    if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) &&
        (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)) &&
        (ip_ptr -> nx_ip_tcp_active_listen_requests))
    {

        /* The incoming SYN packet is a connection request.  */
        is_connection_packet_flag = NX_TRUE;
    }
    else if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT) &&
             (ip_ptr -> nx_ip_tcp_active_listen_requests))
    {

        /* The incoming RST packet is related to a previous connection request.  */
        is_connection_packet_flag = NX_TRUE;
    }

    /* Handle new connection requests or RST packets cancelling existing (queued) connection requests */
    if (is_connection_packet_flag)
    {

        /* Check for LAND attack packet. This is an incoming packet with matching
           Source and Destination IP address, and matching source and destination port. */
        if ((source_ip == packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address) &&
            (source_port == port))
        {

            /* Bogus packet. Drop it! */

#ifndef NX_DISABLE_TCP_INFO

            /* Increment the TCP invalid packet error count.  */
            ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

            /* Release the packet we will not process any further.  */
            _nx_packet_release(packet_ptr);
            return;
        }

        /* Search all ports in listen mode for a match. */
        listen_ptr =  ip_ptr -> nx_ip_tcp_active_listen_requests;
        do
        {

            /* Determine if this port is in a listen mode.  */
            if (listen_ptr -> nx_tcp_listen_port == port)
            {

#ifndef NX_DISABLE_TCP_INFO

                /* Check for a RST (reset) bit set.  */
                if (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
                {

                    /* Increment the passive TCP connections count.  */
                    ip_ptr -> nx_ip_tcp_passive_connections++;

                    /* Increment the TCP connections count.  */
                    ip_ptr -> nx_ip_tcp_connections++;
                }

#endif

                /* Okay, this port is in a listen mode.  We now need to see if
                   there is an available socket for the new connection request
                   present.  */
                if ((listen_ptr -> nx_tcp_listen_socket_ptr) &&
                    ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT) == NX_NULL))
                {

                    /* Yes there is indeed a socket present.  We now need to
                       fill in the appropriate info and call the server callback
                       routine.  */

                    /* Allocate the supplied server socket.  */
                    socket_ptr =  listen_ptr -> nx_tcp_listen_socket_ptr;


#ifndef NX_DISABLE_EXTENDED_NOTIFY_SUPPORT
                    /* If extended notify is enabled, call the syn_received notify function.
                       This user-supplied function decides whether or not this SYN request
                       should be accepted. */
                    if (socket_ptr -> nx_tcp_socket_syn_received_notify)
                    {
                        if ((socket_ptr -> nx_tcp_socket_syn_received_notify)(socket_ptr, packet_ptr) != NX_TRUE)
                        {
                            /* Release the packet.  */
                            _nx_packet_release(packet_ptr);

                            /* Finished processing, simply return!  */
                            return;
                        }
                    }
#endif /* NX_DISABLE_EXTENDED_NOTIFY_SUPPORT */

                    /* If trace is enabled, insert this event into the trace buffer.  */
                    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_SYN_RECEIVE, ip_ptr, socket_ptr, packet_ptr, tcp_header_ptr -> nx_tcp_sequence_number, NX_TRACE_INTERNAL_EVENTS, 0, 0)

                    /* Clear the server socket pointer in the listen request.  If the
                       application wishes to honor more server connections on this port,
                       the application must call relisten with a new server socket
                       pointer.  */
                    listen_ptr -> nx_tcp_listen_socket_ptr =  NX_NULL;

                    /* Fill the socket in with the appropriate information.  */
                    socket_ptr -> nx_tcp_socket_connect_ip =    source_ip;
                    socket_ptr -> nx_tcp_socket_connect_port =  source_port;
                    socket_ptr -> nx_tcp_socket_rx_sequence =   tcp_header_ptr -> nx_tcp_sequence_number;
                    socket_ptr -> nx_tcp_socket_connect_interface = packet_ptr -> nx_packet_ip_interface;

                    if (_nx_ip_route_find(ip_ptr, source_ip, &socket_ptr -> nx_tcp_socket_connect_interface,
                                          &socket_ptr -> nx_tcp_socket_next_hop_address) != NX_SUCCESS)
                    {
                        /* Cannot determine how to send packets to this TCP peer.  Since we are able to
                           receive the syn, use the incoming interface, and send the packet out directly. */

                        socket_ptr -> nx_tcp_socket_next_hop_address = source_ip;
                    }

                    /* Yes, MSS was found store it!  */
                    socket_ptr -> nx_tcp_socket_peer_mss =  mss;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
                    /*
                       Simply record the peer's window scale value. When we move to the
                       ESTABLISHED state, we will set the peer window scale to 0 if the
                       peer does not support this feature.
                     */
                    socket_ptr -> nx_tcp_snd_win_scale_value = rwin_scale;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

                    /* Set the initial slow start threshold to be the advertised window size. */
                    socket_ptr -> nx_tcp_socket_tx_slow_start_threshold = socket_ptr -> nx_tcp_socket_tx_window_advertised;

                    /* Slow start:  setup initial window (IW) to be MSS,  RFC 2581, 3.1 */
                    socket_ptr -> nx_tcp_socket_tx_window_congestion = mss;

                    /* Initialize the transmit outstanding byte count to zero. */
                    socket_ptr -> nx_tcp_socket_tx_outstanding_bytes = 0;

                    /* Calculate the hash index in the TCP port array of the associated IP instance.  */
                    index =  (UINT)((port + (port >> 8)) & NX_TCP_PORT_TABLE_MASK);

                    /* Determine if the list is NULL.  */
                    if (ip_ptr -> nx_ip_tcp_port_table[index])
                    {

                        /* There are already sockets on this list... just add this one
                           to the end.  */
                        socket_ptr -> nx_tcp_socket_bound_next =
                            ip_ptr -> nx_ip_tcp_port_table[index];
                        socket_ptr -> nx_tcp_socket_bound_previous =
                            (ip_ptr -> nx_ip_tcp_port_table[index]) -> nx_tcp_socket_bound_previous;
                        ((ip_ptr -> nx_ip_tcp_port_table[index]) -> nx_tcp_socket_bound_previous) -> nx_tcp_socket_bound_next =
                            socket_ptr;
                        (ip_ptr -> nx_ip_tcp_port_table[index]) -> nx_tcp_socket_bound_previous =   socket_ptr;
                    }
                    else
                    {

                        /* Nothing is on the TCP port list.  Add this TCP socket to an
                           empty list.  */
                        socket_ptr -> nx_tcp_socket_bound_next =      socket_ptr;
                        socket_ptr -> nx_tcp_socket_bound_previous =  socket_ptr;
                        ip_ptr -> nx_ip_tcp_port_table[index] =       socket_ptr;
                    }

                    /* Pickup the listen callback function.  */
                    listen_callback =  listen_ptr -> nx_tcp_listen_callback;

                    /* Release the incoming packet.  */
                    _nx_packet_release(packet_ptr);

                    /* Determine if an accept call with suspension has already been made
                       for this socket.  If so, the SYN message needs to be sent from
                       here.  */
                    if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED)
                    {


                        /* If trace is enabled, insert this event into the trace buffer.  */
                        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_STATE_CHANGE, ip_ptr, socket_ptr, socket_ptr -> nx_tcp_socket_state, socket_ptr -> nx_tcp_socket_state, NX_TRACE_INTERNAL_EVENTS, 0, 0)


                        /* The application is suspended on an accept call for this socket.
                           Simply send the SYN now and keep the thread suspended until the
                           other side completes the connection.  */

                        /* Send the SYN message, but increment the ACK first.  */
                        socket_ptr -> nx_tcp_socket_rx_sequence++;

                        /* Increment the sequence number for the SYN message.  */
                        socket_ptr -> nx_tcp_socket_tx_sequence++;

                        /* Setup a timeout so the connection attempt can be sent again.  */
                        socket_ptr -> nx_tcp_socket_timeout =          socket_ptr -> nx_tcp_socket_timeout_rate;
                        socket_ptr -> nx_tcp_socket_timeout_retries =  0;

                        /* Send the SYN+ACK message.  */
                        _nx_tcp_packet_send_syn(socket_ptr, (socket_ptr -> nx_tcp_socket_tx_sequence - 1));
                    }

                    /* Determine if there is a listen callback function.  */
                    if (listen_callback)
                    {
                        /* Call the user's listen callback function.  */
                        (listen_callback)(socket_ptr, port);
                    }

                    /* Finished processing, just return.  */
                    return;
                }
                else
                {

                    /* There is no server socket available for the new connection.  */

                    /* Note: The application needs to call relisten on a socket to process queued
                       connection requests.  */

                    /* Check for a RST (reset) bit set.  */
                    if (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
                    {

                        /* If trace is enabled, insert this event into the trace buffer.  */
                        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_SYN_RECEIVE, ip_ptr, NX_NULL, packet_ptr, tcp_header_ptr -> nx_tcp_sequence_number, NX_TRACE_INTERNAL_EVENTS, 0, 0)
                    }

                    queued_count =  listen_ptr -> nx_tcp_listen_queue_current;
                    queued_ptr =    listen_ptr -> nx_tcp_listen_queue_head;

                    /* Check for the same connection request already in the queue. If this is a RST packet
                       it will check for a previous connection which should be removed from the queue.  */

                    /* Loop through the queued list.  */
                    while (queued_count--)
                    {

                        /* Pickup the queued source port and source IP address to check for a match.  */
                        queued_source_ip =    *(((ULONG *)queued_ptr -> nx_packet_prepend_ptr) - 2);
                        queued_source_port =  (UINT)(*((ULONG *)queued_ptr -> nx_packet_prepend_ptr) >> NX_SHIFT_BY_16);

                        /* Determine if this matches the current connection request.  */
                        if ((queued_source_ip == source_ip) && (queued_source_port == source_port))
                        {

                            /* Check for a RST (reset) bit set.  */
                            if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
                            {

                                tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

                                /* This matches a previous connection request which needs to be removed from the listen queue. */

                                /* Are there are any connection requests on the queue? */
                                if (listen_ptr -> nx_tcp_listen_queue_current == 0)
                                {

                                    /* No, put the TCP socket back in the listen structure. */
                                    listen_ptr -> nx_tcp_listen_socket_ptr =  socket_ptr;
                                }
                                else
                                {

                                /* Yes, we need to find the connection request in the queue. */
                                NX_PACKET *current_packet_ptr, *prev_packet_ptr;
                                UINT       found_connection_request = NX_FALSE;

                                    /* Start with the oldest one. */
                                    current_packet_ptr = listen_ptr -> nx_tcp_listen_queue_head;

                                    /* Remove the oldest connection request if it matches the current RST packet. */
                                    if (queued_ptr  == listen_ptr -> nx_tcp_listen_queue_head)
                                    {

                                        /* Reset the front (oldest) of the queue to the next request. */
                                        current_packet_ptr =  listen_ptr -> nx_tcp_listen_queue_head;
                                        listen_ptr -> nx_tcp_listen_queue_head =  current_packet_ptr -> nx_packet_queue_next;

                                        /* Was there only one queue request e.g. head == tail?   */
                                        if (current_packet_ptr == listen_ptr -> nx_tcp_listen_queue_tail)
                                        {

                                            /* Yes, and now there are none. Set the queue to empty. */
                                            listen_ptr -> nx_tcp_listen_queue_tail =  NX_NULL;
                                        }

                                        found_connection_request = NX_TRUE;
                                    }
                                    else
                                    {

                                        /* Check the rest of the connection requests. */

                                        prev_packet_ptr = current_packet_ptr;
                                        current_packet_ptr = current_packet_ptr -> nx_packet_queue_next;

                                        /* Loop through the queue to the most recent request or until we find a match. */
                                        while (current_packet_ptr)
                                        {

                                            /* Do we have a match? */
                                            if (queued_ptr == current_packet_ptr)
                                            {

                                                /* Yes, remove this one! */

                                                /* Link around the request we are removing. */
                                                prev_packet_ptr -> nx_packet_queue_next = current_packet_ptr -> nx_packet_queue_next;

                                                /* Is the request being removed the tail (most recent connection?)   */
                                                if (current_packet_ptr == listen_ptr -> nx_tcp_listen_queue_tail)
                                                {

                                                    /* Yes, set the previous connection request as the tail. */
                                                    listen_ptr -> nx_tcp_listen_queue_tail = prev_packet_ptr;
                                                }

                                                /* Make sure the most recent request null terminates the list. */
                                                listen_ptr -> nx_tcp_listen_queue_tail -> nx_packet_queue_next =  NX_NULL;

                                                found_connection_request = NX_TRUE;
                                                break;
                                            }

                                            /* Not the connection request to remove. Check the next one,
                                               and save the current connection request as the 'previous' one. */
                                            prev_packet_ptr = current_packet_ptr;
                                            current_packet_ptr = current_packet_ptr -> nx_packet_queue_next;
                                        }
                                    }

                                    /* Verify we found the connection to remove. */
                                    if (found_connection_request == NX_TRUE)
                                    {

                                        /* Release the connection request packet.  */
                                        _nx_packet_release(current_packet_ptr);

                                        /* Update the listen queue. */
                                        listen_ptr -> nx_tcp_listen_queue_current--;
                                    }
                                }

                                /* Release the protection.  */
                                tx_mutex_put(&(ip_ptr -> nx_ip_protection));
                            }

#ifndef NX_DISABLE_TCP_INFO

                            /* Increment the TCP dropped packet count.  */
                            ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif

                            /* Simply release the packet and return.  */
                            _nx_packet_release(packet_ptr);

                            /* Return!  */
                            return;
                        }

                        /* Move to next item in the queue.  */
                        queued_ptr =  queued_ptr -> nx_packet_queue_next;
                    }

                    /* No duplicate connection requests were found. */

                    /* Is this a RST packet? */
                    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
                    {
                        /* Yes, so not a connection request. Do not place on the listen queue. */

                        /* Release the packet.  */
                        _nx_packet_release(packet_ptr);

                        /* Return!  */
                        return;
                    }

                    /* This is a valid connection request. Place this request on the listen queue.  */

                    /* Set the next pointer of the packet to NULL.  */
                    packet_ptr -> nx_packet_queue_next =  NX_NULL;

                    /* Queue the new connection request.  */
                    if (listen_ptr -> nx_tcp_listen_queue_head)
                    {

                        /* There is a connection request already queued, just link packet to tail.  */
                        (listen_ptr -> nx_tcp_listen_queue_tail) -> nx_packet_queue_next =  packet_ptr;
                    }
                    else
                    {

                        /* The queue is empty.  Setup head pointer to the new packet.  */
                        listen_ptr -> nx_tcp_listen_queue_head =  packet_ptr;
                    }

                    /* Setup the tail pointer to the new packet and increment the queue count.  */
                    listen_ptr -> nx_tcp_listen_queue_tail =  packet_ptr;
                    listen_ptr -> nx_tcp_listen_queue_current++;

                    /* Determine if the queue depth has been exceeded.  */
                    if (listen_ptr -> nx_tcp_listen_queue_current > listen_ptr -> nx_tcp_listen_queue_maximum)
                    {

#ifndef NX_DISABLE_TCP_INFO

                        /* Increment the TCP connections dropped count.  */
                        ip_ptr -> nx_ip_tcp_connections_dropped++;
                        ip_ptr -> nx_ip_tcp_connections--;

                        /* Increment the TCP dropped packet count.  */
                        ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif

                        /* Save the head packet pointer, since this will be released below.  */
                        packet_ptr =  listen_ptr -> nx_tcp_listen_queue_head;

                        /* Remove the oldest packet from the queue.  */
                        listen_ptr -> nx_tcp_listen_queue_head =  (listen_ptr -> nx_tcp_listen_queue_head) -> nx_packet_queue_next;

                        /* Decrement the number of packets in the queue.  */
                        listen_ptr -> nx_tcp_listen_queue_current--;

                        /* We have exceeded the number of connections that can be
                           queued for this port.  */

                        /* Release the packet.  */
                        _nx_packet_release(packet_ptr);
                    }

                    /* Finished processing, just return.  */
                    return;
                }
            }

            /* Move to the next listen request.  */
            listen_ptr =  listen_ptr -> nx_tcp_listen_next;
        } while (listen_ptr != ip_ptr -> nx_ip_tcp_active_listen_requests);
    }

#ifndef NX_DISABLE_TCP_INFO

    /* Determine if a connection request is present.  */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
    {

        /* Yes, increment the TCP connections dropped count.  */
        ip_ptr -> nx_ip_tcp_connections_dropped++;
    }

    /* Increment the TCP dropped packet count.  */
    ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif

    /* Determine if a RST is present. If so, don't send a RST in response.  */
    if (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {

        /* Non RST is present, send reset when no connection is present.  */
        _nx_tcp_no_connection_reset(ip_ptr, packet_ptr, tcp_header_ptr);
    }

    /* Not a connection request, just release the packet.  */
    _nx_packet_release(packet_ptr);
    return;
}

