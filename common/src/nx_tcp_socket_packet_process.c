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


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_packet_process                       PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes an incoming TCP packet relative to the      */
/*    socket it belongs to, including processing state changes, and       */
/*    sending and receiving data.                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to owning socket      */
/*    packet_ptr                            Pointer to packet to process  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Packet release function       */
/*    _nx_tcp_socket_connection_reset       Reset connection              */
/*    _nx_tcp_socket_state_ack_check        Process received ACKs         */
/*    _nx_tcp_socket_state_closing          Process CLOSING state         */
/*    _nx_tcp_socket_state_data_check       Process received data         */
/*    _nx_tcp_socket_state_established      Process ESTABLISHED state     */
/*    _nx_tcp_socket_state_fin_wait1        Process FIN WAIT 1 state      */
/*    _nx_tcp_socket_state_fin_wait2        Process FIN WAIT 2 state      */
/*    _nx_tcp_socket_state_last_ack         Process LAST ACK state        */
/*    _nx_tcp_socket_state_syn_received     Process SYN RECEIVED state    */
/*    _nx_tcp_socket_state_syn_sent         Process SYN SENT state        */
/*    _nx_tcp_socket_state_transmit_check   Check for transmit ability    */
/*    (nx_tcp_urgent_data_callback)         Application urgent callback   */
/*                                            function                    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_packet_process                Process raw TCP packet        */
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
VOID  _nx_tcp_socket_packet_process(NX_TCP_SOCKET *socket_ptr, NX_PACKET *packet_ptr)
{

UINT          packet_queued =  NX_FALSE;
NX_TCP_HEADER tcp_header_copy;
VOID          (*urgent_callback)(NX_TCP_SOCKET *socket_ptr);
ULONG         header_length;
ULONG         packet_data_length;
ULONG         packet_sequence;
ULONG         rx_sequence;
ULONG         rx_window;
UINT          outside_of_window;
ULONG         mss = 0;

    /* Copy the TCP header, since the actual packet can be delivered to
       a waiting socket/thread during this routine and before we are done
       using the header.  */
    tcp_header_copy =  *((NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr);

    /* Get the size of the TCP header.  */
    header_length =  (tcp_header_copy.nx_tcp_header_word_3 >> NX_TCP_HEADER_SHIFT) * sizeof(ULONG);

    /* Detect whether or not the data is outside the window. */
    if ((socket_ptr -> nx_tcp_socket_state >= NX_TCP_SYN_RECEIVED) ||
        (tcp_header_copy.nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {

        /* Pickup the sequence of this packet. */
        packet_sequence = tcp_header_copy.nx_tcp_sequence_number;

        /* Calculate the data length in the packet.  */
        packet_data_length = packet_ptr -> nx_packet_length - header_length;

        /* Pickup the rx sequence.  */
        rx_sequence = socket_ptr -> nx_tcp_socket_rx_sequence;

        /* Pickup the rx window.  */
        rx_window = socket_ptr -> nx_tcp_socket_rx_window_current;

        /* There are four cases for the acceptability test for an incoming segment.
           Section 3.9 Page 69, RFC 793.  */
        outside_of_window = NX_TRUE;

        if (packet_data_length == 0)
        {
            if (((rx_window == 0) &&
                 (packet_sequence == rx_sequence)) ||
                ((rx_window > 0) &&
                 ((int)packet_sequence - (int)rx_sequence >= 0) &&
                 ((int)rx_sequence + (int)rx_window - (int)packet_sequence > 0)))
            {
                outside_of_window = NX_FALSE;
            }
        }
        else
        {
            if ((rx_window > 0) &&
                ((((int)packet_sequence - (int)rx_sequence >= 0) &&
                  ((int)rx_sequence + (int)rx_window - (int)packet_sequence > 0)) ||
                 (((int)packet_sequence + (int)packet_data_length - 1 - (int)rx_sequence >= 0) &&
                 ((int)rx_sequence + (int)rx_window - (int)packet_sequence - (int)packet_data_length + 1 > 0))))
            {
                outside_of_window = NX_FALSE;
            }
        }


        /* Check whether or not a RST (reset) control message is acceptable. */
        if (tcp_header_copy.nx_tcp_header_word_3 & NX_TCP_RST_BIT)
        {

            /* The state is SYN-SENT, Check for an ACK bit is set,According to RFC 793, Section 3.9, Page 67.  */
            if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) &&
                (!(tcp_header_copy.nx_tcp_header_word_3 & NX_TCP_ACK_BIT)))
            {

                /* Release the packet.  */
                _nx_packet_release(packet_ptr);

                /* Finished processing, simply return!  */
                return;
            }

            /*Check whether or not a RST is acceptable, according to RFC 793, Section 3.4, Page 37. */
            if ((outside_of_window && (socket_ptr -> nx_tcp_socket_state != NX_TCP_SYN_SENT)) ||
                ((tcp_header_copy.nx_tcp_acknowledgment_number != socket_ptr -> nx_tcp_socket_tx_sequence) &&
                 (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT)))
            {

                /* This RST packet is unacceptable.  Ignore the RST and release the packet.  */
                _nx_packet_release(packet_ptr);

                /* Finished processing, simply return!  */
                return;
            }

#ifndef NX_DISABLE_TCP_INFO

            /* Increment the resets received count.  */
            (socket_ptr -> nx_tcp_socket_ip_ptr) -> nx_ip_tcp_resets_received++;
#endif

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_RESET_RECEIVE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, packet_ptr, tcp_header_copy.nx_tcp_sequence_number, NX_TRACE_INTERNAL_EVENTS, 0, 0)

            /* Reset connection.  */
            _nx_tcp_socket_connection_reset(socket_ptr);

            /* Release the packet.  */
            _nx_packet_release(packet_ptr);

            /* Finished processing, simply return!  */
            return;
        }
        else if (outside_of_window)
        {

            /* If an incoming segment is not acceptable, an acknowledgment
               should be sent in reply.
               Section 3.9, Page 69, RFC 793.  */
#ifndef NX_DISABLE_TCP_INFO

            /* Increment the TCP dropped packet count.  */
            socket_ptr -> nx_tcp_socket_ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif

            /* Release the packet.  */
            _nx_packet_release(packet_ptr);

            /* Send an immediate ACK.  */
            _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);

            /* Finished processing, simply return!  */
            return;
        }
    }

    /* Illegal option length check. */
    if (header_length > sizeof(NX_TCP_HEADER))
    {
        if (!_nx_tcp_mss_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)),
                                    header_length - sizeof(NX_TCP_HEADER), &mss))
        {

            /* Send RST message.
               TCP MUST be prepared to handle an illegal option length (e.g., zero) without crashing;
               a suggested procedure is to reset the connection and log the reason, outlined in RFC 1122, Section 4.2.2.5, Page85. */
            _nx_tcp_packet_send_rst(socket_ptr, &tcp_header_copy);

            /* Reset connection.  */
            _nx_tcp_socket_connection_reset(socket_ptr);

            /* Release the packet.  */
            _nx_packet_release(packet_ptr);

#ifndef NX_DISABLE_TCP_INFO

            /* Increment the TCP dropped packet count.  */
            socket_ptr -> nx_tcp_socket_ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif

            return;
        }
    }

    /* Process relative to the state of the socket.  */
    switch (socket_ptr -> nx_tcp_socket_state)
    {

    case  NX_TCP_SYN_SENT:
    {

        /* Call the SYN SENT state handling function to process any state
           changes caused by this new packet.  */
        _nx_tcp_socket_state_syn_sent(socket_ptr, &tcp_header_copy);

        /* Check whether socket is established. */
        if (socket_ptr -> nx_tcp_socket_state == NX_TCP_ESTABLISHED)
        {

            /* Check for data in the current packet.  */
            packet_queued =  _nx_tcp_socket_state_data_check(socket_ptr, packet_ptr);
        }

        /* State processing is complete.  */
        break;
    }

    case  NX_TCP_SYN_RECEIVED:
    {


        /* Call the SYN RECEIVED state handling function to process any state
           changes caused by this new packet.  */
        _nx_tcp_socket_state_syn_received(socket_ptr, &tcp_header_copy);

        /* Check whether socket is established. */
        if (socket_ptr -> nx_tcp_socket_state == NX_TCP_ESTABLISHED)
        {

            /* Check for data in the current packet.  */
            packet_queued =  _nx_tcp_socket_state_data_check(socket_ptr, packet_ptr);
        }

        /* State processing is complete.  */
        break;
    }

    case  NX_TCP_ESTABLISHED:
    {

        /* Check and process an ACK specified in the current packet.  */
        _nx_tcp_socket_state_ack_check(socket_ptr, &tcp_header_copy);

        /* Check for data in the current packet.  */
        packet_queued =  _nx_tcp_socket_state_data_check(socket_ptr, packet_ptr);

        /* Call the ESTABLISHED state state handling function to process any state
           changes caused by this new packet.  */
        _nx_tcp_socket_state_established(socket_ptr, &tcp_header_copy);

        /* Determine if any transmit suspension can be lifted.  */
        _nx_tcp_socket_state_transmit_check(socket_ptr);

        /* State processing is complete.  */
        break;
    }

    case  NX_TCP_CLOSE_WAIT:
    {

        /* Not much needs to be done in this state since the application is
           responsible for moving to the next state, which is LAST ACK.  In the
           meantime, this side of the connection is still allowed to transmit
           so we need to check for ACK and threads suspended for transmit.  */

        /* Check and process an ACK specified in the current packet.  */
        _nx_tcp_socket_state_ack_check(socket_ptr, &tcp_header_copy);

        /* Check for data in the current packet.  */
        packet_queued = _nx_tcp_socket_state_data_check(socket_ptr, packet_ptr);

        /* Determine if any transmit suspension can be lifted.  */
        _nx_tcp_socket_state_transmit_check(socket_ptr);

        /* State processing is complete.  */
        break;
    }

    case  NX_TCP_LAST_ACK:
    {


        /* Check and process an ACK specified in the current packet.  */
        _nx_tcp_socket_state_ack_check(socket_ptr, &tcp_header_copy);

        /* Call the LAST ACK state state handling function to process any state
           changes caused by this new packet.  */
        _nx_tcp_socket_state_last_ack(socket_ptr, &tcp_header_copy);

        /* State processing is complete.  */
        break;
    }

    case  NX_TCP_FIN_WAIT_1:
    {

        /* Check and process an ACK specified in the current packet.  */
        _nx_tcp_socket_state_ack_check(socket_ptr, &tcp_header_copy);

        /* Check for data in the current packet.  */
        packet_queued =  _nx_tcp_socket_state_data_check(socket_ptr, packet_ptr);

        /* Call the FIN WAIT 1 state state handling function to process any state
           changes caused by this new packet.  */
        _nx_tcp_socket_state_fin_wait1(socket_ptr, &tcp_header_copy);

        /* State processing is complete.  */
        break;
    }

    case  NX_TCP_FIN_WAIT_2:
    {


        /* Check and process an ACK specified in the current packet.  */
        _nx_tcp_socket_state_ack_check(socket_ptr, &tcp_header_copy);

        /* Check for data in the current packet.  */
        packet_queued =  _nx_tcp_socket_state_data_check(socket_ptr, packet_ptr);

        /* Call the FIN WAIT 2 state state handling function to process any state
           changes caused by this new packet.  */
        _nx_tcp_socket_state_fin_wait2(socket_ptr, &tcp_header_copy);

        /* State processing is complete.  */
        break;
    }

    case  NX_TCP_CLOSING:
    {

        /* Call the CLOSING state state handling function to process any state
           changes caused by this new packet.  */
        _nx_tcp_socket_state_closing(socket_ptr, &tcp_header_copy);

        /* State processing is complete.  */
        break;
    }

    default:
        break;
    }

    /* Check for an URG (urgent) bit set.  */
    if (tcp_header_copy.nx_tcp_header_word_3 & NX_TCP_URG_BIT)
    {

        /* Yes, an Urgent bit is set.  */

        /* Pickup the urgent callback function specified when the socket was created.  */
        urgent_callback =  socket_ptr -> nx_tcp_urgent_data_callback;

        /* Determine if there is an urgent callback function specified.  */
        if (urgent_callback)
        {

            /* Yes, call the application's urgent callback function to alert the application
               of the presence of the urgent bit.  */
            (urgent_callback)(socket_ptr);
        }
    }

    /* Determine if we need to release the packet.  */
    if (!packet_queued)
    {

        /* Yes, the packet was not queued up above, so it needs to be released.  */
        _nx_packet_release(packet_ptr);
    }
}

