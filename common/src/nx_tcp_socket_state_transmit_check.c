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
/*    _nx_tcp_socket_state_transmit_check                 PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function determines if the new receive window value is large   */
/*    enough to satisfy a thread suspended trying to send data on the TCP */
/*    connection.  This is typically called from the ESTABLISHED state.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to owning socket      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_packet_send                    Send IP packet                */
/*    _nx_tcp_socket_thread_resume          Resume suspended thread       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_socket_packet_process         Process TCP packet for socket */
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
VOID  _nx_tcp_socket_state_transmit_check(NX_TCP_SOCKET *socket_ptr)
{

NX_IP     *ip_ptr;
NX_PACKET *packet_ptr;
TX_THREAD *thread_ptr;
ULONG      tx_window_current;


    /* Setup the IP pointer.  */
    ip_ptr =  socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Now check to see if there is a thread suspended attempting to transmit.  */
    if (socket_ptr -> nx_tcp_socket_transmit_suspension_list)
    {

        /* Yes, a thread is suspended attempting to transmit when the transmit window
           is lower than its request size.  Determine if the current transmit window
           size can now accommodate the request.  */

        /* Setup a thread pointer.  */
        thread_ptr =  socket_ptr -> nx_tcp_socket_transmit_suspension_list;

        /* Pickup the packet the thread is trying to send.  */
        packet_ptr =   (NX_PACKET *)thread_ptr -> tx_thread_additional_suspend_info;

        /* Pick up the min(cwnd, swnd) */
        if (socket_ptr -> nx_tcp_socket_tx_window_advertised > socket_ptr -> nx_tcp_socket_tx_window_congestion)
        {
            tx_window_current = socket_ptr -> nx_tcp_socket_tx_window_congestion;

            /* On the first and second duplicate ACKs received, the total FlightSize would
               remain less than or equal to cwnd plus 2*SMSS.
               Section 3.2, Page 9, RFC5681. */
            if ((socket_ptr -> nx_tcp_socket_duplicated_ack_received == 1) ||
                (socket_ptr -> nx_tcp_socket_duplicated_ack_received == 2))
            {
                tx_window_current += (socket_ptr -> nx_tcp_socket_connect_mss << 1);
            }
        }
        else
        {
            tx_window_current = socket_ptr -> nx_tcp_socket_tx_window_advertised;
        }

        /* Substract any data transmitted but unacked (outstanding bytes) */
        if (tx_window_current > socket_ptr -> nx_tcp_socket_tx_outstanding_bytes)
        {
            tx_window_current -= socket_ptr -> nx_tcp_socket_tx_outstanding_bytes;
        }
        else    /* Set tx_window_current to zero. */
        {
            tx_window_current = 0;
        }


        /* Determine if the current transmit window (received from the connected socket)
           is large enough to handle the transmit.  */
        if ((tx_window_current >= (packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER))) &&
            (socket_ptr -> nx_tcp_socket_transmit_sent_count < socket_ptr -> nx_tcp_socket_transmit_queue_maximum))
        {

            /* Is NetX set up with a window update callback? */
            if (socket_ptr -> nx_tcp_socket_window_update_notify)
            {

                /* Yes; Call this function when there is a change in transmit window size. */
                (socket_ptr -> nx_tcp_socket_window_update_notify)(socket_ptr);
            }

            /* Send the packet.  */

            /* Yes, the packet can be sent.  Place the packet on the sent list.  */
            if (socket_ptr -> nx_tcp_socket_transmit_sent_head)
            {

                /* Yes, other packets are on the list already.  Just add this one to the tail.  */
                (socket_ptr -> nx_tcp_socket_transmit_sent_tail) -> nx_packet_tcp_queue_next =  packet_ptr;
                socket_ptr -> nx_tcp_socket_transmit_sent_tail =  packet_ptr;
            }
            else
            {
                /* Empty list, just setup the head and tail to the current packet.  */
                socket_ptr -> nx_tcp_socket_transmit_sent_head =  packet_ptr;
                socket_ptr -> nx_tcp_socket_transmit_sent_tail =  packet_ptr;

                /* Setup a transmit timeout for this packet.  */
                socket_ptr -> nx_tcp_socket_timeout =          socket_ptr -> nx_tcp_socket_timeout_rate;
                socket_ptr -> nx_tcp_socket_timeout_retries =  0;
            }

            /* Set the next pointer to indicate the packet is on a TCP queue.  */
            packet_ptr -> nx_packet_tcp_queue_next =  (NX_PACKET *)NX_PACKET_ENQUEUED;

            /* Increment the packet sent count.  */
            socket_ptr -> nx_tcp_socket_transmit_sent_count++;

            /* Increase the outstanding byte count. */
            socket_ptr -> nx_tcp_socket_tx_outstanding_bytes +=
                (packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER));

            /* Adjust the transmit sequence number to reflect the output data.  */
            socket_ptr -> nx_tcp_socket_tx_sequence =  socket_ptr -> nx_tcp_socket_tx_sequence +
                (packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER));

            /* The packet is already in the native endian format so just send it out
               the IP interface.  */

#ifndef NX_DISABLE_TCP_INFO
            /* Increment the TCP packet sent count and bytes sent count.  */
            ip_ptr -> nx_ip_tcp_packets_sent++;
            ip_ptr -> nx_ip_tcp_bytes_sent += packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER);

            /* Increment the TCP packet sent count and bytes sent count for the socket.  */
            socket_ptr -> nx_tcp_socket_packets_sent++;
            socket_ptr -> nx_tcp_socket_bytes_sent += packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER);
#endif

            /* If trace is enabled, insert this event into the trace buffer.  */
            NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_DATA_SEND, ip_ptr, socket_ptr, packet_ptr, socket_ptr -> nx_tcp_socket_tx_sequence - (packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER)), NX_TRACE_INTERNAL_EVENTS, 0, 0)


            /* Send the TCP packet to the IP component.  */
            _nx_ip_packet_send(ip_ptr, packet_ptr,  socket_ptr -> nx_tcp_socket_connect_ip,
                               socket_ptr -> nx_tcp_socket_type_of_service, socket_ptr -> nx_tcp_socket_time_to_live, NX_IP_TCP, socket_ptr -> nx_tcp_socket_fragment_enable);

            /* Decrement the suspension count.  */
            socket_ptr -> nx_tcp_socket_transmit_suspended_count--;

            /* Remove the suspended thread from the list.  */
            _nx_tcp_socket_thread_resume(&(socket_ptr -> nx_tcp_socket_transmit_suspension_list), NX_SUCCESS);
        }
    }
}

