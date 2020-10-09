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
#include "nx_packet.h"
#include "nx_ip.h"
#include "nx_tcp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_retransmit                           PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function retransmit a TCP packet.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    socket_ptr                            Pointer to owning socket      */
/*    need_fast_retransmit                  Need fast retransmit or not   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_packet_send                    Resend the transmit packet    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing      Process TCP packet for socket */
/*    _nx_tcp_socket_state_ack_check        Process ACK number            */
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
VOID  _nx_tcp_socket_retransmit(NX_IP *ip_ptr, NX_TCP_SOCKET *socket_ptr, UINT need_fast_retransmit)
{
NX_PACKET *packet_ptr;
NX_PACKET *next_ptr;
ULONG      window;
ULONG      available;

    /* If the reciever winodw is zero, we enter the zero window probe phase
       RFC 793 Sec 3.7, p42: keep send new data.

       In the zero window probe phase, we send the zero window probe, and increase
       exponentially the interval between successive probes.
       RFC 1122 Sec 4.2.2.17, p92.  */
    if (socket_ptr -> nx_tcp_socket_tx_window_advertised == 0)
    {

        /* In the zero window probe phase, we send the zero window probe, and increase
         * exponentially the interval between successive probes.  */

        /* Increment the retry counter.  */
        socket_ptr -> nx_tcp_socket_timeout_retries++;

        /* Setup the next timeout.  */
        socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate <<
            (socket_ptr -> nx_tcp_socket_timeout_retries *
             socket_ptr -> nx_tcp_socket_timeout_shift);

        /* Send the zero window probe.  */
        _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);

        return;
    }

    /* Increment the retry counter only if the reciever window is open. */
    /* Increment the retry counter.  */
    socket_ptr -> nx_tcp_socket_timeout_retries++;

    if ((need_fast_retransmit == NX_TRUE) || (socket_ptr -> nx_tcp_socket_fast_recovery == NX_FALSE))
    {

        /* Timed out on an outgoing packet.  Enter slow start mode. */
        /* Compute the flight size / 2 value. */
        window = socket_ptr -> nx_tcp_socket_tx_outstanding_bytes >> 1;

        /* Make sure we have at least 2 * MSS */
        if (window < (socket_ptr -> nx_tcp_socket_connect_mss << 1))
        {
            window = socket_ptr -> nx_tcp_socket_connect_mss << 1;
        }

        /* Set the slow_start_threshold */
        socket_ptr -> nx_tcp_socket_tx_slow_start_threshold = window;

        /* Set the current window to be MSS size. */
        socket_ptr -> nx_tcp_socket_tx_window_congestion = socket_ptr -> nx_tcp_socket_connect_mss;

        /* Determine if this socket needs fast retransmit.  */
        if (need_fast_retransmit == NX_TRUE)
        {

            /* Update cwnd to ssthreshold plus 3 * MSS.  */
            socket_ptr -> nx_tcp_socket_tx_window_congestion += window + (socket_ptr -> nx_tcp_socket_connect_mss << 2);

            /* Now TCP is in fast recovery procedure. */
            socket_ptr -> nx_tcp_socket_fast_recovery = NX_TRUE;

            /* Update the transmit sequence that enters fast transmit. */
            socket_ptr -> nx_tcp_socket_tx_sequence_recover = socket_ptr -> nx_tcp_socket_tx_sequence - 1;
        }
    }

    /* Setup the next timeout.  */
    socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate <<
        (socket_ptr -> nx_tcp_socket_timeout_retries *
         socket_ptr -> nx_tcp_socket_timeout_shift);

    /* Get available size of packet that can be sent. */
    available = socket_ptr -> nx_tcp_socket_tx_window_congestion;

    /* Pickup the head of the transmit queue.  */
    packet_ptr =  socket_ptr -> nx_tcp_socket_transmit_sent_head;

    /* Determine if the packet has been released by the
       application I/O driver.  */
    while (packet_ptr && (packet_ptr -> nx_packet_queue_next == (NX_PACKET *)NX_DRIVER_TX_DONE))
    {

        if (packet_ptr -> nx_packet_length > (available + sizeof(NX_TCP_HEADER)))
        {
            /* This packet can not be sent. */
            break;
        }

        /* Decrease the available size. */
        available -= (packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER));

        /* Pickup next packet. */
        next_ptr = packet_ptr -> nx_packet_tcp_queue_next;

#ifndef NX_DISABLE_TCP_INFO
        /* Increment the TCP retransmit count.  */
        ip_ptr -> nx_ip_tcp_retransmit_packets++;

        /* Increment the TCP retransmit count for the socket.  */
        socket_ptr -> nx_tcp_socket_retransmit_packets++;
#endif

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_RETRY, ip_ptr, socket_ptr, packet_ptr, socket_ptr -> nx_tcp_socket_timeout_retries, NX_TRACE_INTERNAL_EVENTS, 0, 0);

        /* Clear the queue next pointer.  */
        packet_ptr -> nx_packet_queue_next =  NX_NULL;

        /* Yes, the driver has finished with the packet at the head of the
           transmit sent list... so it can be sent again!  */

        /* Yes, the driver has finished with the packet at the head of the
           transmit sent list... so it can be sent again!  */
        _nx_ip_packet_send(ip_ptr, packet_ptr,  socket_ptr -> nx_tcp_socket_connect_ip,
                           socket_ptr -> nx_tcp_socket_type_of_service, socket_ptr -> nx_tcp_socket_time_to_live, NX_IP_TCP,
                           socket_ptr -> nx_tcp_socket_fragment_enable);

        /* Move to next packet. */
        /* During fast recovery, only one packet is retransmitted at once. */
        /* After a timeout, the sending data can be at most one SMSS. */
        if ((next_ptr == (NX_PACKET *)NX_PACKET_ENQUEUED) ||
            (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE))
        {
            break;
        }
        else
        {
            packet_ptr = next_ptr;
        }
    }
}

