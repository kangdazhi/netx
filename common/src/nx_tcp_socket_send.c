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
#include "tx_thread.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_send_internal                        PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a TCP packet through the specified socket.      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to socket             */
/*    packet_ptr                            Pointer to packet to send     */
/*    wait_option                           Suspension option             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_packet_send                    Packet send function          */
/*    _nx_tcp_checksum                      Calculate TCP checksum        */
/*    _nx_tcp_socket_thread_suspend         Suspend calling thread        */
/*    tx_mutex_get                          Get protection mutex          */
/*    tx_mutex_put                          Put protection mutex          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
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
static UINT  _nx_tcp_socket_send_internal(NX_TCP_SOCKET *socket_ptr, NX_PACKET *packet_ptr, ULONG wait_option)
{

TX_INTERRUPT_SAVE_AREA

NX_IP         *ip_ptr;
NX_TCP_HEADER *header_ptr;
ULONG          checksum;
ULONG          sequence_number;
ULONG          tx_window_current;

    /* Determine if the packet is valid.  */
    if (packet_ptr -> nx_packet_tcp_queue_next != (NX_PACKET *)NX_PACKET_ALLOCATED)
    {

#ifndef NX_DISABLE_TCP_INFO
        /* Setup the pointer to the associated IP instance.  */
        ip_ptr =  socket_ptr -> nx_tcp_socket_ip_ptr;

        /* Increment the TCP invalid packet count.  */
        ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif

        return(NX_INVALID_PACKET);
    }

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_TCP_SOCKET_SEND, socket_ptr, packet_ptr, packet_ptr -> nx_packet_length, socket_ptr -> nx_tcp_socket_tx_sequence, NX_TRACE_TCP_EVENTS, 0, 0)

    /* Lockout interrupts.  */
    TX_DISABLE

    /* Determine if the socket is currently bound.  */
    if (!socket_ptr ->  nx_tcp_socket_bound_next)
    {

        /* Restore interrupts.  */
        TX_RESTORE

        /* Socket is not bound, return an error message.  */
        return(NX_NOT_BOUND);
    }

    /* Check for the socket being in an established state.  */
    if ((socket_ptr -> nx_tcp_socket_state != NX_TCP_ESTABLISHED) && (socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSE_WAIT))
    {

        /* Restore interrupts.  */
        TX_RESTORE

        /* Socket is not connected, return an error message.  */
        return(NX_NOT_CONNECTED);
    }

    /* Pickup the important information from the socket.  */

    /* Setup the pointer to the associated IP instance.  */
    ip_ptr =  socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Set the outgoing interface.  It should have been set for this socket. */
    packet_ptr -> nx_packet_ip_interface = socket_ptr -> nx_tcp_socket_connect_interface;
    packet_ptr -> nx_packet_next_hop_address = socket_ptr -> nx_tcp_socket_next_hop_address;

    /* Prepend the TCP header to the packet.  First, make room for the TCP header.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - sizeof(NX_TCP_HEADER);

    /* Add the length of the TCP header.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + sizeof(NX_TCP_HEADER);

    /* Pickup the pointer to the head of the TCP packet.  */
    header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Build the output request in the TCP header.  */
    header_ptr -> nx_tcp_header_word_0 =        (((ULONG)(socket_ptr -> nx_tcp_socket_port)) << NX_SHIFT_BY_16) | (ULONG)socket_ptr -> nx_tcp_socket_connect_port;
    header_ptr -> nx_tcp_acknowledgment_number = socket_ptr -> nx_tcp_socket_rx_sequence;
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | NX_TCP_PSH_BIT | (socket_ptr -> nx_tcp_socket_rx_window_current >> socket_ptr -> nx_tcp_rcv_win_scale_value);
#else /* !NX_ENABLE_TCP_WINDOW_SCALING */
    header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | NX_TCP_PSH_BIT | socket_ptr -> nx_tcp_socket_rx_window_current;
#endif /* !NX_ENABLE_TCP_WINDOW_SCALING */
    header_ptr -> nx_tcp_header_word_4 =        0;

    /* Remember the last ACKed sequence and the last reported window size.  */
    socket_ptr -> nx_tcp_socket_rx_sequence_acked =    socket_ptr -> nx_tcp_socket_rx_sequence;
    socket_ptr -> nx_tcp_socket_rx_window_last_sent =  socket_ptr -> nx_tcp_socket_rx_window_current;

    /* Setup a new delayed ACK timeout.  */
    socket_ptr -> nx_tcp_socket_delayed_ack_timeout =  _nx_tcp_ack_timer_rate;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the TCP header.  */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_4);

    do
    {

        /* Pickup the current transmit sequence number.  */
        header_ptr -> nx_tcp_sequence_number =  socket_ptr -> nx_tcp_socket_tx_sequence;
        sequence_number =  header_ptr -> nx_tcp_sequence_number;
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_sequence_number);

        /* Calculate the TCP checksum without protection.  */
#ifndef NX_DISABLE_TCP_TX_CHECKSUM
        checksum =  _nx_tcp_checksum(packet_ptr, packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_address, socket_ptr -> nx_tcp_socket_connect_ip);
#else
        checksum = 0;
#endif
        /* Place protection while we check the sequence number for the new TCP packet.  */
        tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

        /* Determine if the sequence number is the same.  */
        if (sequence_number != socket_ptr -> nx_tcp_socket_tx_sequence)
        {

            /* Another transmit on this socket took place and changed the sequence.  We need to
               recalculate the checksum with a new sequence number.  Release protection and
               just resume the loop.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        }
        else
        {

            /* We have a good checksum, proceed with sending the packet.  */
            break;
        }
    } while (NX_FOREVER);

    /* Check for the socket being in an established state.  It's possible the connection could have gone
       away during the TCP checksum calculation above.  */
    if ((socket_ptr -> nx_tcp_socket_state != NX_TCP_ESTABLISHED) && (socket_ptr -> nx_tcp_socket_state != NX_TCP_CLOSE_WAIT))
    {

        /* Release protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* Socket is not connected, return an error message.  */
        return(NX_NOT_CONNECTED);
    }

    /* Disable interrupts.  */
    TX_DISABLE

    /* Restore interrupts.  */
    TX_RESTORE

    /* Move the checksum into header.  */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_4);
    header_ptr -> nx_tcp_header_word_4 =  (checksum << NX_SHIFT_BY_16);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_4);

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

    /* Now determine if the request is within the advertised window on the other side
       of the connection.  Also, check for the maximum number of queued transmit packets
       being exceeded.  */
    if (((packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER)) <= tx_window_current) &&
        (socket_ptr -> nx_tcp_socket_transmit_sent_count < socket_ptr -> nx_tcp_socket_transmit_queue_maximum))
    {

        /* Adjust the transmit sequence number to reflect the output data.  */
        socket_ptr -> nx_tcp_socket_tx_sequence =  socket_ptr -> nx_tcp_socket_tx_sequence +
            (packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER));


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

            /* Setup a timeout for the packet at the head of the list.  */
            socket_ptr -> nx_tcp_socket_timeout =          socket_ptr -> nx_tcp_socket_timeout_rate;
            socket_ptr -> nx_tcp_socket_timeout_retries =  0;
            socket_ptr -> nx_tcp_socket_tx_outstanding_bytes = 0;
        }

        /* Set the next pointer to NX_PACKET_ENQUEUED to indicate the packet is part of a TCP queue.  */
        packet_ptr -> nx_packet_tcp_queue_next =  (NX_PACKET *)NX_PACKET_ENQUEUED;

        /* Increment the packet sent count.  */
        socket_ptr -> nx_tcp_socket_transmit_sent_count++;

        /* Increase the transmit outstanding byte count. */
        socket_ptr -> nx_tcp_socket_tx_outstanding_bytes +=
            (packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER));
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

        /* Release the protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* Return successful status.  */
        return(NX_SUCCESS);
    }
    else if ((wait_option) && (_tx_thread_current_ptr != &(ip_ptr -> nx_ip_thread)))
    {

        /* Determine if there is already a thread suspended on transmit for the
           socket.  If so, just return an error.  */
        if (socket_ptr -> nx_tcp_socket_transmit_suspended_count)
        {

            /* Remove the TCP header from the packet.  */
            packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER);
            packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER);

            /* Release protection.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));

            /* Return the already suspended error.  */
            return(NX_ALREADY_SUSPENDED);
        }

        /* Save the return packet pointer address as well.  */
        _tx_thread_current_ptr -> tx_thread_additional_suspend_info =  (VOID *)packet_ptr;

        /* Increment the suspended thread count.  */
        socket_ptr -> nx_tcp_socket_transmit_suspended_count++;

        /* Suspend the thread on the transmit suspension list.  */
        _nx_tcp_socket_thread_suspend(&(socket_ptr -> nx_tcp_socket_transmit_suspension_list), _nx_tcp_transmit_cleanup, socket_ptr, &(ip_ptr -> nx_ip_protection), wait_option);

        /* Determine if the send request was successful.  */
        if (_tx_thread_current_ptr -> tx_thread_suspend_status)
        {

            /* Remove the TCP header from the packet.  */
            packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER);
            packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER);
        }

        /* If not, just return the error code.  */
        return(_tx_thread_current_ptr -> tx_thread_suspend_status);
    }
    else
    {

        /* Remove the TCP header from the packet.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - sizeof(NX_TCP_HEADER);
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER);

        /* Determine which transmit error is present.  */
        if (socket_ptr -> nx_tcp_socket_transmit_sent_count < socket_ptr -> nx_tcp_socket_transmit_queue_maximum)
        {

            /* Release protection.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));

            /* Not a queue depth problem, return a window overflow error.  */
            return(NX_WINDOW_OVERFLOW);
        }
        else
        {

            /* Release protection.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));

            /* Return a transmit queue exceeded error.  */
            return(NX_TX_QUEUE_DEPTH);
        }
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_send                                 PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a TCP packet through the specified socket.      */
/*      If payload size exceeds MSS, this service fragments the payload   */
/*      to fit into MSS.                                                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to socket             */
/*    packet_ptr                            Pointer to packet to send     */
/*    wait_option                           Suspension option             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_INVALID_PARAMETERS                 Unknown packet IP version     */
/*    NX_INVALID_PACKET                     Source packet chain missing   */
/*                                               packet data              */
/*    status                                Actual completion status      */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_socket_send_internal          Transmit TCP payload          */
/*    _nx_packet_allocate                   Packet allocation for         */
/*                                            fragmentation               */
/*    _nx_packet_release                    Packet release                */
/*    _nx_packet_data_append                Move data into fragments      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
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
UINT  _nx_tcp_socket_send(NX_TCP_SOCKET *socket_ptr, NX_PACKET *packet_ptr, ULONG wait_option)
{

ULONG      remaining_bytes;
NX_IP     *ip_ptr;
NX_PACKET *fragment_packet = NX_NULL;
NX_PACKET *current_packet = NX_NULL;
ULONG      ret;
ULONG      source_data_size;
ULONG      fragment_packet_space_remaining = 0;
ULONG      copy_size;
UCHAR     *current_ptr;
ULONG      fragment_length;

    /* Initialize outcome to successful completion. */
    ret = NX_SUCCESS;

    /* MSS size is IP MTU - IP header - optional header - TCP header. */

    /* Send the packet directly if it is within MSS size. */
    if (packet_ptr -> nx_packet_length <= socket_ptr -> nx_tcp_socket_connect_mss)
    {

        return(_nx_tcp_socket_send_internal(socket_ptr, packet_ptr, wait_option));
    }

    /* The packet size is determined to be larger than MSS size. */

    /* Obtain the size of the source packet. */
    remaining_bytes = packet_ptr -> nx_packet_length;

    /* Have a handle on the IP instance. */
    ip_ptr = socket_ptr -> nx_tcp_socket_ip_ptr;

    /* Points to the source packet. */
    current_packet = packet_ptr;
    /* Mark the beginning of data. */
    current_ptr = packet_ptr -> nx_packet_prepend_ptr;

    /* Loop through the entire source packet. */
    while (remaining_bytes)
    {

        /* Obtain a new fragment packet if the previous one has been transmitted. */
        if (fragment_packet == NX_NULL)
        {

            ret = _nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &fragment_packet, NX_TCP_PACKET, wait_option);

            if (ret != NX_SUCCESS)
            {
                return(ret);
            }

            /* The fragment remaining bytes cannot exceed the socket MSS. */
            fragment_packet_space_remaining = socket_ptr -> nx_tcp_socket_connect_mss;

            /* Initialize the fragment packet length. */
            fragment_packet -> nx_packet_length = 0;
        }

        /* Figure out whether or not the source packet still contains data. */
        source_data_size = (ULONG)(current_packet -> nx_packet_append_ptr - current_ptr);
        if (source_data_size == 0)
        {

            /* The current buffer is exhausted.  Move to the next buffer on the source packet chain. */
            current_packet = current_packet -> nx_packet_next;

            if (current_packet == NX_NULL)
            {

                /* No more data in the source packet. However there are still bytes remaining even though
                   the packet is not done yet. This is an unrecoverable error. */
                _nx_packet_release(fragment_packet);

                return(NX_INVALID_PACKET);
            }

            /* Mark the beginning of data in the next packet. */
            current_ptr = current_packet -> nx_packet_prepend_ptr;

            /* Compute the amount of data present in this source buffer. */
            source_data_size = (ULONG)(current_packet -> nx_packet_append_ptr - current_ptr);
        }


        /* copy_size = min(fragment_packet, source) */
        if (fragment_packet_space_remaining > source_data_size)
        {
            copy_size = source_data_size;
        }
        else
        {
            copy_size = fragment_packet_space_remaining;
        }

        /* Append data. */
        ret = _nx_packet_data_append(fragment_packet, current_ptr, copy_size,
                                     ip_ptr -> nx_ip_default_packet_pool, wait_option);

        /* Check for errors with data append. */
        if (ret != NX_SUCCESS)
        {

            /* Append failed. Release the packets we will not send and return
               the error status from the data append call. */
            _nx_packet_release(fragment_packet);
            return(ret);
        }

        /* Reduce the remaining_bytes counter by the amount being copied over. */
        remaining_bytes -= copy_size;

        /* Advance the prepend ptr on the source buffer, by the amount being copied. */
        current_ptr += copy_size;

        /* Tracking the amount of space left in the fragment packet. */
        fragment_packet_space_remaining -= copy_size;

        /* At this point, either the source buffer is exhausted (so during the next iteration
           source buffer will move to the next buffer on the chain), or this fragment has been
           filled up and ready to be transmitted. */

        if (fragment_packet_space_remaining == 0)
        {
            /* A fragment is ready to be transmitted. */
            fragment_length = fragment_packet -> nx_packet_length;
            ret = _nx_tcp_socket_send_internal(socket_ptr, fragment_packet, wait_option);

            if (ret != NX_SUCCESS)
            {

                /* Release the packet fragment that failed to get sent. */
                _nx_packet_release(fragment_packet);

                return(ret);
            }

            /* Adjust the packet for data already sent. */
            packet_ptr -> nx_packet_length -= fragment_length;
            for (fragment_packet = packet_ptr;
                 fragment_packet != NX_NULL;
                 fragment_packet = fragment_packet -> nx_packet_next)
            {
                if (((ULONG)fragment_packet -> nx_packet_append_ptr -
                     (ULONG)fragment_packet -> nx_packet_prepend_ptr) > fragment_length)
                {

                    /* This is the last packet to trim. */
                    fragment_packet -> nx_packet_prepend_ptr += fragment_length;
                    break;
                }

                /* Trim the whole packet. */
                fragment_length -= ((ULONG)fragment_packet -> nx_packet_append_ptr -
                                    (ULONG)fragment_packet -> nx_packet_prepend_ptr);
                fragment_packet -> nx_packet_prepend_ptr = fragment_packet -> nx_packet_append_ptr;
            }
            fragment_packet = NX_NULL;
        }
    }

    /* Transmit the last fragment if not transmitted yet. */
    if (fragment_packet)
    {
        ret =  _nx_tcp_socket_send_internal(socket_ptr, fragment_packet, wait_option);

        if (ret != NX_SUCCESS)
        {

            /* Release the packet fragment that failed to get sent. */
            _nx_packet_release(fragment_packet);

            return(ret);
        }
    }

    _nx_packet_release(packet_ptr);

    return(ret);
}

