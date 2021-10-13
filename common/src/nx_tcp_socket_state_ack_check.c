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
/*    _nx_tcp_socket_state_ack_check                      PORTABLE C      */
/*                                                           6.1.9        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for ACK conditions in various states of the    */
/*    TCP socket.  ACK messages are examined against the queued transmit  */
/*    packets in order to see if one or more transmit packets may be      */
/*    removed from the socket's transmit queue.                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to owning socket      */
/*    tcp_header_ptr                        Pointer to packet header      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_packet_send_ack               Send ACK message              */
/*    _nx_packet_release                    Packet release function       */
/*    _nx_tcp_socket_retransmit             Retransmit packet             */
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
/*  10-15-2021     Yuxin Zhou               Modified comment(s),          */
/*                                            fixed the bug of race       */
/*                                            condition,                  */
/*                                            resulting in version 6.1.9  */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_socket_state_ack_check(NX_TCP_SOCKET *socket_ptr, NX_TCP_HEADER *tcp_header_ptr)
{

TX_INTERRUPT_SAVE_AREA

NX_TCP_HEADER *search_header_ptr;
NX_PACKET     *search_ptr;
NX_PACKET     *previous_ptr;
ULONG          header_length;
ULONG          search_sequence;
ULONG          temp;
ULONG          packet_release_count;
ULONG          ending_packet_sequence;
ULONG          starting_tx_sequence =  0;
ULONG          ending_tx_sequence =  0;
ULONG          acked_bytes;
UINT           wrapped_flag =  NX_FALSE;


    /* Determine if invalid SYN bit is present.  */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
    {

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_SYN_RECEIVE, socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, NX_NULL, tcp_header_ptr -> nx_tcp_sequence_number, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        /* Yes, an invalid SYN bit is present.  Respond with an ACK to let the other
           side of the connection figure out if everything is still okay.  */
        _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
    }

    /* Determine if the header has an ACK bit set.  This is an
       acknowledgement of a previous transmission.  */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
    {

#ifdef NX_ENABLE_TCP_KEEPALIVE
        /* Determine if the socket is in the established state.  */
        if (socket_ptr -> nx_tcp_socket_state == NX_TCP_ESTABLISHED)
        {

            /* Is the keepalive feature enabled on this socket? */
            if (socket_ptr -> nx_tcp_socket_keepalive_enabled)
            {

                /* Yes, reset the TCP Keepalive timer to initial values.  */
                socket_ptr -> nx_tcp_socket_keepalive_timeout =  NX_TCP_KEEPALIVE_INITIAL;
                socket_ptr -> nx_tcp_socket_keepalive_retries =  0;

                /* Determine if we have received a Keepalive ACK request from the other side
                   of the connection.  */
                if (tcp_header_ptr -> nx_tcp_sequence_number == (socket_ptr -> nx_tcp_socket_rx_sequence - 1))
                {

                    /* Yes, a Keepalive ACK probe is present.  Respond with an ACK to let the other
                       side of the connection know that we are still alive.  */
                    _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
                }
            }
        }
#endif


        /* First, determine if incoming ACK matches our transmit sequence.  */
        if (tcp_header_ptr -> nx_tcp_acknowledgment_number == socket_ptr -> nx_tcp_socket_tx_sequence)
        {

            /* In this case, everything on the transmit list is acknowledged.  Simply set the packet
               release count to the number of packets in the transmit queue.  */
            packet_release_count =  socket_ptr -> nx_tcp_socket_transmit_sent_count;

            /* Set the previous pointer to the socket transmit tail pointer.  */
            previous_ptr =  socket_ptr -> nx_tcp_socket_transmit_sent_tail;

            /* In this case, all data is acked, so we just need to set starting_tx_seq and ending_tx_seq to the current
               TX sequence number, which is the same as the ACK number. */
            starting_tx_sequence =  socket_ptr -> nx_tcp_socket_tx_sequence;
            ending_tx_sequence   =  socket_ptr -> nx_tcp_socket_tx_sequence;
            /* Update this socket's transmit window with the advertised window size in the ACK message.  */
            socket_ptr -> nx_tcp_socket_tx_window_advertised =  (tcp_header_ptr -> nx_tcp_header_word_3) & NX_LOWER_16_MASK;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
            socket_ptr -> nx_tcp_socket_tx_window_advertised <<= socket_ptr -> nx_tcp_snd_win_scale_value;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
        }
        else
        {

            /* Calculate the start and end of the transmit sequence.  */

            /* Pickup the head of the transmit queue.  */
            search_ptr =    socket_ptr -> nx_tcp_socket_transmit_sent_head;

            /* Determine if there is a packet on the transmit queue... and determine if the packet has been
               transmitted.  */
            if ((search_ptr) && (search_ptr -> nx_packet_queue_next == ((NX_PACKET *)NX_DRIVER_TX_DONE)))
            {

                /* Setup a pointer to header of this packet in the sent list.  */
                search_header_ptr =  (NX_TCP_HEADER *)search_ptr -> nx_packet_prepend_ptr;

                /* Pickup the starting sequence number.  */
                starting_tx_sequence =  search_header_ptr -> nx_tcp_sequence_number;

                NX_CHANGE_ULONG_ENDIAN(starting_tx_sequence);

                /* Determine if the incoming ACK matches the front of our transmit queue. If so,
                   decrease the retransmit timeout by 50% in order to improve the retry time.  */
                if (tcp_header_ptr -> nx_tcp_acknowledgment_number == starting_tx_sequence)
                {

                    /* Handle duplicated ACK packet.  */
                    socket_ptr -> nx_tcp_socket_duplicated_ack_received++;

                    if (socket_ptr -> nx_tcp_socket_duplicated_ack_received == 3)
                    {
                        if ((INT)((tcp_header_ptr -> nx_tcp_acknowledgment_number - 1) -
                                  socket_ptr -> nx_tcp_socket_tx_sequence_recover > 0))
                        {

                            /* Cumulative acknowledge covers more than recover. */
                            /* Section 3.2, Page 5, RFC6582. */
                            /* Retransmit packet immediately. */
                            _nx_tcp_socket_retransmit(socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, NX_TRUE);
                        }
                        else if ((socket_ptr -> nx_tcp_socket_tx_window_congestion > socket_ptr -> nx_tcp_socket_connect_mss) &&
                                 ((INT)(tcp_header_ptr -> nx_tcp_acknowledgment_number - (socket_ptr -> nx_tcp_socket_previous_highest_ack +
                                                                                          (socket_ptr -> nx_tcp_socket_connect_mss << 2))) < 0))
                        {

                            /* Congestion window is greater than SMSS bytes and
                               the difference between highest_ack and prev_highest_ack is at most 4*SMSS bytes.*/
                            /* Section 4.1, Page 5, RFC6582. */
                            /* Retransmit packet immediately. */
                            _nx_tcp_socket_retransmit(socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, NX_TRUE);
                        }
                    }
                    else if ((socket_ptr -> nx_tcp_socket_duplicated_ack_received > 3) &&
                             (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE))
                    {

                        /* CWND += MSS  */
                        socket_ptr -> nx_tcp_socket_tx_window_congestion += socket_ptr -> nx_tcp_socket_connect_mss;
                    }
                }


                /* Pickup the ending transmit queue sequence.  */
                ending_tx_sequence =  socket_ptr -> nx_tcp_socket_tx_sequence;

                /* Determine if the transmit queue has wrapped.  */
                if (ending_tx_sequence > starting_tx_sequence)
                {

                    /* Clear the wrapped flag.  */
                    wrapped_flag =  NX_FALSE;
                }
                else
                {

                    /* Set the wrapped flag.  */
                    wrapped_flag =  NX_TRUE;
                }
            }
            else
            {

                if (search_ptr == NX_NULL)
                {

                    /* No outstanding packets so the valid sequence number is the current tx sequence number. */
                    starting_tx_sequence =  socket_ptr -> nx_tcp_socket_tx_sequence;
                    ending_tx_sequence   =  socket_ptr -> nx_tcp_socket_tx_sequence;
                }
                else
                {

                    /* ACK Number is not TX Seq, but there are no packet waiting for ACK
                       (the 1st packet in the tx queue has not been sent yet).
                       In this case, we do not need to send an ACK back. */
                    starting_tx_sequence =  socket_ptr -> nx_tcp_socket_tx_sequence - socket_ptr -> nx_tcp_socket_tx_outstanding_bytes;
                    ending_tx_sequence   =  starting_tx_sequence;
                }
            }

            /* Determine if the transmit window size should be updated.  */
            if (tcp_header_ptr -> nx_tcp_sequence_number == socket_ptr -> nx_tcp_socket_rx_sequence)
            {

                /* Update this socket's transmit window with the advertised window size in the ACK message.  */
                socket_ptr -> nx_tcp_socket_tx_window_advertised =  (tcp_header_ptr -> nx_tcp_header_word_3) & NX_LOWER_16_MASK;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
                socket_ptr -> nx_tcp_socket_tx_window_advertised <<= socket_ptr -> nx_tcp_snd_win_scale_value;
#endif
            }

            /* Initialize the packet release count.  */
            packet_release_count =  0;

            /* See if we can find the sequence number in the sent queue for this socket.  */
            previous_ptr =  NX_NULL;

            while (search_ptr)
            {

                /* Determine if the packet has been transmitted.  */
                if (search_ptr -> nx_packet_queue_next != ((NX_PACKET *)NX_DRIVER_TX_DONE))
                {
                    break;
                }

                /* Setup a pointer to header of this packet in the sent list.  */
                search_header_ptr =  (NX_TCP_HEADER *)search_ptr -> nx_packet_prepend_ptr;

                /* Determine the size of the TCP header.  */
                temp =  search_header_ptr -> nx_tcp_header_word_3;
                NX_CHANGE_ULONG_ENDIAN(temp);
                header_length =  (temp >> NX_TCP_HEADER_SHIFT) * sizeof(ULONG);

                /* Determine the sequence number in the TCP header.  */
                search_sequence =  search_header_ptr -> nx_tcp_sequence_number;
                NX_CHANGE_ULONG_ENDIAN(search_sequence);

                /* Calculate the ending packet sequence.  */
                ending_packet_sequence =  (search_sequence + (search_ptr -> nx_packet_length - header_length));

                /* Determine if the transmit window is wrapped.  */
                if (wrapped_flag == NX_FALSE)
                {

                    /* No, the transmit window is not wrapped. Perform a simple compare to determine if the ACK
                       covers the current search packet.  */

                    /* Is this ACK before the current search packet or after the transmit sequence?  */
                    if ((tcp_header_ptr -> nx_tcp_acknowledgment_number < ending_packet_sequence) ||
                        (tcp_header_ptr -> nx_tcp_acknowledgment_number > ending_tx_sequence))
                    {

                        /* The ACK is less than the current packet, just get out of the loop!  */
                        break;
                    }
                }
                else
                {

                    /* Yes, the transmit window has wrapped.  We need to now check for all the wrap conditions to
                       determine if ACK covers the current search packet.  */

                    /* Is the search packet's ending sequence number in the wrapped part of the window.  */
                    if (ending_packet_sequence < starting_tx_sequence)
                    {

                        /* The search packet ends in the wrapped portion of the window.  Determine if the ACK
                           sequence in the wrapped portion as well.  */
                        if (tcp_header_ptr -> nx_tcp_acknowledgment_number < starting_tx_sequence)
                        {

                            /* Yes, the ACK sequence is in the wrapped portion as well. Simply compare the ACK
                               number with the search packet sequence.  */
                            if (tcp_header_ptr -> nx_tcp_acknowledgment_number < ending_packet_sequence)
                            {

                                /* ACK does not cover the search packet. Break out of the loop.  */
                                break;
                            }
                        }
                        else
                        {

                            /* The ACK sequence is in the non-wrapped portion of the window and the ending sequence
                               of the search packet is in the wrapped portion - so the ACK doesn't cover the search
                               packet.  Break out of the loop!  */
                            break;
                        }
                    }
                    else
                    {

                        /* The search packet is in the non-wrapped portion of the window.  Determine if the ACK
                           sequence is in the non-wrapped portion as well.  */
                        if (tcp_header_ptr -> nx_tcp_acknowledgment_number >= starting_tx_sequence)
                        {

                            /* Yes, the ACK sequence is in the non-wrapped portion of the window. Simply compare the ACK
                               sequence with the search packet sequence.  */
                            if (tcp_header_ptr -> nx_tcp_acknowledgment_number < ending_packet_sequence)
                            {

                                /* ACK does not cover the search packet. Break out of the loop.  */
                                break;
                            }
                        }
                    }
                }

                /* At this point we know that the ACK received covers the search packet.  */

                /* Increase the packet release count.  */
                packet_release_count++;

                /* Update this socket's transmit window with the advertised window size in the ACK message.  */
                socket_ptr -> nx_tcp_socket_tx_window_advertised =  (tcp_header_ptr -> nx_tcp_header_word_3) & NX_LOWER_16_MASK;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
                socket_ptr -> nx_tcp_socket_tx_window_advertised <<= socket_ptr -> nx_tcp_snd_win_scale_value;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

                /* Move the search and previous pointers forward.  */
                previous_ptr =  search_ptr;
                search_ptr =  search_ptr -> nx_packet_tcp_queue_next;

                /* Determine if we are at the end of the TCP queue.  */
                if (search_ptr == ((NX_PACKET *)NX_PACKET_ENQUEUED))
                {

                    /* Yes, set the search pointer to NULL.  */
                    search_ptr =  NX_NULL;
                }
            }
        }

        /* Determine if anything needs to be released.  */
        if (!packet_release_count)
        {

            /* No, check and see if the ACK is valid.  */
            if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_ESTABLISHED) &&
                (socket_ptr -> nx_tcp_socket_transmit_sent_head) &&
                (tcp_header_ptr -> nx_tcp_acknowledgment_number != socket_ptr -> nx_tcp_socket_tx_sequence))
            {

                /* Determine if the transmit sequence is wrapped.  */
                if (wrapped_flag == NX_FALSE)
                {


                    /* No, not wrapped. Typical compare of sequence number with ACK.  */
                    if ((tcp_header_ptr -> nx_tcp_acknowledgment_number < starting_tx_sequence) ||
                        (tcp_header_ptr -> nx_tcp_acknowledgment_number > ending_tx_sequence))
                    {

                        /* The ACK sequence is invalid. Respond with an ACK to let the other
                           side of the connection figure out if everything is still okay.  */
                        _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
                    }
                }
                else
                {

                    /* Yes, the transmit sequence is wrapped. Compare the ACK with the wrapped
                       sequence numbers.  */
                    if ((tcp_header_ptr -> nx_tcp_acknowledgment_number > ending_tx_sequence) &&
                        (tcp_header_ptr -> nx_tcp_acknowledgment_number < starting_tx_sequence))
                    {

                        /* The ACK sequence is invalid. Respond with an ACK to let the other
                           side of the connection figure out if everything is still okay.  */
                        _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
                    }
                }
            }

            /* Done, return to caller.  */
            return;
        }
        else
        {

            /* Congestion window adjustment during slow start and congestion avoidance is executed
               on every incoming ACK that acknowledges new data. RFC5681, Section3.1, Page4-8.  */
            /* Check whether the socket is in fast recovery procedure. */
            if (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE)
            {

                /* Yes. */
                if ((INT)(tcp_header_ptr -> nx_tcp_acknowledgment_number -
                          socket_ptr -> nx_tcp_socket_tx_sequence_recover) > 0)
                {

                    /* All packets sent before entering fast recovery are ACKed. */
                    /* Exit fast recovery procedure. */
                    socket_ptr -> nx_tcp_socket_fast_recovery = NX_FALSE;
                    socket_ptr -> nx_tcp_socket_tx_window_congestion = socket_ptr -> nx_tcp_socket_tx_slow_start_threshold;
                }
            }

            if ((INT)(socket_ptr -> nx_tcp_socket_tx_sequence_recover -
                      (tcp_header_ptr -> nx_tcp_acknowledgment_number - 2)) < 0)
            {

                /* Update the transmit sequence that enters fast transmit. */
                socket_ptr -> nx_tcp_socket_tx_sequence_recover = tcp_header_ptr -> nx_tcp_acknowledgment_number - 2;
            }

            /* Reset the duplicated ACK counter. */
            socket_ptr -> nx_tcp_socket_duplicated_ack_received = 0;


            /* Determine if the packet has been transmitted.  */
            /*lint -e{923} suppress cast of ULONG to pointer.  */
            if (socket_ptr -> nx_tcp_socket_transmit_sent_head -> nx_packet_queue_next != ((NX_PACKET *)NX_DRIVER_TX_DONE))
            {

                /* Not yet. This could be only when all packets are ACKed. */
                /* Set previous cumulative acknowlesgement. */
                socket_ptr -> nx_tcp_socket_previous_highest_ack = socket_ptr -> nx_tcp_socket_tx_sequence -
                    socket_ptr -> nx_tcp_socket_tx_outstanding_bytes;

                /* Calculate ACKed length. */
                acked_bytes = socket_ptr -> nx_tcp_socket_tx_outstanding_bytes;
            }
            else
            {

                /* Setup a pointer to header of this packet in the sent list.  */
                /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
                search_header_ptr =  (NX_TCP_HEADER *)socket_ptr -> nx_tcp_socket_transmit_sent_head -> nx_packet_prepend_ptr;

                /* Pickup the starting sequence number.  */
                starting_tx_sequence =  search_header_ptr -> nx_tcp_sequence_number;
                NX_CHANGE_ULONG_ENDIAN(starting_tx_sequence);

                /* Set previous cumulative acknowlesgement. */
                socket_ptr -> nx_tcp_socket_previous_highest_ack = starting_tx_sequence;

                /* Calculate ACKed length. */
                acked_bytes = tcp_header_ptr -> nx_tcp_acknowledgment_number - starting_tx_sequence;
            }

            if (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE)
            {

                /* Process cwnd in fast recovery procedure. */
                socket_ptr -> nx_tcp_socket_tx_window_congestion -= acked_bytes;
                if (acked_bytes > socket_ptr -> nx_tcp_socket_connect_mss)
                {
                    socket_ptr -> nx_tcp_socket_tx_window_congestion += socket_ptr -> nx_tcp_socket_connect_mss;
                }
            }
            else
            {

                /* Adjust the transmit window.  In slow start phase, the transmit window is incremented for every ACK.
                   In Congestion Avoidance phase, the window is incremented for every RTT.  */
                if (socket_ptr -> nx_tcp_socket_tx_window_congestion >= socket_ptr -> nx_tcp_socket_tx_slow_start_threshold)
                {

                    /* In Congestion avoidance phase, for every ACK it receives, increase the window size using the
                       following approximation:
                       cwnd = cwnd + MSS * MSS / cwnd;
                     */
                    temp = socket_ptr -> nx_tcp_socket_connect_mss2 / socket_ptr -> nx_tcp_socket_tx_window_congestion;

                    /* If the above formula yields 0, the result SHOULD be rounded up to 1 byte.  */
                    if (temp == 0)
                    {
                        temp = 1;
                    }

                    socket_ptr -> nx_tcp_socket_tx_window_congestion = socket_ptr -> nx_tcp_socket_tx_window_congestion + temp;
                }
                else
                {

                    /* cwnd += min (N, SMSS).
                       where N is the number of ACKed bytes. */
                    /* Section 3.1, Page 6, RFC5681. */
                    if (acked_bytes < socket_ptr -> nx_tcp_socket_connect_mss)
                    {

                        /* In Slow start phase. Increase the cwnd by full MSS for every ack.*/
                        socket_ptr -> nx_tcp_socket_tx_window_congestion += (tcp_header_ptr -> nx_tcp_acknowledgment_number - starting_tx_sequence);
                    }
                    else
                    {

                        /* In Slow start phase. Increase the cwnd by full MSS for every ack.*/
                        socket_ptr -> nx_tcp_socket_tx_window_congestion += socket_ptr -> nx_tcp_socket_connect_mss;
                    }
                }
            }
        }


        /* Save the front of the of the transmit queue.  */
        search_ptr =  socket_ptr -> nx_tcp_socket_transmit_sent_head;


        /* Okay so now the packet after the previous pointer needs to be the front of the
           queue.  */
        if (previous_ptr != socket_ptr -> nx_tcp_socket_transmit_sent_tail)
        {

            /* Just update the head pointer.  */
            socket_ptr -> nx_tcp_socket_transmit_sent_head  =
                previous_ptr -> nx_packet_tcp_queue_next;

            /* And decrease the transmit queue count accordingly.  */
            socket_ptr -> nx_tcp_socket_transmit_sent_count =
                socket_ptr -> nx_tcp_socket_transmit_sent_count - packet_release_count;

            /* Setup a new transmit timeout.  */
            socket_ptr -> nx_tcp_socket_timeout =          socket_ptr -> nx_tcp_socket_timeout_rate;
            socket_ptr -> nx_tcp_socket_timeout_retries =  0;
        }
        else
        {

            /* The transmit list is now cleared, just set the head and tail pointers to
               NULL.  */
            socket_ptr -> nx_tcp_socket_transmit_sent_head  =  NX_NULL;
            socket_ptr -> nx_tcp_socket_transmit_sent_tail  =  NX_NULL;

            /* Clear the transmit queue count.  */
            socket_ptr -> nx_tcp_socket_transmit_sent_count =  0;

            /* Determine if a disconnect FIN has been sent from this side of the connection.  */
            if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) ||
                (socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSING)    ||
                (socket_ptr -> nx_tcp_socket_state == NX_TCP_LAST_ACK))
            {

                /* Yes, setup timeout such that the FIN can be retried if it is lost.  */
                socket_ptr -> nx_tcp_socket_timeout =          socket_ptr -> nx_tcp_socket_timeout_rate;
                socket_ptr -> nx_tcp_socket_timeout_retries =  0;
            }
            else
            {

                /* Otherwise, a FIN has not been sent, simply clear the transmit timeout.  */
                socket_ptr -> nx_tcp_socket_timeout =  0;
            }
        }

        /* Now walk through the packets to release and set them free.  */
        while (packet_release_count--)
        {

            /* Use the previous pointer as the release pointer.  */
            previous_ptr =  search_ptr;

            /* Move to the next packet in the queue before we clip the
               next pointer.  */
            search_ptr =  search_ptr -> nx_packet_tcp_queue_next;

            /* Disable interrupts temporarily.  */
            TX_DISABLE

            /* Set the packet to allocated to indicate it is no longer part of the TCP queue.  */
            previous_ptr -> nx_packet_tcp_queue_next =  ((NX_PACKET *)NX_PACKET_ALLOCATED);

            /* Has the packet been transmitted? This is only pertinent if a retransmit of
               the packet occurred prior to receiving the ACK. If so, the packet could be
               in an ARP queue or in a driver queue waiting for transmission so we can't
               release it directly at this point.  The driver or the ARP processing will
               release it when finished.  */
            if (previous_ptr -> nx_packet_queue_next ==  ((NX_PACKET *)NX_DRIVER_TX_DONE))
            {

                /* Restore interrupts.  */
                TX_RESTORE

                /* Yes, the driver has already released the packet.  */

                /* Open up the transmit window. */
                search_header_ptr = (NX_TCP_HEADER *)previous_ptr -> nx_packet_prepend_ptr;

                temp = search_header_ptr -> nx_tcp_header_word_3;
                NX_CHANGE_ULONG_ENDIAN(temp);
                header_length = (temp >> NX_TCP_HEADER_SHIFT) * sizeof(ULONG);
                if (socket_ptr -> nx_tcp_socket_tx_outstanding_bytes > (previous_ptr -> nx_packet_length - header_length))
                {
                    socket_ptr -> nx_tcp_socket_tx_outstanding_bytes -= previous_ptr -> nx_packet_length - header_length;
                }
                else
                {
                    socket_ptr -> nx_tcp_socket_tx_outstanding_bytes = 0;
                }
                /* Release the packet.  */
                _nx_packet_release(previous_ptr);
            }
            else
            {

                /* Not yet. This could be only when all packets are ACKed. */
                /* Simply reset the outstanding bytes. */
                socket_ptr -> nx_tcp_socket_tx_outstanding_bytes = 0;

                /* Restore interrupts.  */
                TX_RESTORE
            }
        }

        if (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE)
        {

            /* Only partial data are ACKed. Retransmit packet immediately. */
            _nx_tcp_socket_retransmit(socket_ptr -> nx_tcp_socket_ip_ptr, socket_ptr, NX_FALSE);
        }
    }
}

