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
#include "tx_thread.h"
#include "nx_packet.h"
#include "nx_udp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_udp_socket_receive                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function retrieves UDP packet received on the socket; if a wait*/
/*    option is specified, it suspends; otherwise it returns immediately. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to UDP socket         */
/*    packet_ptr                            Pointer to UDP packet pointer */
/*    wait_option                           Suspension option             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Release data packet           */
/*    _tx_thread_system_suspend             Suspend thread                */
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
UINT  _nx_udp_socket_receive(NX_UDP_SOCKET *socket_ptr, NX_PACKET **packet_ptr, ULONG wait_option)
{
TX_INTERRUPT_SAVE_AREA

#ifndef NX_DISABLE_UDP_RX_CHECKSUM
ULONG      checksum;
ULONG      length;
ULONG      temp;
ULONG     *temp_ptr;
UCHAR     *word_ptr;
UCHAR     *pad_ptr;
ULONG      packet_length;
ULONG      adjusted_packet_length;
NX_PACKET *current_packet;
#endif
TX_THREAD *thread_ptr;

#ifdef TX_ENABLE_EVENT_TRACE
TX_TRACE_BUFFER_ENTRY *trace_event;
ULONG                  trace_timestamp;
#endif


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_UDP_SOCKET_RECEIVE, socket_ptr -> nx_udp_socket_ip_ptr, socket_ptr, 0, 0, NX_TRACE_UDP_EVENTS, &trace_event, &trace_timestamp)

    /* Set the return pointer to NULL initially.  */
    *packet_ptr =   NX_NULL;

    /* Loop to retrieve a packet from the interface.  */
    do
    {

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

        /* Determine if there is a packet already queued up for this socket.  */
        if (socket_ptr -> nx_udp_socket_receive_count)
        {

            /* Yes, there is a packet waiting.  */

            /* Remove it and place it in the thread's destination.  */
            *packet_ptr =  socket_ptr -> nx_udp_socket_receive_head;
            socket_ptr -> nx_udp_socket_receive_head =  (*packet_ptr) -> nx_packet_queue_next;

            /* If this was the last packet, set the tail pointer to NULL.  */
            if (socket_ptr -> nx_udp_socket_receive_head == NX_NULL)
            {
                socket_ptr -> nx_udp_socket_receive_tail =  NX_NULL;
            }

            /* Decrease the queued packet count.  */
            socket_ptr -> nx_udp_socket_receive_count--;

            /* Restore interrupts.  */
            TX_RESTORE
        }
        else
        {

            /* Determine if the request specifies suspension.  */
            if (wait_option)
            {

                /* Prepare for suspension of this thread.  */

                /* Pickup thread pointer.  */
                thread_ptr =  _tx_thread_current_ptr;

                /* Setup cleanup routine pointer.  */
                thread_ptr -> tx_thread_suspend_cleanup =  _nx_udp_receive_cleanup;

                /* Setup cleanup information, i.e. this pool control
                   block.  */
                thread_ptr -> tx_thread_suspend_control_block =  (void *)socket_ptr;

                /* Save the return packet pointer address as well.  */
                thread_ptr -> tx_thread_additional_suspend_info =  (void *)packet_ptr;

                /* Setup suspension list.  */
                if (socket_ptr -> nx_udp_socket_receive_suspension_list)
                {

                    /* This list is not NULL, add current thread to the end. */
                    thread_ptr -> tx_thread_suspended_next =
                        socket_ptr -> nx_udp_socket_receive_suspension_list;
                    thread_ptr -> tx_thread_suspended_previous =
                        (socket_ptr -> nx_udp_socket_receive_suspension_list) -> tx_thread_suspended_previous;
                    ((socket_ptr -> nx_udp_socket_receive_suspension_list) -> tx_thread_suspended_previous) -> tx_thread_suspended_next =
                        thread_ptr;
                    (socket_ptr -> nx_udp_socket_receive_suspension_list) -> tx_thread_suspended_previous =   thread_ptr;
                }
                else
                {

                    /* No other threads are suspended.  Setup the head pointer and
                       just setup this threads pointers to itself.  */
                    socket_ptr -> nx_udp_socket_receive_suspension_list =   thread_ptr;
                    thread_ptr -> tx_thread_suspended_next =                       thread_ptr;
                    thread_ptr -> tx_thread_suspended_previous =                   thread_ptr;
                }

                /* Increment the suspended thread count.  */
                socket_ptr -> nx_udp_socket_receive_suspended_count++;

                /* Set the state to suspended.  */
                thread_ptr -> tx_thread_state =  TX_TCP_IP;

                /* Set the suspending flag.  */
                thread_ptr -> tx_thread_suspending =  TX_TRUE;

                /* Temporarily disable preemption.  */
                _tx_thread_preempt_disable++;

                /* Save the timeout value.  */
                thread_ptr -> tx_thread_timer.tx_timer_internal_remaining_ticks =  wait_option;

                /* Restore interrupts.  */
                TX_RESTORE

                /* Call actual thread suspension routine.  */
                _tx_thread_system_suspend(thread_ptr);

                /* Determine if a packet was received successfully.  */
                if (thread_ptr -> tx_thread_suspend_status != NX_SUCCESS)
                {

                    /* If not, just return the error code.  */
                    return(thread_ptr -> tx_thread_suspend_status);
                }

                /* Otherwise, just fall through to the checksum logic for the UDP
                   packet.  */
            }
            else
            {

                /* Restore interrupts.  */
                TX_RESTORE

                /* Immediate return, return error completion.  */
                return(NX_NO_PACKET);
            }
        }

#ifndef NX_DISABLE_UDP_RX_CHECKSUM

        /* Determine if we need to compute the UDP checksum.  If it is disabled for this socket
           or if the UDP packet has a zero in the checksum field (indicating it was not computed
           by the sender, skip the checksum processing.  */
        temp_ptr =  (ULONG *)(*packet_ptr) -> nx_packet_prepend_ptr;
        if ((!socket_ptr -> nx_udp_socket_disable_checksum) && (*(temp_ptr + 1) & NX_LOWER_16_MASK))
        {

            /* Yes, we need to compute the UDP checksum.  */

            /* First calculate the checksum of the pseudo UDP header that includes the source IP
               address, destination IP address, protocol word, and the UDP length.  */
            temp =  *(temp_ptr - 2);
            checksum =  (temp >> NX_SHIFT_BY_16);
            checksum += (temp & NX_LOWER_16_MASK);
            temp =  *(temp_ptr - 1);
            checksum += (temp >> NX_SHIFT_BY_16);
            checksum += (temp & NX_LOWER_16_MASK);
            checksum += (NX_IP_UDP >> NX_SHIFT_BY_16);
            checksum += (*packet_ptr) -> nx_packet_length;

            /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
               swap the endian of the UDP header.  */
            NX_CHANGE_ULONG_ENDIAN(*(temp_ptr));
            NX_CHANGE_ULONG_ENDIAN(*(temp_ptr + 1));

            /* Setup the length of the packet checksum. */
            length = (*packet_ptr) -> nx_packet_length;

            /* Initialize the current packet to the input packet pointer.  */
            current_packet =  *packet_ptr;

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

            /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
               swap the endian of the UDP header.  */
            NX_CHANGE_ULONG_ENDIAN(*(temp_ptr));
            NX_CHANGE_ULONG_ENDIAN(*(temp_ptr + 1));

            /* Add in the carry bits into the checksum.  */
            checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

            /* Do it again in case previous operation generates an overflow.  */
            checksum = (checksum >> NX_SHIFT_BY_16) + (checksum & NX_LOWER_16_MASK);

            /* Perform the one's complement processing on the checksum.  */
            checksum =  NX_LOWER_16_MASK & ~checksum;

            /* Determine if it is valid.  */
            if (checksum == 0)
            {

                /* The checksum is okay, so get out of the loop. */
                break;
            }
            else
            {

#ifndef NX_DISABLE_UDP_INFO

                /* Disable interrupts.  */
                TX_DISABLE

                /* Increment the UDP checksum error count.  */
                (socket_ptr -> nx_udp_socket_ip_ptr) -> nx_ip_udp_checksum_errors++;

                /* Increment the UDP invalid packets error count.  */
                (socket_ptr -> nx_udp_socket_ip_ptr) -> nx_ip_udp_invalid_packets++;

                /* Increment the UDP checksum error count for this socket.  */
                socket_ptr -> nx_udp_socket_checksum_errors++;

                /* Decrement the total UDP receive packets count.  */
                (socket_ptr -> nx_udp_socket_ip_ptr) -> nx_ip_udp_packets_received--;

                /* Decrement the total UDP receive bytes.  */
                (socket_ptr -> nx_udp_socket_ip_ptr) -> nx_ip_udp_bytes_received -=  (*packet_ptr) -> nx_packet_length - sizeof(NX_UDP_HEADER);

                /* Decrement the total UDP receive packets count.  */
                socket_ptr -> nx_udp_socket_packets_received--;

                /* Decrement the total UDP receive bytes.  */
                socket_ptr -> nx_udp_socket_bytes_received -=  (*packet_ptr) -> nx_packet_length - sizeof(NX_UDP_HEADER);

                /* Restore interrupts.  */
                TX_RESTORE
#endif

                /* Bad UDP checksum.  Release the packet. */
                _nx_packet_release(*packet_ptr);
            }
        }
        else
        {

            /* Checksum logic is either disabled for this socket or the received
               UDP packet checksum was not calculated - get out of the loop.  */
            break;
        }
#else

        /* Simply break - checksum logic is conditionally disabled.  */
        break;
#endif
    } while (NX_FOREVER);

    /* At this point, we have a valid UDP packet for the caller.  */

    /* Remove the UDP header.  */

    /* Decrease the packet length.  */
    (*packet_ptr) -> nx_packet_length =  (*packet_ptr) -> nx_packet_length - sizeof(NX_UDP_HEADER);

    /* Position past the UDP header pointer.  */
    (*packet_ptr) -> nx_packet_prepend_ptr =   (*packet_ptr) -> nx_packet_prepend_ptr + sizeof(NX_UDP_HEADER);

    /* Update the trace event with the status.  */
    NX_TRACE_EVENT_UPDATE(trace_event, trace_timestamp, NX_TRACE_UDP_SOCKET_RECEIVE, 0, 0, *packet_ptr, (*packet_ptr) -> nx_packet_length)

    /* Return a successful status to the caller.  */
    return(NX_SUCCESS);
}

