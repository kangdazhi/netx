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
/**   Internet Control Message Protocol (ICMP)                            */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "tx_thread.h"
#include "nx_packet.h"
#include "nx_ip.h"
#include "nx_icmp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_icmp_packet_process                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes the ICMP received packet and lifts any      */
/*    associated threads suspended on it.                                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            ICMP packet pointer           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_icmp_checksum_compute             Computer ICMP checksum        */
/*    _nx_ip_packet_send                    Send ICMP packet out          */
/*    _nx_packet_release                    Packet release function       */
/*    _tx_thread_system_resume              Resume suspended thread       */
/*    _tx_thread_system_preempt_check       Check for preemption          */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_icmp_packet_receive               ICMP packet receive           */
/*    _nx_icmp_queue_process                ICMP packet queue processing  */
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
VOID  _nx_icmp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

TX_INTERRUPT_SAVE_AREA

NX_ICMP_HEADER *header_ptr;
TX_THREAD      *thread_ptr;
ULONG           suspended;
ULONG          *message_ptr;
ULONG           message_type;
ULONG           sequence_num;

#if (!defined(NX_DISABLE_ICMP_TX_CHECKSUM) || !defined(NX_DISABLE_ICMP_RX_CHECKSUM))
ULONG           checksum;
#endif

    /* Point to the ICMP message header.  */
    header_ptr =  (NX_ICMP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

#ifndef NX_DISABLE_ICMP_RX_CHECKSUM
    /* Calculate the ICMP message checksum.  */
    checksum =  _nx_icmp_checksum_compute(packet_ptr);
    checksum =  ~checksum & NX_LOWER_16_MASK;

    /* Determine if the checksum is valid.  */
    if (checksum)
    {

#ifndef NX_DISABLE_ICMP_INFO

        /* Increment the ICMP invalid packet error.  */
        ip_ptr -> nx_ip_icmp_invalid_packets++;

        /* Increment the ICMP checksum error count.  */
        ip_ptr -> nx_ip_icmp_checksum_errors++;
#endif

        /* Nope, the checksum is invalid.  Toss this ICMP packet out.  */
        _nx_packet_release(packet_ptr);

        return;
    }
#endif
    /* If NX_LITTLE_ENDIAN is defined, the header needs to be swapped
       so we can examine the ICMP message type.  */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);

    /* Pickup the ICMP message type.  */
    message_type =  (header_ptr -> nx_icmp_header_word_0) >> 24;

    /* Is the message an Echo Reply?  */
    if (message_type == NX_ICMP_ECHO_REPLY_TYPE)
    {

#ifndef NX_DISABLE_ICMP_INFO

        /* Increment the ICMP responses received count.  */
        ip_ptr -> nx_ip_ping_responses_received++;
#endif

        /* If NX_LITTLE_ENDIAN is defined, the second word of the header
           needs to be swapped back so we can examine the ICMP sequence number.  */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_1);

        /* Pickup sequence number.  */
        sequence_num =  (header_ptr -> nx_icmp_header_word_1) & NX_LOWER_16_MASK;

        /* Disable interrupts.  */
        TX_DISABLE

        /* Pickup the head pointer and the suspended count.  */
        thread_ptr =  ip_ptr -> nx_ip_icmp_ping_suspension_list;
        suspended =   ip_ptr -> nx_ip_icmp_ping_suspended_count;

        /* Temporarily disable preemption.  */
        _tx_thread_preempt_disable++;

        /* Restore interrupts.  */
        TX_RESTORE

        /* Search through the suspended threads waiting for a ECHO (ping) response
           in an attempt to find a matching sequence number.  */
        while (suspended--)
        {

            /* Determine if the sequence number matches a suspended thread.  */
            if (thread_ptr ->  tx_thread_suspend_info == sequence_num)
            {

                /* Disable interrupts.  */
                TX_DISABLE

                /* See if this is the only suspended thread on the list.  */
                if (thread_ptr == thread_ptr -> tx_thread_suspended_next)
                {

                    /* Yes, the only suspended thread.  */

                    /* Update the head pointer.  */
                    ip_ptr -> nx_ip_icmp_ping_suspension_list =  NX_NULL;
                }
                else
                {

                    /* At least one more thread is on the same expiration list.  */

                    /* Update the list head pointer.  */
                    if (ip_ptr -> nx_ip_icmp_ping_suspension_list == thread_ptr)
                    {
                        ip_ptr -> nx_ip_icmp_ping_suspension_list =  thread_ptr -> tx_thread_suspended_next;
                    }

                    /* Update the links of the adjacent threads.  */
                    (thread_ptr -> tx_thread_suspended_next) -> tx_thread_suspended_previous =
                        thread_ptr -> tx_thread_suspended_previous;
                    (thread_ptr -> tx_thread_suspended_previous) -> tx_thread_suspended_next =
                        thread_ptr -> tx_thread_suspended_next;
                }

                /* Decrement the suspension count.  */
                ip_ptr -> nx_ip_icmp_ping_suspended_count--;

                /* Prepare for resumption of the first thread.  */

                /* Clear cleanup routine to avoid timeout.  */
                thread_ptr -> tx_thread_suspend_cleanup =  TX_NULL;

                /* Temporarily disable preemption.  */
                _tx_thread_preempt_disable++;

                /* Restore interrupts.  */
                TX_RESTORE

                /* Adjust this packet to remove the ICMP header that is still in front of
                   the response message.  */
                packet_ptr -> nx_packet_length =       packet_ptr -> nx_packet_length - sizeof(NX_ICMP_HEADER);
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_ICMP_HEADER);

                /* Return this block pointer to the suspended thread waiting for
                   a block.  */
                *((NX_PACKET **)thread_ptr -> tx_thread_additional_suspend_info) =  packet_ptr;

                /* Clear packet pointer so we don't try to release it below.  */
                packet_ptr =  NX_NULL;

                /* Put return status into the thread control block.  */
                thread_ptr -> tx_thread_suspend_status =  NX_SUCCESS;

                /* Resume thread.  */
                _tx_thread_system_resume(thread_ptr);

                /* Get out of the loop.  */
                break;
            }
            else
            {
                /* Just move to the next suspended thread.  */
                thread_ptr =  thread_ptr -> tx_thread_suspended_next;
            }
        }

        /* Determine if no match was made and we just have to release the packet.  */
        if (packet_ptr)
        {

            /* Yes, just release the packet.  */
            _nx_packet_release(packet_ptr);
        }

        /* Disable interrupts.  */
        TX_DISABLE

        /* Release preemption disable.  */
        _tx_thread_preempt_disable--;

        /* Restore interrupts.  */
        TX_RESTORE

        /* Check for preemption.  */
        _tx_thread_system_preempt_check();
    }
    else if (message_type == NX_ICMP_ECHO_REQUEST_TYPE)
    {

#ifndef NX_DISABLE_ICMP_INFO
        /* Increment the ICMP pings received count.  */
        ip_ptr -> nx_ip_pings_received++;
#endif

        /* Change the type to Echo Reply and send back the message to the caller.  */
        header_ptr -> nx_icmp_header_word_0 =  NX_ICMP_ECHO_REPLY_TYPE << 24;

#ifndef NX_DISABLE_ICMP_TX_CHECKSUM
        /* If NX_LITTLE_ENDIAN is defined, the header need to be swapped back
           to match the data area.  */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);

        /* Compute the checksum of the Echo Reply.  */
        checksum =  _nx_icmp_checksum_compute(packet_ptr);

        /* If NX_LITTLE_ENDIAN is defined, the header need to be swapped back
           so we insert the checksum.  */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);

        /* Store the checksum.  */
        header_ptr -> nx_icmp_header_word_0 =  header_ptr -> nx_icmp_header_word_0 | (~checksum & NX_LOWER_16_MASK);
#endif
        /* If NX_LITTLE_ENDIAN is defined, the header need to be swapped back
           for output.  */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);

        /* Pickup the return IP address.  */
        message_ptr =  (ULONG *)packet_ptr -> nx_packet_prepend_ptr;

        /* Figure out the best interface to send the ICMP packet on. */
        if (_nx_ip_route_find(ip_ptr, *(message_ptr - 2), &packet_ptr -> nx_packet_ip_interface,
                              &packet_ptr -> nx_packet_next_hop_address) != NX_SUCCESS)
        {

            /* Not a valid interface available. */
            _nx_packet_release(packet_ptr);

            return;
        }

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_ICMP_RECEIVE, ip_ptr, *(message_ptr - 2), packet_ptr, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

#ifndef NX_DISABLE_ICMP_INFO
        /* Increment the ICMP pings responded to count.  */
        ip_ptr -> nx_ip_pings_responded_to++;
#endif

        /* Send the ICMP packet to the IP component.  */
        _nx_ip_packet_send(ip_ptr, packet_ptr, *(message_ptr - 2),
                           NX_IP_NORMAL, NX_IP_TIME_TO_LIVE, NX_IP_ICMP, NX_FRAGMENT_OKAY);
    }
    else
    {

#ifndef NX_DISABLE_ICMP_INFO

        /* Increment the ICMP unhandled message count.  */
        ip_ptr -> nx_ip_icmp_unhandled_messages++;
#endif

#ifdef TX_ENABLE_EVENT_TRACE

        /* Pickup the return IP address.  */
        message_ptr =  (ULONG *)packet_ptr -> nx_packet_prepend_ptr;
#endif

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_ICMP_RECEIVE, ip_ptr, *(message_ptr - 2), packet_ptr, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        /* Unhandled ICMP message, just release it.  */
        _nx_packet_release(packet_ptr);
    }

    return;
}

