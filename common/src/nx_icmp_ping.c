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
#include "nx_icmp.h"
#include "nx_packet.h"
#include "nx_ip.h"
#include "tx_thread.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_icmp_ping                                       PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function builds an ICMP ping request packet and calls the      */
/*    associated driver to send it out on the network.  The function will */
/*    then suspend for the specified time waiting for the ICMP ping       */
/*    response.                                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP instance        */
/*    ip_address                            IP address to ping            */
/*    data_ptr                              User Data pointer             */
/*    data_size                             Size of User Data             */
/*    response_ptr                          Pointer to Response Packet    */
/*    wait_option                           Suspension option             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_icmp_checksum_compute             Computer ICMP checksum        */
/*    _nx_ip_packet_send                    IP packet send function       */
/*    _nx_ip_route_find                     Find a suitable outgoing      */
/*                                            interface.                  */
/*    _nx_packet_allocate                   Allocate a packet for the     */
/*                                            ICMP ping request           */
/*    _nx_packet_release                    Release packet on error       */
/*    tx_mutex_get                          Obtain protection mutex       */
/*    tx_mutex_put                          Release protection mutex      */
/*    _tx_thread_system_suspend             Suspend thread                */
/*    _tx_thread_system_preempt_check       Check for preemption          */
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
/*  09-30-2020     Yuxin Zhou               Modified comment(s), and      */
/*                                            verified memcpy use cases,  */
/*                                            resulting in version 6.1    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_icmp_ping(NX_IP *ip_ptr, ULONG ip_address,
                    CHAR *data_ptr, ULONG data_size,
                    NX_PACKET **response_ptr, ULONG wait_option)
{

TX_INTERRUPT_SAVE_AREA

UINT            status;
NX_PACKET      *request_ptr;
NX_ICMP_HEADER *header_ptr;
ULONG           sequence;
TX_THREAD      *thread_ptr;

#ifndef NX_DISABLE_ICMP_TX_CHECKSUM
ULONG checksum;
#endif

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_ICMP_PING, ip_ptr, ip_address, data_ptr, data_size, NX_TRACE_ICMP_EVENTS, 0, 0)

    /* Clear the destination pointer.  */
    * response_ptr =  NX_NULL;

    /* Allocate a packet to place the ICMP echo request message in.  */
    status =  _nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &request_ptr, NX_ICMP_PACKET, wait_option);
    if (status)
    {

        /* Error getting packet, so just get out!  */
        return(status);
    }

    /* Determine if the size of the data and the ICMP header is larger than
       the packet payload area.  */
    if ((data_size + NX_ICMP_HEADER_SIZE) > (ULONG)(request_ptr -> nx_packet_data_end - request_ptr -> nx_packet_append_ptr))
    {

        /* Release the packet.  */
        _nx_packet_release(request_ptr);

        /* Error, the data area is too big for the default packet payload.  */
        return(NX_OVERFLOW);
    }

    /* Find a suitable interface for sending the ping packet. */
    if (_nx_ip_route_find(ip_ptr, ip_address, &request_ptr -> nx_packet_ip_interface, &request_ptr -> nx_packet_next_hop_address) != NX_SUCCESS)
    {

        /* Release the packet. */
        _nx_packet_release(request_ptr);

        return(NX_IP_ADDRESS_ERROR);
    }

#ifndef NX_DISABLE_ICMP_INFO
    /* Increment the ICMP ping count.  */
    ip_ptr -> nx_ip_pings_sent++;
#endif

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_ICMP_SEND, ip_ptr, ip_address, request_ptr, (((ULONG)NX_ICMP_ECHO_REQUEST_TYPE) << 24), NX_TRACE_INTERNAL_EVENTS, 0, 0)

    /* Calculate the ICMP echo request message size and store it in the
       packet header.  */
    request_ptr -> nx_packet_length =  data_size + NX_ICMP_HEADER_SIZE;

    /* Setup the append pointer to the end of the message.  */
    request_ptr -> nx_packet_append_ptr =  request_ptr -> nx_packet_prepend_ptr + (data_size + NX_ICMP_HEADER_SIZE);

    /* Build the ICMP request packet.  */

    /* Setup the pointer to the message area.  */
    header_ptr =  (NX_ICMP_HEADER *)request_ptr -> nx_packet_prepend_ptr;

    /* Write the ICMP type into the message.  Use the lower 16-bits of the IP address for
       the ICMP identifier.  */
    header_ptr -> nx_icmp_header_word_0 =  (ULONG)(NX_ICMP_ECHO_REQUEST_TYPE << 24);
    sequence =                             (ip_ptr -> nx_ip_icmp_sequence++ & NX_LOWER_16_MASK);
    header_ptr -> nx_icmp_header_word_1 =  (ULONG)(request_ptr -> nx_packet_ip_interface -> nx_interface_ip_address << 16) | sequence;

    /* Copy the data into the packet payload area.  */
    memcpy(request_ptr -> nx_packet_prepend_ptr + sizeof(NX_ICMP_HEADER), data_ptr, data_size); /* Use case of memcpy is verified. */

    /* If NX_LITTLE_ENDIAN is defined, the headers need to be swapped to match
       that of the data area.  */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_1);

#ifndef NX_DISABLE_ICMP_TX_CHECKSUM
    /* Compute the checksum of the ICMP packet.  */
    checksum =  _nx_icmp_checksum_compute(request_ptr);

    /* If NX_LITTLE_ENDIAN is defined, the headers need to be swapped back so
       we can place the checksum in the ICMP header.  */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);

    /* Place the checksum into the first header word.  */
    header_ptr -> nx_icmp_header_word_0 =  header_ptr -> nx_icmp_header_word_0 | (~checksum & NX_LOWER_16_MASK);

    /* If NX_LITTLE_ENDIAN is defined, the first header word needs to be swapped
       back.  */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_icmp_header_word_0);
#endif
    /* Obtain the IP internal mutex to prevent against possible suspension later in the
       call to IP packet send.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);


    /* Disable interrupts.  */
    TX_DISABLE

    /* Temporarily disable preemption.  */
    _tx_thread_preempt_disable++;

    /* Pickup thread pointer.  */
    thread_ptr =  _tx_thread_current_ptr;

    /* Determine if the request specifies suspension.  */
    if (wait_option)
    {

        /* Prepare for suspension of this thread.  */

        /* Setup cleanup routine pointer.  */
        thread_ptr -> tx_thread_suspend_cleanup =  _nx_icmp_cleanup;

        thread_ptr -> tx_thread_suspend_status =   NX_NO_RESPONSE;

        /* Setup cleanup information, i.e. this pool control
           block.  */
        thread_ptr -> tx_thread_suspend_control_block =  (void *)ip_ptr;

        /* Save the return packet pointer address as well.  */
        thread_ptr -> tx_thread_additional_suspend_info =  (void *)response_ptr;

        /* Save the sequence number so this can be matched up with an ICMP
           response later.  */
        thread_ptr -> tx_thread_suspend_info =  sequence;

        /* Setup suspension list.  */
        if (ip_ptr -> nx_ip_icmp_ping_suspension_list)
        {

            /* This list is not NULL, add current thread to the end. */
            thread_ptr -> tx_thread_suspended_next =
                ip_ptr -> nx_ip_icmp_ping_suspension_list;
            thread_ptr -> tx_thread_suspended_previous =
                (ip_ptr -> nx_ip_icmp_ping_suspension_list) -> tx_thread_suspended_previous;
            ((ip_ptr -> nx_ip_icmp_ping_suspension_list) -> tx_thread_suspended_previous) -> tx_thread_suspended_next =
                thread_ptr;
            (ip_ptr -> nx_ip_icmp_ping_suspension_list) -> tx_thread_suspended_previous =   thread_ptr;
        }
        else
        {

            /* No other threads are suspended.  Setup the head pointer and
               just setup this threads pointers to itself.  */
            ip_ptr -> nx_ip_icmp_ping_suspension_list =    thread_ptr;
            thread_ptr -> tx_thread_suspended_next =       thread_ptr;
            thread_ptr -> tx_thread_suspended_previous =   thread_ptr;
        }

        /* Increment the suspended thread count.  */
        ip_ptr -> nx_ip_icmp_ping_suspended_count++;

        /* Set the state to suspended.  */
        thread_ptr -> tx_thread_state =  TX_TCP_IP;

        /* Set the suspending flag.  */
        thread_ptr -> tx_thread_suspending =  TX_TRUE;

        /* Save the timeout value.  */
        thread_ptr -> tx_thread_timer.tx_timer_internal_remaining_ticks =  wait_option;
    }

    /* Restore interrupts.  */
    TX_RESTORE

    /* Send the ICMP packet to the IP component.  */
    _nx_ip_packet_send(ip_ptr, request_ptr, ip_address,
                       NX_IP_NORMAL, NX_IP_TIME_TO_LIVE, NX_IP_ICMP, NX_FRAGMENT_OKAY);

    /* If wait option is requested, suspend the thread.  */
    if (wait_option)
    {

        /* Release the protection on the ARP list.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* Call actual thread suspension routine.  */
        _tx_thread_system_suspend(thread_ptr);

        /* Return the status from the thread control block.  */
        return(thread_ptr -> tx_thread_suspend_status);
    }
    else
    {

        /* Disable interrupts.  */
        TX_DISABLE

        /* Release preemption disable.  */
        _tx_thread_preempt_disable--;

        /* Restore interrupts.  */
        TX_RESTORE

        /* Release the protection mutex.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* Check for preemption.  */
        _tx_thread_system_preempt_check();

        /* Immediate return, return error completion.  */
        return(NX_NO_RESPONSE);
    }
}

