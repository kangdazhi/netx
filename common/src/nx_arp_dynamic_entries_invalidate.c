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
/**   Address Resolution Protocol (ARP)                                   */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_arp.h"
#include "nx_ip.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_arp_dynamic_entries_invalidate                  PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function invalidates all ARP dynamic entries currently in      */
/*    the ARP cache.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Obtain protection mutex       */
/*    tx_mutex_put                          Release protection mutex      */
/*    _nx_packet_transmit_release           Release queued packet         */
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
UINT  _nx_arp_dynamic_entries_invalidate(NX_IP *ip_ptr)
{

TX_INTERRUPT_SAVE_AREA
NX_ARP    *arp_entry;
NX_ARP    *last_arp_entry;
NX_PACKET *packet_ptr;
NX_PACKET *next_packet_ptr;


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_ARP_DYNAMIC_ENTRIES_INVALIDATE, ip_ptr, ip_ptr -> nx_ip_arp_dynamic_active_count, 0, 0, NX_TRACE_ARP_EVENTS, 0, 0)

    /* Obtain protection on this IP instance for access into the ARP dynamic
       list.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Setup pointers to the starting and ending ARP entries in the dynamic list.  */
    arp_entry =       ip_ptr -> nx_ip_arp_dynamic_list;
    if (arp_entry)
    {
        last_arp_entry =  arp_entry -> nx_arp_pool_previous;
    }
    else
    {
        last_arp_entry =  NX_NULL;
    }

    /* Walk through the dynamic ARP list until there are no more active entries.  */
    while ((arp_entry) && (ip_ptr -> nx_ip_arp_dynamic_active_count))
    {

        /* Yes there is one or more dynamic entries.  */

        /* Determine if this ARP entry is already active.  */
        if (arp_entry -> nx_arp_active_list_head)
        {

            /* Remove this dynamic ARP entry from the associated list.  */

            /* Disable interrupts.  */
            TX_DISABLE

            /* Determine if this is the only ARP entry on the list.  */
            if (arp_entry == arp_entry -> nx_arp_active_next)
            {

                /* Remove the entry from the list.  */
                *(arp_entry -> nx_arp_active_list_head) =  NX_NULL;
            }
            else
            {

                /* Remove the entry from a list of more than one entry.  */

                /* Update the list head pointer.  */
                if (*(arp_entry -> nx_arp_active_list_head) == arp_entry)
                {
                    *(arp_entry -> nx_arp_active_list_head) =  arp_entry -> nx_arp_active_next;
                }

                /* Update the links of the adjacent ARP entries.  */
                (arp_entry -> nx_arp_active_next) -> nx_arp_active_previous =
                    arp_entry -> nx_arp_active_previous;
                (arp_entry -> nx_arp_active_previous) -> nx_arp_active_next =
                    arp_entry -> nx_arp_active_next;
            }

            /* No longer active, clear the active list head.  */
            arp_entry -> nx_arp_active_list_head =  NX_NULL;

            /* Decrease the number of active ARP entries.  */
            ip_ptr -> nx_ip_arp_dynamic_active_count--;

            /* Pickup the queued packets head pointer.  */
            next_packet_ptr =  arp_entry -> nx_arp_packets_waiting;

            /* Clear the queued packets head pointer.  */
            arp_entry -> nx_arp_packets_waiting =  NX_NULL;

            /* Restore interrupts.  */
            TX_RESTORE

            /* Loop to remove all queued packets.  */
            while (next_packet_ptr)
            {

                /* Pickup the packet pointer at the head of the queue.  */
                packet_ptr =  next_packet_ptr;

                /* Move to the next packet in the queue.  */
                next_packet_ptr =  next_packet_ptr -> nx_packet_queue_next;

                /* Clear the next packet queue pointer.  */
                packet_ptr -> nx_packet_queue_next =  NX_NULL;

#ifndef NX_DISABLE_IP_INFO

                /* Increment the IP send packets dropped count.  */
                ip_ptr -> nx_ip_send_packets_dropped++;
#endif

                /* Release the packet that was queued from the previous ARP entry.  */
                _nx_packet_transmit_release(packet_ptr);
            }
        }

        /* Determine if we are at the end of the dynamic list.  */
        if (arp_entry -> nx_arp_pool_next != last_arp_entry)
        {

            /* No, simply move to the next dynamic entry.  */
            arp_entry =  arp_entry -> nx_arp_pool_next;
        }
        else
        {

            /* Yes, we are at the end of the dynamic list, break out of the loop.  */
            break;
        }
    }

    /* Release the mutex.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return successful status to the caller.  */
    return(NX_SUCCESS);
}

