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
/*    _nx_arp_static_entry_create                         PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function dynamically allocates an ARP entry for the application*/
/*    to make a static IP to hardware mapping.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    ip_address                            IP Address to bind to         */
/*    physical_msw                          Physical address MSW          */
/*    physical_lsw                          Physical address LSW          */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_transmit_release           Release queued packet         */
/*    _nx_ip_route_find                     Find suitable outgoing        */
/*                                            interface                   */
/*    tx_mutex_get                          Obtain protection mutex       */
/*    tx_mutex_put                          Release protection mutex      */
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
UINT  _nx_arp_static_entry_create(NX_IP *ip_ptr, ULONG ip_address,
                                  ULONG physical_msw, ULONG physical_lsw)
{

TX_INTERRUPT_SAVE_AREA
NX_ARP       *arp_entry;
NX_ARP      **arp_list_ptr;
UINT          index;
UINT          status;
NX_PACKET    *packet_ptr;
NX_PACKET    *next_packet_ptr =  NX_NULL;
NX_INTERFACE *nx_interface;
ULONG         next_hop_address;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_ARP_STATIC_ENTRY_CREATE, ip_ptr, ip_address, physical_msw, physical_lsw, NX_TRACE_ARP_EVENTS, 0, 0)

    /* Make sure the destination address is directly accessible. */
    if ((_nx_ip_route_find(ip_ptr, ip_address, &nx_interface, &next_hop_address) != NX_SUCCESS) ||
        (next_hop_address != ip_address))
    {

        return(NX_IP_ADDRESS_ERROR);
    }

    /* Obtain protection on this IP instance for access into the ARP dynamic
       list.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Determine if there is an ARP entry available in the dynamic list.  */
    if (ip_ptr -> nx_ip_arp_dynamic_list)
    {

        /* Yes there are one or more free entries.  */

#ifndef NX_DISABLE_ARP_INFO
        /* Increment the ARP static entry count.  */
        ip_ptr -> nx_ip_arp_static_entries++;
#endif

        /* Disable interrupts.  */
        TX_DISABLE

        /* Pickup pointer to last used dynamic ARP entry, which is also the oldest or least
           recently used.  */
        arp_entry =  (ip_ptr -> nx_ip_arp_dynamic_list) -> nx_arp_pool_previous;

        /* Determine if this ARP entry is already active.  */
        if (arp_entry -> nx_arp_active_list_head)
        {

            /* Remove this dynamic ARP entry from the associated list.  */

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

            /* Decrease the number of active ARP entries.  */
            ip_ptr -> nx_ip_arp_dynamic_active_count--;

            /* Pickup the queued packets head pointer.  */
            next_packet_ptr =  arp_entry -> nx_arp_packets_waiting;

            /* Clear the queued packets head pointer.  */
            arp_entry -> nx_arp_packets_waiting =  NX_NULL;
        }

        /* Remove this entry from the ARP dynamic list.  */

        /* Determine if this is the only ARP entry on the dynamic list.  */
        if (arp_entry == arp_entry -> nx_arp_pool_next)
        {

            /* Remove the sole entry from the dynamic list head.  */
            ip_ptr -> nx_ip_arp_dynamic_list =  NX_NULL;
        }
        else
        {

            /* Remove the entry from a list of more than one entry.  */

            /* Update the links of the adjacent ARP dynamic pool entries.  */
            (arp_entry -> nx_arp_pool_next) -> nx_arp_pool_previous =
                arp_entry -> nx_arp_pool_previous;
            (arp_entry -> nx_arp_pool_previous) -> nx_arp_pool_next =
                arp_entry -> nx_arp_pool_next;

            /* Update the list head pointer.  */
            if (ip_ptr -> nx_ip_arp_dynamic_list == arp_entry)
            {
                ip_ptr -> nx_ip_arp_dynamic_list =  arp_entry -> nx_arp_pool_next;
            }
        }

        /* Restore interrupts briefly.  */
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

            /* Release the packet that was queued from the removed ARP entry.  */
            _nx_packet_transmit_release(packet_ptr);
        }

        /* Calculate the hash index for the IP address.  */
        index =  (UINT)((ip_address + (ip_address >> 8)) & NX_ROUTE_TABLE_MASK);

        /* Indicate the entry does not need updating.  */
        arp_entry -> nx_arp_entry_next_update =  0;

        /* Place the important information in the ARP structure.  */
        arp_entry -> nx_arp_route_static =          NX_TRUE;
        arp_entry -> nx_arp_ip_address =            ip_address;
        arp_entry -> nx_arp_physical_address_msw =  physical_msw;
        arp_entry -> nx_arp_physical_address_lsw =  physical_lsw;
        arp_entry -> nx_arp_ip_interface =          nx_interface;

        /* Setup the active ARP list head.  */
        arp_list_ptr =  &(ip_ptr -> nx_ip_arp_table[index]);

        /* Disable interrupts.  */
        TX_DISABLE

        /* Add the entry to the ARP static list.  */

        /* Determine if the ARP static list is empty.  */
        if (ip_ptr -> nx_ip_arp_static_list == NX_NULL)
        {

            /* Just place this single ARP entry on the list.  */
            arp_entry -> nx_arp_pool_next =     arp_entry;
            arp_entry -> nx_arp_pool_previous = arp_entry;
            ip_ptr -> nx_ip_arp_static_list =   arp_entry;
        }
        else
        {

            /* Add to the end of the ARP static list.  */
            arp_entry -> nx_arp_pool_next =
                ip_ptr -> nx_ip_arp_static_list;
            arp_entry -> nx_arp_pool_previous =
                (ip_ptr -> nx_ip_arp_static_list) -> nx_arp_pool_previous;
            ((ip_ptr -> nx_ip_arp_static_list) -> nx_arp_pool_previous) -> nx_arp_pool_next =
                arp_entry;
            (ip_ptr -> nx_ip_arp_static_list) -> nx_arp_pool_previous =   arp_entry;
        }

        /* Link the ARP entry at the head of the active ARP list.  */

        /* Determine if the ARP entry is being added to an empty list.  */
        if (*arp_list_ptr)
        {

            /* Add the ARP entry to the beginning of the nonempty ARP
               list.  */
            arp_entry -> nx_arp_active_list_head =  arp_list_ptr;
            arp_entry -> nx_arp_active_next =      *arp_list_ptr;
            arp_entry -> nx_arp_active_previous =  (*arp_list_ptr) -> nx_arp_active_previous;
            (arp_entry -> nx_arp_active_previous) -> nx_arp_active_next =  arp_entry;
            (*arp_list_ptr) -> nx_arp_active_previous =  arp_entry;
        }
        else
        {

            /* Empty list, just put the ARP entry at the beginning.  */
            arp_entry -> nx_arp_active_list_head =  arp_list_ptr;
            arp_entry -> nx_arp_active_next =       arp_entry;
            arp_entry -> nx_arp_active_previous =   arp_entry;

            /* Now setup the list head.  */
            *arp_list_ptr =  arp_entry;
        }

        /* Restore interrupts.  */
        TX_RESTORE

        /* Setup a successful status return.  */
        status =  NX_SUCCESS;
    }
    else
    {

        /* No more ARP entries are available, all the ARP entries must be
           allocated on the static list.  */
        status =  NX_NO_MORE_ENTRIES;
    }

    /* Release the protection on the ARP list.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return status to the caller.  */
    return(status);
}

