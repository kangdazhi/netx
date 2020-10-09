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
/**   Internet Group Management Protocol (IGMP)                           */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_igmp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_igmp_multicast_leave                            PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the request to leave the specified multicast  */
/*    group.                                                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    group_address                         Multicast group to leave      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Obtain protection mutex       */
/*    tx_mutex_put                          Release protection mutex      */
/*    (ip_link_driver)                      Associated IP link driver     */
/*    nx_igmp_interface_report_send         Send IGMP group report        */
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
UINT  _nx_igmp_multicast_leave(NX_IP *ip_ptr, ULONG group_address)
{

UINT         i;
#ifndef NX_DISABLE_IGMPV2
UINT         interface_index = 0;
#endif
ULONG       *join_list_ptr;
NX_IP_DRIVER driver_request;


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_IGMP_MULTICAST_LEAVE, ip_ptr, group_address, 0, 0, NX_TRACE_IGMP_EVENTS, 0, 0)

    /* Obtain the IP mutex so we can search the multicast join list.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Search the multicast join list for either the same group request.  */
    join_list_ptr =  &(ip_ptr -> nx_ip_igmp_join_list[0]);

    for (i = 0; i < NX_MAX_MULTICAST_GROUPS; i++)
    {

        /* Determine if the specified entry is present.  */
        if (*join_list_ptr == group_address)
        {

        /* Yes, we have found the same entry.  */
#ifndef NX_DISABLE_IGMPV2
        UINT          index;
        NX_INTERFACE *nx_interface = ip_ptr -> nx_ip_igmp_join_interface_list[i];
#endif
            /* Decrease the join count.  */
            ip_ptr -> nx_ip_igmp_join_count[i]--;

            /* Determine if there are no other join requests.  */
            if (ip_ptr -> nx_ip_igmp_join_count[i] == 0)
            {

                /* Clear the group join value.  */
                *join_list_ptr =  0;

                /* Un-register the new multicast group with the underlying driver.  */
                driver_request.nx_ip_driver_ptr                  =   ip_ptr;
                driver_request.nx_ip_driver_command              =   NX_LINK_MULTICAST_LEAVE;
                driver_request.nx_ip_driver_physical_address_msw =   NX_IP_MULTICAST_UPPER;
                driver_request.nx_ip_driver_physical_address_lsw =   NX_IP_MULTICAST_LOWER | (group_address & NX_IP_MULTICAST_MASK);
                driver_request.nx_ip_driver_interface            =   ip_ptr -> nx_ip_igmp_join_interface_list[i];
                /* If trace is enabled, insert this event into the trace buffer.  */
                NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_MULTICAST_LEAVE, ip_ptr, 0, 0, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

                (ip_ptr -> nx_ip_igmp_join_interface_list[i] -> nx_interface_link_driver_entry) (&driver_request);

#ifdef NX_DISABLE_IGMPV2
                /* Clear the interface entry for version IGMPv1. We don't need it anymore. */
                ip_ptr -> nx_ip_igmp_join_interface_list[i] = NX_NULL;
#endif

#ifndef NX_DISABLE_IGMP_INFO
                /* Decrement the IGMP groups joined count.  */
                ip_ptr -> nx_ip_igmp_groups_joined--;
#endif

#ifndef NX_DISABLE_IGMPV2

                /* IGMPv2 hosts should send a leave group message. IGMPv1
                   hosts do not. */
                if (ip_ptr -> nx_ip_igmp_router_version == NX_IGMP_HOST_VERSION_1)
                {

                    /* Release the IP protection.  */
                    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

                    /* Return success!  */
                    return(NX_SUCCESS);
                }

                /* Find the interface for this group address. */
                for (index = 0; index < NX_MAX_PHYSICAL_INTERFACES; index++)
                {

                    if (nx_interface == &(ip_ptr -> nx_ip_interface[index]))
                    {
                        /* Found it. */
                        interface_index = index;

                        break;
                    }
                }

                /* Build and send the leave report packet. */
                _nx_igmp_interface_report_send(ip_ptr, group_address, interface_index, NX_FALSE);

#endif  /* NX_DISABLE_IGMPV2 */
            }

            /* Release the IP protection.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));

            /* Return success!  */
            return(NX_SUCCESS);
        }

        /* Move to the next entry in the join list.  */
        join_list_ptr++;
    }

    /* The group address was not found in the multicast join list.
       Release the protection of the IP instance and quit.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return an error code.  */
    return(NX_ENTRY_NOT_FOUND);
}

