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
/*    _nx_igmp_periodic_processing                        PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function handles the sending of periodic processing of IGMP    */
/*    messages.                                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_igmp_interface_report_send         Send IGMP group report        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_thread_entry                   IP helper thread              */
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
VOID  _nx_igmp_periodic_processing(NX_IP *ip_ptr)
{

UINT   i;
UINT   status;
UINT   interface_index = 0;
ULONG *join_list_ptr;
UINT   sent_count = 0;


    /* Search the multicast join list for pending IGMP responses.  */
    join_list_ptr =  &(ip_ptr -> nx_ip_igmp_join_list[0]);
    for (i = 0; i < NX_MAX_MULTICAST_GROUPS; i++)
    {

        /* Determine if the specified entry is active.  */
        if (*join_list_ptr)
        {

            /* Now determine if a response is pending.  */
            if (ip_ptr -> nx_ip_igmp_update_time[i] > 0)
            {

                /* Yes, it is active.  Decrement and check for expiration.  */

                /* We don't want to decrement a join group if we cannot send it. Check
                   if we've already sent a packet on this periodic. */
                if (sent_count > 0)
                {

                    /* We have. So only decrement groups with a update time > 1. */
                    if (ip_ptr -> nx_ip_igmp_update_time[i] > 1)
                    {

                        /* Ok to decrement.  */
                        ip_ptr -> nx_ip_igmp_update_time[i]--;
                    }

                    /* Else don't decrement because we cannot send on this periodic; we've already sent out a packet. */
                }
                else
                {

                    /* No packets sent out yet. Ok to decrement this group. */
                    ip_ptr -> nx_ip_igmp_update_time[i]--;
                }

                /* Has time expired and have we not sent an IGMP report in this period?  */
                if ((ip_ptr -> nx_ip_igmp_update_time[i] == 0) && (sent_count == 0))
                {

                /* Time has expired and we have not yet sent a packet out on this periodic. */

                UINT          index;
                NX_INTERFACE *nx_interface = ip_ptr -> nx_ip_igmp_join_interface_list[i];

                    /* We need to find the interface this group address is on. */
                    for (index = 0; index < NX_MAX_PHYSICAL_INTERFACES; index++)
                    {

                        if (nx_interface == &(ip_ptr -> nx_ip_interface[index]))
                        {
                            /* Found it. */
                            interface_index = index;

                            break;
                        }
                    }

                    /* Build a IGMP host response packet for a join report and send it!  */
                    status = _nx_igmp_interface_report_send(ip_ptr, *join_list_ptr, interface_index, NX_TRUE);

                    if (status == NX_SUCCESS)
                    {
                        /* Update the sent count. Only one report sent per IP periodic. */
                        sent_count++;
                    }
                }
            }
        }

        /* Move to the next entry in the join list.  */
        join_list_ptr++;
    }
}

