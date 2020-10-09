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
/**   Internet Protocol (IP)                                              */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_ip.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_fragment_timeout_check                       PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks for timeout conditions on the first fragment   */
/*    in the IP re-assembly list.  If the head pointer is the same        */
/*    between execution of this routine the head fragment is deleted and  */
/*    its packets are released.                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP instance        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Release packet                */
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
VOID  _nx_ip_fragment_timeout_check(NX_IP *ip_ptr)
{

NX_PACKET *fragment;
NX_PACKET *next_fragment;


    /* Determine if the head packet is still there.  */
    if ((ip_ptr -> nx_ip_timeout_fragment) &&
        (ip_ptr -> nx_ip_timeout_fragment ==  ip_ptr -> nx_ip_fragment_assembly_head))
    {

        /* Save the head fragment pointer.  */
        fragment =  ip_ptr -> nx_ip_fragment_assembly_head;

        /* Yes, we need to remove this fragment from the assembly queue and release it.  */
        ip_ptr -> nx_ip_fragment_assembly_head =  fragment -> nx_packet_queue_next;

        /* Determine if we need to modify the fragment assembly tail pointer.  */
        if (ip_ptr -> nx_ip_fragment_assembly_tail == fragment)
        {

            /* If the tail pointer is the same, then the list is really empty now so
               just set the tail pointer to NULL.  */
            ip_ptr -> nx_ip_fragment_assembly_tail =  NX_NULL;
        }

#ifndef NX_DISABLE_IP_INFO

        /* Increment the re-assembly failures count.  */
        ip_ptr -> nx_ip_reassembly_failures++;
#endif

        /* Walk the chain of fragments for this fragment re-assembly.  */
        do
        {

#ifndef NX_DISABLE_IP_INFO

            /* Increment the IP receive packets dropped count.  */
            ip_ptr -> nx_ip_receive_packets_dropped++;
#endif

            /* Pickup the next fragment.  */
            next_fragment =  fragment -> nx_packet_fragment_next;

            /* Release this fragment.  */
            _nx_packet_release(fragment);

            /* Reassign the fragment pointer.  */
            fragment =  next_fragment;
        } while (fragment);

        /* Set the timeout fragment head to NULL so the next fragment gets a full timeout.  */
        ip_ptr -> nx_ip_timeout_fragment =  NX_NULL;
    }
    else
    {

        /* Assign the fragment head to the timeout pointer.  */
        ip_ptr -> nx_ip_timeout_fragment =  ip_ptr -> nx_ip_fragment_assembly_head;
    }
}

