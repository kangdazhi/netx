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
/*    _nx_ip_fragment_disable                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function disables IP fragment assembly processing and releases */
/*    all partial fragments being assembled.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP instance        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Release packet                */
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
UINT  _nx_ip_fragment_disable(NX_IP *ip_ptr)
{

TX_INTERRUPT_SAVE_AREA

NX_PACKET *new_fragment_head;
NX_PACKET *assemble_head;
NX_PACKET *next_packet;
NX_PACKET *release_packet;


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_IP_FRAGMENT_DISABLE, ip_ptr, 0, 0, 0, NX_TRACE_IP_EVENTS, 0, 0)

    /* Get mutex protection.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Disable interrupts temporarily.  */
    TX_DISABLE

    /* Clear the IP fragment processing routine pointer.  */
    ip_ptr -> nx_ip_fragment_processing =  NX_NULL;

    /* Clear the IP fragment assembly routine pointer.  */
    ip_ptr -> nx_ip_fragment_assembly =  NX_NULL;

    /* Clear the IP fragment timeout routine pointer.  */
    ip_ptr -> nx_ip_fragment_timeout_check =  NX_NULL;

    /* Pickup the fragment list pointer.  */
    new_fragment_head = ip_ptr -> nx_ip_received_fragment_head;
    assemble_head =     ip_ptr -> nx_ip_fragment_assembly_head;

    /* Clear the IP structure lists.  */
    ip_ptr -> nx_ip_received_fragment_head =  NX_NULL;
    ip_ptr -> nx_ip_received_fragment_tail =  NX_NULL;
    ip_ptr -> nx_ip_fragment_assembly_head =  NX_NULL;
    ip_ptr -> nx_ip_fragment_assembly_tail =  NX_NULL;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Release mutex protection.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Now walk through the receive and assembly lists to free the packets.  */
    next_packet =  new_fragment_head;
    while (next_packet)
    {

        /* Set the release packet to this packet.  */
        release_packet =  next_packet;

        /* Move next packet to the next in the list.  */
        next_packet =  next_packet -> nx_packet_queue_next;

        /* Release the current packet.  */
        _nx_packet_release(release_packet);
    }

    /* Now walk through the assemble list and release all packets.  */
    while (assemble_head)
    {

        /* Walk through the list of packets being assembled for this packet and release them.  */
        next_packet =  assemble_head;
        assemble_head =  next_packet -> nx_packet_queue_next;
        while (next_packet)
        {

            /* Set the release packet to this packet.  */
            release_packet =  next_packet;

            /* Move next packet to the next in the list.  */
            next_packet =  next_packet -> nx_packet_fragment_next;

            /* Release the current packet.  */
            _nx_packet_release(release_packet);
        }
    }

    /* Return success to the caller.  */
    return(NX_SUCCESS);
}

