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
/*    _nx_ip_raw_packet_send                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a raw IP packet through the specified IP        */
/*    interface.                                                          */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*    destination_ip                        Destination IP address        */
/*    type_of_service                       Type of service for packet    */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_ip_packet_send                     Core IP packet send service   */
/*    nx_ip_route_find                      Find a suitable outgoing      */
/*                                            interface.                  */
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
UINT  _nx_ip_raw_packet_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr,
                             ULONG destination_ip, ULONG type_of_service)
{


    /* Determine if raw IP packet sending/receiving is enabled.  */
    if (ip_ptr -> nx_ip_raw_ip_processing)
    {

        /* Get mutex protection.  */
        tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

        /* Figure out a suitable outgoing interface. */
        if (_nx_ip_route_find(ip_ptr, destination_ip, &packet_ptr -> nx_packet_ip_interface, &packet_ptr -> nx_packet_next_hop_address) != NX_SUCCESS)
        {

            /* Release the protection on the ARP list.  */
            tx_mutex_put(&(ip_ptr -> nx_ip_protection));

            return(NX_IP_ADDRESS_ERROR);
        }

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_IP_RAW_PACKET_SEND, ip_ptr, packet_ptr, destination_ip, type_of_service, NX_TRACE_IP_EVENTS, 0, 0)

        /* Yes, raw packet sending and receiving is enabled send packet!  */
        _nx_ip_packet_send(ip_ptr, packet_ptr, destination_ip, type_of_service, NX_IP_TIME_TO_LIVE, NX_IP_RAW, NX_FRAGMENT_OKAY);

        /* Release mutex protection.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        /* Return a successful status!  */
        return(NX_SUCCESS);
    }
    else
    {

        /* Return an error.  */
        return(NX_NOT_ENABLED);
    }
}

