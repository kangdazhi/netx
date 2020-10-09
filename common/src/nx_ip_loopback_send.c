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
/*    _nx_ip_loopback_send                                PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function prepends an IP header and sends an IP packet to the   */
/*    appropriate link driver.                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*    packet_release                        Whether or not to release     */
/*                                            the original packet         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_packet_deferred_receive        Receive loopback packet       */
/*    _nx_packet_copy                       Copy packet for loopback      */
/*    _nx_packet_transmit_release           Release transmit packet       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX Source Code                                                    */
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
VOID _nx_ip_loopback_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT packet_release)
{

NX_PACKET *packet_copy;

    /* Copy the packet so it can be enqueued properly by the receive
       processing.  */
    if (_nx_packet_copy(packet_ptr, &packet_copy, ip_ptr -> nx_ip_default_packet_pool, NX_NO_WAIT) == NX_SUCCESS)
    {

#ifndef NX_DISABLE_IP_INFO

        /* Increment the IP packet sent count.  */
        ip_ptr -> nx_ip_total_packets_sent++;

        /* Increment the IP bytes sent count.  */
        ip_ptr -> nx_ip_total_bytes_sent +=  packet_ptr -> nx_packet_length - sizeof(NX_IP_HEADER);
#endif

        /* Send the packet to this IP's receive processing queue like it came in from the
           driver.  */
        _nx_ip_packet_deferred_receive(ip_ptr, packet_copy);
    }
#ifndef NX_DISABLE_IP_INFO
    else
    {

        /* Increment the IP send packets dropped count.  */
        ip_ptr -> nx_ip_send_packets_dropped++;

        /* Increment the IP transmit resource error count.  */
        ip_ptr -> nx_ip_transmit_resource_errors++;
    }
#endif

    if (packet_release)
    {
        /* Release the transmit packet.  */
        _nx_packet_transmit_release(packet_ptr);
    }


    return;
}

