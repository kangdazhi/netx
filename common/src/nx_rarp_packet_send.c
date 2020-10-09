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
/**   Reverse Address Resolution Protocol (RARP)                          */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_rarp.h"
#include "nx_packet.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_rarp_packet_send                                PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function builds an RARP packet for each interface on the host  */
/*    without a valid IP address and calls the associated driver to send  */
/*    to send it out on its network interface.                            */
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
/*    _nx_packet_allocate                   Allocate a packet for the     */
/*                                            RARP request                */
/*    (ip_link_driver)                      User supplied link driver     */
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
VOID  _nx_rarp_packet_send(NX_IP *ip_ptr)
{

NX_PACKET   *request_ptr;
ULONG       *message_ptr;
NX_IP_DRIVER driver_request;
ULONG        i;


    /* Determine which interfaces to send RARP packets out from (e.g. do not have IP addresses). */
    for (i = 0; i < NX_MAX_IP_INTERFACES; i++)
    {

        /* Skip this interface if it is not initialized yet. */
        if (ip_ptr -> nx_ip_interface[i].nx_interface_valid == 0)
        {
            continue;
        }

        /* If the interface has a valid address, skip it. */
        if (ip_ptr -> nx_ip_interface[i].nx_interface_ip_address != 0)
        {
            continue;
        }

        /* Allocate a packet to build the RARP message in.  */
        if (_nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool, &request_ptr, (NX_PHYSICAL_HEADER + NX_RARP_MESSAGE_SIZE), NX_NO_WAIT))
        {

            /* Error getting packet, so just get out!  */
            return;
        }

#ifndef NX_DISABLE_RARP_INFO
        /* Increment the RARP requests sent count.  */
        ip_ptr -> nx_ip_rarp_requests_sent++;
#endif
        request_ptr -> nx_packet_ip_interface = &(ip_ptr -> nx_ip_interface[i]);
        /* Build the RARP request packet.  */

        /* Setup the size of the RARP message.  */
        request_ptr -> nx_packet_length =  NX_RARP_MESSAGE_SIZE;

        /* Setup the prepend pointer.  */
        request_ptr -> nx_packet_prepend_ptr -= NX_RARP_MESSAGE_SIZE;

        /* Setup the pointer to the message area.  */
        message_ptr =  (ULONG *)request_ptr -> nx_packet_prepend_ptr;

        /* Write the Hardware type into the message.  */
        *message_ptr =      (ULONG)(NX_RARP_HARDWARE_TYPE << 16) | (NX_RARP_PROTOCOL_TYPE);
        *(message_ptr + 1) =  (ULONG)(NX_RARP_HARDWARE_SIZE << 24) | (NX_RARP_PROTOCOL_SIZE << 16) |
            NX_RARP_OPTION_REQUEST;
        *(message_ptr + 2) =  (ULONG)(request_ptr -> nx_packet_ip_interface -> nx_interface_physical_address_msw << 16) |
            (request_ptr -> nx_packet_ip_interface -> nx_interface_physical_address_lsw >> 16);
        *(message_ptr + 3) =  (ULONG)(request_ptr -> nx_packet_ip_interface -> nx_interface_physical_address_lsw << 16);
        *(message_ptr + 4) =  (ULONG)(request_ptr -> nx_packet_ip_interface -> nx_interface_physical_address_msw & NX_LOWER_16_MASK);
        *(message_ptr + 5) =  (ULONG)(request_ptr -> nx_packet_ip_interface -> nx_interface_physical_address_lsw);
        *(message_ptr + 6) =  (ULONG)0;

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_RARP_SEND, ip_ptr, 0, request_ptr, *(message_ptr + 1), NX_TRACE_INTERNAL_EVENTS, 0, 0)

        /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will swap the endian of the RARP message.  */
        NX_CHANGE_ULONG_ENDIAN(*(message_ptr));
        NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 1));
        NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 2));
        NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 3));
        NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 4));
        NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 5));
        NX_CHANGE_ULONG_ENDIAN(*(message_ptr + 6));

        /* Send the RARP request to the driver.  */
        driver_request.nx_ip_driver_ptr =                   ip_ptr;
        driver_request.nx_ip_driver_command =               NX_LINK_RARP_SEND;
        driver_request.nx_ip_driver_packet =                request_ptr;
        driver_request.nx_ip_driver_physical_address_msw =  0xFFFFUL;
        driver_request.nx_ip_driver_physical_address_lsw =  0xFFFFFFFFUL;
        driver_request.nx_ip_driver_interface            =  request_ptr -> nx_packet_ip_interface;

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_RARP_SEND, ip_ptr, request_ptr, request_ptr -> nx_packet_length, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        (request_ptr -> nx_packet_ip_interface -> nx_interface_link_driver_entry) (&driver_request);
    }

    return;
}

