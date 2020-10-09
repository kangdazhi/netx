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


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_packet_receive                               PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function attempts to forward the IP packet to the destination  */
/*    IP by using the NetX send packet routine.  Note that the IP header  */
/*    is still intact prior to the packet.                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to forward  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_packet_send                    Send IP packet                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_packet_receive                 Receive IP packet             */
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
VOID  _nx_ip_forward_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

NX_IP_HEADER *ip_header_ptr;


    /* The NetX IP forwarding consists of simply sending the same packet out through
       the internal send routine.  Applications may choose to modify this code or
       replace the nx_ip_forward_packet_process pointer in the IP structure to point
       at an application-specific routine for forwarding.  */

    /* It's assumed that the IP header is still present in front of the packet.  Position
       backwards to access it.  */
    ip_header_ptr =  (NX_IP_HEADER *)(packet_ptr -> nx_packet_prepend_ptr - sizeof(NX_IP_HEADER));

    /* Call the IP send routine to forward the packet.  */
    _nx_ip_packet_send(ip_ptr, packet_ptr, ip_header_ptr -> nx_ip_header_destination_ip,
                       (ip_header_ptr -> nx_ip_header_word_0 & NX_IP_TOS_MASK),
                       (ip_header_ptr -> nx_ip_header_word_2 & NX_IP_TIME_TO_LIVE_MASK) >> NX_IP_TIME_TO_LIVE_SHIFT,
                       (ip_header_ptr -> nx_ip_header_word_2 & NX_IP_PROTOCOL_MASK),
                       (ip_header_ptr -> nx_ip_header_word_1 & NX_DONT_FRAGMENT));

    /* Return to caller.  */
    return;
}

