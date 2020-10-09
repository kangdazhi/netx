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
/**   User Datagram Protocol (UDP)                                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_udp.h"
#include "nx_ip.h"

/* Bring in externs for caller checking code.  */

NX_CALLER_CHECKING_EXTERNS
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxe_udp_pacekt_info_extract                        PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function performs error checking for UDP packet info extract   */
/*    service.                                                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    packet_ptr                            Pointer to UDP packet pointer */
/*    ip_address                            Pointer to destination for IP */
/*                                            address, or NULL            */
/*    protocol                              Pointer to destination for    */
/*                                            protocol information, or    */
/*                                            NULL                        */
/*    port                                  Pointer to destination for    */
/*                                            source port.  This service  */
/*                                            always returns 17 (UDP), or */
/*                                            NULL                        */
/*    interface_index                       Pointer to destination for    */
/*                                            incoming interface ID, or   */
/*                                            NULL                        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_udp_packet_info_extract           The actual service routine.   */
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
UINT  _nxe_udp_packet_info_extract(NX_PACKET *packet_ptr, ULONG *ip_address,
                                   UINT *protocol, UINT *port, UINT *interface_index)
{
UINT   status;
NX_IP *ip_ptr;

    if (packet_ptr == NX_NULL)
    {
        return(NX_PTR_ERROR);
    }

    /* If interface field is present in the packet structure,
       validate that the interface is attached to an IP instance. */
    if (packet_ptr -> nx_packet_ip_interface)
    {
        ip_ptr = packet_ptr -> nx_packet_ip_interface -> nx_interface_ip_instance;

        if (ip_ptr == NX_NULL)
        {
            return(NX_PTR_ERROR);
        }

        if (ip_ptr -> nx_ip_id != NX_IP_ID)
        {
            return(NX_PTR_ERROR);
        }
    }

    /* Check for appropriate caller.  */
    NX_THREADS_ONLY_CALLER_CHECKING

    status = _nx_udp_packet_info_extract(packet_ptr, ip_address, protocol, port, interface_index);


    return(status);
}

