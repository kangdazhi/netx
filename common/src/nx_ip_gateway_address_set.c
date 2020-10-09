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
#include "nx_arp.h"
#include "nx_ip.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_gateway_address_set                          PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function finds the correct interface for the supplied ip       */
/*    address and applies that interface and the supplied gateway address */
/*    as the IP task gateway for sending IP packets with addresses not in */
/*    the local network.                                                  */
/*                                                                        */
/*    Note 1: if the gateway address is zero, the IP gateway address and  */
/*    gateway interface pointer are set to null.                          */
/*                                                                        */
/*    Note 2: For a gateway address is non zero, the IP gateway address   */
/*    and gateway interface pointer must be non null, or this function    */
/*    will return an error status.                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP control block pointer      */
/*    ip_address                            Gateway IP address            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
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
UINT  _nx_ip_gateway_address_set(NX_IP *ip_ptr, ULONG ip_address)
{

int           i;
TX_INTERRUPT_SAVE_AREA
NX_INTERFACE *nx_ip_interface = NX_NULL;


    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_IP_GATEWAY_ADDRESS_SET, ip_ptr, ip_address, 0, 0, NX_TRACE_IP_EVENTS, 0, 0)

    /* Obtain the IP internal mutex so the Gateway IP address can be setup.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Determine if the caller is trying to clear the IP gateway. */
    if (ip_address == 0x0)
    {

        /* They are. Ok to clear gateway and gateway interface. */

        /* Disable interrupts.  */
        TX_DISABLE

        ip_ptr -> nx_ip_gateway_address =  0x0;
        ip_ptr -> nx_ip_gateway_interface = NX_NULL;

        /* Restore interrupts.  */
        TX_RESTORE

        /* Unlock the mutex, and return success status. */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_SUCCESS);
    }

    /* Loop through all the interfaces to find the one for the input gateway address. */
    for (i = 0; i < NX_MAX_IP_INTERFACES; i++)
    {

        /* Must be a valid interface. Match the network subnet of the interface and input address. */
        if ((ip_ptr -> nx_ip_interface[i].nx_interface_valid) &&
            ((ip_address & (ip_ptr -> nx_ip_interface[i].nx_interface_ip_network_mask)) ==
             ip_ptr -> nx_ip_interface[i].nx_interface_ip_network))
        {

            /* This is the interface for the gateway.  */
            nx_ip_interface = &(ip_ptr -> nx_ip_interface[i]);

            /* Break out of the search. */
            break;
        }
    }

    /* Check if we found an interface. */
    if (nx_ip_interface == NX_NULL)
    {

        /* None found. Unlock the mutex, and return the error status. */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_IP_ADDRESS_ERROR);
    }

    /* Disable interrupts.  */
    TX_DISABLE

    /* Setup the gateway address and interface for the IP task.  */
    ip_ptr -> nx_ip_gateway_address =  ip_address;
    ip_ptr -> nx_ip_gateway_interface = nx_ip_interface;

    /* Restore interrupts.  */
    TX_RESTORE

    /* Release the protection mutex.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    /* Return completion status.  */
    return(NX_SUCCESS);
}

