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

/* Include necessary system files. */
#include "nx_api.h"
#include "nx_ip.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ip_diferred_link_status_process                 PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes link status change event.                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    link_driver_entry                     Link driver                   */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    nx_ip_thread_entry                                                  */
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
VOID _nx_ip_deferred_link_status_process(NX_IP *ip_ptr)
{

UINT         i;
NX_IP_DRIVER driver_request;
ULONG        link_up;

    if (ip_ptr -> nx_ip_link_status_change_callback == NX_NULL)
    {

        /* Callback function is not set. */
        return;
    }

    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {
        if ((ip_ptr -> nx_ip_interface[i].nx_interface_valid) &&
            (ip_ptr -> nx_ip_interface[i].nx_interface_link_status_change))
        {

            /* Reset the flag. */
            ip_ptr -> nx_ip_interface[i].nx_interface_link_status_change = NX_FALSE;

            driver_request.nx_ip_driver_ptr       = ip_ptr;
            driver_request.nx_ip_driver_command   = NX_LINK_GET_STATUS;
            driver_request.nx_ip_driver_interface = &(ip_ptr -> nx_ip_interface[i]);
            driver_request.nx_ip_driver_return_ptr = &link_up;

            (ip_ptr -> nx_ip_interface[i].nx_interface_link_driver_entry)(&driver_request);

            /* Invoke the callback function. */
            ip_ptr -> nx_ip_link_status_change_callback(ip_ptr, i, link_up);
        }
    }
}

