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
/*    _nx_ip_interface_attach                             PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function attaches a physical network interface to the IP       */
/*    instance, initializes and enables the driver.                       */
/*                                                                        */
/*    Note that the priority of this function is determined by the IP     */
/*    create service.                                                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr_value                          Pointer to IP control block   */
/*    interface_name                        Name of this interface        */
/*    ip_address                            IP Address, in host byte order*/
/*    network_mask                          Network Mask, in host byte    */
/*                                             order                      */
/*    ip_link_driver                        User supplied link driver     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    tx_mutex_get                          Obtain protection mutex       */
/*    tx_mutex_put                          Release protection mutex      */
/*    (ip_link_driver)                      User supplied link driver     */
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
UINT _nx_ip_interface_attach(NX_IP *ip_ptr, CHAR *interface_name, ULONG ip_address, ULONG network_mask, VOID (*ip_link_driver)(struct NX_IP_DRIVER_STRUCT *))
{

int           i;
NX_INTERFACE *nx_interface = NX_NULL;
NX_IP_DRIVER  driver_request;


    /* This function must be called within the system initialization
       after nx_ip_create, before nx ip thread runs. */
    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {

        nx_interface = &(ip_ptr -> nx_ip_interface[i]);

        if (!(nx_interface -> nx_interface_valid))
        {
            /* Find a valid entry. */
            break;
        }
    }

    if ((nx_interface == NX_NULL) || (i == NX_MAX_PHYSICAL_INTERFACES))
    {
        /* No more free entry.  return. */
        return(NX_NO_MORE_ENTRIES);
    }

    /* Obtain the IP internal mutex before calling the driver.  */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Mark the entry as valid. */
    nx_interface -> nx_interface_valid = NX_TRUE;

    /* Fill in the interface information. */
    nx_interface -> nx_interface_ip_address        = ip_address;
    nx_interface -> nx_interface_ip_network_mask   = network_mask;
    nx_interface -> nx_interface_ip_network        = ip_address & network_mask;
    nx_interface -> nx_interface_link_driver_entry = ip_link_driver;
    nx_interface -> nx_interface_ip_instance       = ip_ptr;

    nx_interface -> nx_interface_name = interface_name;

    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_IP_INTERFACE_ATTACH, ip_ptr, ip_address, i, 0, NX_TRACE_IP_EVENTS, 0, 0)

    /* If the IP thread is already running, this service needs to go through the rest of the initializeation process. */
    if (ip_ptr -> nx_ip_initialize_done == NX_TRUE)
    {

        /* First attach the interface to the device. */
        driver_request.nx_ip_driver_ptr       =  ip_ptr;
        driver_request.nx_ip_driver_command   =  NX_LINK_INTERFACE_ATTACH;
        driver_request.nx_ip_driver_interface = &(ip_ptr -> nx_ip_interface[i]);
        (ip_ptr -> nx_ip_interface[i].nx_interface_link_driver_entry)(&driver_request);


        /* Call the link driver to initialize the hardware. Among other
           responsibilities, the driver is required to provide the
           Maximum Transfer Unit (MTU) for the physical layer. The MTU
           should represent the actual physical layer transfer size
           less the physical layer headers and trailers.  */
        driver_request.nx_ip_driver_ptr =      ip_ptr;
        driver_request.nx_ip_driver_command =  NX_LINK_INITIALIZE;

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_INITIALIZE, ip_ptr, 0, 0, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        /*
           When an IP instance is created, the first interface (nx_ip_interface[0]) is configured using parameters
           provided in the IP create call.

           When IP thread runs, it invokes the 1st interface link driver for link initialization.
        */
        (ip_ptr -> nx_ip_interface[i].nx_interface_link_driver_entry) (&driver_request);



        /* Call the link driver again to enable the interface.  */
        driver_request.nx_ip_driver_ptr =      ip_ptr;
        driver_request.nx_ip_driver_command =  NX_LINK_ENABLE;

        /* If trace is enabled, insert this event into the trace buffer.  */
        NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_IO_DRIVER_LINK_ENABLE, ip_ptr, 0, 0, 0, NX_TRACE_INTERNAL_EVENTS, 0, 0)

        (ip_ptr -> nx_ip_interface[i].nx_interface_link_driver_entry) (&driver_request);
    }

    /* Release the IP internal mutex.  */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));


    /* All done.  Return. */
    return(NX_SUCCESS);
}

