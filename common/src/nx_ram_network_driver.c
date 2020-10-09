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
/**   RAM Network (RAM)                                                   */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/


/* Include necessary system files.  */

#include "nx_api.h"


#define NX_LINK_MTU      8096


/* Define Ethernet address format.  This is prepended to the incoming IP
   and ARP/RARP messages.  The frame beginning is 14 bytes, but for speed
   purposes, we are going to assume there are 16 bytes free in front of the
   prepend pointer and that the prepend pointer is 32-bit aligned.

    Byte Offset     Size            Meaning

        0           6           Destination Ethernet Address
        6           6           Source Ethernet Address
        12          2           Ethernet Frame Type, where:

                                        0x0800 -> IP Datagram
                                        0x0806 -> ARP Request/Reply
                                        0x0835 -> RARP request reply

        42          18          Padding on ARP and RARP messages only.  */

#define NX_ETHERNET_IP   0x0800
#define NX_ETHERNET_ARP  0x0806
#define NX_ETHERNET_RARP 0x8035
#define NX_ETHERNET_SIZE 14

/* For the simulated ethernet driver, physical addresses are allocated starting
   at the preset value and then incremented before the next allocation.  */

ULONG   simulated_address_msw =  0x1122;
ULONG   simulated_address_lsw =  0x33445566;


/* Define driver prototypes.  */

VOID _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
void _nx_ram_network_driver_output(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT device_instance_id);
void _nx_ram_network_driver_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT device_instance_id);

#define NX_MAX_RAM_INTERFACES 4


typedef struct _nx_ram_network_driver_instance_type
{
    UINT          nx_ram_network_driver_in_use;

    UINT          nx_ram_network_driver_id;

    NX_INTERFACE *nx_ram_driver_interface_ptr;

    NX_IP        *nx_ram_driver_ip_ptr;

    ULONG         nx_ram_driver_simulated_address_msw;
    ULONG         nx_ram_driver_simulated_address_lsw;
} _nx_ram_network_driver_instance_type;

static _nx_ram_network_driver_instance_type nx_ram_driver[NX_MAX_RAM_INTERFACES];


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ram_network_driver                              PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function acts as a virtual network for testing the NetX source */
/*    and driver concepts.                                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP protocol block  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ram_network_driver_output         Send physical packet out      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX IP processing                                                  */
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
VOID  _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr)
{
UINT          i =  0;
NX_IP        *ip_ptr;
NX_PACKET    *packet_ptr;
ULONG        *ethernet_frame_ptr;
NX_INTERFACE *interface_ptr;


    /* Setup the IP pointer from the driver request.  */
    ip_ptr =  driver_req_ptr -> nx_ip_driver_ptr;

    /* Default to successful return.  */
    driver_req_ptr -> nx_ip_driver_status =  NX_SUCCESS;

    /* Setup interface pointer.  */
    interface_ptr = driver_req_ptr -> nx_ip_driver_interface;


    /* Find out the driver instance if the driver command is not ATTACH. */
    if (driver_req_ptr -> nx_ip_driver_command != NX_LINK_INTERFACE_ATTACH)
    {
        for (i = 0; i < NX_MAX_RAM_INTERFACES; i++)
        {
            if (nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
            {
                continue;
            }

            if (nx_ram_driver[i].nx_ram_driver_ip_ptr != ip_ptr)
            {
                continue;
            }

            if (nx_ram_driver[i].nx_ram_driver_interface_ptr != driver_req_ptr -> nx_ip_driver_interface)
            {
                continue;
            }
            else
            {
                break;
            }
        }

        if (i == NX_MAX_RAM_INTERFACES)
        {
            driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
            return;
        }
    }


    /* Process according to the driver request type in the IP control
       block.  */
    switch (driver_req_ptr -> nx_ip_driver_command)
    {

    case NX_LINK_INTERFACE_ATTACH:
    {

        /* Find an available driver instance to attach the interface. */
        for (i = 0; i < NX_MAX_RAM_INTERFACES; i++)
        {
            if (nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
            {
                break;
            }
        }
        /* An available entry is found. */
        if (i < NX_MAX_RAM_INTERFACES)
        {
            /* Set the IN USE flag.*/
            nx_ram_driver[i].nx_ram_network_driver_in_use  = 1;

            nx_ram_driver[i].nx_ram_network_driver_id = i;

            /* Record the interface attached to the IP instance. */
            nx_ram_driver[i].nx_ram_driver_interface_ptr = driver_req_ptr -> nx_ip_driver_interface;

            /* Record the IP instance. */
            nx_ram_driver[i].nx_ram_driver_ip_ptr = ip_ptr;

            nx_ram_driver[i].nx_ram_driver_simulated_address_msw = simulated_address_msw;
            nx_ram_driver[i].nx_ram_driver_simulated_address_lsw = simulated_address_lsw + i;
        }
        else
        {
            driver_req_ptr -> nx_ip_driver_status =  NX_INVALID_INTERFACE;
        }

        break;
    }

    case NX_LINK_INITIALIZE:
    {

        /* Process driver initialization.  */
#ifdef NX_DEBUG
        printf("NetX RAM Driver Initialization - %s\n", ip_ptr -> nx_ip_name);
        printf("  IP Address =%08X\n", ip_ptr -> nx_ip_address);
#endif

        /* Setup the link maximum transfer unit. Note that the MTU should
           take into account the physical header needs and alignment
           requirements. For example, we are going to report actual
           MTU less the ethernet header and 2 bytes to keep alignment. */
        interface_ptr -> nx_interface_ip_mtu_size =  (NX_LINK_MTU - NX_ETHERNET_SIZE - 2);

        /* Setup the physical address of this IP instance.  Increment the
           physical address lsw to simulate multiple nodes on the
           ethernet.  */
        interface_ptr -> nx_interface_physical_address_msw =  nx_ram_driver[i].nx_ram_driver_simulated_address_msw;
        interface_ptr -> nx_interface_physical_address_lsw =  nx_ram_driver[i].nx_ram_driver_simulated_address_lsw;

        /* Indicate to the IP software that IP to physical mapping
           is required.  */
        interface_ptr -> nx_interface_address_mapping_needed =  NX_TRUE;

        break;
    }

    case NX_LINK_UNINITIALIZE:
    {

        /* Zero out the driver instance. */
        memset(&(nx_ram_driver[i]), 0, sizeof(_nx_ram_network_driver_instance_type));

        break;
    }

    case NX_LINK_ENABLE:
    {

        /* Process driver link enable.  */

        /* In the RAM driver, just set the enabled flag.  */
        interface_ptr -> nx_interface_link_up =  NX_TRUE;

#ifdef NX_DEBUG
        printf("NetX RAM Driver Link Enabled - %s\n", ip_ptr -> nx_ip_name);
#endif
        break;
    }

    case NX_LINK_DISABLE:
    {

        /* Process driver link disable.  */

        /* In the RAM driver, just clear the enabled flag.  */
        interface_ptr -> nx_interface_link_up =  NX_FALSE;

#ifdef NX_DEBUG
        printf("NetX RAM Driver Link Disabled - %s\n", ip_ptr -> nx_ip_name);
#endif
        break;
    }

    case NX_LINK_PACKET_SEND:
    case NX_LINK_PACKET_BROADCAST:
    case NX_LINK_ARP_SEND:
    case NX_LINK_ARP_RESPONSE_SEND:
    case NX_LINK_RARP_SEND:
    {

        /* Process driver send packet.  */

        /* Place the ethernet frame at the front of the packet.  */
        packet_ptr =  driver_req_ptr -> nx_ip_driver_packet;

        /* Adjust the prepend pointer.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr - NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length + NX_ETHERNET_SIZE;

        /* Setup the ethernet frame pointer to build the ethernet frame.  Backup another 2
           bytes to get 32-bit word alignment.  */
        ethernet_frame_ptr =  (ULONG *)(packet_ptr -> nx_packet_prepend_ptr - 2);

        /* Build the ethernet frame.  */
        *ethernet_frame_ptr     =  driver_req_ptr -> nx_ip_driver_physical_address_msw;
        *(ethernet_frame_ptr + 1) =  driver_req_ptr -> nx_ip_driver_physical_address_lsw;
        *(ethernet_frame_ptr + 2) =  (interface_ptr -> nx_interface_physical_address_msw << 16) |
            (interface_ptr -> nx_interface_physical_address_lsw >> 16);
        *(ethernet_frame_ptr + 3) =  (interface_ptr -> nx_interface_physical_address_lsw << 16);

        if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_SEND)
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_ARP;
        }
        else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_ARP_RESPONSE_SEND)
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_ARP;
        }
        else if (driver_req_ptr -> nx_ip_driver_command == NX_LINK_RARP_SEND)
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_RARP;
        }
        else
        {
            *(ethernet_frame_ptr + 3) |= NX_ETHERNET_IP;
        }


        /* Endian swapping if NX_LITTLE_ENDIAN is defined.  */
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr));
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 1));
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 2));
        NX_CHANGE_ULONG_ENDIAN(*(ethernet_frame_ptr + 3));
#ifdef NX_DEBUG_PACKET
        printf("NetX RAM Driver Packet Send - %s\n", ip_ptr -> nx_ip_name);
#endif
        _nx_ram_network_driver_output(ip_ptr, packet_ptr, i);
        break;
    }

    case NX_LINK_MULTICAST_JOIN:
    {

        /* For real ethernet devices the hardware registers that support IP multicast
           need to be searched for an open entry.  If found, the multicast ethernet
           address contained in the driver request structure
           (nx_ip_driver_physical_address_msw & nx_ip_driver_physical_address_lsw)
           needs to be loaded into ethernet chip.  If no free entries are found,
           an NX_NO_MORE_ENTRIES error should be returned to the caller.  */
        break;
    }

    case NX_LINK_MULTICAST_LEAVE:
    {

        /* For real ethernet devices the hardware registers that support IP multicast
           need to be searched for a matching entry.  If found, the multicast ethernet
           address should be cleared in the hardware so that a new entry may use it
           on the next join operation.  */
        break;
    }

    case NX_LINK_GET_STATUS:
    {

        /* Return the link status in the supplied return pointer.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) =  ip_ptr -> nx_ip_interface[0].nx_interface_link_up;
        break;
    }

    case NX_LINK_GET_SPEED:
    {

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_DUPLEX_TYPE:
    {

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_ERROR_COUNT:
    {

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_RX_COUNT:
    {

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_TX_COUNT:
    {

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_GET_ALLOC_ERRORS:
    {

        /* Return the link's line speed in the supplied return pointer. Unsupported feature.  */
        *(driver_req_ptr -> nx_ip_driver_return_ptr) = 0;
        break;
    }

    case NX_LINK_DEFERRED_PROCESSING:
    {

        /* Driver defined deferred processing... this is typically used to defer interrupt
           processing to the thread level. In this driver, nothing is done here!  */
        break;
    }

    default:
    {

        /* Invalid driver request.  */

        /* Return the unhandled command status.  */
        driver_req_ptr -> nx_ip_driver_status =  NX_UNHANDLED_COMMAND;

#ifdef NX_DEBUG
        printf("NetX RAM Driver Received invalid request - %s\n", ip_ptr -> nx_ip_name);
#endif
    }
    }
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ram_network_driver_output                       PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function simply sends the packet to the IP instance on the     */
/*    created IP list that matches the physical destination specified in  */
/*    the Ethernet packet.  In a real hardware setting, this routine      */
/*    would simply put the packet out on the wire.                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP protocol block  */
/*    packet_ptr                            Packet pointer                */
/*    device_instance_id                    The interface from which the  */
/*                                            packet was sent.            */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    nx_packet_copy                        Copy a packet                 */
/*    nx_packet_transmit_release            Release a packet              */
/*    _nx_ram_network_driver_receive        RAM driver receive processing */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX IP processing                                                  */
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
void  _nx_ram_network_driver_output(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT device_instance_id)
{

NX_IP     *next_ip;
NX_PACKET *packet_copy;
ULONG      destination_address_msw;
ULONG      destination_address_lsw;
UINT       old_threshold;
UINT       i;

#ifdef NX_DEBUG_PACKET
UCHAR *ptr;
UINT   j;

    ptr =  packet_ptr -> nx_packet_prepend_ptr;
    printf("Ethernet Packet: ");
    for (j = 0; j < 6; j++)
    {
        printf("%02X", *ptr++);
    }
    printf(" ");
    for (j = 0; j < 6; j++)
    {
        printf("%02X", *ptr++);
    }
    printf(" %02X", *ptr++);
    printf("%02X ", *ptr++);

    i = 0;
    for (j = 0; j < (packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE); j++)
    {
        printf("%02X", *ptr++);
        i++;
        if (i > 3)
        {
            i = 0;
            printf(" ");
        }
    }
    printf("\n");


#endif

    /* Pickup the destination IP address from the packet_ptr.  */
    destination_address_msw =  (ULONG)*(packet_ptr -> nx_packet_prepend_ptr);
    destination_address_msw =  (destination_address_msw << 8) | (ULONG)*(packet_ptr -> nx_packet_prepend_ptr + 1);
    destination_address_lsw =  (ULONG)*(packet_ptr -> nx_packet_prepend_ptr + 2);
    destination_address_lsw =  (destination_address_lsw << 8) | (ULONG)*(packet_ptr -> nx_packet_prepend_ptr + 3);
    destination_address_lsw =  (destination_address_lsw << 8) | (ULONG)*(packet_ptr -> nx_packet_prepend_ptr + 4);
    destination_address_lsw =  (destination_address_lsw << 8) | (ULONG)*(packet_ptr -> nx_packet_prepend_ptr + 5);


    /* Disable preemption.  */
    tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

    /* Loop through all instances of created IPs to see who gets the packet.  */
    next_ip =  ip_ptr -> nx_ip_created_next;

    for (i = 0; i < NX_MAX_RAM_INTERFACES; i++)
    {

        /* Skip the interface from which the packet was sent. */
        if (i == device_instance_id)
        {
            continue;
        }

        /* Skip the instance that has not been initialized. */
        if (nx_ram_driver[i].nx_ram_network_driver_in_use == 0)
        {
            continue;
        }


        /* If the destination MAC address is broadcast or the destination matches the interface MAC,
           accept the packet. */
        if (((destination_address_msw == ((ULONG)0x0000FFFF)) && (destination_address_lsw == ((ULONG)0xFFFFFFFF))) ||
            ((destination_address_msw == nx_ram_driver[i].nx_ram_driver_simulated_address_msw) &&
             (destination_address_lsw == nx_ram_driver[i].nx_ram_driver_simulated_address_lsw)))
        {
            /* Make a copy of packet for the forwarding.  */
            if (nx_packet_copy(packet_ptr, &packet_copy, next_ip -> nx_ip_default_packet_pool, NX_NO_WAIT))
            {

                /* Remove the Ethernet header.  */
                packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

                /* Adjust the packet length.  */
                packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

                /* Error, no point in continuing, just release the packet.  */
                nx_packet_transmit_release(packet_ptr);
                return;
            }

            _nx_ram_network_driver_receive(next_ip, packet_copy, i);
        }
    }

    /* Remove the Ethernet header.  In real hardware environments, this is typically
       done after a transmit complete interrupt.  */
    packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

    /* Adjust the packet length.  */
    packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

    /* Now that the Ethernet frame has been removed, release the packet.  */
    nx_packet_transmit_release(packet_ptr);

    /* Restore preemption.  */
    tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_ram_network_driver_receive                      PORTABLE C      */
/*                                                           6.1          */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processing incoming packets.  In the RAM network      */
/*    driver, the incoming packets are coming from the RAM driver output  */
/*    routine.  In real hardware settings, this routine would be called   */
/*    from the receive packet ISR.                                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP protocol block  */
/*    packet_ptr                            Packet pointer                */
/*    device_instance_id                    The device ID the packet is   */
/*                                            destined for                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_packet_receive                 IP receive packet processing  */
/*    _nx_ip_packet_deferred_receive        IP deferred receive packet    */
/*                                            processing                  */
/*    _nx_arp_packet_deferred_receive       ARP receive processing        */
/*    _nx_rarp_packet_deferred_receive      RARP receive processing       */
/*    nx_packet_release                     Packet release                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    NetX IP processing                                                  */
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
void  _nx_ram_network_driver_receive(NX_IP *ip_ptr, NX_PACKET *packet_ptr, UINT device_instance_id)
{

UINT packet_type;

    /* Pickup the packet header to determine where the packet needs to be
       sent.  */
    packet_type =  (((UINT)(*(packet_ptr -> nx_packet_prepend_ptr + 12))) << 8) |
        ((UINT)(*(packet_ptr -> nx_packet_prepend_ptr + 13)));


    /* Setup interface pointer.  */
    packet_ptr -> nx_packet_ip_interface = nx_ram_driver[device_instance_id].nx_ram_driver_interface_ptr;


    /* Route the incoming packet according to its ethernet type.  */
    if (packet_type == NX_ETHERNET_IP)
    {

        /* Note:  The length reported by some Ethernet hardware includes bytes after the packet
           as well as the Ethernet header.  In some cases, the actual packet length after the
           Ethernet header should be derived from the length in the IP header (lower 16 bits of
           the first 32-bit word).  */

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        /* Route to the ip receive function.  */
#ifdef NX_DEBUG_PACKET
        printf("NetX RAM Driver IP Packet Receive - %s\n", ip_ptr -> nx_ip_name);
#endif

#ifdef NX_DIRECT_ISR_CALL
        _nx_ip_packet_receive(ip_ptr, packet_ptr);
#else
        _nx_ip_packet_deferred_receive(ip_ptr, packet_ptr);
#endif
    }
    else if (packet_type == NX_ETHERNET_ARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        /* Route to the ARP receive function.  */
#ifdef NX_DEBUG
        printf("NetX RAM Driver ARP Receive - %s\n", ip_ptr -> nx_ip_name);
#endif
        _nx_arp_packet_deferred_receive(ip_ptr, packet_ptr);
    }
    else if (packet_type == NX_ETHERNET_RARP)
    {

        /* Clean off the Ethernet header.  */
        packet_ptr -> nx_packet_prepend_ptr =  packet_ptr -> nx_packet_prepend_ptr + NX_ETHERNET_SIZE;

        /* Adjust the packet length.  */
        packet_ptr -> nx_packet_length =  packet_ptr -> nx_packet_length - NX_ETHERNET_SIZE;

        /* Route to the RARP receive function.  */
#ifdef NX_DEBUG
        printf("NetX RAM Driver RARP Receive - %s\n", ip_ptr -> nx_ip_name);
#endif
        _nx_rarp_packet_deferred_receive(ip_ptr, packet_ptr);
    }
    else
    {

        /* Invalid ethernet header... release the packet.  */
        nx_packet_release(packet_ptr);
    }
}

