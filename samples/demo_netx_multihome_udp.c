/* This is a small demo of the high-performance NetX TCP/IP stack.  This demo concentrates
   on UDP packet sending and receiving - with ARP - using a simulated Ethernet driver in
   a multihome environment.  */



/*
   IP_0 has two simulated phyiscal interfaces.
   The primary interface is 1.2.3.4/255.255.255.0
   the secondary interface is 2.2.3.4/255.255.255.0

   IP_1 has two simulated physical interface.
   The primary interface is 1.2.3.5/255.255.255.0
   the secondary interface is 2.2.3.5/255.255.255.0

   These four simulated interfaces are connected to the same channel.



       ---------   Primary                                  ---------
       |       |  Interface                                 |       |
       | IP_0  |----------------------     |----------------| IP_1  |
       |       |1.2.3.4              |     |       1.2.3.5  |       |
       |       |                     |     |                |       |
       |       |   Secondary         |     |                |       |
       |       |  Interface          |     |                |       |
       |       |-------------------  |     |  --------------|       |
       |       |2.2.3.4           |  |     |  |    2.2.3.5  |       |
       ---------                  |  |     |  |             ---------
                                  |  |     |  |
                                  |  |     |  |
                               ------------------
                               |                |
                               |   Switch Box   |
                               |                |
                               ------------------


 */

#include   "tx_api.h"
#include   "nx_api.h"

#if (NX_MAX_PHYSICAL_INTERFACES > 1)

#define     DEMO_STACK_SIZE 2048
#define     DEMO_DATA       "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
#define     PACKET_SIZE     1536
#define     POOL_SIZE       ((sizeof(NX_PACKET) + PACKET_SIZE) * 16)

/* Define the ThreadX and NetX object control blocks.  */

TX_THREAD               thread_0;
TX_THREAD               thread_1;

NX_PACKET_POOL          pool_0;
NX_IP                   ip_0;
NX_IP                   ip_1;


NX_UDP_SOCKET           socket_0;
NX_UDP_SOCKET           socket_1;


/* Define the counters used in the demo application...  */

ULONG                   thread_0_counter;
ULONG                   thread_1_counter;
ULONG                   error_counter;
UCHAR                   pool_buffer[POOL_SIZE];

/* Define thread prototypes.  */

void thread_0_entry(ULONG thread_input);
void thread_1_entry(ULONG thread_input);
void _nx_ram_network_driver(struct NX_IP_DRIVER_STRUCT *driver_req);


/* Define main entry point.  */

int main()
{

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}


/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{

CHAR *pointer;
UINT  status;


    /* Setup the working pointer.  */
    pointer =  (CHAR *)first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* .  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_buffer, POOL_SIZE);

    /* Check for pool creation error.  */
    if (status)
    {
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFF000UL, &pool_0, _nx_ram_network_driver,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Check for IP create errors.  */
    if (status)
    {
        error_counter++;
    }

    /* Attach the second interface to IP_0. Note that this interface is attached during initialization time.
       Alternatively the second interface may also be attached in thread context, as illustrated below
       in thead_1_entry function. */
    status = nx_ip_interface_attach(&ip_0, "IP_0 Secondary Interface", IP_ADDRESS(2, 2, 3, 4), 0xFFFFFF00, _nx_ram_network_driver);

    if (status)
    {
        error_counter++;
    }

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&ip_0, (void *)pointer, 1024);
    pointer = pointer + 1024;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status +=  nx_arp_enable(&ip_1, (void *)pointer, 1024);
    pointer = pointer + 1024;

    /* Check for ARP enable errors.  */
    if (status)
    {
        error_counter++;
    }

    /* Enable UDP traffic.  */
    status =  nx_udp_enable(&ip_0);
    status += nx_udp_enable(&ip_1);

    /* Check for UDP enable errors.  */
    if (status)
    {
        error_counter++;
    }
}



/* Define the test threads.  */

void    thread_0_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET *my_packet;


    NX_PARAMETER_NOT_USED(thread_input);

    /* Let the IP threads and thread 1 execute.    */
    tx_thread_relinquish();

    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_0, &socket_0, "Socket 0", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_0, 0x88, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Disable checksum logic for this socket.  */
    nx_udp_socket_checksum_disable(&socket_0);

    /* Setup the ARP entry for the UDP send.  */
    nx_arp_dynamic_entry_set(&ip_0, IP_ADDRESS(1, 2, 3, 5), 0, 0);

    /* Let other threads run again.  */
    tx_thread_relinquish();

    while (1)
    {


        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_UDP_PACKET, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            break;
        }

        /* Write ABCs into the packet payload!  */
        memcpy(my_packet -> nx_packet_prepend_ptr, DEMO_DATA, sizeof(DEMO_DATA));

        /* Adjust the write pointer.  */
        my_packet -> nx_packet_length =  sizeof(DEMO_DATA);
        my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + sizeof(DEMO_DATA);

        /* Send the UDP packet.  */
        if (thread_0_counter & 1)
        {
            status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(1, 2, 3, 5), 0x89);
        }
        else
        {
            status =  nx_udp_socket_send(&socket_0, my_packet, IP_ADDRESS(2, 2, 3, 5), 0x89);
        }

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            error_counter++;
            break;
        }

        /* Increment thread 0's counter.  */
        thread_0_counter++;

        /* Relinquish to thread 1.  */
        tx_thread_relinquish();
    }
}


void    thread_1_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET *my_packet;

    NX_PARAMETER_NOT_USED(thread_input);

    /*
       Attch the second interface to IP_1.  Note that this interface is attached in thread context.
       Alternatively the second interface may also be attached during system initilization, as illustrated
       above in tx_application_define.
     */

    /* Attach the 2nd interface to IP_1 */
    status = nx_ip_interface_attach(&ip_1, "IP_1 Secondary Interface", IP_ADDRESS(2, 2, 3, 5), 0xFFFFFF00, _nx_ram_network_driver);

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }


    /* Create a UDP socket.  */
    status = nx_udp_socket_create(&ip_1, &socket_1, "Socket 1", NX_IP_NORMAL, NX_FRAGMENT_OKAY, 0x80, 5);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Bind the UDP socket to the IP port.  */
    status =  nx_udp_socket_bind(&socket_1, 0x89, TX_WAIT_FOREVER);

    /* Check status.  */
    if (status)
    {
        error_counter++;
        return;
    }

    while (1)
    {


        /* Receive a UDP packet.  */
        status =  nx_udp_socket_receive(&socket_1, &my_packet, TX_WAIT_FOREVER);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            break;
        }

        /* Release the packet.  */
        status =  nx_packet_release(my_packet);

        /* Check status.  */
        if (status != NX_SUCCESS)
        {
            break;
        }

        /* Increment thread 1's counter.  */
        thread_1_counter++;
    }
}


#endif

