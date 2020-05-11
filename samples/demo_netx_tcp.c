/* This is a small demo of the high-performance NetX TCP/IP stack.  This demo concentrates
   on TCP connection, disconnection, sending, and receiving using ARP and a simulated
   Ethernet driver.  */

#include   "tx_api.h"
#include   "nx_api.h"

#define     DEMO_STACK_SIZE 2048
#define     DEMO_DATA       "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
#define     PACKET_SIZE     1536
#define     POOL_SIZE       ((sizeof(NX_PACKET) + PACKET_SIZE) * 16)


/* Define the ThreadX and NetX object control blocks...  */

TX_THREAD               thread_0;
TX_THREAD               thread_1;

NX_PACKET_POOL          pool_0;
NX_IP                   ip_0;
NX_IP                   ip_1;
NX_TCP_SOCKET           client_socket;
NX_TCP_SOCKET           server_socket;
UCHAR                   pool_buffer[POOL_SIZE];



/* Define the counters used in the demo application...  */

ULONG                   thread_0_counter;
ULONG                   thread_1_counter;
ULONG                   error_counter;


/* Define thread prototypes.  */

void thread_0_entry(ULONG thread_input);
void thread_1_entry(ULONG thread_input);
void thread_1_connect_received(NX_TCP_SOCKET *server_socket, UINT port);
void thread_1_disconnect_received(NX_TCP_SOCKET *server_socket);

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

    /* Create the main thread.  */
    tx_thread_create(&thread_1, "thread 1", thread_1_entry, 0,
                     pointer, DEMO_STACK_SIZE,
                     3, 3, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer =  pointer + DEMO_STACK_SIZE;


    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Create a packet pool.  */
    status =  nx_packet_pool_create(&pool_0, "NetX Main Packet Pool", PACKET_SIZE, pool_buffer, POOL_SIZE);

    if (status)
    {
        error_counter++;
    }

    /* Create an IP instance.  */
    status = nx_ip_create(&ip_0, "NetX IP Instance 0", IP_ADDRESS(1, 2, 3, 4), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                          pointer, 2048, 1);
    pointer =  pointer + 2048;

    /* Create another IP instance.  */
    status += nx_ip_create(&ip_1, "NetX IP Instance 1", IP_ADDRESS(1, 2, 3, 5), 0xFFFFFF00UL, &pool_0, _nx_ram_network_driver,
                           pointer, 2048, 1);
    pointer =  pointer + 2048;

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

    /* Check ARP enable status.  */
    if (status)
    {
        error_counter++;
    }

    /* Enable TCP processing for both IP instances.  */
    status =  nx_tcp_enable(&ip_0);
    status += nx_tcp_enable(&ip_1);

    /* Check TCP enable status.  */
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
ULONG      length;

    NX_PARAMETER_NOT_USED(thread_input);

    /* Loop to repeat things over and over again!  */
    while (1)
    {

        /* Increment thread 0's counter.  */
        thread_0_counter++;

        /* Create a socket.  */
        status =  nx_tcp_socket_create(&ip_0, &client_socket, "Client Socket",
                                       NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 200,
                                       NX_NULL, NX_NULL);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }

        /* Bind the socket.  */
        status =  nx_tcp_client_socket_bind(&client_socket, 12, NX_WAIT_FOREVER);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }

        /* Attempt to connect the socket.  */
        status =  nx_tcp_client_socket_connect(&client_socket, IP_ADDRESS(1, 2, 3, 5), 12, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }

        /* Allocate a packet.  */
        status =  nx_packet_allocate(&pool_0, &my_packet, NX_TCP_PACKET, NX_WAIT_FOREVER);

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

        status =  nx_packet_length_get(my_packet, &length);
        if ((status) || (length != sizeof(DEMO_DATA)))
        {
            error_counter++;
        }

        /* Send the packet out!  */
        status =  nx_tcp_socket_send(&client_socket, my_packet, NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
        {
            error_counter++;
            nx_packet_release(my_packet);
        }

        /* Disconnect this socket.  */
        status =  nx_tcp_socket_disconnect(&client_socket, NX_IP_PERIODIC_RATE);

        /* Determine if the status is valid.  */
        if (status)
        {
            error_counter++;
        }

        /* Unbind the socket.  */
        status =  nx_tcp_client_socket_unbind(&client_socket);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }

        /* Delete the socket.  */
        status =  nx_tcp_socket_delete(&client_socket);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
    }
}


void    thread_1_entry(ULONG thread_input)
{

UINT       status;
NX_PACKET *packet_ptr;
ULONG      actual_status;

    NX_PARAMETER_NOT_USED(thread_input);

    /* Ensure the IP instance has been initialized.  */
    status =  nx_ip_status_check(&ip_1, NX_IP_INITIALIZE_DONE, &actual_status, NX_IP_PERIODIC_RATE);

    /* Check status...  */
    if (status != NX_SUCCESS)
    {

        error_counter++;
        return;
    }

    /* Create a socket.  */
    status =  nx_tcp_socket_create(&ip_1, &server_socket, "Server Socket",
                                   NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE, 100,
                                   NX_NULL, thread_1_disconnect_received);

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }

    /* Setup this thread to listen.  */
    status =  nx_tcp_server_socket_listen(&ip_1, 12, &server_socket, 5, thread_1_connect_received);

    /* Check for error.  */
    if (status)
    {
        error_counter++;
    }

    /* Loop to create and establish server connections.  */
    while (1)
    {

        /* Increment thread 1's counter.  */
        thread_1_counter++;

        /* Accept a client socket connection.  */
        status =  nx_tcp_server_socket_accept(&server_socket, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }

        /* Receive a TCP message from the socket.  */
        status =  nx_tcp_socket_receive(&server_socket, &packet_ptr, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
        else
        {
            /* Release the packet.  */
            nx_packet_release(packet_ptr);
        }

        /* Disconnect the server socket.  */
        status =  nx_tcp_socket_disconnect(&server_socket, NX_IP_PERIODIC_RATE);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }

        /* Unaccept the server socket.  */
        status =  nx_tcp_server_socket_unaccept(&server_socket);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }

        /* Setup server socket for listening again.  */
        status =  nx_tcp_server_socket_relisten(&ip_1, 12, &server_socket);

        /* Check for error.  */
        if (status)
        {
            error_counter++;
        }
    }
}


void  thread_1_connect_received(NX_TCP_SOCKET *socket_ptr, UINT port)
{

    /* Check for the proper socket and port.  */
    if ((socket_ptr != &server_socket) || (port != 12))
    {
        error_counter++;
    }
}


void  thread_1_disconnect_received(NX_TCP_SOCKET *socket)
{

    /* Check for proper disconnected socket.  */
    if (socket != &server_socket)
    {
        error_counter++;
    }
}

