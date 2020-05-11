/* This is a small demo of TFTP on the high-performance NetX TCP/IP stack.  This demo 
   relies on ThreadX and NetX , to show a simple file transfer from the client 
   and then back to the server.  */
                 
/* Indicate if using a NetX TFTP services. To port a NetX TFTP application to NetX TFTP
   undefine this term.  */


#include    "tx_api.h"
#include    "nx_api.h"
#include    "nx_tftp_client.h"
#include    "nx_tftp_server.h"
#ifndef     NX_TFTP_NO_FILEX
#include    "fx_api.h"
#endif


#define     DEMO_STACK_SIZE         4096
#define     DEMO_DATA               "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

/* To use another file storage utility define this symbol: 
#define NX_TFTP_NO_FILEX
*/

/* Define the ThreadX, NetX, and FileX object control blocks...  */

TX_THREAD               server_thread;
TX_THREAD               client_thread;
NX_PACKET_POOL          server_pool;
NX_IP                   server_ip;
NX_PACKET_POOL          client_pool;
NX_IP                   client_ip;
FX_MEDIA                ram_disk;

/* Define the NetX TFTP object control blocks.  */

NX_TFTP_CLIENT          client;
NX_TFTP_SERVER          server;

/* Define the application global variables */

#define                 CLIENT_ADDRESS  IP_ADDRESS(1, 2, 3, 5)
#define                 SERVER_ADDRESS  IP_ADDRESS(1, 2, 3, 4)
          

UINT                    error_counter = 0;

/* Define buffer used in the demo application.  */
UCHAR                   buffer[255];
ULONG                   data_length;


/* Define the memory area for the FileX RAM disk.  */
#ifndef NX_TFTP_NO_FILEX
UCHAR                   ram_disk_memory[32000];
UCHAR                   ram_disk_sector_cache[512];
#endif


/* Define function prototypes.  */

VOID    _fx_ram_driver(FX_MEDIA *media_ptr);
VOID    _nx_ram_network_driver(NX_IP_DRIVER *driver_req_ptr);
void    client_thread_entry(ULONG thread_input);
void    server_thread_entry(ULONG thread_input);


/* Define main entry point.  */

int main()
{

    /* Enter the ThreadX kernel.  */
    tx_kernel_enter();
}


/* Define what the initial system looks like.  */

void    tx_application_define(void *first_unused_memory)
{

UINT    status;
UCHAR   *pointer;

    
    /* Setup the working pointer.  */
    pointer =  (UCHAR *) first_unused_memory;


    /* Create the main TFTP server thread.  */
    status = tx_thread_create(&server_thread, "TFTP Server Thread", server_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              4,4, TX_NO_TIME_SLICE, TX_AUTO_START);

    pointer += DEMO_STACK_SIZE ;

    /* Check for errors.  */
    if (status)
        error_counter++;


    /* Create the main TFTP client thread at a slightly lower priority.  */
    status = tx_thread_create(&client_thread, "TFTP Client Thread", client_thread_entry, 0,  
                              pointer, DEMO_STACK_SIZE, 
                              5, 5, TX_NO_TIME_SLICE, TX_DONT_START);

    pointer += DEMO_STACK_SIZE ;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Initialize the NetX system.  */
    nx_system_initialize();

    /* Note: The data portion of a packet is exactly 512 bytes, but the packet payload size must 
       be at least 580 bytes. The remaining bytes are used for the UDP, IP, and Ethernet 
       headers and byte alignment requirements. */

    status =  nx_packet_pool_create(&server_pool, "TFTP Server Packet Pool", NX_TFTP_PACKET_SIZE, pointer, 8192);
    pointer = pointer + 8192;
    
    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Create the IP instance for the TFTP Server.  */
    status = nx_ip_create(&server_ip, "NetX Server IP Instance", SERVER_ADDRESS, 0xFFFFFF00UL, 
                                        &server_pool, _nx_ram_network_driver, pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable ARP and supply ARP cache memory for IP Instance 0.  */
    status =  nx_arp_enable(&server_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Check for errors.  */
    if (status)
        error_counter++;

    /* Enable UDP.  */
    status =  nx_udp_enable(&server_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;


    /* Create the TFTP server.  */
    status =  nx_tftp_server_create(&server, "TFTP Server Instance", &server_ip, &ram_disk, 
                                      pointer, DEMO_STACK_SIZE, &server_pool);

    pointer =  pointer + DEMO_STACK_SIZE;

    /* Check for errors for the server.  */
    if (status)
        error_counter++;

    /* Create a packet pool for the TFTP client.  */

    /* Note: The data portion of a packet is exactly 512 bytes, but the packet payload size must 
       be at least 580 bytes. The remaining bytes are used for the UDP, IP, and Ethernet 
       headers and byte alignment requirements. */

    status =  nx_packet_pool_create(&client_pool, "TFTP Client Packet Pool", NX_TFTP_PACKET_SIZE, pointer, 8192);
    pointer =  pointer + 8192;

    /* Create an IP instance for the TFTP client.  */
    status = nx_ip_create(&client_ip, "TFTP Client IP Instance", CLIENT_ADDRESS, 0xFFFFFF00UL, 
                                                &client_pool, _nx_ram_network_driver, pointer, 2048, 1);
    pointer = pointer + 2048;

    /* Enable ARP and supply ARP cache memory for IP Instance 1.  */
    status =  nx_arp_enable(&client_ip, (void *) pointer, 1024);
    pointer = pointer + 1024;

    /* Enable UDP for client IP instance.  */
    status =  nx_udp_enable(&client_ip);

    /* Check for errors.  */
    if (status)
        error_counter++;

    tx_thread_resume(&client_thread);
}

void server_thread_entry(ULONG thread_input)
{

UINT        status, running;  

    NX_PARAMETER_NOT_USED(thread_input);

    /* Allow time for the network driver and NetX to get initialized. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);

#ifndef  NX_TFTP_NO_FILEX

    /* Format the RAM disk - the memory for the RAM disk was defined above.  */
    status = fx_media_format(&ram_disk, 
                            _fx_ram_driver,                  /* Driver entry             */
                            ram_disk_memory,                 /* RAM disk memory pointer  */
                            ram_disk_sector_cache,           /* Media buffer pointer     */
                            sizeof(ram_disk_sector_cache),   /* Media buffer size        */
                            "MY_RAM_DISK",                   /* Volume Name              */
                            1,                               /* Number of FATs           */
                            32,                              /* Directory Entries        */
                            0,                               /* Hidden sectors           */
                            256,                             /* Total sectors            */
                            128,                             /* Sector size              */
                            1,                               /* Sectors per cluster      */
                            1,                               /* Heads                    */
                            1);                              /* Sectors per track        */

    /* Check for errors.  */
    if (status != FX_SUCCESS)
    {
        return;
    }

    /* Open the RAM disk.  */
    status = fx_media_open(&ram_disk, "RAM DISK", _fx_ram_driver, ram_disk_memory, ram_disk_sector_cache, sizeof(ram_disk_sector_cache));

    /* Check for errors.  */
    if (status != FX_SUCCESS)
    {
        return;
    }

#endif /*  NX_TFTP_NO_FILEX */
               

    /* Start the NetX TFTP server.  */ 
    status =  nx_tftp_server_start(&server);

    /* Check for errors.  */
    if (status)
    {
        error_counter++;
        return;
    }

    /* Run for a while */
    running = NX_TRUE;
    while(running)
        tx_thread_sleep(NX_IP_PERIODIC_RATE);

    nx_tftp_server_delete(&server);

    /* Flush the media of changed file data, close all open files and ensure
       directory information is also written out to the media.*/
    status = fx_media_close(&ram_disk);
    if (status)
        error_counter++;

    return;
}

/* Define the TFTP client thread.  */

void    client_thread_entry(ULONG thread_input)
{

NX_PACKET   *my_packet;
UINT        status;
UINT        all_done = NX_FALSE;    

    NX_PARAMETER_NOT_USED(thread_input);

    /* Allow time for the network driver and NetX to get initialized. */
    tx_thread_sleep(NX_IP_PERIODIC_RATE);
    


    /* The TFTP services used below include the NetX equivalent service which will work with 
       NetX TFTP.  
    */

    /* Create a TFTP client.  */ 
    status =  nx_tftp_client_create(&client, "TFTP Client", &client_ip, &client_pool);

    /* Check status.  */
    if (status)
        return;

    /* Open a TFTP file for writing.  */
    status =  nx_tftp_client_file_open(&client, "test.txt", SERVER_ADDRESS, NX_TFTP_OPEN_FOR_WRITE, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        return;

    /* Allocate a TFTP packet.  */
    status =  nx_tftp_client_packet_allocate(&client_pool, &my_packet, NX_IP_PERIODIC_RATE);
    /* Check status.  */
    if (status)
        error_counter++;

    /* Write ABCs into the packet payload!  */
    memcpy(my_packet -> nx_packet_prepend_ptr, DEMO_DATA, sizeof(DEMO_DATA));

    /* Adjust the write pointer.  */
    my_packet -> nx_packet_length =  sizeof(DEMO_DATA);
    my_packet -> nx_packet_append_ptr =  my_packet -> nx_packet_prepend_ptr + sizeof(DEMO_DATA);

    /* Write this packet to the file via TFTP.  */  
    status =  nx_tftp_client_file_write(&client, my_packet, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Close this file.  */ 
    status =  nx_tftp_client_file_close(&client);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Open the same file for reading.  */   
    status =  nx_tftp_client_file_open(&client, "test.txt", SERVER_ADDRESS, NX_TFTP_OPEN_FOR_READ, NX_IP_PERIODIC_RATE);

    /* Check status.  */
    if (status)
        error_counter++;
    do
    {

    /* Read the file back.  */   
        status =  nx_tftp_client_file_read(&client, &my_packet, NX_IP_PERIODIC_RATE);
        /* Check for retranmission/dropped packet error. Benign. Try again... */
        if (status == NX_TFTP_INVALID_BLOCK_NUMBER)
        {

            continue;
        }
        else if (status == NX_TFTP_END_OF_FILE)
        {

            /* All done. */
            all_done = NX_TRUE;
        }
        else if (status != NX_SUCCESS)
        {

            /* Internal error, invalid packet or error on read. */
            break;
        }


        /* Do something with the packet data and release when done. */
        nx_packet_data_retrieve(my_packet, buffer, &data_length);
        buffer[data_length] = 0;
        printf("Receive data: %s\n", buffer);

        printf("release packet in demo.\n");

        nx_packet_release(my_packet);

    } while (all_done == NX_FALSE);

    /* Close the file again.  */   
    status =  nx_tftp_client_file_close(&client);

    /* Check status.  */
    if (status)
        error_counter++;

    /* Delete the client.  */ 
    status =  nx_tftp_client_delete(&client);

    /* Check status.  */
    if (status)
        error_counter++;

    return;
}
