/**
 * @file HSM.c
 * @author Samuel Meyers
 * @brief Production-ready Boot code and main function for the HSM
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). 
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initializes peripherals for system boot.
*/
void init() {
    // Initialize all hardware components via TI SysConfig
    SYSCFG_DL_init();

    // Initialize the flash-based filesystem
    init_fs();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // Initialize the device hardware and filesystem
    init();

    // Process commands forever
    while (1) {
        // LED indicates the HSM is powered and waiting for a command
        STATUS_LED_ON();

        pkt_len = 0;
        // Wait for a packet from the CONTROL_INTERFACE (Host)
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        // Turn LED off during processing to show activity/busy state
        STATUS_LED_OFF();

        if (result != MSG_OK) {
            // Handle communication errors
            switch (result) {
                case MSG_BAD_PTR:
                    print_error("Bad cmd pointer\n");
                    break;
                case MSG_NO_ACK:
                    print_error("Failed to receive ACK from host\n");
                    break;
                case MSG_BAD_LEN:
                    print_error("Received bad length\n");
                    break;
                default:
                    print_error("Failed to receive cmd from host\n");
                    break;
            }
            continue;
        }

        // Handle the requested command via handlers in commands.c
        switch (cmd) {
            case LIST_MSG:
                list(pkt_len, uart_buf);
                break;

            case READ_MSG:
                read(pkt_len, uart_buf);
                break;

            case WRITE_MSG:
                write(pkt_len, uart_buf);
                break;

            case RECEIVE_MSG:
                receive(pkt_len, uart_buf);
                break;

            case INTERROGATE_MSG:
                interrogate(pkt_len, uart_buf);
                break;

            case LISTEN_MSG:
                listen(pkt_len, uart_buf);
                break;

            default:
                // If the command is unrecognized, notify the host explicitly
                write_packet(CONTROL_INTERFACE, ERROR_MSG, "Invalid Command", 15);
                print_error("Invalid Command Received\n");
                break;
        }
    }
}
