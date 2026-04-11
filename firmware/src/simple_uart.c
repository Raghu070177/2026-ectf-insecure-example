/**
 * @file simple_uart.c
 * @author Samuel Meyers
 * @brief Simple UART Interface Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_uart.h"

/** @brief Reads the next available character from UART.
 *
 *  @param uart_id The index of UART to use (0 = CONTROL, 1 = TRANSFER)
 *  @return The character read, or negative on error.
 */
int uart_readbyte(int uart_id) {
    UART_Regs *uart;

    if (uart_id == 0) {
        uart = UART_0_INST;
    } else if (uart_id == 1) {
        uart = UART_1_INST;
    } else {
        return -1;
    }

    // Wait until data is available
    while (DL_UART_Main_isRXFIFOEmpty(uart));

    return (int)DL_UART_Main_receiveData(uart);
}

/** @brief Writes a byte to UART.
 *
 *  @param uart_id The index of UART to use (0 = CONTROL, 1 = TRANSFER)
 *  @param data The byte to be written.
 */
void uart_writebyte(int uart_id, uint8_t data) {
    UART_Regs *uart;

    if (uart_id == 0) {
        uart = UART_0_INST;
    } else if (uart_id == 1) {
        uart = UART_1_INST;
    } else {
        return;
    }

    // Wait until TX FIFO has space
    while (DL_UART_Main_isTXFIFOFull(uart));

    DL_UART_Main_transmitData(uart, data);
}
