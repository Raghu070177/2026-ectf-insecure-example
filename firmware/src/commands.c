/**
 * @file commands.c
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "secrets.h"
#include <string.h>

void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);
            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name);
            file_list->n_files++;
        }
    }
}

int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;
    if (!check_pin(command->pin)) { print_error("Invalid pin"); return -1; }
    memset(&file_list, 0, sizeof(file_list));
    generate_list_files(&file_list);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, LIST_PKT_LEN(file_list.n_files));
    return 0;
}

int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;
    if (!check_pin(command->pin)) { print_error("Invalid pin"); return -1; }
    memset(&file_info, 0, sizeof(read_response_t));
    if (read_file(command->slot, &curr_file) < 0) { print_error("Failed to read file"); return -1; }
    if (!validate_permission(curr_file.group_id, PERM_READ)) { print_error("Invalid permission - read access denied"); return -1; }
    memcpy(file_info.name, curr_file.name, strlen((char *)curr_file.name));
    if (curr_file.contents_len > 0) memcpy(file_info.contents, curr_file.contents, curr_file.contents_len);
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, MAX_NAME_SIZE + curr_file.contents_len);
    return 0;
}

int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    file_t curr_file;
    if (!check_pin(command->pin)) { print_error("Invalid pin"); return -1; }
    if (!validate_permission(command->group_id, PERM_WRITE)) { print_error("Invalid permission - write access denied"); return -1; }
    create_file(&curr_file, command->group_id, command->name, command->contents_len, command->contents);
    if (write_file(command->slot, &curr_file, command->uuid) < 0) { print_error("Error storing file"); return -1; }
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}

int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_t recv_resp;
    msg_type_t cmd;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) { print_error("Invalid pin"); return -1; }

    memset(&recv_resp, 0, sizeof(recv_resp));
    memset(&request, 0, sizeof(request));
    request.slot = command->read_slot;
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));

    len_recv_msg = 0xffff;
    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);

    // If other HSM denied or returned error, print_error sends ONE error packet on CONTROL
    // print_error is a macro for write_packet(CONTROL_INTERFACE, ERROR_MSG, ...) — DO NOT add another
    if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}

int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    if (!check_pin(command->pin)) { print_error("Invalid pin"); return -1; }

    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);
    len_recv_msg = 0xffff;
    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);

    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}

int listen(uint16_t pkt_len, uint8_t *buf) {
    uint8_t uart_buf[sizeof(receive_request_t)];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;
    list_response_t file_list;
    receive_request_t *command;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;

    read_length = sizeof(uart_buf);
    memset(uart_buf, 0, sizeof(uart_buf));
    read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length);

    switch (cmd) {
        case INTERROGATE_MSG:
            memset(&file_list, 0, sizeof(file_list));
            generate_list_files(&file_list);
            write_length = LIST_PKT_LEN(file_list.n_files);
            write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);
            break;

        case RECEIVE_MSG:
            command = (receive_request_t *)uart_buf;

            metadata = get_file_metadata(command->slot);
            if (metadata == NULL) {
                // Send error on TRANSFER so requester doesn't hang, then LISTEN_MSG so host knows we're done
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Getting metadata failed", 22);
                print_error("Getting metadata failed");
                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                return -1;
            }

            if (read_file(command->slot, &recv_resp.file) < 0) {
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Failed to read file", 19);
                print_error("Failed to read file");
                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                return -1;
            }

            // Check requester has RECEIVE permission for this file's group
            {
                bool requester_has_permission = false;
                for (int i = 0; i < MAX_PERMS; i++) {
                    if (command->permissions[i].group_id == recv_resp.file.group_id
                        && command->permissions[i].receive) {
                        requester_has_permission = true;
                        break;
                    }
                }
                if (!requester_has_permission) {
                    write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Could not import file", 21);
                    print_error("Requester lacks receive permission");
                    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                    return -1;
                }
            }

            memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);
            // Send only actual data: UUID + file header + actual contents (not full 8KB struct)
            write_length = UUID_SIZE + FILE_TOTAL_SIZE(recv_resp.file.contents_len);
            write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);
            break;

        default:
            print_error("Bad message type");
            write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
            return -1;
    }

    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}
