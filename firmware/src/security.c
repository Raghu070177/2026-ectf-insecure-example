/**
 * @file security.c
 * @brief Security implementation
 */

#include "security.h"
#include "host_messaging.h"
#include "simple_crypto.h"
#include <string.h>

// Add this definition - make it non-static so it can be used by other files
const group_permission_t global_permissions[MAX_PERMS] = {
    {.group_id = 1, .read = true, .write = true, .receive = true},   // Admin group - full access
    {.group_id = 2, .read = true, .write = false, .receive = true},  // Reader group - read only
    {.group_id = 3, .read = false, .write = false, .receive = false}, // Restricted group - no access
    // Add more groups as needed
};

// Forward declaration
int hash(void *data, size_t len, uint8_t *hash_out);

bool secure_compare(const uint8_t *a, const uint8_t *b, uint32_t len) {
    uint8_t result = 0;
    for (uint32_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

bool check_pin(unsigned char *pin) {
    if (pin == NULL) return false;
    
    // This hash should match your PIN
    // You can calculate this by running hash() on your PIN
    // For PIN "123456", the hash would be calculated
    static const uint8_t stored_pin_hash[16] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    uint8_t input_hash[16];
    if (hash(pin, strlen((char*)pin), input_hash) != 0) return false;
    return secure_compare(input_hash, stored_pin_hash, 16);
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    for (int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            switch (perm) {
                case PERM_READ:
                    return global_permissions[i].read;
                case PERM_WRITE:
                    return global_permissions[i].write;
                case PERM_RECEIVE:
                    return global_permissions[i].receive;
                default:
                    return false;
            }
        }
    }
    return false;  // Group not found - deny access
}
