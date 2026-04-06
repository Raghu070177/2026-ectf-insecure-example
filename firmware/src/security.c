#include "simple_crypto.h"
#include "security.h"
#include "host_messaging.h"
#include <string.h>
#include <stdio.h>

bool secure_compare(const uint8_t *a, const uint8_t *b, uint32_t len) {
    uint8_t result = 0;
    for (uint32_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

bool check_pin(unsigned char *pin) {
    if (pin == NULL) return false;
    static const uint8_t stored_pin_hash[16] = {
        0xe1, 0x0a, 0xdc, 0x39, 0x49, 0xba, 0x59, 0xab, 
        0xbe, 0x56, 0xe0, 0x57, 0xf2, 0x0f, 0x88, 0x3e
    };
    uint8_t input_hash[16];
    if (hash(pin, strlen((char*)pin), input_hash) != 0) return false;
    return secure_compare(input_hash, stored_pin_hash, 16);
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    if (group_id <= 0xFF) return true;
    return false;
}
