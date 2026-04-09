/**
 * @file security.c
 * @brief Security implementation
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "security.h"
#include "secrets.h"
#include "host_messaging.h"
#include "simple_crypto.h"
#include <string.h>

/**
 * global_permissions defines which groups this HSM has permissions for.
 * Defined as const so it matches the 'extern const' declaration in security.h.
 * The build system generates secrets.h with the actual permission values.
 * These are placeholder values - the real values come from generate_secrets.
 */
const group_permission_t global_permissions[MAX_PERMS] = {
    {.group_id = 0, .read = false, .write = false, .receive = false},
    {.group_id = 0, .read = false, .write = false, .receive = false},
    {.group_id = 0, .read = false, .write = false, .receive = false},
    {.group_id = 0, .read = false, .write = false, .receive = false},
    {.group_id = 0, .read = false, .write = false, .receive = false},
    {.group_id = 0, .read = false, .write = false, .receive = false},
    {.group_id = 0, .read = false, .write = false, .receive = false},
    {.group_id = 0, .read = false, .write = false, .receive = false},
};

/**
 * @brief Constant-time comparison to prevent timing attacks.
 *        Compares two byte arrays of length `len`.
 *        Returns true only if all bytes match.
 */
static bool secure_compare(const uint8_t *a, const uint8_t *b, uint32_t len) {
    uint8_t result = 0;
    for (uint32_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/**
 * @brief Validate a pin against the stored PIN hash.
 *        Hashes the input PIN and compares it against PIN_HASH
 *        using constant-time comparison.
 *
 * @param pin Pointer to the input PIN bytes.
 * @return true if PIN matches, false otherwise.
 */
bool check_pin(unsigned char *pin) {
    if (pin == NULL) return false;

    uint8_t input_hash[HASH_SIZE];
    memset(input_hash, 0, sizeof(input_hash));

    if (hash(pin, PIN_LENGTH, input_hash) != 0) return false;

    return secure_compare(input_hash, PIN_HASH, HASH_SIZE);
}

/**
 * @brief Validate that this HSM has the requested permission for a group.
 *
 * @param group_id The group ID to check.
 * @param perm The permission type to check.
 * @return true if permission granted, false otherwise.
 */
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
