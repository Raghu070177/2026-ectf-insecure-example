/**
 * @file security.c
 * @brief Security implementation
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "security.h"
#include "secrets.h"
#include <string.h>

// Provide a default definition of global_permissions for linking.
// The build system MAY provide its own definition in secrets.h.
// If secrets.h provides a definition, this weak symbol will be overridden.
// This ensures the symbol is always defined for the linker.
__attribute__((weak)) 
const group_permission_t global_permissions[MAX_PERMS] = {0};

/**
 * @brief Constant-time comparison to prevent timing attacks.
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
 * @brief Validate a pin against the HSM_PIN from secrets.h.
 *        Uses constant-time comparison to prevent timing attacks.
 *
 * @param pin Pointer to the input PIN bytes (6 bytes).
 * @return true if PIN matches, false otherwise.
 */
bool check_pin(unsigned char *pin) {
    if (pin == NULL) return false;

    // HSM_PIN is a string macro injected by the build system into secrets.h
    // e.g. #define HSM_PIN "4a95ee"
    return secure_compare(pin, (const uint8_t *)HSM_PIN, PIN_LENGTH);
}

/**
 * @brief Validate that this HSM has the requested permission for a group.
 *        Uses global_permissions defined in secrets.h.
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
