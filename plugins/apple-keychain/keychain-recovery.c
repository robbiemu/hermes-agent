#include "keychain-native.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

void recovery_service(const char *service, const char *account, char *out, size_t cap) {
    CC_SHA256_CTX ctx;
    char digest[65];
    CC_SHA256_Init(&ctx);
    hash_piece(&ctx, service, strlen(service));
    hash_piece(&ctx, account, strlen(account));
    hash_finish(&ctx, digest);
    if (snprintf(out, cap, "%s%s", RECOVERY_PREFIX, digest) >= (int)cap) fail("failure");
}

static int valid_uuid(const char *s) {
    if (strlen(s) != 36) return 0;
    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') return 0;
        } else if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    }
    return 1;
}

static void new_uuid(void) {
    CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
    CFStringRef string = uuid ? CFUUIDCreateString(kCFAllocatorDefault, uuid) : NULL;
    if (!string || !CFStringGetCString(string, recovery_id, sizeof(recovery_id), kCFStringEncodingUTF8)) fail("failure");
    for (size_t i = 0; recovery_id[i]; ++i) {
        if (recovery_id[i] >= 'A' && recovery_id[i] <= 'F') recovery_id[i] += 'a' - 'A';
    }
    CFRelease(string);
    CFRelease(uuid);
}

static char *item_account(SecKeychainItemRef item) {
    SecKeychainAttribute attr = {kSecAccountItemAttr, 0, NULL};
    SecKeychainAttributeList attrs = {1, &attr};
    check(SecKeychainItemCopyContent(item, NULL, &attrs, NULL, NULL));
    char *value = malloc((size_t)attr.length + 1);
    if (!value) fail("failure");
    memcpy(value, attr.data, attr.length);
    value[attr.length] = '\0';
    SecKeychainItemFreeContent(&attrs, NULL);
    return value;
}

/* Scan only our target-specific recovery namespace; malformed entries fail closed. */
int scan_recoveries(const char *service, int print_items, const char *except_pending_id) {
    SecKeychainAttribute attr = {kSecServiceItemAttr, (UInt32)strlen(service), (void *)service};
    SecKeychainAttributeList attrs = {1, &attr};
    SecKeychainSearchRef search = NULL;
    check(SecKeychainSearchCreateFromAttributes(target_keychain, kSecGenericPasswordItemClass, &attrs, &search));
    int pending = 0;
    for (;;) {
        SecKeychainItemRef item = NULL;
        OSStatus status = SecKeychainSearchCopyNext(search, &item);
        if (status == errSecItemNotFound) break;
        check(status);
        char *account = item_account(item);
        const char *state = NULL, *id = NULL;
        if (strncmp(account, "preparing-", 10) == 0) { state = "preparing"; id = account + 10; }
        else if (strncmp(account, "pending-", 8) == 0) { state = "pending"; id = account + 8; }
        else if (strncmp(account, "kept-", 5) == 0) { state = "kept"; id = account + 5; }
        if (!state || !valid_uuid(id)) fail("failure");
        if (print_items) printf("RECOVERY %s %s\n", state, id);
        if (strcmp(state, "preparing") == 0 ||
            (strcmp(state, "pending") == 0 && (!except_pending_id || strcmp(id, except_pending_id) != 0))) {
            if (!pending) pending = strcmp(state, "preparing") == 0 ? 2 : 1;
            if (!recovery_id[0]) memcpy(recovery_id, id, 37);
        }
        free(account);
        CFRelease(item);
    }
    CFRelease(search);
    return pending;
}

SecKeychainItemRef recovery_item(const char *service, const char *id, int *is_pending) {
    if (!valid_uuid(id)) fail("invalid");
    char account[64];
    snprintf(account, sizeof(account), "pending-%s", id);
    SecKeychainItemRef item = find_item(target_keychain, service, account);
    *is_pending = item != NULL;
    if (!item) {
        snprintf(account, sizeof(account), "kept-%s", id);
        item = find_item(target_keychain, service, account);
    }
    if (!item) {
        snprintf(account, sizeof(account), "preparing-%s", id);
        item = find_item(target_keychain, service, account);
        if (item) *is_pending = 2;
    }
    if (!item) fail("missing");
    return item;
}

static void mark_state(SecKeychainItemRef backup, const char *state, const char *id) {
    char account[64];
    snprintf(account, sizeof(account), "%s-%s", state, id);
    SecKeychainAttribute attr = {kSecAccountItemAttr, (UInt32)strlen(account), account};
    SecKeychainAttributeList attrs = {1, &attr};
    check(SecKeychainItemModifyAttributesAndData(backup, &attrs, 0, NULL));
}

static void read_exact(void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    while (length) {
        ssize_t n = read(STDIN_FILENO, cursor, length);
        if (n <= 0) fail("failure");
        cursor += n;
        length -= (size_t)n;
    }
}

static unsigned char *read_input(UInt32 *length) {
    unsigned char header[4];
    read_exact(header, sizeof(header));
    uint32_t n = (uint32_t)header[0] << 24 | (uint32_t)header[1] << 16 |
                 (uint32_t)header[2] << 8 | header[3];
    if (!n || n > MAX_SECRET) fail("invalid");
    unsigned char *data = malloc(n);
    if (!data) fail("failure");
    read_exact(data, n);
    *length = n;
    return data;
}

static SecKeychainItemRef prepare_placeholder(const char *service, SecAccessRef original_access) {
    SecAccessRef input_access = access_for_copy(original_access);
    char account[64];
    snprintf(account, sizeof(account), "preparing-%s", recovery_id);
    unsigned char placeholder = 0;
    SecKeychainItemRef item = create_item(service, account, &placeholder, 1, input_access);
    CFRelease(input_access);
    SecAccessRef access = copy_access(item);
    if (!same_access(original_access, access)) fail("access_mismatch");
    CFRelease(access);
    /* Exercise the same value-update path before placing a secret in the item. */
    placeholder = 1;
    check(SecKeychainItemModifyAttributesAndData(item, NULL, 1, &placeholder));
    access = copy_access(item);
    if (!same_value(item, &placeholder, 1) || !same_access(original_access, access)) fail("access_mismatch");
    CFRelease(access);
    return item;
}

void do_write(const char *service, const char *account, const char *recovery_service_name,
                     int allow_any, int keep_backup, int expected) {
    UInt32 length = 0;
    unsigned char *data = read_input(&length);
    int blocked = scan_recoveries(recovery_service_name, 0, NULL);
    if (blocked) fail(blocked == 2 ? "recovery_preparing" : "recovery_pending");
    SecKeychainItemRef original = find_item(target_keychain, service, account);
    if (expected >= 0 && !!original != expected) fail("conflict");
    if (!original) {
        SecAccessRef access = new_access(allow_any);
        SecKeychainItemRef created = create_item(service, account, data, length, access);
        if (!same_value(created, data, length)) fail("verify");
        puts("OK created");
        CFRelease(created);
        CFRelease(access);
    } else {
        SecAccessRef old_access = copy_access(original);
        new_uuid();
        SecKeychainItemRef backup = prepare_placeholder(recovery_service_name, old_access);
        UInt32 old_length = 0;
        void *old_data = NULL;
        get_value(original, &old_length, &old_data);
        check(SecKeychainItemModifyAttributesAndData(backup, NULL, old_length, old_data));
        SecAccessRef backup_access = copy_access(backup);
        if (!same_value(backup, old_data, old_length) || !same_access(old_access, backup_access)) fail("verify");
        mark_state(backup, "pending", recovery_id);
        SecAccessRef pending_access = copy_access(backup);
        if (!same_access(old_access, pending_access)) fail("verify");
        CFRelease(pending_access);
        printf("RECOVERY %s\n", recovery_id);
        fflush(stdout);
        unsigned char ack = 0;
        read_exact(&ack, 1);
        if (ack != 1) fail("failure");
        check(SecKeychainItemModifyAttributesAndData(original, NULL, length, data));
        if (!same_value(original, data, length)) fail("verify");
        SecAccessRef updated_access = copy_access(original);
        if (!same_access(old_access, updated_access)) fail("verify");
        if (keep_backup) {
            mark_state(backup, "kept", recovery_id);
            SecAccessRef kept_access = copy_access(backup);
            if (!same_value(backup, old_data, old_length) || !same_access(old_access, kept_access)) fail("verify");
            CFRelease(kept_access);
        } else check(SecKeychainItemDelete(backup));
        printf("OK updated %s\n", recovery_id);
        if (old_data) SecKeychainItemFreeContent(NULL, old_data);
        CFRelease(updated_access);
        CFRelease(backup_access);
        CFRelease(old_access);
        CFRelease(backup);
        CFRelease(original);
    }
    wipe(data, length);
    free(data);
}

void do_restore(const char *service, const char *account, const char *recovery_service_name,
                       const char *id) {
    if (!valid_uuid(id)) fail("invalid");
    int blocked = scan_recoveries(recovery_service_name, 0, id);
    if (blocked) fail(blocked == 2 ? "recovery_preparing" : "recovery_pending");
    int pending = 0;
    SecKeychainItemRef backup = recovery_item(recovery_service_name, id, &pending);
    if (pending == 2) fail("recovery_preparing");
    memcpy(recovery_id, id, 37);
    SecKeychainItemRef original = find_item(target_keychain, service, account);
    if (!original) fail("missing");
    SecAccessRef original_access = copy_access(original), backup_access = copy_access(backup);
    if (!same_access(original_access, backup_access)) fail("access_mismatch");
    /* Restores also regenerate the partition; check it with nonsecret data first. */
    new_uuid();
    SecKeychainItemRef probe = prepare_placeholder(recovery_service_name, original_access);
    check(SecKeychainItemDelete(probe));
    CFRelease(probe);
    memcpy(recovery_id, id, 37);
    UInt32 length = 0;
    void *data = NULL;
    get_value(backup, &length, &data);
    check(SecKeychainItemModifyAttributesAndData(original, NULL, length, data));
    if (!same_value(original, data, length)) fail("verify");
    SecAccessRef after = copy_access(original);
    if (!same_access(original_access, after)) fail("verify");
    if (pending) {
        mark_state(backup, "kept", id);
        SecAccessRef kept_access = copy_access(backup);
        if (!same_value(backup, data, length) || !same_access(backup_access, kept_access)) fail("verify");
        CFRelease(kept_access);
    }
    puts("OK restored");
    if (data) SecKeychainItemFreeContent(NULL, data);
    CFRelease(after);
    CFRelease(backup_access);
    CFRelease(original_access);
    CFRelease(original);
    CFRelease(backup);
}

