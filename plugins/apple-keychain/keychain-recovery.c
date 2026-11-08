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
        if (strncmp(account, "pending-", 8) == 0) { state = "pending"; id = account + 8; }
        else if (strncmp(account, "kept-", 5) == 0) { state = "kept"; id = account + 5; }
        if (!state || !valid_uuid(id)) fail("failure");
        if (print_items) printf("RECOVERY %s %s\n", state, id);
        if (strcmp(state, "pending") == 0 && (!except_pending_id || strcmp(id, except_pending_id) != 0)) {
            pending = 1;
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
    if (!item) fail("missing");
    return item;
}

static void mark_kept(SecKeychainItemRef backup, const char *id) {
    char account[64];
    snprintf(account, sizeof(account), "kept-%s", id);
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

void do_write(const char *service, const char *account, const char *recovery_service_name,
                     int allow_any, int keep_backup, int expected) {
    UInt32 length = 0;
    unsigned char *data = read_input(&length);
    if (scan_recoveries(recovery_service_name, 0, NULL)) fail("recovery_pending");
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
        UInt32 old_length = 0;
        void *old_data = NULL;
        get_value(original, &old_length, &old_data);
        SecAccessRef old_access = copy_access(original);
        new_uuid();
        char backup_account[64];
        snprintf(backup_account, sizeof(backup_account), "pending-%s", recovery_id);
        SecKeychainItemRef backup = create_item(recovery_service_name, backup_account, old_data, old_length, old_access);
        SecAccessRef backup_access = copy_access(backup);
        if (!same_value(backup, old_data, old_length) || !same_access(old_access, backup_access)) fail("verify");
        printf("RECOVERY %s\n", recovery_id);
        fflush(stdout);
        unsigned char ack = 0;
        read_exact(&ack, 1);
        if (ack != 1) fail("failure");
        check(SecKeychainItemModifyAttributesAndData(original, NULL, length, data));
        if (!same_value(original, data, length)) fail("verify");
        SecAccessRef updated_access = copy_access(original);
        if (!same_access(old_access, updated_access)) fail("verify");
        if (keep_backup) mark_kept(backup, recovery_id);
        else check(SecKeychainItemDelete(backup));
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
    if (scan_recoveries(recovery_service_name, 0, id)) fail("recovery_pending");
    int pending = 0;
    SecKeychainItemRef backup = recovery_item(recovery_service_name, id, &pending);
    memcpy(recovery_id, id, 37);
    SecKeychainItemRef original = find_item(target_keychain, service, account);
    if (!original) fail("missing");
    SecAccessRef original_access = copy_access(original), backup_access = copy_access(backup);
    if (!same_access(original_access, backup_access)) fail("access_mismatch");
    UInt32 length = 0;
    void *data = NULL;
    get_value(backup, &length, &data);
    check(SecKeychainItemModifyAttributesAndData(original, NULL, length, data));
    if (!same_value(original, data, length)) fail("verify");
    SecAccessRef after = copy_access(original);
    if (!same_access(original_access, after)) fail("verify");
    if (pending) mark_kept(backup, id);
    puts("OK restored");
    if (data) SecKeychainItemFreeContent(NULL, data);
    CFRelease(after);
    CFRelease(backup_access);
    CFRelease(original_access);
    CFRelease(original);
    CFRelease(backup);
}

