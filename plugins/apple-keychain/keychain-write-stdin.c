/* macOS file-keychain helper. Values travel only through pipes, never argv. */
#define _DARWIN_C_SOURCE
#include "keychain-native.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

SecKeychainRef target_keychain;
char recovery_id[37];

_Noreturn void fail(const char *kind) {
    fprintf(stderr, "ERR %s", kind);
    if (recovery_id[0]) fprintf(stderr, " %s", recovery_id);
    fputc('\n', stderr);
    exit(1);
}

void check(OSStatus status) {
    if (status == errSecSuccess) return;
    if (status == errSecItemNotFound) fail("missing");
    if (status == errSecInteractionNotAllowed || status == errSecAuthFailed ||
        status == errSecUserCanceled || status == errSecACLNotSimple) {
        SecKeychainStatus state = 0;
        if (target_keychain && SecKeychainGetStatus(target_keychain, &state) == errSecSuccess &&
            !(state & kSecUnlockStateStatus)) fail("locked");
        fail("denied");
    }
    fail("failure");
}

void hash_piece(CC_SHA256_CTX *ctx, const void *data, size_t n) {
    uint64_t length = n;
    CC_SHA256_Update(ctx, &length, sizeof(length));
    CC_SHA256_Update(ctx, data, (CC_LONG)n);
}

void hash_finish(CC_SHA256_CTX *ctx, char out[65]) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, ctx);
    for (size_t i = 0; i < sizeof(digest); ++i) sprintf(out + i * 2, "%02x", digest[i]);
    out[64] = '\0';
}

/* Keep a stable inode for each lock; never unlink it while other processes may hold it. */
int keychain_lock_file(const char *path, uid_t owner, uid_t caller) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) {
        /* A foreign user must not create a lock that the keychain owner would reject. */
        if (caller != 0 && caller != owner) fail("failure");
        fd = open(path, O_RDONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
        if (fd >= 0) {
            if (fchmod(fd, 0644) != 0) fail("failure");
        } else if (errno == EEXIST) {
            fd = open(path, O_RDONLY | O_NOFOLLOW);
        }
    }
    struct stat info;
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_nlink != 1 || (info.st_uid != 0 && info.st_uid != owner) ||
        (info.st_mode & 022) != 0 || flock(fd, LOCK_EX) != 0) fail("failure");
    return fd;
}

/* macOS replaces Keychain database inodes during writes; lock the canonical path. */
static int item_lock(const char *service, const char *account, char identity[65]) {
    char path[PATH_MAX], canonical[PATH_MAX], lock_path[PATH_MAX], digest[65];
    UInt32 path_len = sizeof(path);
    struct stat keychain_stat, tmp_stat;
    check(SecKeychainGetPath(target_keychain, &path_len, path));
    if (!realpath(path, canonical) || stat(canonical, &keychain_stat) != 0 ||
        keychain_stat.st_nlink != 1 || stat("/private/tmp", &tmp_stat) != 0 ||
        !S_ISDIR(tmp_stat.st_mode) || tmp_stat.st_uid != 0 || !(tmp_stat.st_mode & S_ISVTX)) fail("failure");
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    hash_piece(&ctx, canonical, strlen(canonical));
    hash_finish(&ctx, identity);
    CC_SHA256_Init(&ctx);
    hash_piece(&ctx, canonical, strlen(canonical));
    hash_piece(&ctx, service, strlen(service));
    hash_piece(&ctx, account, strlen(account));
    hash_finish(&ctx, digest);
    if (snprintf(lock_path, sizeof(lock_path), "/private/tmp/hermes-apple-keychain-%s.lock", digest) >= (int)sizeof(lock_path)) fail("failure");
    return keychain_lock_file(lock_path, keychain_stat.st_uid, geteuid());
}

int main(int argc, char **argv) {
    if (argc < 5) fail("invalid");
    const char *command = argv[1], *path = argv[2], *service = argv[3], *account = argv[4];
    if (!*service || !*account) fail("invalid");
    check(SecKeychainSetUserInteractionAllowed(false));
    if (*path) check(SecKeychainOpen(path, &target_keychain));
    else if (strcmp(command, "read") != 0) fail("invalid");
    if (strcmp(command, "read") == 0) {
        SecKeychainItemRef item = find_item(target_keychain, service, account);
        if (!item) fail("missing");
        UInt32 length = 0;
        void *data = NULL;
        get_value(item, &length, &data);
        if (length && fwrite(data, 1, length, stdout) != length) fail("failure");
        if (data) SecKeychainItemFreeContent(NULL, data);
        CFRelease(item);
        return 0;
    }
    char identity[65];
    int lock_fd = item_lock(service, account, identity);
    char backup_service[sizeof(RECOVERY_PREFIX) + 65];
    recovery_service(service, account, backup_service, sizeof(backup_service));
    if (strcmp(command, "probe") == 0 || strcmp(command, "list") == 0) {
        if (strcmp(command, "probe") == 0) {
            SecKeychainItemRef item = find_item(target_keychain, service, account);
            if (item) {
                UInt32 length = 0;
                void *data = NULL;
                get_value(item, &length, &data);
                if (data) SecKeychainItemFreeContent(NULL, data);
                CFRelease(item);
                puts("PRESENT");
            } else puts("MISSING");
            printf("IDENTITY %s\n", identity);
        }
        scan_recoveries(backup_service, 1, NULL);
    } else if (strcmp(command, "write") == 0 && argc == 8) {
        do_write(service, account, backup_service, atoi(argv[5]), atoi(argv[6]), atoi(argv[7]));
    } else if (strcmp(command, "restore") == 0 && argc == 6) {
        do_restore(service, account, backup_service, argv[5]);
    } else if (strcmp(command, "discard") == 0 && argc == 6) {
        int pending = 0;
        SecKeychainItemRef item = recovery_item(backup_service, argv[5], &pending);
        check(SecKeychainItemDelete(item));
        CFRelease(item);
        puts("OK discarded");
    } else fail("invalid");
    close(lock_fd);
    if (target_keychain) CFRelease(target_keychain);
    return 0;
}
