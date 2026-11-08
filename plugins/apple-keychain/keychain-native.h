#ifndef HERMES_KEYCHAIN_NATIVE_H
#define HERMES_KEYCHAIN_NATIVE_H

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <sys/types.h>
#include <stddef.h>

#define MAX_SECRET (1024U * 1024U)
#define RECOVERY_PREFIX "com.hermes.apple-keychain.recovery.v1."

extern SecKeychainRef target_keychain;
extern char recovery_id[37];

_Noreturn void fail(const char *kind);
void check(OSStatus status);
void hash_piece(CC_SHA256_CTX *ctx, const void *data, size_t n);
void hash_finish(CC_SHA256_CTX *ctx, char out[65]);
int keychain_lock_file(const char *path, uid_t owner, uid_t caller);

SecKeychainItemRef find_item(SecKeychainRef keychain, const char *service, const char *account);
void get_value(SecKeychainItemRef item, UInt32 *length, void **data);
int same_value(SecKeychainItemRef item, const void *data, UInt32 length);
int same_access(SecAccessRef a, SecAccessRef b);
SecAccessRef copy_access(SecKeychainItemRef item);
SecKeychainItemRef create_item(const char *service, const char *account, const void *data,
                               UInt32 length, SecAccessRef access);
SecAccessRef new_access(int allow_any);

void recovery_service(const char *service, const char *account, char *out, size_t cap);
int scan_recoveries(const char *service, int print_items, const char *except_pending_id);
SecKeychainItemRef recovery_item(const char *service, const char *id, int *is_pending);
void do_write(const char *service, const char *account, const char *recovery_service_name,
              int allow_any, int keep_backup, int expected);
void do_restore(const char *service, const char *account, const char *recovery_service_name,
                const char *id);

#endif
