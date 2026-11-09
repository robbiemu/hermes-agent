#include "keychain-native.h"
#include <Security/cssmapple.h>
#include <signal.h>
#include <stdlib.h>

OSStatus test_modify(SecKeychainItemRef item, const SecKeychainAttributeList *attrs,
                     UInt32 length, const void *data) {
    static int calls;
    const char *at = getenv("HERMES_TEST_INTERRUPT_AT");
    if (at && ++calls == atoi(at)) raise(SIGKILL);
    return SecKeychainItemModifyAttributesAndData(item, attrs, length, data);
}

OSStatus test_copy_access(SecKeychainItemRef item, SecAccessRef *access) {
    static int calls;
    OSStatus status = SecKeychainItemCopyAccess(item, access);
    const char *change = getenv("HERMES_TEST_DIFFERENT_PARTITION");
    if (status != errSecSuccess || !change || ++calls > atoi(change)) return status;
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL;
    uint32 count = 0;
    status = SecAccessGetOwnerAndACL(*access, &owner, &count, &entries);
    if (status != errSecSuccess) return status;
    int changed = 0;
    for (uint32 i = 0; i < count; ++i) {
        CSSM_ACL_ENTRY_PROTOTYPE *entry = &entries[i].EntryPublicInfo;
        if (entry->Authorization.NumberOfAuthTags != 1 ||
            entry->Authorization.AuthTags[0] != CSSM_ACL_AUTHORIZATION_PARTITION_ID) continue;
        CSSM_LIST_ELEMENT *part = entry->TypedSubject.Tail;
        if (!part || part->ElementType != CSSM_LIST_ELEMENT_DATUM || !part->Element.Word.Length) return errSecParam;
        part->Element.Word.Data[part->Element.Word.Length - 1] ^= 1;
        changed = 1;
    }
    if (!changed) return errSecParam;
    SecAccessRef altered = NULL;
    status = SecAccessCreateFromOwnerAndACL(owner, count, entries, &altered);
    if (status == errSecSuccess) {
        CFRelease(*access);
        *access = altered;
    }
    return status;
}
