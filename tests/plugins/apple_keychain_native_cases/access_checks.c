#include "keychain-native.h"
#include <Security/cssmapple.h>
#include <stdio.h>
#include <stdlib.h>

SecKeychainRef target_keychain;
char recovery_id[37];
_Noreturn void fail(const char *kind) { (void)kind; exit(2); }
void check(OSStatus status) { if (status != errSecSuccess) exit(2); }

static SecAccessRef changed(SecAccessRef input, int mutation) {
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL;
    uint32 count = 0;
    check(SecAccessGetOwnerAndACL(input, &owner, &count, &entries));
    if (mutation == 1) owner->Delegate = !owner->Delegate;
    if (mutation == 2 || mutation == 3) {
        CSSM_ACL_AUTHORIZATION_TAG tag = mutation == 2 ? CSSM_ACL_AUTHORIZATION_PARTITION_ID :
                                                        CSSM_ACL_AUTHORIZATION_INTEGRITY;
        int found = 0;
        for (uint32 i = 0; i < count; ++i) {
            CSSM_ACL_ENTRY_PROTOTYPE *entry = &entries[i].EntryPublicInfo;
            if (entry->Authorization.NumberOfAuthTags != 1 || entry->Authorization.AuthTags[0] != tag) continue;
            CSSM_LIST_ELEMENT *data = entry->TypedSubject.Tail;
            if (!data || data->ElementType != CSSM_LIST_ELEMENT_DATUM || !data->Element.Word.Length) exit(2);
            data->Element.Word.Data[data->Element.Word.Length - 1] ^= 1;
            found = 1;
        }
        if (!found) return NULL;
    }
    SecAccessRef out = NULL;
    check(SecAccessCreateFromOwnerAndACL(owner, count, entries, &out));
    return out;
}

static SecACLRef decrypt_acl(SecAccessRef access, CFArrayRef *owner) {
    *owner = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
    if (!*owner || CFArrayGetCount(*owner) != 1) exit(2);
    return (SecACLRef)CFArrayGetValueAtIndex(*owner, 0);
}

static void check_simple(SecAccessRef original, int mutation) {
    SecAccessRef copy = changed(original, 0);
    CFArrayRef list = NULL, apps = NULL;
    CFStringRef description = NULL;
    SecKeychainPromptSelector prompt = 0;
    SecACLRef acl = decrypt_acl(copy, &list);
    check(SecACLCopyContents(acl, &apps, &description, &prompt));
    if (mutation == 1) {
        check(SecACLSetContents(acl, apps, CFSTR("different prompt description"), prompt));
    } else if (mutation == 2) {
        check(SecACLSetContents(acl, apps, description, prompt ^ 1));
    } else if (mutation == 3) {
        CFArrayRef empty = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
        check(SecACLSetContents(acl, empty, description, prompt));
        CFRelease(empty);
    } else {
        const void *right[] = {kSecACLAuthorizationDecrypt};
        CFArrayRef rights = CFArrayCreate(NULL, right, 1, &kCFTypeArrayCallBacks);
        check(SecACLUpdateAuthorizations(acl, rights));
        CFRelease(rights);
    }
    if (same_access(original, copy)) exit(3);
    if (apps) CFRelease(apps);
    if (description) CFRelease(description);
    CFRelease(list);
    CFRelease(copy);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    check(SecKeychainSetUserInteractionAllowed(false));
    check(SecKeychainOpen(argv[1], &target_keychain));
    SecKeychainItemRef item = find_item(target_keychain, argv[2], argv[3]);
    if (!item) return 2;
    SecAccessRef original = copy_access(item);
    SecAccessRef unchanged = changed(original, 0), owner = changed(original, 1);
    if (!same_access(original, unchanged) || same_access(original, owner)) return 3;
    for (int i = 1; i <= 4; ++i) check_simple(original, i);
    SecAccessRef partition = changed(original, 2), integrity = changed(original, 3);
    int expect_system = atoi(argv[4]);
    if (expect_system && (!partition || !integrity)) return 4;
    if (partition && same_access(original, partition)) return 3;
    if (integrity && !same_access(original, integrity)) return 3;
    if (partition) CFRelease(partition);
    if (integrity) CFRelease(integrity);
    CFRelease(owner);
    CFRelease(unchanged);
    CFRelease(original);
    CFRelease(item);
    CFRelease(target_keychain);
    puts("owner, prompt, trusted applications and rights: PASS");
    if (expect_system) puts("partition change rejected; integrity-only change ignored: PASS");
    return 0;
}
