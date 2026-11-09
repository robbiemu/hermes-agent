#include "keychain-native.h"
#include <Security/cssmapple.h>
#include <stdlib.h>
#include <string.h>

SecKeychainItemRef find_item(SecKeychainRef keychain, const char *service, const char *account) {
    SecKeychainAttribute attrs[] = {
        {kSecServiceItemAttr, (UInt32)strlen(service), (void *)service},
        {kSecAccountItemAttr, (UInt32)strlen(account), (void *)account},
    };
    SecKeychainAttributeList list = {2, attrs};
    SecKeychainSearchRef search = NULL;
    SecKeychainItemRef item = NULL;
    check(SecKeychainSearchCreateFromAttributes(keychain, kSecGenericPasswordItemClass, &list, &search));
    OSStatus status = SecKeychainSearchCopyNext(search, &item);
    CFRelease(search);
    if (status == errSecItemNotFound) return NULL;
    check(status);
    return item;
}

void get_value(SecKeychainItemRef item, UInt32 *length, void **data) {
    check(SecKeychainItemCopyContent(item, NULL, NULL, length, data));
}

int same_value(SecKeychainItemRef item, const void *data, UInt32 length) {
    UInt32 found_length = 0;
    void *found = NULL;
    get_value(item, &found_length, &found);
    int same = found_length == length && (!length || memcmp(found, data, length) == 0);
    if (found) SecKeychainItemFreeContent(NULL, found);
    return same;
}

typedef struct {
    CSSM_ACL_OWNER_PROTOTYPE *owner;
    CSSM_ACL_ENTRY_INFO *entries;
    uint32 count;
} RawAccess;

/* SecAccessGetOwnerAndACL returns chunk-allocated CSSM trees. */
static void free_list(CSSM_LIST *list) {
    CSSM_LIST_ELEMENT *entry = list->Head;
    while (entry) {
        CSSM_LIST_ELEMENT *next = entry->NextElement;
        if (entry->ElementType == CSSM_LIST_ELEMENT_DATUM) free(entry->Element.Word.Data);
        else if (entry->ElementType == CSSM_LIST_ELEMENT_SUBLIST) free_list(&entry->Element.Sublist);
        free(entry);
        entry = next;
    }
}

static void free_raw(RawAccess *raw) {
    if (raw->owner) {
        free_list(&raw->owner->TypedSubject);
        free(raw->owner);
    }
    for (uint32 i = 0; raw->entries && i < raw->count; ++i) {
        CSSM_ACL_ENTRY_PROTOTYPE *entry = &raw->entries[i].EntryPublicInfo;
        free_list(&entry->TypedSubject);
        free(entry->Authorization.AuthTags);
        free(entry->TimeRange.StartDate.Data);
        free(entry->TimeRange.EndDate.Data);
    }
    free(raw->entries);
}

static int read_raw(SecAccessRef access, RawAccess *raw) {
    memset(raw, 0, sizeof(*raw));
    return SecAccessGetOwnerAndACL(access, &raw->owner, &raw->count, &raw->entries) == errSecSuccess &&
           raw->owner && (raw->count == 0 || raw->entries);
}

static int same_data(CSSM_DATA a, CSSM_DATA b) {
    return a.Length == b.Length && (!a.Length || (a.Data && b.Data && memcmp(a.Data, b.Data, a.Length) == 0));
}

static int same_list(const CSSM_LIST *a, const CSSM_LIST *b, unsigned depth) {
    if (depth > 64 || a->ListType != b->ListType) return 0;
    const CSSM_LIST_ELEMENT *left = a->Head, *right = b->Head;
    unsigned count = 0;
    for (; left && right; left = left->NextElement, right = right->NextElement) {
        if (++count > 4096 || left->ElementType != right->ElementType || left->WordID != right->WordID) return 0;
        if (left->ElementType == CSSM_LIST_ELEMENT_DATUM) {
            if (!same_data(left->Element.Word, right->Element.Word)) return 0;
        } else if (left->ElementType == CSSM_LIST_ELEMENT_SUBLIST) {
            if (!same_list(&left->Element.Sublist, &right->Element.Sublist, depth + 1)) return 0;
        } else if (left->ElementType != CSSM_LIST_ELEMENT_WORDID) return 0;
    }
    return !left && !right;
}

/* Return -1 for a system right combined with other rights: never drop those rights. */
static int system_right(const CSSM_ACL_ENTRY_INFO *entry, CSSM_ACL_AUTHORIZATION_TAG right) {
    CSSM_AUTHORIZATIONGROUP group = entry->EntryPublicInfo.Authorization;
    if (group.NumberOfAuthTags && !group.AuthTags) return -1;
    for (uint32 i = 0; i < group.NumberOfAuthTags; ++i) {
        if (group.AuthTags[i] == right) return group.NumberOfAuthTags == 1 ? 1 : -1;
    }
    return 0;
}

static int same_entry(const CSSM_ACL_ENTRY_INFO *a, const CSSM_ACL_ENTRY_INFO *b) {
    const CSSM_ACL_ENTRY_PROTOTYPE *left = &a->EntryPublicInfo, *right = &b->EntryPublicInfo;
    CSSM_AUTHORIZATIONGROUP la = left->Authorization, ra = right->Authorization;
    if (left->Delegate != right->Delegate || la.NumberOfAuthTags != ra.NumberOfAuthTags ||
        (la.NumberOfAuthTags && (!la.AuthTags || !ra.AuthTags)) ||
        strncmp(left->EntryTag, right->EntryTag, sizeof(left->EntryTag)) != 0 ||
        !same_data(left->TimeRange.StartDate, right->TimeRange.StartDate) ||
        !same_data(left->TimeRange.EndDate, right->TimeRange.EndDate) ||
        !same_list(&left->TypedSubject, &right->TypedSubject, 0)) return 0;
    for (uint32 i = 0; i < la.NumberOfAuthTags; ++i) {
        if (la.AuthTags[i] != ra.AuthTags[i]) return 0;
    }
    return 1;
}

int same_access(SecAccessRef a, SecAccessRef b) {
    RawAccess left, right;
    int have_left = read_raw(a, &left), have_right = read_raw(b, &right);
    int equal = have_left && have_right && left.owner->Delegate == right.owner->Delegate &&
                same_list(&left.owner->TypedSubject, &right.owner->TypedSubject, 0);
    unsigned char *matched = equal ? calloc(right.count ? right.count : 1, 1) : NULL;
    if (equal && !matched) equal = 0;
    for (uint32 i = 0; equal && i < left.count; ++i) {
        int integrity = system_right(&left.entries[i], CSSM_ACL_AUTHORIZATION_INTEGRITY);
        if (integrity < 0) { equal = 0; break; }
        if (integrity) continue;
        uint32 j = 0;
        for (; j < right.count; ++j) {
            int other_integrity = system_right(&right.entries[j], CSSM_ACL_AUTHORIZATION_INTEGRITY);
            if (other_integrity < 0) { equal = 0; break; }
            if (!other_integrity && !matched[j] && same_entry(&left.entries[i], &right.entries[j])) {
                matched[j] = 1;
                break;
            }
        }
        if (j == right.count) equal = 0;
    }
    for (uint32 j = 0; equal && j < right.count; ++j) {
        int integrity = system_right(&right.entries[j], CSSM_ACL_AUTHORIZATION_INTEGRITY);
        if (integrity < 0 || (!integrity && !matched[j])) equal = 0;
    }
    free(matched);
    free_raw(&left);
    free_raw(&right);
    return equal;
}

/* macOS regenerates per-item integrity and the writer's partition at creation. */
SecAccessRef access_for_copy(SecAccessRef access) {
    RawAccess raw;
    if (!read_raw(access, &raw)) fail("failure");
    CSSM_ACL_ENTRY_INFO *entries = calloc(raw.count ? raw.count : 1, sizeof(*entries));
    if (!entries) fail("failure");
    uint32 count = 0;
    for (uint32 i = 0; i < raw.count; ++i) {
        int integrity = system_right(&raw.entries[i], CSSM_ACL_AUTHORIZATION_INTEGRITY);
        int partition = system_right(&raw.entries[i], CSSM_ACL_AUTHORIZATION_PARTITION_ID);
        if (integrity < 0 || partition < 0) fail("failure");
        if (!integrity && !partition) entries[count++] = raw.entries[i];
    }
    SecAccessRef copy = NULL;
    OSStatus status = SecAccessCreateFromOwnerAndACL(raw.owner, count, entries, &copy);
    free(entries);
    free_raw(&raw);
    check(status);
    if (!copy) fail("failure");
    return copy;
}

SecAccessRef copy_access(SecKeychainItemRef item) {
    SecAccessRef access = NULL;
    check(SecKeychainItemCopyAccess(item, &access));
    if (!access) fail("failure");
    return access;
}

SecKeychainItemRef create_item(const char *service, const char *account,
                                       const void *data, UInt32 length, SecAccessRef access) {
    SecKeychainAttribute attrs[] = {
        {kSecServiceItemAttr, (UInt32)strlen(service), (void *)service},
        {kSecAccountItemAttr, (UInt32)strlen(account), (void *)account},
    };
    SecKeychainAttributeList list = {2, attrs};
    SecKeychainItemRef result = NULL;
    check(SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &list,
                                            length, data, target_keychain, access, &result));
    if (!result) fail("failure");
    return result;
}

SecAccessRef new_access(int allow_any) {
    SecTrustedApplicationRef helper = NULL, security = NULL;
    check(SecTrustedApplicationCreateFromPath(NULL, &helper));
    check(SecTrustedApplicationCreateFromPath("/usr/bin/security", &security));
    const void *apps[] = {helper, security};
    CFArrayRef trusted = CFArrayCreate(NULL, apps, 2, &kCFTypeArrayCallBacks);
    SecAccessRef access = NULL;
    check(SecAccessCreate(CFSTR("Hermes secret"), trusted, &access));
    if (allow_any) {
        CFArrayRef decrypt = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
        if (!decrypt || CFArrayGetCount(decrypt) == 0) fail("failure");
        for (CFIndex i = 0; i < CFArrayGetCount(decrypt); ++i) {
            check(SecACLSetContents((SecACLRef)CFArrayGetValueAtIndex(decrypt, i), NULL, CFSTR("Hermes secret"), 0));
        }
        CFRelease(decrypt);
    }
    CFRelease(trusted);
    CFRelease(helper);
    CFRelease(security);
    return access;
}

