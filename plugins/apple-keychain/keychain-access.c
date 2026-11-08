#include "keychain-native.h"
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

static int same_apps(CFArrayRef a, CFArrayRef b) {
    if (!a || !b) return a == b;
    CFIndex count = CFArrayGetCount(a);
    if (count != CFArrayGetCount(b)) return 0;
    for (CFIndex i = 0; i < count; ++i) {
        CFDataRef left = NULL, right = NULL;
        if (SecTrustedApplicationCopyData((SecTrustedApplicationRef)CFArrayGetValueAtIndex(a, i), &left) != errSecSuccess ||
            SecTrustedApplicationCopyData((SecTrustedApplicationRef)CFArrayGetValueAtIndex(b, i), &right) != errSecSuccess) {
            if (left) CFRelease(left);
            if (right) CFRelease(right);
            return 0;
        }
        int equal = CFEqual(left, right);
        CFRelease(left);
        CFRelease(right);
        if (!equal) return 0;
    }
    return 1;
}

static int same_acl(SecACLRef a, SecACLRef b) {
    CFArrayRef apps_a = NULL, apps_b = NULL;
    CFStringRef desc_a = NULL, desc_b = NULL;
    SecKeychainPromptSelector prompt_a = 0, prompt_b = 0;
    CFArrayRef auth_a = SecACLCopyAuthorizations(a), auth_b = SecACLCopyAuthorizations(b);
    OSStatus sa = SecACLCopyContents(a, &apps_a, &desc_a, &prompt_a);
    OSStatus sb = SecACLCopyContents(b, &apps_b, &desc_b, &prompt_b);
    int equal = sa == errSecSuccess && sb == errSecSuccess && auth_a && auth_b &&
        CFEqual(auth_a, auth_b) && prompt_a == prompt_b &&
        ((!desc_a && !desc_b) || (desc_a && desc_b && CFEqual(desc_a, desc_b))) &&
        same_apps(apps_a, apps_b);
    if (apps_a) CFRelease(apps_a);
    if (apps_b) CFRelease(apps_b);
    if (desc_a) CFRelease(desc_a);
    if (desc_b) CFRelease(desc_b);
    if (auth_a) CFRelease(auth_a);
    if (auth_b) CFRelease(auth_b);
    return equal;
}

int same_access(SecAccessRef a, SecAccessRef b) {
    uid_t ua = 0, ub = 0;
    gid_t ga = 0, gb = 0;
    SecAccessOwnerType ta = 0, tb = 0;
    CFArrayRef aa = NULL, ab = NULL;
    if (SecAccessCopyOwnerAndACL(a, &ua, &ga, &ta, NULL) != errSecSuccess ||
        SecAccessCopyOwnerAndACL(b, &ub, &gb, &tb, NULL) != errSecSuccess ||
        SecAccessCopyACLList(a, &aa) != errSecSuccess ||
        SecAccessCopyACLList(b, &ab) != errSecSuccess || !aa || !ab) {
        if (aa) CFRelease(aa);
        if (ab) CFRelease(ab);
        return 0;
    }
    CFIndex count = CFArrayGetCount(aa);
    int equal = ua == ub && ga == gb && ta == tb && count == CFArrayGetCount(ab);
    for (CFIndex i = 0; equal && i < count; ++i) {
        if (!same_acl((SecACLRef)CFArrayGetValueAtIndex(aa, i),
                      (SecACLRef)CFArrayGetValueAtIndex(ab, i))) equal = 0;
    }
    CFRelease(aa);
    CFRelease(ab);
    return equal;
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

