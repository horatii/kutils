#include "stdafx.h"
#include "registry.h"

namespace tinker {
static const ULONG REG_TAG = 'REG';

RegKey::RegKey() : key_(NULL) {

}

RegKey::RegKey(HANDLE key) : key_(key) {

}

RegKey::RegKey(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access) : key_(NULL) {
    if (rootkey) {
        if (access & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK))
            Create(rootkey, subkey, access);
        else
            Open(rootkey, subkey, access);
    }
}

RegKey::~RegKey() {
    Close();
}

NTSTATUS RegKey::Create(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access) {
    ULONG disposition_value;
    return CreateWithDisposition(rootkey, subkey, access, &disposition_value);
}

NTSTATUS RegKey::Create(PUNICODE_STRING path, ULONG access) {
    return Create(NULL, path, access);
}

NTSTATUS RegKey::CreateWithDisposition(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access, PULONG disposition) {
    OBJECT_ATTRIBUTES ObjectAttr;
    HANDLE subhkey = NULL;
    InitializeObjectAttributes(&ObjectAttr, subkey, OBJ_CASE_INSENSITIVE, rootkey, NULL);
    NTSTATUS result = ZwCreateKey(&subhkey, access, &ObjectAttr, 0, NULL, REG_OPTION_NON_VOLATILE, disposition);

    if (result == STATUS_SUCCESS) {
        Close();
        key_ = subhkey;
    }
    return result;
}

NTSTATUS RegKey::CreateKey(PUNICODE_STRING name, ULONG access) {
    OBJECT_ATTRIBUTES ObjectAttr;    
    InitializeObjectAttributes(&ObjectAttr, name, OBJ_CASE_INSENSITIVE, key_, NULL);
    HANDLE subkey = NULL;
    NTSTATUS result = ZwCreateKey(&subkey, access, &ObjectAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (result == STATUS_SUCCESS) {
        Close();
        key_ = subkey;
    }
    return result;
}

NTSTATUS RegKey::Open(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access) {
    OBJECT_ATTRIBUTES obj_attr;
    HANDLE subhkey = NULL;
    InitializeObjectAttributes(&obj_attr, subkey, OBJ_CASE_INSENSITIVE, rootkey, NULL);
    NTSTATUS result = ZwOpenKey(&subhkey, access, &obj_attr);
    if (result == STATUS_SUCCESS) {
        Close();
        key_ = subhkey;
    }

    return result;
}

NTSTATUS RegKey::OpenKey(PUNICODE_STRING relative_key_name, ULONG access) {
    OBJECT_ATTRIBUTES ObjectAttr;
    HANDLE subhkey = NULL;
    InitializeObjectAttributes(&ObjectAttr, relative_key_name, OBJ_CASE_INSENSITIVE, key_, NULL);

    NTSTATUS result = ZwOpenKey(&subhkey, access, &ObjectAttr);
    if (result == STATUS_SUCCESS) {
        Close();
        key_ = subhkey;
    }

    return result;
}

void RegKey::Close() {
    if (key_ != NULL) {
        ZwClose(key_);
        key_ = NULL;
    }
}

void RegKey::Set(HANDLE key) {
    if (key_ != key) {
        Close();
        key_ = key;
    }
}

HANDLE RegKey::Take() {
    HANDLE key = key_;
    key_ = NULL;
    return key;
}

NTSTATUS RegKey::ReadValueDW(PUNICODE_STRING value_name, DWORD32* out_value) const {    
    ULONG dtype = REG_DWORD;
    ULONG size = sizeof(DWORD32);
    return ReadValue(value_name, out_value, &size, &dtype);
}

NTSTATUS RegKey::ReadValueQW(PUNICODE_STRING value_name, DWORD64* out_value) const {
    ULONG dtype = REG_QWORD;
    ULONG size = sizeof(DWORD64);
    return ReadValue(value_name, out_value, &size, &dtype);
}

NTSTATUS RegKey::ReadValueSZ(PUNICODE_STRING value_name, PUNICODE_STRING out_value) const {
    ULONG size = 0;
    ULONG dtype = REG_NONE;
    
    NTSTATUS Status = ReadValue(value_name, NULL, &size, &dtype);
    if (Status != STATUS_SUCCESS && Status != STATUS_BUFFER_TOO_SMALL &&
        Status != STATUS_BUFFER_OVERFLOW) {
        return Status;
    }

    if (dtype != REG_SZ) {
        return  STATUS_INSUFFICIENT_RESOURCES;
    }

    if (out_value->MaximumLength < size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Status = ReadValue(value_name, out_value->Buffer, &size, &dtype);
    if (NT_SUCCESS(Status)) {
        out_value->Length = (USHORT)size;
        if (out_value->Buffer[out_value->Length / sizeof(WCHAR) -1] == UNICODE_NULL) {
            out_value->Length -= sizeof(WCHAR);
        }
    }
    return Status;
}

NTSTATUS RegKey::ReadValue(PUNICODE_STRING value_name, void* data, ULONG* size, ULONG* dtype) const {
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG length;
    PKEY_VALUE_PARTIAL_INFORMATION Information;

    length = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + *size;
    Information = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, length, REG_TAG);

    if (Information) {
        status = ZwQueryValueKey(key_,
                                 value_name,
                                 KeyValuePartialInformation,
                                 Information,
                                 length,
                                 &length);
        if (NT_SUCCESS(status)) {
            if (Information->DataLength <= *size && (*dtype == REG_NONE || *dtype == Information->Type)) {
                RtlCopyMemory(data, Information->Data, Information->DataLength);
                *size = Information->DataLength;
                *dtype = Information->Type;
            }
            else {
                *dtype = Information->Type;
                *size = Information->DataLength;
                status = STATUS_BUFFER_TOO_SMALL;
            }
        } else if (status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL) {
            *dtype = Information->Type;
            *size = Information->DataLength;
        }
        ExFreePool(Information);
    }

    return (status);
}

NTSTATUS RegKey::WriteValueDW(PUNICODE_STRING value_name, DWORD32 in_value) {
    return WriteValue(value_name, &in_value, sizeof(DWORD32), REG_DWORD);
}

NTSTATUS RegKey::WriteValueQW(PUNICODE_STRING value_name, DWORD64 in_value) {
    return WriteValue(value_name, &in_value, sizeof(DWORD64), REG_QWORD);
}

NTSTATUS RegKey::WriteValueSZ(PUNICODE_STRING value_name, PUNICODE_STRING in_value) {    
    if (in_value->Buffer[in_value->Length / sizeof(WCHAR) -1] == UNICODE_NULL) {
        return WriteValue(value_name, in_value->Buffer, in_value->Length, REG_SZ);
    }
    ULONG Size =  in_value->Length + sizeof(WCHAR);
    PWCH pBuffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, Size, REG_TAG);
    RtlCopyMemory(pBuffer, in_value->Buffer, in_value->Length);
    pBuffer[Size / sizeof(WCHAR) - 1] = UNICODE_NULL;

    NTSTATUS NtStatus = WriteValue(value_name, pBuffer, Size, REG_SZ);
    ExFreePool(pBuffer);
    return NtStatus;
}

NTSTATUS RegKey::WriteValueESZ(PUNICODE_STRING value_name, PUNICODE_STRING in_value) {
    if (in_value->Buffer[in_value->Length / sizeof(WCHAR) -1] == UNICODE_NULL) {
        return WriteValue(value_name, in_value->Buffer, in_value->Length, REG_EXPAND_SZ);
    }
    ULONG Size =  in_value->Length + sizeof(WCHAR);
    PWCH pBuffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, Size, REG_TAG);
    RtlCopyMemory(pBuffer, in_value->Buffer, in_value->Length);
    pBuffer[Size / sizeof(WCHAR) - 1] = UNICODE_NULL;

    NTSTATUS NtStatus = WriteValue(value_name, pBuffer, Size, REG_EXPAND_SZ);
    ExFreePool(pBuffer);
    return NtStatus;
}

//
// TODO
// 
NTSTATUS RegKey::WriteValueMSZ(PUNICODE_STRING value_name, PUNICODE_STRING in_value) {    
    ULONG Size =  in_value->Length + sizeof(WCHAR) + sizeof(WCHAR);
    PWCH pBuffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, Size, REG_TAG);
    RtlCopyMemory(pBuffer, in_value->Buffer, in_value->Length);
    pBuffer[Size / sizeof(WCHAR) - 1] = UNICODE_NULL;
    pBuffer[Size / sizeof(WCHAR) - 2] = UNICODE_NULL;
    NTSTATUS NtStatus = WriteValue(value_name, pBuffer, Size, REG_MULTI_SZ);
    ExFreePool(pBuffer);
    return NtStatus;
}

NTSTATUS RegKey::WriteValue(PUNICODE_STRING value_name, const void* data, DWORD32 dsize, DWORD32 dtype) {
    return ZwSetValueKey(key_,
                         value_name,
                         0,   /* optional */
                         dtype,
                         (PVOID)data,
                         dsize);
}


RegistryKeyIterator::RegistryKeyIterator(HANDLE root_key, PUNICODE_STRING folder_key) {
    Initialize(root_key, folder_key);
}

RegistryKeyIterator::RegistryKeyIterator(PUNICODE_STRING path) {
    Initialize(NULL, path);
}

RegistryKeyIterator::~RegistryKeyIterator() {
    if (key_) {
        ::ZwClose(key_);
    }        
}

ULONG RegistryKeyIterator::SubkeyCount() const {
    PKEY_FULL_INFORMATION	pFullKeyInformation;
    NTSTATUS				NtStatus;
    ULONG					ResultLength;

    NtStatus = ZwQueryKey(key_, KeyFullInformation, NULL, 0, &ResultLength);
    if (NtStatus != STATUS_BUFFER_TOO_SMALL) {
        return 0;
    }

    pFullKeyInformation = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, REG_TAG);
    if (pFullKeyInformation == NULL) {
        return 0;
    }
    NtStatus = ZwQueryKey(key_, KeyFullInformation, pFullKeyInformation, ResultLength, &ResultLength);

    return pFullKeyInformation->SubKeys;
}

bool RegistryKeyIterator::Valid() const {
    return key_ != NULL && index_ >= 0;
}

void RegistryKeyIterator::operator++() {
    --index_;
    Read();
}

bool RegistryKeyIterator::Read() {
    UCHAR Buf[sizeof(KEY_BASIC_INFORMATION) + sizeof(wchar_t) * 260] = { };
    PKEY_BASIC_INFORMATION Information = (PKEY_BASIC_INFORMATION)Buf;
    if (Valid()) {
        ULONG ResultLength = 0;
        if (!NT_SUCCESS(ZwEnumerateKey(key_, index_, KeyBasicInformation, Buf, sizeof(Buf), &ResultLength))) {
            return false;
        }
        Information->Name;
        Information->NameLength;
        RtlCopyMemory(name_, Information->Name, Information->NameLength);
        name_[Information->NameLength / sizeof(wchar_t)] = '\0';
        return true;
    }
    name_[0] = '\0';
    return false;
}

void RegistryKeyIterator::Initialize(HANDLE root_key, PUNICODE_STRING folder_key) {
    OBJECT_ATTRIBUTES ObjectAttr;
    InitializeObjectAttributes(&ObjectAttr, folder_key, OBJ_CASE_INSENSITIVE, root_key, NULL);
    if (NT_SUCCESS(ZwOpenKey(&key_, KEY_READ, &ObjectAttr))) {
        ULONG count = SubkeyCount();
        index_ = count -1;
    }
    else {
        key_ = NULL;
    }
    Read();
}
}
