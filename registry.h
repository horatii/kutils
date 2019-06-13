#ifndef REGISTRY_H_
#define REGISTRY_H_

namespace tinker {
class RegKey {
public:
    RegKey();
    RegKey(HANDLE key);
    RegKey(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access);
    ~RegKey();

    NTSTATUS Create(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access);

    NTSTATUS Create(PUNICODE_STRING path, ULONG access);

    NTSTATUS CreateWithDisposition(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access, PULONG disposition);

    // Create a subkey or open it if it already exists.
    NTSTATUS CreateKey(PUNICODE_STRING name, ULONG access);

    // Open an exists reg key.
    NTSTATUS Open(HANDLE rootkey, PUNICODE_STRING subkey, ULONG access);

    // Open an existing reg key, given the relative key name.
    NTSTATUS OpenKey(PUNICODE_STRING relative_key_name, ULONG access);

    // Closes this reg key.
    void Close();

    void Set(HANDLE key);

    // Transfers ownership away from this object.
    HANDLE Take();

    HANDLE Handle() const { return key_; }

    bool Valid() const { return key_ != NULL; }

    // Returns an int32_t value. If |name| is NULL or empty, returns the default
    // value, if any.
    NTSTATUS ReadValueDW(PUNICODE_STRING value_name, DWORD32* out_value) const;

    // Returns an int64_t value. If |name| is NULL or empty, returns the default
    // value, if any.
    NTSTATUS ReadValueQW(PUNICODE_STRING value_name, DWORD64* out_value) const;

    // Returns a string value. If |name| is NULL or empty, returns the default
    // value, if any.
    NTSTATUS ReadValueSZ(PUNICODE_STRING value_name, PUNICODE_STRING out_value) const;

    NTSTATUS ReadValue(PUNICODE_STRING value_name, void* data, ULONG* size, ULONG* dtype) const;


    // Sets an int32_t value.
    NTSTATUS WriteValueDW(PUNICODE_STRING value_name, DWORD32 in_value);

    // Sets an int32_t value.
    NTSTATUS WriteValueQW(PUNICODE_STRING value_name, DWORD64 in_value);

    // Sets a string value.
    NTSTATUS WriteValueSZ(PUNICODE_STRING value_name, PUNICODE_STRING in_value);

    NTSTATUS WriteValueESZ(PUNICODE_STRING value_name, PUNICODE_STRING in_value);

    NTSTATUS WriteValueMSZ(PUNICODE_STRING value_name, PUNICODE_STRING in_value);
    
    // Sets raw data, including type.
    NTSTATUS WriteValue(PUNICODE_STRING value_name,
                        const void* data,
                        DWORD32 dsize,
                        DWORD32 dtype);

private:
    HANDLE key_;
};

class RegistryKeyIterator {
public:
    // Construct a Registry Key Iterator with default WOW64 access.
    RegistryKeyIterator(HANDLE root_key, PUNICODE_STRING folder_key);

    // 
    RegistryKeyIterator(PUNICODE_STRING path);

    ~RegistryKeyIterator();

    ULONG SubkeyCount() const;

    // True while the iterator is valid.
    bool Valid() const;

    // Advances to the next entry in the folder.
    void operator++();

    const wchar_t* Name() const { return name_; }

    int Index() const { return index_; }

    HANDLE Key() const { return key_; }
    
private:
    // Read in the current values.
    bool Read();

    void Initialize(HANDLE root_key, PUNICODE_STRING folder_key);

    // The registry key being iterated.
    HANDLE key_;
    // Current index of the iteration.
    int index_;

    wchar_t name_[260];
};
}
#endif //  REGISTRY_H_