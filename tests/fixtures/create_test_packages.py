"""Generate test fixture packages for HAP scanner tests."""

import json
import os
import struct
import zipfile

FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))


def create_minimal_elf64_so():
    """Create minimal ELF64 shared library bytes (aarch64)."""
    e_ident = b'\x7fELF'
    e_ident += b'\x02'          # EI_CLASS: ELFCLASS64
    e_ident += b'\x01'          # EI_DATA: ELFDATA2LSB
    e_ident += b'\x01'          # EI_VERSION: EV_CURRENT
    e_ident += b'\x00'          # EI_OSABI: ELFOSABI_NONE
    e_ident += b'\x00' * 8      # padding

    header = e_ident
    header += struct.pack('<H', 3)    # e_type: ET_DYN
    header += struct.pack('<H', 183)  # e_machine: EM_AARCH64
    header += struct.pack('<I', 1)    # e_version
    header += struct.pack('<Q', 0)    # e_entry
    header += struct.pack('<Q', 0)    # e_phoff
    header += struct.pack('<Q', 0)    # e_shoff
    header += struct.pack('<I', 0)    # e_flags
    header += struct.pack('<H', 64)   # e_ehsize
    header += struct.pack('<H', 0)    # e_phentsize
    header += struct.pack('<H', 0)    # e_phnum
    header += struct.pack('<H', 0)    # e_shentsize
    header += struct.pack('<H', 0)    # e_shnum
    header += struct.pack('<H', 0)    # e_shstrndx
    return header


def create_minimal_elf32_so():
    """Create minimal ELF32 shared library bytes (ARM)."""
    e_ident = b'\x7fELF'
    e_ident += b'\x01'          # EI_CLASS: ELFCLASS32
    e_ident += b'\x01'          # EI_DATA: ELFDATA2LSB
    e_ident += b'\x01'          # EI_VERSION: EV_CURRENT
    e_ident += b'\x00' * 9      # padding

    header = e_ident
    header += struct.pack('<H', 3)    # e_type: ET_DYN
    header += struct.pack('<H', 40)   # e_machine: EM_ARM
    header += struct.pack('<I', 1)    # e_version
    header += struct.pack('<I', 0)    # e_entry
    header += struct.pack('<I', 0)    # e_phoff
    header += struct.pack('<I', 0)    # e_shoff
    header += struct.pack('<I', 0)    # e_flags
    header += struct.pack('<H', 52)   # e_ehsize
    header += struct.pack('<H', 0)    # e_phentsize
    header += struct.pack('<H', 0)    # e_phnum
    header += struct.pack('<H', 0)    # e_shentsize
    header += struct.pack('<H', 0)    # e_shnum
    header += struct.pack('<H', 0)    # e_shstrndx
    return header


def make_module_json(bundle_name, module_name, module_type="entry"):
    return json.dumps({
        "module": {
            "name": module_name,
            "type": module_type,
            "description": "$string:module_desc",
            "mainElement": "EntryAbility",
            "deviceTypes": ["default", "tablet"],
            "deliveryWithInstall": True,
            "installationFree": False,
            "pages": "$profile:main_pages",
        },
        "app": {
            "bundleName": bundle_name,
            "vendor": "test",
            "versionCode": 1000000,
            "versionName": "1.0.0",
            "icon": "$media:app_icon",
            "label": "$string:app_name",
        }
    }, indent=2).encode()


def create_test_basic_hap():
    path = os.path.join(FIXTURES_DIR, "test_basic.hap")
    elf = create_minimal_elf64_so()
    module = make_module_json("com.test.basic", "entry", "entry")

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", module)
        zf.writestr("libs/arm64-v8a/libentry.so", elf)

    return path


def create_test_no_native_hap():
    path = os.path.join(FIXTURES_DIR, "test_no_native.hap")
    module = make_module_json("com.test.nonative", "entry", "entry")

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", module)
        zf.writestr("ets/modules.abc", b'\x00' * 128)

    return path


def create_test_multi_abi_hap():
    path = os.path.join(FIXTURES_DIR, "test_multi_abi.hap")
    elf64 = create_minimal_elf64_so()
    elf32 = create_minimal_elf32_so()
    module = make_module_json("com.test.multiabi", "entry", "entry")

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", module)
        zf.writestr("libs/arm64-v8a/libentry.so", elf64)
        zf.writestr("libs/armeabi-v7a/libentry.so", elf32)

    return path


def create_test_with_openssl_hap():
    path = os.path.join(FIXTURES_DIR, "test_with_openssl.hap")
    elf = create_minimal_elf64_so()
    module = make_module_json("com.test.openssl", "entry", "entry")

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", module)
        zf.writestr("libs/arm64-v8a/libentry.so", elf)
        zf.writestr("libs/arm64-v8a/libcrypto.so.3", elf)
        zf.writestr("libs/arm64-v8a/libssl.so.3", elf)

    return path


def create_test_basic_har():
    path = os.path.join(FIXTURES_DIR, "test_basic.har")
    elf = create_minimal_elf64_so()
    module = make_module_json("com.test.library", "library", "shared")

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", module)
        zf.writestr("libs/arm64-v8a/liblibrary.so", elf)

    return path


def create_test_basic_app():
    path = os.path.join(FIXTURES_DIR, "test_basic.app")
    elf = create_minimal_elf64_so()

    entry_module = make_module_json("com.test.app", "entry", "entry")
    feature_module = make_module_json("com.test.app", "feature", "feature")

    pack_info = json.dumps({
        "summary": {
            "app": {
                "bundleName": "com.test.app",
                "version": {
                    "code": 1000000,
                    "name": "1.0.0"
                }
            },
            "modules": [
                {"mainAbility": "EntryAbility", "deviceType": ["default"]},
                {"mainAbility": "FeatureAbility", "deviceType": ["default"]},
            ]
        },
        "packages": [
            {"name": "entry.hap", "moduleType": "entry"},
            {"name": "feature.hap", "moduleType": "feature"},
        ]
    }, indent=2).encode()

    import io

    entry_buf = io.BytesIO()
    with zipfile.ZipFile(entry_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", entry_module)
        zf.writestr("libs/arm64-v8a/libentry.so", elf)
    entry_bytes = entry_buf.getvalue()

    feature_buf = io.BytesIO()
    with zipfile.ZipFile(feature_buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("module.json", feature_module)
        zf.writestr("libs/arm64-v8a/libfeature.so", elf)
    feature_bytes = feature_buf.getvalue()

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as zf:
        zf.writestr("pack.info", pack_info)
        zf.writestr("entry.hap", entry_bytes)
        zf.writestr("feature.hap", feature_bytes)

    return path


def create_test_invalid_hap():
    path = os.path.join(FIXTURES_DIR, "test_invalid.hap")
    with open(path, 'wb') as f:
        f.write(b'\xde\xad\xbe\xef' * 64)
    return path


def main():
    generators = [
        ("test_basic.hap", create_test_basic_hap),
        ("test_no_native.hap", create_test_no_native_hap),
        ("test_multi_abi.hap", create_test_multi_abi_hap),
        ("test_with_openssl.hap", create_test_with_openssl_hap),
        ("test_basic.har", create_test_basic_har),
        ("test_basic.app", create_test_basic_app),
        ("test_invalid.hap", create_test_invalid_hap),
    ]

    for name, gen_func in generators:
        path = gen_func()
        size = os.path.getsize(path)
        print(f"  {name:30s} {size:>8d} bytes")

    print(f"\nAll fixtures written to {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
