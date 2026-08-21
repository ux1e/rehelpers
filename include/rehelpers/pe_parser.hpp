// pe_parser.hpp
//
// Минимальный read-only парсер формата PE (Portable Executable): DOS/NT
// заголовки, таблица секций, конвертация RVA -> file offset, список
// импортируемых DLL. Работает над байтовым буфером — платформенно
// независим, читает .exe/.dll как обычные данные, ничего не грузит и не
// исполняет.
//
// Header-only, без внешних зависимостей. Структуры описаны вручную
// (а не через <windows.h>), чтобы парсер собирался и на Linux/macOS.

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <vector>
#include <stdexcept>

namespace rehelpers {

#pragma pack(push, 1)

struct DosHeader {
    std::uint16_t e_magic;      // 0x5A4D ("MZ")
    std::uint8_t  _reserved[58];
    std::int32_t  e_lfanew;     // смещение до NT-заголовков
};
static_assert(sizeof(DosHeader) == 64, "DosHeader layout mismatch");

struct FileHeader {
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
};
static_assert(sizeof(FileHeader) == 20, "FileHeader layout mismatch");

struct DataDirectory {
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
};

struct OptionalHeader32 {
    std::uint16_t Magic; // 0x10B
    std::uint8_t MajorLinkerVersion, MinorLinkerVersion;
    std::uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint32_t BaseOfData;
    std::uint32_t ImageBase;
    std::uint32_t SectionAlignment, FileAlignment;
    std::uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion,
        MajorSubsystemVersion, MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage, SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    DataDirectory Directories[16];
};
static_assert(sizeof(OptionalHeader32) == 224, "OptionalHeader32 layout mismatch");

struct OptionalHeader64 {
    std::uint16_t Magic; // 0x20B
    std::uint8_t MajorLinkerVersion, MinorLinkerVersion;
    std::uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment, FileAlignment;
    std::uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion,
        MajorSubsystemVersion, MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage, SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    DataDirectory Directories[16];
};
static_assert(sizeof(OptionalHeader64) == 240, "OptionalHeader64 layout mismatch");

struct RawSectionHeader {
    char Name[8];
    std::uint32_t VirtualSize;
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfRawData;
    std::uint32_t PointerToRawData;
    std::uint32_t PointerToRelocations;
    std::uint32_t PointerToLinenumbers;
    std::uint16_t NumberOfRelocations;
    std::uint16_t NumberOfLinenumbers;
    std::uint32_t Characteristics;
};
static_assert(sizeof(RawSectionHeader) == 40, "RawSectionHeader layout mismatch");

struct RawImportDescriptor {
    std::uint32_t OriginalFirstThunk;
    std::uint32_t TimeDateStamp;
    std::uint32_t ForwarderChain;
    std::uint32_t Name;
    std::uint32_t FirstThunk;
};
static_assert(sizeof(RawImportDescriptor) == 20, "RawImportDescriptor layout mismatch");

#pragma pack(pop)

constexpr std::uint16_t kDosSignature = 0x5A4D;      // "MZ"
constexpr std::uint32_t kNtSignature = 0x00004550;   // "PE\0\0"
constexpr std::uint16_t kOptMagic32 = 0x10B;
constexpr std::uint16_t kOptMagic64 = 0x20B;
constexpr std::uint32_t kImportDirectoryIndex = 1;

struct SectionInfo {
    std::string name;
    std::uint32_t virtual_address;
    std::uint32_t virtual_size;
    std::uint32_t size_of_raw_data;
    std::uint32_t pointer_to_raw_data;
    std::uint32_t characteristics;

    bool executable() const { return characteristics & 0x20000000u; }
    bool writable() const { return characteristics & 0x80000000u; }
    bool readable() const { return characteristics & 0x40000000u; }
};

// Read-only разбор PE-образа, лежащего в буфере [data, data+size).
// Буфер должен пережить время жизни PeFile — класс его не копирует.
class PeFile {
public:
    PeFile(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {
        parse();
    }

    bool valid() const { return valid_; }
    bool is64() const { return is64_; }
    std::uint16_t machine() const { return file_header_.Machine; }
    std::uint16_t subsystem() const { return subsystem_; }
    std::uint32_t entry_point_rva() const { return entry_point_rva_; }
    std::uint64_t image_base() const { return image_base_; }
    std::uint32_t size_of_image() const { return size_of_image_; }
    const std::vector<SectionInfo>& sections() const { return sections_; }

    // Переводит виртуальный адрес (RVA, относительно ImageBase) в смещение
    // внутри файла на диске, используя таблицу секций.
    std::optional<std::size_t> rva_to_offset(std::uint32_t rva) const {
        for (const auto& s : sections_) {
            const std::uint32_t span = s.virtual_size ? s.virtual_size : s.size_of_raw_data;
            if (rva >= s.virtual_address && rva < s.virtual_address + span) {
                return static_cast<std::size_t>(s.pointer_to_raw_data) + (rva - s.virtual_address);
            }
        }
        return std::nullopt;
    }

    // Имена DLL из таблицы импорта (import directory).
    std::vector<std::string> imported_dlls() const {
        std::vector<std::string> result;
        if (import_dir_rva_ == 0) return result;

        auto off = rva_to_offset(import_dir_rva_);
        if (!off) return result;

        std::size_t cursor = *off;
        while (cursor + sizeof(RawImportDescriptor) <= size_) {
            RawImportDescriptor desc{};
            std::memcpy(&desc, data_ + cursor, sizeof(desc));
            if (desc.OriginalFirstThunk == 0 && desc.Name == 0 && desc.FirstThunk == 0) {
                break; // терминальная нулевая запись
            }
            if (auto name_off = rva_to_offset(desc.Name)) {
                result.push_back(read_cstring(*name_off));
            }
            cursor += sizeof(RawImportDescriptor);
        }
        return result;
    }

private:
    void parse() {
        if (size_ < sizeof(DosHeader)) return;
        DosHeader dos{};
        std::memcpy(&dos, data_, sizeof(dos));
        if (dos.e_magic != kDosSignature) return;
        if (dos.e_lfanew < 0 || static_cast<std::size_t>(dos.e_lfanew) + 4 + sizeof(FileHeader) > size_) return;

        std::size_t nt_off = static_cast<std::size_t>(dos.e_lfanew);
        std::uint32_t sig = 0;
        std::memcpy(&sig, data_ + nt_off, 4);
        if (sig != kNtSignature) return;

        std::memcpy(&file_header_, data_ + nt_off + 4, sizeof(FileHeader));

        std::size_t opt_off = nt_off + 4 + sizeof(FileHeader);
        if (opt_off + 2 > size_) return;
        std::uint16_t opt_magic = 0;
        std::memcpy(&opt_magic, data_ + opt_off, 2);

        if (opt_magic == kOptMagic64) {
            is64_ = true;
            if (opt_off + sizeof(OptionalHeader64) > size_) return;
            OptionalHeader64 oh{};
            std::memcpy(&oh, data_ + opt_off, sizeof(oh));
            entry_point_rva_ = oh.AddressOfEntryPoint;
            image_base_ = oh.ImageBase;
            size_of_image_ = oh.SizeOfImage;
            subsystem_ = oh.Subsystem;
            if (oh.NumberOfRvaAndSizes > kImportDirectoryIndex) {
                import_dir_rva_ = oh.Directories[kImportDirectoryIndex].VirtualAddress;
            }
        } else if (opt_magic == kOptMagic32) {
            is64_ = false;
            if (opt_off + sizeof(OptionalHeader32) > size_) return;
            OptionalHeader32 oh{};
            std::memcpy(&oh, data_ + opt_off, sizeof(oh));
            entry_point_rva_ = oh.AddressOfEntryPoint;
            image_base_ = oh.ImageBase;
            size_of_image_ = oh.SizeOfImage;
            subsystem_ = oh.Subsystem;
            if (oh.NumberOfRvaAndSizes > kImportDirectoryIndex) {
                import_dir_rva_ = oh.Directories[kImportDirectoryIndex].VirtualAddress;
            }
        } else {
            return; // неизвестный формат optional header
        }

        std::size_t sec_off = opt_off + file_header_.SizeOfOptionalHeader;
        for (std::uint16_t i = 0; i < file_header_.NumberOfSections; ++i) {
            if (sec_off + sizeof(RawSectionHeader) > size_) break;
            RawSectionHeader raw{};
            std::memcpy(&raw, data_ + sec_off, sizeof(raw));

            SectionInfo info;
            info.name.assign(raw.Name, strnlen_(raw.Name, 8));
            info.virtual_address = raw.VirtualAddress;
            info.virtual_size = raw.VirtualSize;
            info.size_of_raw_data = raw.SizeOfRawData;
            info.pointer_to_raw_data = raw.PointerToRawData;
            info.characteristics = raw.Characteristics;
            sections_.push_back(std::move(info));

            sec_off += sizeof(RawSectionHeader);
        }

        valid_ = true;
    }

    std::string read_cstring(std::size_t offset) const {
        if (offset >= size_) return {};
        std::size_t len = 0;
        while (offset + len < size_ && data_[offset + len] != 0) ++len;
        return std::string(reinterpret_cast<const char*>(data_ + offset), len);
    }

    static std::size_t strnlen_(const char* s, std::size_t maxlen) {
        std::size_t i = 0;
        while (i < maxlen && s[i] != '\0') ++i;
        return i;
    }

    const std::uint8_t* data_;
    std::size_t size_;
    bool valid_ = false;
    bool is64_ = false;
    FileHeader file_header_{};
    std::uint32_t entry_point_rva_ = 0;
    std::uint64_t image_base_ = 0;
    std::uint32_t size_of_image_ = 0;
    std::uint16_t subsystem_ = 0;
    std::uint32_t import_dir_rva_ = 0;
    std::vector<SectionInfo> sections_;
};

} // namespace rehelpers
