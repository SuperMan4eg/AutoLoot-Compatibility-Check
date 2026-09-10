#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr wchar_t kGameExecutable[] = L"ACOdyssey.exe";
constexpr wchar_t kReportName[] = L"AutoLootCompatibilityReport.txt";
constexpr std::size_t kSha256Size = 32;

struct KnownBuild {
    std::string_view name;
    std::string_view sha256;
    std::uint64_t size;
    bool supported;
};

constexpr std::array<KnownBuild, 3> kKnownBuilds{{
    {"steam_1_5_6", "AC327DAD2CBBDD72A3FDA8E99CBEAB9D12AF328363E4F09BC5674BDD36B8C483", 286453072ULL, true},
    {"ubisoft_connect_1_5_6_candidate", "3CB92F72823DB2C5EC24B77ADCD2325C9E1C61DBDB3E7EEA87151374F49B1A07", 285838672ULL, false},
    {"game_1_5_3_candidate", "3453FC6A34792F5C1D71053B7BAB7446E700DAF347F2575E1E8B25006F33F400", 285195944ULL, false},
}};

struct ReferenceSignature {
    std::string_view name;
    std::uint32_t steamRva;
    std::array<std::uint8_t, 48> bytes;
};

constexpr std::array<ReferenceSignature, 5> kReferenceSignatures{{
    {"interaction_wrapper", 0x3458E20U, {0x40,0x53,0x48,0x83,0xEC,0x20,0x48,0x8B,0x49,0x38,0x48,0x8B,0xDA,0x49,0x8B,0xD0,0x48,0x8B,0x09,0xE8,0x88,0x09,0x00,0x00,0x88,0x03,0x48,0x83,0xC4,0x20,0x5B,0xC3,0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20,0x48,0x8B,0xD9,0xE8,0x3E,0xED}},
    {"game_update", 0x36CEE60U, {0x48,0x89,0x5C,0x24,0x10,0x55,0x56,0x57,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x40,0x48,0x8B,0x05,0x49,0xBD,0xFB,0x01,0x48,0x33,0xC4,0x48,0x89,0x44,0x24,0x30,0x8B,0x6A,0x08,0x33,0xF6,0xC1,0xED,0x11,0x49,0x8B,0xF8,0x4C,0x8B,0xF2,0x48,0x8B,0xD9}},
    {"get_targeting", 0x29E7C80U, {0x48,0x83,0xEC,0x28,0x48,0x85,0xC9,0x74,0x23,0xE8,0x12,0x7B,0xA7,0xFE,0x48,0x85,0xC0,0x74,0x19,0x48,0x8B,0xC8,0xE8,0xF5,0x74,0xC8,0xFE,0x48,0x85,0xC0,0x74,0x0C,0x48,0x8B,0x80,0xD8,0x10,0x00,0x00,0x48,0x83,0xC4,0x28,0xC3,0x33,0xC0,0x48,0x83}},
    {"get_selected", 0x36B0370U, {0x48,0x8B,0x81,0x38,0x02,0x00,0x00,0x8D,0x14,0xD5,0x00,0x00,0x00,0x00,0x48,0x8B,0x04,0x02,0x48,0x83,0xE0,0xFE,0x81,0x78,0x18,0x00,0x00,0x02,0x00,0x72,0x2C,0x48,0x8B,0x40,0x10,0x48,0x8B,0x10,0x4C,0x8B,0x42,0x10,0x4C,0x39,0x81,0xE8,0x00,0x00}},
    {"interaction_emitter", 0x3642E20U, {0x40,0x53,0x55,0x56,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x50,0x48,0x8B,0x05,0x8A,0x7D,0x04,0x02,0x48,0x33,0xC4,0x48,0x89,0x44,0x24,0x48,0x33,0xC0,0x4C,0x8B,0xE1,0x89,0x44,0x24,0x24,0x48,0x8D,0x4C,0x24,0x30,0x83,0xE0,0x01,0x48}},
}};

struct PeInfo {
    const IMAGE_NT_HEADERS64* headers{};
    const IMAGE_SECTION_HEADER* sections{};
    std::uint16_t sectionCount{};
};

std::string Hex(const std::uint8_t* data, std::size_t size) {
    std::ostringstream out;
    out << std::uppercase << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i) {
        out << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return out.str();
}

std::string Hex32(std::uint32_t value) {
    std::ostringstream out;
    out << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << value;
    return out.str();
}

std::optional<std::array<std::uint8_t, kSha256Size>> Sha256(const std::uint8_t* data,
                                                            std::size_t size) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
                          &resultSize, 0) < 0) {
        if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::nullopt;
    }
    std::vector<std::uint8_t> object(objectSize);
    std::array<std::uint8_t, kSha256Size> digest{};
    const NTSTATUS createStatus = BCryptCreateHash(algorithm, &hash, object.data(), objectSize,
                                                    nullptr, 0, 0);
    bool ok = createStatus >= 0;
    constexpr std::size_t kChunk = 16U * 1024U * 1024U;
    for (std::size_t offset = 0; ok && offset < size; offset += kChunk) {
        const std::size_t chunk = std::min(kChunk, size - offset);
        ok = BCryptHashData(hash, const_cast<PUCHAR>(data + offset),
                            static_cast<ULONG>(chunk), 0) >= 0;
    }
    ok = ok && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
    if (hash != nullptr) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok) return std::nullopt;
    return digest;
}

std::optional<PeInfo> ParsePe(const std::vector<std::uint8_t>& file) {
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return std::nullopt;
    const auto ntOffset = static_cast<std::size_t>(dos->e_lfanew);
    if (ntOffset > file.size() || file.size() - ntOffset < sizeof(IMAGE_NT_HEADERS64)) {
        return std::nullopt;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + ntOffset);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return std::nullopt;
    }
    const std::size_t sectionsOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                                       nt->FileHeader.SizeOfOptionalHeader;
    const std::size_t sectionsSize = static_cast<std::size_t>(nt->FileHeader.NumberOfSections) *
                                     sizeof(IMAGE_SECTION_HEADER);
    if (sectionsOffset > file.size() || sectionsSize > file.size() - sectionsOffset) {
        return std::nullopt;
    }
    return PeInfo{nt, reinterpret_cast<const IMAGE_SECTION_HEADER*>(file.data() + sectionsOffset),
                  nt->FileHeader.NumberOfSections};
}

std::optional<std::size_t> RvaToOffset(const PeInfo& pe, std::uint32_t rva,
                                       std::size_t required, std::size_t fileSize) {
    if (rva < pe.headers->OptionalHeader.SizeOfHeaders) {
        if (rva <= fileSize && required <= fileSize - rva) return rva;
        return std::nullopt;
    }
    for (std::uint16_t i = 0; i < pe.sectionCount; ++i) {
        const auto& section = pe.sections[i];
        const std::uint32_t span = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (rva < section.VirtualAddress || rva - section.VirtualAddress >= span) continue;
        const std::uint64_t offset = static_cast<std::uint64_t>(section.PointerToRawData) +
                                     (rva - section.VirtualAddress);
        if (offset <= fileSize && required <= fileSize - static_cast<std::size_t>(offset)) {
            return static_cast<std::size_t>(offset);
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::vector<std::uint32_t> FindExecutableMatches(const std::vector<std::uint8_t>& file,
                                                 const PeInfo& pe,
                                                 const std::uint8_t* pattern,
                                                 std::size_t patternSize) {
    std::vector<std::uint32_t> matches;
    constexpr std::size_t kMaxReportedMatches = 64;
    for (std::uint16_t index = 0; index < pe.sectionCount; ++index) {
        const auto& section = pe.sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            section.PointerToRawData >= file.size()) continue;
        const std::size_t begin = section.PointerToRawData;
        const std::size_t available = file.size() - begin;
        const std::size_t length = std::min<std::size_t>(section.SizeOfRawData, available);
        if (length < patternSize) continue;
        const auto first = file.begin() + static_cast<std::ptrdiff_t>(begin);
        const auto last = first + static_cast<std::ptrdiff_t>(length);
        auto cursor = first;
        while (cursor != last) {
            const auto found = std::search(cursor, last, pattern, pattern + patternSize);
            if (found == last) break;
            const auto rawOffset = static_cast<std::uint64_t>(found - file.begin());
            const auto delta = rawOffset - section.PointerToRawData;
            matches.push_back(section.VirtualAddress + static_cast<std::uint32_t>(delta));
            if (matches.size() >= kMaxReportedMatches) return matches;
            cursor = found + 1;
        }
    }
    return matches;
}

std::filesystem::path ModuleDirectory() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return std::filesystem::current_path();
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

std::string JoinRvas(const std::vector<std::uint32_t>& rvas) {
    if (rvas.empty()) return "none";
    std::ostringstream out;
    for (std::size_t i = 0; i < rvas.size(); ++i) {
        if (i != 0) out << ',';
        out << Hex32(rvas[i]);
    }
    return out.str();
}

int Run(const std::filesystem::path& executablePath, const std::filesystem::path& reportPath) {
    std::ofstream report(reportPath, std::ios::binary | std::ios::trunc);
    if (!report) {
        std::wcerr << L"Cannot create report: " << reportPath << L"\n";
        return 2;
    }
    report << "AutoLoot compatibility report\r\n"
           << "tool_version=1\r\n"
           << "read_only=true\r\n";

    std::ifstream input(executablePath, std::ios::binary | std::ios::ate);
    if (!input) {
        report << "result=error\r\nerror=cannot_open_ACOdyssey_exe\r\n";
        std::wcerr << L"Cannot open: " << executablePath << L"\n";
        return 3;
    }
    const std::streamoff end = input.tellg();
    if (end <= 0) {
        report << "result=error\r\nerror=invalid_file_size\r\n";
        return 4;
    }
    std::vector<std::uint8_t> file(static_cast<std::size_t>(end));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(file.data()), static_cast<std::streamsize>(file.size()))) {
        report << "result=error\r\nerror=read_failed\r\n";
        return 5;
    }

    report << "file_name=ACOdyssey.exe\r\nfile_size=" << file.size() << "\r\n";
    const auto digest = Sha256(file.data(), file.size());
    if (!digest) {
        report << "result=error\r\nerror=sha256_failed\r\n";
        return 6;
    }
    const std::string sha = Hex(digest->data(), digest->size());
    report << "sha256=" << sha << "\r\n";

    const KnownBuild* known = nullptr;
    for (const auto& candidate : kKnownBuilds) {
        if (candidate.sha256 == sha && candidate.size == file.size()) {
            known = &candidate;
            break;
        }
    }
    report << "known_build=" << (known != nullptr ? known->name : "unknown_or_modified") << "\r\n"
           << "currently_supported=" << (known != nullptr && known->supported ? "true" : "false") << "\r\n";

    const auto pe = ParsePe(file);
    if (!pe) {
        report << "result=error\r\nerror=invalid_pe64\r\n";
        return 7;
    }
    report << "pe_machine=" << Hex32(pe->headers->FileHeader.Machine) << "\r\n"
           << "pe_timestamp=" << Hex32(pe->headers->FileHeader.TimeDateStamp) << "\r\n"
           << "pe_image_size=" << pe->headers->OptionalHeader.SizeOfImage << "\r\n"
           << "pe_entry_rva=" << Hex32(pe->headers->OptionalHeader.AddressOfEntryPoint) << "\r\n"
           << "pe_image_base=0x" << std::uppercase << std::hex
           << pe->headers->OptionalHeader.ImageBase << std::dec << "\r\n"
           << "section_count=" << pe->sectionCount << "\r\n";

    for (std::uint16_t i = 0; i < pe->sectionCount; ++i) {
        const auto& section = pe->sections[i];
        char name[9]{};
        std::copy_n(reinterpret_cast<const char*>(section.Name), 8, name);
        report << "section." << i << ".name=" << name << "\r\n"
               << "section." << i << ".rva=" << Hex32(section.VirtualAddress) << "\r\n"
               << "section." << i << ".raw_size=" << section.SizeOfRawData << "\r\n";
        if (section.PointerToRawData <= file.size() &&
            section.SizeOfRawData <= file.size() - section.PointerToRawData) {
            const auto sectionDigest = Sha256(file.data() + section.PointerToRawData,
                                              section.SizeOfRawData);
            if (sectionDigest) {
                report << "section." << i << ".sha256="
                       << Hex(sectionDigest->data(), sectionDigest->size()) << "\r\n";
            }
        }
    }

    for (const auto& signature : kReferenceSignatures) {
        const auto offset = RvaToOffset(*pe, signature.steamRva, signature.bytes.size(), file.size());
        report << "signature." << signature.name << ".steam_rva=" << Hex32(signature.steamRva) << "\r\n";
        if (offset) {
            report << "signature." << signature.name << ".bytes_at_steam_rva="
                   << Hex(file.data() + *offset, signature.bytes.size()) << "\r\n";
        } else {
            report << "signature." << signature.name << ".bytes_at_steam_rva=unmapped\r\n";
        }
        const auto matches = FindExecutableMatches(file, *pe, signature.bytes.data(), signature.bytes.size());
        report << "signature." << signature.name << ".exact48_count=" << matches.size() << "\r\n"
               << "signature." << signature.name << ".exact48_rvas=" << JoinRvas(matches) << "\r\n";
    }

    const std::array<std::uint8_t, 16> wrapperPrologue{
        0x40,0x53,0x48,0x83,0xEC,0x20,0x48,0x8B,0x49,0x38,0x48,0x8B,0xDA,0x49,0x8B,0xD0};
    const std::array<std::uint8_t, 16> updatePrologue{
        0x48,0x89,0x5C,0x24,0x10,0x55,0x56,0x57,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x40};
    const auto wrapperMatches = FindExecutableMatches(file, *pe, wrapperPrologue.data(), wrapperPrologue.size());
    const auto updateMatches = FindExecutableMatches(file, *pe, updatePrologue.data(), updatePrologue.size());
    report << "hook.wrapper_prefix16_count=" << wrapperMatches.size() << "\r\n"
           << "hook.wrapper_prefix16_rvas=" << JoinRvas(wrapperMatches) << "\r\n"
           << "hook.update_prefix16_count=" << updateMatches.size() << "\r\n"
           << "hook.update_prefix16_rvas=" << JoinRvas(updateMatches) << "\r\n"
           << "result=report_complete\r\n";
    report.close();

    std::wcout << L"Compatibility report created:\n" << reportPath << L"\n\n"
               << L"The game executable was only read and was not modified.\n";
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const std::filesystem::path toolDirectory = ModuleDirectory();
    const std::filesystem::path executablePath = argc >= 2
        ? std::filesystem::path(argv[1])
        : toolDirectory / kGameExecutable;
    return Run(executablePath, toolDirectory / kReportName);
}

