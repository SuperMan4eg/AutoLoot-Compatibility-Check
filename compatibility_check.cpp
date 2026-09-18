#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
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

constexpr std::array<std::wstring_view, 2> kGameExecutables{{L"ACOdyssey.exe", L"ACOdyssey_plus.exe"}};
constexpr wchar_t kReportName[] = L"AutoLootCompatibilityReport.txt";
constexpr std::size_t kSha256Size = 32;
constexpr unsigned kToolVersion = 13;

struct KnownBuild {
    std::string_view name;
    std::string_view sha256;
    std::uint64_t size;
    bool supported;
};

constexpr std::array<KnownBuild, 5> kKnownBuilds{{
    {"steam_1_5_6", "AC327DAD2CBBDD72A3FDA8E99CBEAB9D12AF328363E4F09BC5674BDD36B8C483", 286453072ULL, true},
    {"ubisoft_connect_1_5_6", "3CB92F72823DB2C5EC24B77ADCD2325C9E1C61DBDB3E7EEA87151374F49B1A07", 285838672ULL, true},
    {"game_1_5_3_candidate", "3453FC6A34792F5C1D71053B7BAB7446E700DAF347F2575E1E8B25006F33F400", 285195944ULL, false},
    {"gamepass_plus_1_5_6_candidate", "422439DA0C0F282B29C6C17F3BDC7B3D81B624B7ACEC2B9C69AED2CA22896560", 501398864ULL, false},
    {"steam_1_5_6_longer_draw_distance_candidate", "72BEF41A699ED58EE326262FB8621BF118EA9767B5C9B1BC642668F81A738351", 286453072ULL, false},
}};

struct ReferenceSignature {
    std::string_view name;
    std::uint32_t steamRva;
    std::array<std::uint8_t, 48> bytes;
};

struct StaticProbe {
    std::string_view name;
    std::uint32_t steamRva;
};

constexpr std::array<std::uint8_t, 8> kInstantPrimaryHoldPattern{
    0xF3,0x0F,0x10,0xBF,0x34,0x04,0x00,0x00};
constexpr std::array<std::uint8_t, 8> kInstantDismantleHoldPattern{
    0xF3,0x0F,0x10,0xBF,0x38,0x04,0x00,0x00};
constexpr std::array<std::uint8_t, 18> kCorpseLootRequestPattern{
    0x48,0x83,0xEC,0x68,0x4C,0x8D,0x44,0x24,0x20,
    0x48,0xC7,0x44,0x24,0x58,0x00,0x00,0x00,0x00};

constexpr std::array<StaticProbe, 39> kStaticProbes{{
    {"activation_logic_component", 0x43AD428U},
    {"interact_component", 0x43AA2C0U},
    {"visual", 0x40C28C8U},
    {"visual_proxy_component", 0x40C6898U},
    {"animus_pulse_component", 0x439F900U},
    {"reward_component", 0x43AC3A8U},
    {"sound_component", 0x41B3358U},
    {"fx_component", 0x4190FF8U},
    {"rigid_body_component", 0x4106C50U},
    {"guidance_system", 0x416A9E8U},
    {"rack_component_4397f28", 0x4397F28U},
    {"rack_component_43979a8", 0x43979A8U},
    {"rack_component_4152998", 0x4152998U},
    {"rack_component_41b2d08", 0x41B2D08U},
    {"rack_component_4134cb8", 0x4134CB8U},
    {"rack_component_4159860", 0x4159860U},
    {"rack_variant_component_414ffe8", 0x414FFE8U},
    {"rack_variant_component_414fc10", 0x414FC10U},
    {"ammo_rack_component_418d188", 0x418D188U},
    {"icon_offset_component", 0x4417AE8U},
    {"eagle_vision_component", 0x43CC248U},
    {"skeleton_component", 0x40FEEE8U},
    {"anim_component", 0x4100438U},
    {"instant_primary_hold_end_load", 0x18E5D2DU},
    {"instant_dismantle_end_load", 0x18E5D3BU},
    {"corpse_player_kill_event_vtable", 0x43CAA28U},
    {"corpse_character_entity_vtable", 0x417AB98U},
    {"corpse_player_only_component_vtable", 0x4417548U},
    {"corpse_collectible_component_vtable", 0x439D608U},
    {"corpse_event_dispatch_thunk", 0x00A5DC70U},
    {"corpse_loot_request_function", 0x02918AE0U},
    {"extended_reach_spatial_filter", 0x36A9870U},
    {"extended_reach_target_range_filter", 0x36A99D0U},
    {"extended_reach_world_transform", 0x00A608C0U},
    {"extended_reach_target_range_callsite", 0x36AE0C0U},
    {"extended_reach_spatial_callsite_1", 0x36B5907U},
    {"extended_reach_spatial_callsite_2", 0x36B5A98U},
    {"extended_reach_spatial_callsite_3", 0x36B5BD7U},
    {"extended_reach_spatial_callsite_4", 0x36B5E0FU},
}};

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


struct Rel32Resolution {
    std::uint32_t sourceRva{};
    std::uint32_t resolvedRva{};
    unsigned depth{};
};

std::optional<Rel32Resolution> ResolveRel32JumpChain(
        const std::vector<std::uint8_t>& file, const PeInfo& pe,
        std::uint32_t sourceRva, unsigned maxDepth = 4) {
    std::uint32_t current = sourceRva;
    unsigned depth = 0;
    for (; depth < maxDepth; ++depth) {
        const auto offset = RvaToOffset(pe, current, 5, file.size());
        if (!offset || file[*offset] != 0xE9) break;
        std::int32_t displacement = 0;
        std::memcpy(&displacement, file.data() + *offset + 1, sizeof(displacement));
        const std::int64_t next = static_cast<std::int64_t>(current) + 5 + displacement;
        if (next < 0 || next > 0xFFFFFFFFLL || next == current) return std::nullopt;
        current = static_cast<std::uint32_t>(next);
    }
    if (depth == 0 || !RvaToOffset(pe, current, 1, file.size())) return std::nullopt;
    return Rel32Resolution{sourceRva, current, depth};
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

bool IsRelocationByte(std::string_view name, std::size_t index) {
    if (name == "interaction_wrapper") return index >= 20 && index <= 23;
    if (name == "game_update") return index >= 19 && index <= 22;
    if (name == "get_targeting") {
        return (index >= 10 && index <= 13) || (index >= 23 && index <= 26);
    }
    if (name == "interaction_emitter") return index >= 19 && index <= 22;
    return false;
}

bool MaskedEqual(const std::uint8_t* candidate, const ReferenceSignature& signature) {
    for (std::size_t index = 0; index < signature.bytes.size(); ++index) {
        if (!IsRelocationByte(signature.name, index) && candidate[index] != signature.bytes[index]) {
            return false;
        }
    }
    return true;
}

std::vector<std::uint32_t> FindMaskedExecutableMatches(const std::vector<std::uint8_t>& file,
                                                       const PeInfo& pe,
                                                       const ReferenceSignature& signature) {
    std::vector<std::uint32_t> matches;
    constexpr std::size_t kMaxReportedMatches = 64;
    for (std::uint16_t index = 0; index < pe.sectionCount; ++index) {
        const auto& section = pe.sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            section.PointerToRawData >= file.size()) continue;
        const std::size_t begin = section.PointerToRawData;
        const std::size_t available = file.size() - begin;
        const std::size_t length = std::min<std::size_t>(section.SizeOfRawData, available);
        if (length < signature.bytes.size()) continue;
        const std::size_t finalOffset = begin + length - signature.bytes.size();
        for (std::size_t offset = begin; offset <= finalOffset; ++offset) {
            if (file[offset] != signature.bytes[0]) continue;
            if (!MaskedEqual(file.data() + offset, signature)) continue;
            const auto delta = offset - section.PointerToRawData;
            matches.push_back(section.VirtualAddress + static_cast<std::uint32_t>(delta));
            if (matches.size() >= kMaxReportedMatches) return matches;
        }
    }
    return matches;
}

std::vector<std::uint32_t> FindRelativeCallSites(const std::vector<std::uint8_t>& file,
                                                 const PeInfo& pe,
                                                 std::uint32_t targetRva) {
    std::vector<std::uint32_t> matches;
    constexpr std::size_t kMaxReportedMatches = 64;
    for (std::uint16_t index = 0; index < pe.sectionCount; ++index) {
        const auto& section = pe.sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            section.PointerToRawData >= file.size()) continue;
        const std::size_t begin = section.PointerToRawData;
        const std::size_t available = file.size() - begin;
        const std::size_t length = std::min<std::size_t>(section.SizeOfRawData, available);
        if (length < 5) continue;
        for (std::size_t offset = begin; offset <= begin + length - 5; ++offset) {
            if (file[offset] != 0xE8) continue;
            std::int32_t displacement = 0;
            std::memcpy(&displacement, file.data() + offset + 1, sizeof(displacement));
            const std::uint64_t callRva = static_cast<std::uint64_t>(section.VirtualAddress) +
                                          (offset - begin);
            const std::int64_t destination = static_cast<std::int64_t>(callRva + 5) +
                                             displacement;
            if (destination == static_cast<std::int64_t>(targetRva)) {
                matches.push_back(static_cast<std::uint32_t>(callRva));
                if (matches.size() >= kMaxReportedMatches) return matches;
            }
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


void WriteRel32Resolution(std::ofstream& report,
                          const std::vector<std::uint8_t>& file,
                          const PeInfo& pe,
                          std::string_view key,
                          std::uint32_t sourceRva,
                          const ReferenceSignature* signature = nullptr) {
    const auto resolution = ResolveRel32JumpChain(file, pe, sourceRva);
    report << key << ".jump_rel32=" << (resolution ? "true" : "false") << "\r\n";
    if (!resolution) return;
    report << key << ".jump_depth=" << resolution->depth << "\r\n"
           << key << ".resolved_rva=" << Hex32(resolution->resolvedRva) << "\r\n";
    const auto bytes = RvaToOffset(pe, resolution->resolvedRva, 128, file.size());
    report << key << ".resolved_bytes128="
           << (bytes ? Hex(file.data() + *bytes, 128) : "unmapped") << "\r\n";
    if (signature != nullptr) {
        const auto sigOffset = RvaToOffset(pe, resolution->resolvedRva,
                                           signature->bytes.size(), file.size());
        const bool exact = sigOffset && std::equal(signature->bytes.begin(), signature->bytes.end(),
                                                   file.begin() + static_cast<std::ptrdiff_t>(*sigOffset));
        const bool masked = sigOffset && MaskedEqual(file.data() + *sigOffset, *signature);
        report << key << ".resolved_exact48_match=" << (exact ? "true" : "false") << "\r\n"
               << key << ".resolved_masked48_match=" << (masked ? "true" : "false") << "\r\n";
    }
}

void WriteCandidateWindows(std::ofstream& report,
                           const std::vector<std::uint8_t>& file,
                           const PeInfo& pe,
                           std::string_view label,
                           const std::vector<std::uint32_t>& rvas,
                           std::size_t windowSize = 128) {
    report << "candidate." << label << ".count=" << rvas.size() << "\r\n";
    for (std::size_t index = 0; index < rvas.size(); ++index) {
        report << "candidate." << label << '.' << index << ".rva="
               << Hex32(rvas[index]) << "\r\n";
        const auto offset = RvaToOffset(pe, rvas[index], windowSize, file.size());
        if (offset) {
            report << "candidate." << label << '.' << index << ".bytes"
                   << windowSize << '=' << Hex(file.data() + *offset, windowSize) << "\r\n";
        } else {
            report << "candidate." << label << '.' << index << ".bytes"
                   << windowSize << "=unmapped\r\n";
        }
    }
}

void WriteCandidateCallers(std::ofstream& report,
                           const std::vector<std::uint8_t>& file,
                           const PeInfo& pe,
                           std::string_view label,
                           const std::vector<std::uint32_t>& targets) {
    for (std::size_t index = 0; index < targets.size(); ++index) {
        const auto callers = FindRelativeCallSites(file, pe, targets[index]);
        report << "xref." << label << '.' << index << ".target_rva="
               << Hex32(targets[index]) << "\r\n"
               << "xref." << label << '.' << index << ".count="
               << callers.size() << "\r\n"
               << "xref." << label << '.' << index << ".call_rvas="
               << JoinRvas(callers) << "\r\n";
        std::vector<std::uint32_t> windows;
        windows.reserve(callers.size());
        for (const auto caller : callers) {
            windows.push_back(caller >= 32 ? caller - 32 : caller);
        }
        WriteCandidateWindows(report, file, pe,
                              std::string(label) + "_caller_" + std::to_string(index),
                              windows, 96);
    }
}

int Run(const std::filesystem::path& executablePath, const std::filesystem::path& reportPath) {
    std::ofstream report(reportPath, std::ios::binary | std::ios::trunc);
    if (!report) {
        std::wcerr << L"Cannot create report: " << reportPath << L"\n";
        return 2;
    }
    report << "AutoLoot compatibility report\r\n"
           << "tool_version=" << kToolVersion << "\r\n"
           << "read_only=true\r\n";

    std::ifstream input(executablePath, std::ios::binary | std::ios::ate);
    if (!input) {
        report << "result=error\r\nerror=cannot_open_executable\r\n";
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

    report << "file_name=" << executablePath.filename().string() << "\r\nfile_size=" << file.size() << "\r\n";
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
    const bool binaryProfileSupported = known != nullptr && known->supported;
    const bool runtimeFilenameSupported = executablePath.filename().wstring() == L"ACOdyssey.exe";
    const bool currentlySupported = binaryProfileSupported && runtimeFilenameSupported;
    report << "known_build=" << (known != nullptr ? known->name : "unknown_or_modified") << "\r\n"
           << "binary_profile_supported=" << (binaryProfileSupported ? "true" : "false") << "\r\n"
           << "runtime_filename_supported=" << (runtimeFilenameSupported ? "true" : "false") << "\r\n"
           << "currently_supported=" << (currentlySupported ? "true" : "false") << "\r\n";

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

    constexpr std::size_t kProbeSize = 64;
    for (const auto& probe : kStaticProbes) {
        const auto offset = RvaToOffset(*pe, probe.steamRva, kProbeSize, file.size());
        report << "probe." << probe.name << ".steam_rva=" << Hex32(probe.steamRva) << "\r\n";
        if (offset) {
            report << "probe." << probe.name << ".bytes64="
                   << Hex(file.data() + *offset, kProbeSize) << "\r\n";
        } else {
            report << "probe." << probe.name << ".bytes64=unmapped\r\n";
        }
        WriteRel32Resolution(report, file, *pe,
                             "probe." + std::string(probe.name), probe.steamRva);
    }

    const auto instantPrimaryMatches = FindExecutableMatches(
        file, *pe, kInstantPrimaryHoldPattern.data(), kInstantPrimaryHoldPattern.size());
    const auto instantDismantleMatches = FindExecutableMatches(
        file, *pe, kInstantDismantleHoldPattern.data(), kInstantDismantleHoldPattern.size());
    report << "instant_hold.primary.count=" << instantPrimaryMatches.size() << "\r\n"
           << "instant_hold.primary.rvas=" << JoinRvas(instantPrimaryMatches) << "\r\n"
           << "instant_hold.dismantle.count=" << instantDismantleMatches.size() << "\r\n"
           << "instant_hold.dismantle.rvas=" << JoinRvas(instantDismantleMatches) << "\r\n";
    WriteCandidateWindows(report, file, *pe, "instant_hold_primary", instantPrimaryMatches, 96);
    WriteCandidateWindows(report, file, *pe, "instant_hold_dismantle", instantDismantleMatches, 96);

    const auto corpseLootRequestMatches = FindExecutableMatches(
        file, *pe, kCorpseLootRequestPattern.data(), kCorpseLootRequestPattern.size());
    report << "corpse.loot_request.count=" << corpseLootRequestMatches.size() << "\r\n"
           << "corpse.loot_request.rvas=" << JoinRvas(corpseLootRequestMatches) << "\r\n";
    WriteCandidateWindows(report, file, *pe, "corpse_loot_request", corpseLootRequestMatches, 128);

    for (const auto& signature : kReferenceSignatures) {
        const auto offset = RvaToOffset(*pe, signature.steamRva, signature.bytes.size(), file.size());
        report << "signature." << signature.name << ".steam_rva=" << Hex32(signature.steamRva) << "\r\n";
        if (offset) {
            report << "signature." << signature.name << ".bytes_at_steam_rva="
                   << Hex(file.data() + *offset, signature.bytes.size()) << "\r\n";
        } else {
            report << "signature." << signature.name << ".bytes_at_steam_rva=unmapped\r\n";
        }
        WriteRel32Resolution(report, file, *pe,
                             "signature." + std::string(signature.name),
                             signature.steamRva, &signature);
        const auto matches = FindExecutableMatches(file, *pe, signature.bytes.data(), signature.bytes.size());
        const auto maskedMatches = FindMaskedExecutableMatches(file, *pe, signature);
        report << "signature." << signature.name << ".exact48_count=" << matches.size() << "\r\n"
               << "signature." << signature.name << ".exact48_rvas=" << JoinRvas(matches) << "\r\n"
               << "signature." << signature.name << ".masked48_count=" << maskedMatches.size() << "\r\n"
               << "signature." << signature.name << ".masked48_rvas=" << JoinRvas(maskedMatches) << "\r\n";
        if (signature.name == "interaction_wrapper" ||
            signature.name == "interaction_emitter") {
            WriteCandidateWindows(report, file, *pe, signature.name, maskedMatches);
            WriteCandidateCallers(report, file, *pe, signature.name, maskedMatches);
        }
    }

    const std::array<std::uint8_t, 16> wrapperPrologue{
        0x40,0x53,0x48,0x83,0xEC,0x20,0x48,0x8B,0x49,0x38,0x48,0x8B,0xDA,0x49,0x8B,0xD0};
    const std::array<std::uint8_t, 16> updatePrologue{
        0x48,0x89,0x5C,0x24,0x10,0x55,0x56,0x57,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x40};
    const std::array<std::uint8_t, 18> spatialFilterPrologue{
        0x40,0x55,0x56,0x57,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x58,
        0x41,0x8B,0x68,0x08};
    const std::array<std::uint8_t, 19> targetRangeFilterPrologue{
        0x4C,0x8B,0xDC,0x55,0x56,0x57,0x41,0x54,0x41,0x56,0x41,0x57,0x48,0x81,
        0xEC,0xF8,0x00,0x00,0x00};
    const auto wrapperMatches = FindExecutableMatches(file, *pe, wrapperPrologue.data(), wrapperPrologue.size());
    const auto updateMatches = FindExecutableMatches(file, *pe, updatePrologue.data(), updatePrologue.size());
    const auto spatialFilterMatches = FindExecutableMatches(
        file, *pe, spatialFilterPrologue.data(), spatialFilterPrologue.size());
    const auto targetRangeFilterMatches = FindExecutableMatches(
        file, *pe, targetRangeFilterPrologue.data(), targetRangeFilterPrologue.size());
    report << "hook.wrapper_prefix16_count=" << wrapperMatches.size() << "\r\n"
           << "hook.wrapper_prefix16_rvas=" << JoinRvas(wrapperMatches) << "\r\n"
           << "hook.update_prefix16_count=" << updateMatches.size() << "\r\n"
           << "hook.update_prefix16_rvas=" << JoinRvas(updateMatches) << "\r\n"
           << "hook.spatial_filter_prefix18_count=" << spatialFilterMatches.size() << "\r\n"
           << "hook.spatial_filter_prefix18_rvas=" << JoinRvas(spatialFilterMatches) << "\r\n"
           << "hook.target_range_filter_prefix19_count=" << targetRangeFilterMatches.size() << "\r\n"
           << "hook.target_range_filter_prefix19_rvas=" << JoinRvas(targetRangeFilterMatches) << "\r\n";
    WriteCandidateWindows(report, file, *pe, "wrapper_prefix16", wrapperMatches);
    WriteCandidateCallers(report, file, *pe, "wrapper_prefix16", wrapperMatches);
    WriteCandidateWindows(report, file, *pe, "spatial_filter_prefix18", spatialFilterMatches);
    WriteCandidateWindows(report, file, *pe, "target_range_filter_prefix19", targetRangeFilterMatches);

    // A transparent manual-E wrapper trace on the exact 1.5.3 build returned
    // to RVA 0x3626DAE. Resolve the PE unwind entry that contains that return
    // address instead of assuming the callback has the same offset as 1.5.6.
    constexpr std::uint32_t kManualWrapperReturn153Rva = 0x3626DAEU;
    report << "trace.manual_wrapper_return_153_rva="
           << Hex32(kManualWrapperReturn153Rva) << "\r\n";
    struct RuntimeFunctionEntry {
        std::uint32_t beginAddress;
        std::uint32_t endAddress;
        std::uint32_t unwindInfoAddress;
    };
    static_assert(sizeof(RuntimeFunctionEntry) == 12);
    const auto& exceptionDirectory =
        pe->headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    const auto exceptionOffset = RvaToOffset(
        *pe, exceptionDirectory.VirtualAddress, exceptionDirectory.Size, file.size());
    const RuntimeFunctionEntry* containingFunction = nullptr;
    if (exceptionOffset &&
        exceptionDirectory.Size % sizeof(RuntimeFunctionEntry) == 0) {
        const auto* entries = reinterpret_cast<const RuntimeFunctionEntry*>(
            file.data() + *exceptionOffset);
        const std::size_t entryCount =
            exceptionDirectory.Size / sizeof(RuntimeFunctionEntry);
        for (std::size_t index = 0; index < entryCount; ++index) {
            if (kManualWrapperReturn153Rva >= entries[index].beginAddress &&
                kManualWrapperReturn153Rva < entries[index].endAddress) {
                containingFunction = &entries[index];
                break;
            }
        }
    }
    if (containingFunction != nullptr) {
        report << "trace.containing_function_153_begin_rva="
               << Hex32(containingFunction->beginAddress) << "\r\n"
               << "trace.containing_function_153_end_rva="
               << Hex32(containingFunction->endAddress) << "\r\n"
               << "trace.containing_function_153_unwind_rva="
               << Hex32(containingFunction->unwindInfoAddress) << "\r\n";
        constexpr std::size_t kContainingFunctionWindowSize = 512;
        const auto functionOffset = RvaToOffset(
            *pe, containingFunction->beginAddress,
            kContainingFunctionWindowSize, file.size());
        if (functionOffset) {
            report << "trace.containing_function_153_bytes512="
                   << Hex(file.data() + *functionOffset,
                          kContainingFunctionWindowSize) << "\r\n";
        } else {
            report << "trace.containing_function_153_bytes512=unmapped\r\n";
        }
    } else {
        report << "trace.containing_function_153_begin_rva=not_found\r\n";
    }

    const bool isExact153 = known != nullptr &&
        known->name == "game_1_5_3_candidate";
    const std::uint32_t mappedSpatialFilterRva =
        isExact153 ? 0x368D4E0U : 0x36A9870U;
    const std::uint32_t mappedTargetRangeFilterRva =
        isExact153 ? 0x368D640U : 0x36A99D0U;
    report << "reach.mapping_profile="
           << (isExact153 ? "game_1_5_3" : "steam_reference") << "\r\n"
           << "reach.spatial_filter_rva=" << Hex32(mappedSpatialFilterRva) << "\r\n"
           << "reach.target_range_filter_rva="
           << Hex32(mappedTargetRangeFilterRva) << "\r\n";
    WriteCandidateCallers(report, file, *pe, "reach_spatial_filter",
                          std::vector<std::uint32_t>{mappedSpatialFilterRva});
    WriteCandidateCallers(report, file, *pe, "reach_target_range_filter",
                          std::vector<std::uint32_t>{mappedTargetRangeFilterRva});
    report << "result=report_complete\r\n";
    report.close();

    return 0;
}

struct ReportSummary {
    std::string fileName{"unknown"};
    std::string knownBuild{"unknown_or_modified"};
    std::string profileHint{"unknown_odyssey_build"};
    std::string assessment{"unknown_requires_manual_mapping"};
    bool supported{};
    bool binaryProfileSupported{};
    bool runtimeFilenameSupported{};
    unsigned signatureUnique{};
    unsigned signatureAmbiguous{};
    unsigned signatureMissing{};
    unsigned hookUnique{};
    unsigned hookAmbiguous{};
    unsigned hookMissing{};
    std::array<std::string, 5> signatureStates{};
    std::array<std::string, 4> hookStates{};
};

std::vector<std::string> ReadReportLines(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}
std::optional<std::string> ReportValue(const std::vector<std::string>& lines,
                                       std::string_view key) {
    const std::string prefix = std::string(key) + '=';
    for (const auto& line : lines) {
        if (line.rfind(prefix, 0) == 0) return line.substr(prefix.size());
    }
    return std::nullopt;
}

unsigned ReportCount(const std::vector<std::string>& lines, std::string_view key) {
    const auto value = ReportValue(lines, key);
    if (!value) return 0;
    try {
        return static_cast<unsigned>(std::stoul(*value));
    } catch (...) {
        return 0;
    }
}

std::string CandidateState(unsigned count) {
    if (count == 1) return "unique";
    if (count > 1) return "ambiguous";
    return "missing";
}

void ClassifyCandidateCount(unsigned count, unsigned& unique,
                            unsigned& ambiguous, unsigned& missing) {
    if (count == 1) ++unique;
    else if (count > 1) ++ambiguous;
    else ++missing;
}
ReportSummary SummarizeReport(const std::filesystem::path& path) {
    const auto lines = ReadReportLines(path);
    ReportSummary summary{};
    if (const auto value = ReportValue(lines, "file_name")) summary.fileName = *value;
    if (const auto value = ReportValue(lines, "known_build")) summary.knownBuild = *value;
    summary.supported = ReportValue(lines, "currently_supported").value_or("false") == "true";
    summary.binaryProfileSupported = ReportValue(lines, "binary_profile_supported").value_or("false") == "true";
    summary.runtimeFilenameSupported = ReportValue(lines, "runtime_filename_supported").value_or("false") == "true";

    constexpr std::array<std::string_view, 5> signatures{{
        "interaction_wrapper", "game_update", "get_targeting",
        "get_selected", "interaction_emitter"}};
    for (std::size_t index = 0; index < signatures.size(); ++index) {
        const auto name = signatures[index];
        const std::string base = "signature." + std::string(name);
        const unsigned exact = ReportCount(lines, base + ".exact48_count");
        const unsigned masked = ReportCount(lines, base + ".masked48_count");
        const bool resolvedMatch = ReportValue(lines, base + ".resolved_masked48_match").value_or("false") == "true";
        const unsigned effective = exact != 0 ? exact : (masked != 0 ? masked : (resolvedMatch ? 1U : 0U));
        summary.signatureStates[index] = resolvedMatch && exact == 0 && masked == 0
            ? "resolved_unique" : CandidateState(effective);
        ClassifyCandidateCount(effective, summary.signatureUnique,
                               summary.signatureAmbiguous, summary.signatureMissing);
    }

    constexpr std::array<std::string_view, 4> hooks{{
        "hook.wrapper_prefix16_count", "hook.update_prefix16_count",
        "hook.spatial_filter_prefix18_count", "hook.target_range_filter_prefix19_count"}};
    for (std::size_t index = 0; index < hooks.size(); ++index) {
        const unsigned count = ReportCount(lines, hooks[index]);
        summary.hookStates[index] = CandidateState(count);
        ClassifyCandidateCount(count, summary.hookUnique, summary.hookAmbiguous, summary.hookMissing);
    }

    const bool recognized = summary.knownBuild != "unknown_or_modified";
    if (recognized) summary.profileHint = summary.knownBuild;
    else if (summary.fileName == "ACOdyssey_plus.exe")
        summary.profileHint = "gamepass_or_ubisoft_plus_unknown";

    if (summary.supported) summary.assessment = "recognized_supported";
    else if (recognized && summary.binaryProfileSupported && !summary.runtimeFilenameSupported)
        summary.assessment = "recognized_binary_profile_runtime_name_unsupported";
    else if (recognized) summary.assessment = "recognized_unsupported_candidate";
    else if (summary.signatureUnique >= 2 || summary.hookUnique >= 1)
        summary.assessment = "unknown_partially_mappable";
    return summary;
}

void AppendPrefixedReport(std::ofstream& report, const std::filesystem::path& path,
                          std::size_t index) {
    for (const auto& line : ReadReportLines(path)) {
        if (line.empty() || line == "AutoLoot compatibility report" ||
            line.rfind("tool_version=", 0) == 0 || line == "read_only=true") continue;
        report << "scan." << index << '.' << line << "\r\n";
    }
}
void WriteSummary(std::ofstream& report, const ReportSummary& summary, std::size_t index) {
    const bool recognized = summary.knownBuild != "unknown_or_modified";
    report << "summary." << index << ".file_name=" << summary.fileName << "\r\n"
           << "summary." << index << ".recognized=" << (recognized ? "true" : "false") << "\r\n"
           << "summary." << index << ".supported=" << (summary.supported ? "true" : "false") << "\r\n"
           << "summary." << index << ".binary_profile_supported=" << (summary.binaryProfileSupported ? "true" : "false") << "\r\n"
           << "summary." << index << ".runtime_filename_supported=" << (summary.runtimeFilenameSupported ? "true" : "false") << "\r\n"
           << "summary." << index << ".profile_hint=" << summary.profileHint << "\r\n"
           << "summary." << index << ".signature_unique=" << summary.signatureUnique << "\r\n"
           << "summary." << index << ".signature_ambiguous=" << summary.signatureAmbiguous << "\r\n"
           << "summary." << index << ".signature_missing=" << summary.signatureMissing << "\r\n"
           << "summary." << index << ".hook_unique=" << summary.hookUnique << "\r\n"
           << "summary." << index << ".hook_ambiguous=" << summary.hookAmbiguous << "\r\n"
           << "summary." << index << ".hook_missing=" << summary.hookMissing << "\r\n"
           << "summary." << index << ".known_build=" << summary.knownBuild << "\r\n"
           << "summary." << index << ".porting_assessment=" << summary.assessment << "\r\n";
    constexpr std::array<std::string_view, 5> signatureNames{{"interaction_wrapper", "game_update", "get_targeting", "get_selected", "interaction_emitter"}};
    for (std::size_t item = 0; item < signatureNames.size(); ++item)
        report << "summary." << index << ".signature." << signatureNames[item] << '=' << summary.signatureStates[item] << "\r\n";
    constexpr std::array<std::string_view, 4> hookNames{{"wrapper_prefix16", "update_prefix16", "spatial_filter_prefix18", "target_range_filter_prefix19"}};
    for (std::size_t item = 0; item < hookNames.size(); ++item)
        report << "summary." << index << ".hook." << hookNames[item] << '=' << summary.hookStates[item] << "\r\n";
}

void AddIfPresent(std::vector<std::filesystem::path>& paths,
                  const std::filesystem::path& candidate) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(candidate, error)) return;
    if (std::find(paths.begin(), paths.end(), candidate) == paths.end()) paths.push_back(candidate);
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    const std::filesystem::path toolDirectory = ModuleDirectory();
    std::vector<std::filesystem::path> executables;
    const bool explicitMode = argc >= 2;
    if (explicitMode) {
        for (int index = 1; index < argc; ++index) AddIfPresent(executables, argv[index]);
    } else {
        for (const auto name : kGameExecutables) AddIfPresent(executables, toolDirectory / name);
    }

    const std::filesystem::path reportPath = toolDirectory / kReportName;
    if (executables.empty()) {
        std::ofstream report(reportPath, std::ios::binary | std::ios::trunc);
        report << "AutoLoot compatibility report\r\n"
               << "tool_version=" << kToolVersion << "\r\nread_only=true\r\n"
               << "scan_mode=" << (explicitMode ? "explicit" : "automatic") << "\r\n"
               << "scan_count=0\r\n"
               << "expected_file_names=ACOdyssey.exe,ACOdyssey_plus.exe\r\n"
               << "result=error\r\nerror=no_game_executable_found\r\n";
        std::wcerr << L"No ACOdyssey.exe or ACOdyssey_plus.exe found next to the checker.\n";
        return 3;
    }
    std::vector<std::filesystem::path> temporaryReports;
    std::vector<ReportSummary> summaries;
    std::vector<int> statuses;
    for (std::size_t index = 0; index < executables.size(); ++index) {
        const auto temp = toolDirectory /
            (L".AutoLootCompatibilityReport." + std::to_wstring(index) + L".tmp");
        statuses.push_back(Run(executables[index], temp));
        temporaryReports.push_back(temp);
        summaries.push_back(SummarizeReport(temp));
    }

    std::ofstream report(reportPath, std::ios::binary | std::ios::trunc);
    if (!report) {
        std::wcerr << L"Cannot create report: " << reportPath << L"\n";
        return 2;
    }
    report << "AutoLoot compatibility report\r\n"
           << "tool_version=" << kToolVersion << "\r\n"
           << "read_only=true\r\n"
           << "scan_mode=" << (explicitMode ? "explicit" : "automatic") << "\r\n"
           << "scan_count=" << executables.size() << "\r\n"
           << "expected_file_names=ACOdyssey.exe,ACOdyssey_plus.exe\r\n";
    bool anyError = false;
    for (std::size_t index = 0; index < executables.size(); ++index) {
        report << "scan." << index << ".requested_file_name="
               << executables[index].filename().string() << "\r\n";
        AppendPrefixedReport(report, temporaryReports[index], index);
        WriteSummary(report, summaries[index], index);
        if (statuses[index] != 0) anyError = true;
    }
    report << "result=" << (anyError ? "report_complete_with_errors" : "report_complete") << "\r\n";
    report.close();

    for (const auto& temp : temporaryReports) {
        std::error_code error;
        std::filesystem::remove(temp, error);
    }

    std::wcout << L"Compatibility report created:\n" << reportPath << L"\n\n"
               << L"Scanned " << executables.size() << L" executable(s).\n"
               << L"The game executable files were only read and were not modified.\n";
    return anyError ? 1 : 0;
}
