// Copyright (C) 2020 Can Boluk
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
#include "vmprotect/debug.hpp"
#include "vmprotect/image_desc.hpp"
#include "vmprotect/vm_state.hpp"
#include "vmprotect/vtil_lifter.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <future>
#include <linuxpe>
#include <tuple>
#include <vector>
#include <x86intrin.h>

using namespace vtil::logger;

uint8_t vmp::verbosity = 0;

static std::vector<uint8_t> read_raw(const std::string &file_path) {
    // Try to open file as binary
    std::ifstream file(file_path, std::ios::binary);
    if (!file.good())
        error("Input file cannot be opened.");

    // Read the whole file
    std::vector<uint8_t> bytes = std::vector<uint8_t>(std::istreambuf_iterator<char>(file), {});
    if (bytes.size() == 0)
        error("Input file is empty.");
    return bytes;
}

static void write_raw(void *data, size_t size, const std::string &file_path) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.good())
        error("File cannot be opened for write.");
    file.write((char *)data, size);
}

int main(int argc, const char **argv) {
    vtil::logger::error_hook = [](const std::string &message) {
        log<CON_RED>("[*] Unexpected error: %s\n", message);
        throw std::runtime_error(message);
    };

    // Parse command line.
    //
    if (argc < 2)
        error("No input file provided.");
    std::filesystem::path image_path(argv[1]);
    std::filesystem::path working_directory = vtil::make_copy(image_path).remove_filename() / "vms";
    std::filesystem::create_directory(working_directory);

    // Create the basic descriptor for the image
    //
    vmp::image_desc *desc = new vmp::image_desc;
    desc->raw = read_raw(image_path.string());
    desc->override_image_base = 0;
    desc->has_relocs =
        desc->get_nt_headers()->optional_header.data_directories.basereloc_directory.present();

    // Warn if relocs are stripped.
    //
    if (!desc->has_relocs)
        warning("This image has relocations stripped, NoVmp is not 100%% compatible with this "
                "switch yet.");

    // Parse options:
    //
    bool optimize = true;
    bool entrypoint = false;
    std::vector<uint32_t> target_vms;
    for (int i = 2; i < argc;) {
        if (!strcmp(argv[i], "-vms")) {
            while (++i < argc && argv[i][0] != '-')
                target_vms.emplace_back(strtoul(argv[i], nullptr, 16));
        } else if (!strcmp(argv[i], "-sections")) {
            while (++i < argc && argv[i][0] != '-')
                vmp::section_prefixes.emplace_back(argv[i]);
        } else if (!strcmp(argv[i], "-base")) {
            fassert(++i < argc);
            desc->override_image_base = strtoull(argv[i], nullptr, 16);
            desc->has_relocs = true;
            i++;
        } else if (!strcmp(argv[i], "-noopt")) {
            optimize = false;
            i++;
        } else if (!strcmp(argv[i], "-entry")) {
            entrypoint = true;
            i++;
        } else if (!strcmp(argv[i], "-verbosity")) {
            if (i + 1 >= argc)
                error("Missing verbosity value");
            vmp::verbosity = strtoul(argv[i + 1], nullptr, 10);
            i += 2;
        } else {
            error("Unknown parameter: %s", argv[i]);
        }
    }

    if (entrypoint) {
        // FIXME: ensure the entrypoint contains a vmenter
        uint32_t entry_rva = desc->get_nt_headers()->optional_header.entry_point;
        log<CON_YLW>("Discovered vmenter at entrypoint (%p)\n", entry_rva);
        desc->virt_routines.push_back(
            vmp::virtual_routine{.jmp_rva = entry_rva, .mid_routine = false});
    }

    // Iterate each section:
    //
    uint32_t rva_high = 0;
    uint32_t raw_low = 0;
    for (int i = 0; i < desc->get_nt_headers()->file_header.num_sections; i++) {
        // Reference section and re-calculate some stats
        //
        win::section_header_t *scn = desc->get_nt_headers()->get_section(i);
        rva_high = std::max(scn->virtual_address + std::max(scn->virtual_size, scn->size_raw_data),
                            rva_high);
        raw_low = std::max(scn->ptr_raw_data, raw_low);

        log<CON_YLW>("Parsing section %s\n", scn->name.short_name);

        // Skip if it cannot be executed
        //
        if (!scn->characteristics.mem_execute)
            continue;

        // Iterate each byte
        //
        uint8_t *scn_begin = desc->raw.data() + scn->ptr_raw_data;
        uint8_t *scn_end = scn_begin + std::min(scn->size_raw_data, scn->virtual_size);

        for (uint8_t *it = scn_begin; it < (scn_end - 10); it++) {
            // Skip if not [JMP rel32] OR [CALL rel32 NOP]
            //
            bool mid_func = false;
            if (it[0] == 0xE9)
                mid_func = true;
            else if (it[0] == 0xE8)
                mid_func = false;
            else
                continue;
            uint32_t jmp_rva = scn->virtual_address + (it - scn_begin) + 5 + *(int32_t *)&it[1];

            // Skip if JMP target is in the same section / in a non-executable section
            //
            win::section_header_t *scn_jmp = desc->rva_to_section(jmp_rva);
            if (!scn_jmp || scn_jmp == scn || !scn_jmp->characteristics.mem_execute)
                continue;

            // Skip if it's not VMENTER
            //
            uint8_t *jmp_target_bytes =
                desc->raw.data() + jmp_rva + scn_jmp->ptr_raw_data - scn_jmp->virtual_address;
            if (jmp_target_bytes > &desc->raw.back() || jmp_target_bytes[0] != 0x68 ||
                jmp_target_bytes[5] != 0xE8)
                continue;

            // Add to image descriptor
            //
            uint64_t ptr = (scn->virtual_address + (it - scn_begin));

            desc->virt_routines.push_back(
                vmp::virtual_routine{.jmp_rva = jmp_rva, .mid_routine = mid_func});

            log<CON_YLW>("Discovered vmenter at %p\n", ptr);
        }
    }

    // If VM list is given, replace discovery.
    //
    if (!target_vms.empty())
        desc->virt_routines.clear();
    for (uint32_t rva : target_vms) {
        desc->virt_routines.push_back(vmp::virtual_routine{
            .jmp_rva = rva,
        });
    }

    // Declare the worker.
    //
    const auto vm_lifter = [&](int vm_index) -> vtil::routine * {
        // Lift the virtual machine.
        //
        vmp::virtual_routine *vr = &desc->virt_routines[vm_index];
        log<CON_DEF>("Lifting virtual-machine at %p...\n", vr->jmp_rva);
        vmp::vm_state state = {desc, vr->jmp_rva};
        vtil::routine *rtn = lift_il(&state);
        if (!rtn)
            return nullptr;

        // Save unoptimized routine.
        //
        vtil::save_routine(rtn,
                           (working_directory / vtil::format::str("%s-%p.premature.vtil",
                                                                  image_path.stem(), vr->jmp_rva))
                               .string());

        // If noopt set, return.
        //
        if (!optimize)
            return rtn;

        // Apply optimizations.
        //
        int64_t ins = rtn->num_instructions();
        int64_t blks = rtn->num_blocks();
        vtil::optimizer::apply_all_profiled(rtn);
        int64_t oins = rtn->num_instructions();
        int64_t oblks = rtn->num_blocks();

        // Write routine and optimization information.
        //
        {
            std::lock_guard _g{logger_state};
            log<CON_GRN>("\nLifted & optimized virtual-machine at %p\n", vr->jmp_rva);

            log<CON_YLW>("Optimizer stats:\n");
            log<CON_CYN>(" - Block count:       %-5d => %-5d (%.2f%%).\n", blks, oblks,
                         100.0f * float(float(oblks - blks) / blks));
            log<CON_CYN>(" - Instruction count: %-5d => %-5d (%.2f%%).\n", ins, oins,
                         100.0f * float(float(oins - ins) / ins));

            std::vector<uint8_t> bytes;
            for (auto &[_, block] : rtn->explored_blocks) {
                for (auto &ins : *block) {
                    if (ins.base->name == "vemit") {
                        uint8_t *bs = (uint8_t *)&ins.operands[0].imm().u64;
                        bytes.insert(bytes.end(), bs, bs + ins.operands[0].size());
                    }
                }
            }

            if (bytes.size()) {
                log<CON_YLW>("Special instructions:\n");

                size_t n = 0;
                auto dasm = vtil::amd64::disasm(bytes.data(), 0, bytes.size());
                for (auto &ins : dasm) {
                    n++;
                    log<CON_PRP>(" - %s\n", ins);
                    if (n > 10) {
                        log<CON_PRP>(" - ...\n");
                        break;
                    }
                }
            }
        }

        // Save optimized routine.
        //
        vtil::save_routine(rtn,
                           (working_directory / vtil::format::str("%s-%p.optimized.vtil",
                                                                  image_path.stem(), vr->jmp_rva))
                               .string());
        return rtn;
    };

    // Lift every routine and wait for completion.
    //
    std::vector<std::pair<size_t, std::future<vtil::routine *>>> worker_pool;
    for (int i = 0; i < desc->virt_routines.size(); i++)
        worker_pool.emplace_back(i, std::async(std::launch::deferred, vm_lifter, i));

    for (auto &[idx, rtn] : worker_pool) {
        try {
            desc->virt_routines[idx].routine = rtn.get();
        } catch (const std::runtime_error &ex) {
            return -1;
        } catch (const std::exception &ex) {
            log<CON_RED>("Error: %s\n", ex.what());
            return -1;
        }
    }

    return 0;
}