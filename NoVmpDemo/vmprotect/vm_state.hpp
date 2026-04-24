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
#pragma once
#include "debug.hpp"
#include "deobfuscator.hpp"
#include "image_desc.hpp"
#include <functional>
#include <linuxpe>
#include <set>
#include <stdint.h>
#include <vtil/amd64>
#include <vtil/vtil>

namespace vmp {
using namespace vtil::logger;

struct vm_parameter {
    // Register where the parameter is written.
    //
    x86_reg output_register = X86_REG_INVALID;

    // Value of the parameter.
    //
    union {
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;

        int64_t i64;
        int32_t i32;
        int16_t i16;
        int8_t i8;
    };

    // Size of this parameter.
    //
    uint32_t size;

    // Address of the instruction where the parameter is read
    //
    uint64_t address;

    // Some helpers to extend from original size.
    //
    int64_t get_signed() const {
        switch (size) {
        case 8:
            return i64;
        case 4:
            return i32;
        case 2:
            return i16;
        case 1:
            return i8;
        default:
            unreachable();
        }
    }

    uint64_t get() const {
        switch (size) {
        case 8:
            return u64;
        case 4:
            return u32;
        case 2:
            return u16;
        case 1:
            return u8;
        default:
            unreachable();
        }
    }
};

struct vm_state {
    // The associated image
    //
    image_desc *img = nullptr;

    // RVA of the current handler
    //
    uint32_t current_handler_rva = 0;

    // RVA of the handler table
    //
    uint32_t handler_table_rva = 0;

    // RVA of the current point in virtual instruction stream
    //
    vtil::vip_t vip = 0;

    // Register that holds the virtual instruction pointer
    //
    x86_reg reg_vip = X86_REG_INVALID;

    // Register that holds the virtual stack pointer
    //
    x86_reg reg_vsp = X86_REG_INVALID;

    // Register that holds the virtual handler table
    //
    x86_reg reg_vht = X86_REG_INVALID;

    // Direction of the virtual machine instruction stream
    //
    int8_t dir_vip = 0;

    // Unrolls all instructions for the current handler
    //
    instruction_stream unroll() { return deobfuscate(img, current_handler_rva); }

    // Peeks at the virtual instruction stream without forwarding it
    //
    uint8_t *peek_vip(size_t num_bytes = 0) {
        // If inverse stream, we substract the number of bytes being read first
        if (dir_vip == -1)
            return img->rva_to_ptr<uint8_t>(vip - num_bytes);

        // Otherwise we use the current RVA
        else if (dir_vip == +1)
            return img->rva_to_ptr<uint8_t>(vip);

        // Cannot execute this operation when direction is unknown
        unreachable();
        return nullptr;
    }

    // References the N bytes from the virtual instruction stream and skips them
    //
    uint8_t *read_vip(size_t num_bytes) {
        // Peek at the stream
        uint8_t *ret = peek_vip(num_bytes);

        // If invalid, throw
        if (!ret)
            throw std::runtime_error("Invalid VIP.");

        // Skip the bytes
        vip += num_bytes * dir_vip;

        // Return the output
        return ret;
    }

    // Skips to next instruction
    //
    vtil::vip_t next() {
        vtil::vip_t handler_vip = vip;
        uint8_t handler_index = *read_vip(1);
        uint64_t *handler_table = img->rva_to_ptr<uint64_t>(handler_table_rva);
        uint64_t handler = handler_table[handler_index];
        current_handler_rva = handler - img->get_real_image_base();

        if (verbosity >= 1) {
            log<CON_BLU>("> HANDLER\n");
            log<CON_GRN>("[VIP] = [%p] = %#x\n", handler_vip, handler_index);
            log<CON_GRN>("VHT[%p] = %p\n", handler_index, current_handler_rva);
        }

        return handler_vip;
    }
};
}; // namespace vmp