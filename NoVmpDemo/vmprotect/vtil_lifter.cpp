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
#include "vtil_lifter.hpp"
#include "architecture.hpp"
#include "debug.hpp"
#include "deobfuscator.hpp"
#include "il2vtil.hpp"
#include "subroutines.hpp"
#include <vector>

using namespace vtil::logger;

namespace vmp {
vtil::basic_block *lift_il(vtil::basic_block *block, vm_state *vstate) {
    // If virtual instruction pointer is not set:
    //
    if (!vstate->vip) {
        // Parse VMENTER:
        //
        auto [entry_stack, entry_vip] = parse_vmenter(vstate, vstate->current_handler_rva);
        vstate->vip = entry_vip;

        // Begin block if none passed.
        //
        if (!block) {
            block = vtil::basic_block::begin(entry_vip);
        }
        // Otherwise, fork the block.
        //
        else {
            auto new_block = block->fork(entry_vip);
            // If returned nullptr, it's already explored, skip.
            //
            if (!new_block) {
                std::lock_guard g(block->owner->mutex);
                block = block->owner->explored_blocks[entry_vip];
                fassert(block);
                // TODO: Trace possible exits once more ?.
                //
                return block;
            }
            block = new_block;
        }

        // Insert push instructions.
        //
        for (auto &op : entry_stack)
            block->push(op);

        // Push relocation offset.
        //
        auto treloc = block->tmp(64);
        block->mov(treloc, vtil::REG_IMGBASE)
            ->sub(treloc, vstate->img->get_real_image_base())
            ->push(treloc);
    } else {
        // If passed block is nullptr, it's already explored, skip.
        //
        if (!block)
            return nullptr;
    }

    instruction_stream is;
    arch::instruction il_instruction;
    while (1) {
        // Skip to next handler and continue parsing the flow linearly
        //
        vtil::vip_t handler_vip = vstate->next();

        if (!vstate->img->rva_to_section(vstate->current_handler_rva)) {
            // TODO: Whoooops.
            //
            vtil::debug::dump(block->prev[0]);
            throw std::runtime_error("Whoooops invalid virtual jump.");
        }

        // Unroll the stream
        //
        is = vstate->unroll();
        instruction_stream is_reduced = is;

        // Classify the handler into an instruction
        //
        std::vector parameters = extract_parameters(vstate, is_reduced);
        reduce_chunk(vstate, is_reduced, parameters);
        il_instruction = arch::classify(vstate, is_reduced);

        if (verbosity >= 1) {
            log<CON_YLW>("%s (", il_instruction.op);
            for (int i = 0; i < il_instruction.parameters.size(); i++) {
                log<CON_YLW>("%#x,", il_instruction.parameters[i]);
            }
            log<CON_YLW>(")\n", il_instruction.op);
            log<CON_BLU>(">> REDUCED\n");
            is_reduced.dump();
            if (verbosity >= 2) {
                log<CON_BLU>(">> FULL\n");
                is.dump();
            }
        }

        // Break out of the loop to handle special VM instructions
        //
        if (il_instruction.op == "VJMP" || il_instruction.op == "VEXIT")
            break;

        // Translate from VMP Arch to VTIL and continue processing
        //
        block->label_begin(handler_vip);
        translate(block, il_instruction);
        block->label_end();
    }

    if (il_instruction.op == "VJMP") {
        handle_vjmp(vstate, block);
    } else if (il_instruction.op == "VEXIT") {
        handle_vexit(vstate, block, is);
    }

    return block;
}
}; // namespace vmp