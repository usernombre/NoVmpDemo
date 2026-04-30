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
        if (verbosity >= 2) {
            log<CON_BLU>(">> FULL\n");
            is.dump();
        }

        // Classify the handler into an instruction
        //
        std::vector parameters = extract_parameters(vstate, is);
        instruction_stream is_reduced = is;
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
        // Pop target from stack.
        //
        auto jmp_dest = block->tmp(64);
        block->pop(jmp_dest);

        if (vstate->dir_vip < 0)
            block->sub(jmp_dest, 1);

        // If relocs stripped, substract image base, uses absolute address.
        //
        if (!vstate->img->has_relocs)
            block->sub(jmp_dest, vstate->img->get_real_image_base());

        // Insert jump to the location.
        //
        block->jmp(jmp_dest);

        // Copy the current block and pass it through optimization.
        //
        // FIXME: find a better way of cloning a block
        auto routine_copy = block->owner->clone();
        auto block_copy = routine_copy->get_block(block->entry_vip);
        vtil::optimizer::apply_all(block_copy);

        // Allocate an array of resolved destinations.
        //
        vtil::tracer tracer = {};
        std::vector<vtil::vip_t> destination_list;
        uint64_t image_base = vstate->img->has_relocs ? 0 : vstate->img->get_real_image_base();
        auto branch_info =
            vtil::optimizer::aux::analyze_branch(block_copy, &tracer, {.pack = true});
        if (vmp::verbosity >= 1) {
            log<CON_YLW>("CC: %s\n", branch_info.cc);
            log<CON_YLW>("VJMP => %s\n", branch_info.destinations);
        }
        for (auto &branch : branch_info.destinations) {
            // If not constant:
            //
            if (!branch->is_constant()) {
                // Recursively trace the expression and remove any matches of REG_IMGBASE.
                //
                branch = tracer.rtrace_pexp(*branch);
                branch
                    .transform([image_base](vtil::symbolic::expression::delegate &ex) {
                        if (ex->is_variable()) {
                            auto &var = ex->uid.get<vtil::symbolic::variable>();
                            if (var.is_register() && var.reg() == vtil::REG_IMGBASE)
                                *+ex = {image_base, ex->size()};
                        }
                    })
                    .simplify(true);
            }

            // If still not constant:
            //
            if (!branch->is_constant()) {
                // TODO: Handle switch table patterns.
                //
                log<CON_YLW>("VJMP =>\n");
                for (auto [branch, idx] : vtil::zip(branch_info.destinations, vtil::iindices)) {
                    log<CON_YLW>("-- %d) %s\n", idx, branch);
                    log<CON_YLW>(">> %s\n", tracer.rtrace_exp(*branch));
                }
                log<CON_YLW>("CC: %s\n", branch_info.cc);
                // vtil::optimizer::aux::analyze_branch( block, &tracer, false );
                throw std::runtime_error("Whoooops hit switch case...");
            }

            destination_list.push_back(*branch->get<vtil::vip_t>());
        }

        for (auto &dst : destination_list) {
            if (vmp::verbosity >= 1) {
                log<CON_YLW>("Exploring branch => %p\n", dst);
            }
            vm_state vstate_dup = *vstate;
            vstate_dup.vip = dst + (vstate->dir_vip < 0 ? +1 : 0);
            // vstate_dup.next();
            lift_il(block->fork(dst), &vstate_dup);
        }
    } else if (il_instruction.op == "VEXIT") {
        // Parse VEXIT to resolve the order registers are popped
        //
        std::vector exit_stack = parse_vmexit(vstate, is);

        // Simulate the VPOP for each register being popped in the routine
        //
        for (auto &op : exit_stack)
            block->pop(op);

        // Pop target from stack.
        //
        vtil::operand jmp_dest = block->tmp(64);
        block->pop(jmp_dest);

        // Insert vexit to the location.
        //
        block->vexit(jmp_dest);
        jmp_dest = block->back().operands[0];
    }

    return block;
}
}; // namespace vmp