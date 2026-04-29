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
#include "subroutines.hpp"
#include "debug.hpp"
#include "vtil_lifter.hpp"

using namespace vtil::logger;

namespace vmp {
// Extracts the next parameter within the given instruction stream
// - On failure returns -1 as the iterator index
std::pair<int, vm_parameter> extract_next_parameter(vm_state *state, const instruction_stream &is,
                                                    int index) {
    vm_parameter out;

    auto parameter_filter = [&](const vtil::amd64::instruction &ins) {
        if (ins.is(X86_INS_MOV, {X86_OP_REG, X86_OP_MEM}) ||
            ins.is(X86_INS_MOVZX, {X86_OP_REG, X86_OP_MEM})) {
            return ins.operands[1].mem.base == state->reg_vip && ins.operands[1].mem.disp == 0 &&
                   ins.operands[1].mem.scale == 1 && ins.operands[1].mem.index == X86_REG_INVALID;
        }
        return false;
    };

    // Find the next parameter, if available, stopping at the next handler index
    //
    int parameter_index = is.next(parameter_filter, index);
    // FIXME: find a better way of skipping the handler index
    if (parameter_index == -1 || is.size() - parameter_index <= 3)
        return {-1, {}};

    // Fill out the block details
    //
    out.address = is[parameter_index].address;
    out.size = is[parameter_index].operands[1].size;
    out.output_register = is[parameter_index].operands[0].reg;
    memcpy(&out.u64, state->read_vip(out.size), out.size);

    return {parameter_index + 1, out};
}

// Extracts all of the parameters within the given instruction stream
//
std::vector<vm_parameter> extract_parameters(vm_state *vstate, const instruction_stream &is) {
    // Iterate entire instruction stream:
    //
    std::vector<vm_parameter> out;
    for (int iterator = 0; iterator != -1 && iterator < is.stream.size();) {
        // Try to extract the next block
        //
        auto [it_next, parameter] = extract_next_parameter(vstate, is, iterator);

        // Break the loop if failed to find the block
        //
        if (it_next == -1)
            break;

        // Else push on the output list and continue iteration
        //
        out.push_back(parameter);
        iterator = it_next;
    }

    return out;
}

// Reduces the given virtualized instruction handler to the base
// (AKA Deobfuscation + I/O based Register tracing)
//
void reduce_chunk(vm_state *vstate, instruction_stream &is,
                  const std::vector<vm_parameter> &parameters) {
    // Replace parameter fetching with constants
    //
    for (const auto &parameter : parameters) {
        int index = 0;
        for (int i = 0; i < is.stream.size(); i++) {
            if (is[i].address == parameter.address) {
                index = i;
                break;
            }
        }

        // Create fake load instruction
        vtil::amd64::instruction ins;
        ins.address = -1;
        ins.id = X86_INS_INVALID;
        ins.mnemonic = "loadc";
        ins.operand_string = vtil::amd64::name(parameter.output_register);
        ins.operand_string += ", " + std::to_string(parameter.get());
        ins.regs_write.insert(parameter.output_register);

        ins.operands.resize(2);
        ins.eflags = 0;
        ins.operands[0].type = X86_OP_REG;
        ins.operands[0].reg = parameter.output_register;
        ins.operands[0].access = CS_AC_WRITE;
        ins.operands[0].size = parameter.size;

        ins.operands[1].type = X86_OP_IMM;
        ins.operands[1].imm = parameter.get();
        ins.operands[1].size = parameter.size;
        is.stream[index].second = ins;
    };

    // Trace all changes to RSP and VSP
    //
    std::map<x86_reg, bool> traced = {};
    traced[X86_REG_RSP] = true;
    traced[vstate->reg_vsp] = true;

    // If JA is present, always take the branch
    //
    int ja_i = is.next(X86_INS_JA, {X86_OP_IMM});
    if (ja_i != -1)
        is.stream.resize(ja_i);

    // Trace the instruction from the end of the control flow
    //
    instruction_stream is_reduced = {};
    for (int i = is.stream.size() - 1; i >= 0; i--) {
        auto &ins = is[i];

        // Blacklist certain instructions as they
        // mess up with our vtil::amd64::registers.extend logic or FLAGS
        //
        if (ins.id == X86_INS_CQO || ins.id == X86_INS_CWD || ins.id == X86_INS_CBW ||
            ins.id == X86_INS_CWDE || ins.id == X86_INS_CDQ || ins.id == X86_INS_CDQE ||
            ins.id == X86_INS_LAHF || ins.id == X86_INS_TEST || ins.id == X86_INS_CMP) {
            continue;
        }
        // PUSHFQ is always logged
        //
        if (ins.is(X86_INS_PUSHFQ, {})) {
            // Nothing to trace
            //
            is_reduced.stream.push_back(is.stream[i]);
            continue;
        }

        // Check whether the register is read / written to by this instruction
        // (Non-implicit operand-invoked R/W only)
        //
        std::map<x86_reg, bool> reads;
        std::map<x86_reg, bool> writes;
        uint64_t mem_read = false;
        uint64_t mem_write = false;
        uint32_t eflags_write = ins.eflags;

        for (auto &op : ins.operands) {
            if (op.type == X86_OP_REG) {
                if (op.access & CS_AC_READ)
                    reads[vtil::amd64::registers.extend(op.reg)] = true;
                if (op.access & CS_AC_WRITE)
                    writes[vtil::amd64::registers.extend(op.reg)] = true;
            } else if (op.type == X86_OP_MEM) {
                for (auto reg : {op.mem.base, op.mem.index}) {
                    if (reg != X86_REG_INVALID)
                        reads[vtil::amd64::registers.extend(reg)] = true;
                }

                mem_read |= op.access & CS_AC_READ;
                mem_write |= op.access & CS_AC_WRITE;
            }
        }

        // Consider the side effects of the register execution
        // (With the exception of RSP and RFLAGS)
        //
        for (uint16_t _r : ins.regs_read) {
            x86_reg r = vtil::amd64::registers.extend(_r);
            if (r == X86_REG_EFLAGS || r == X86_REG_RSP)
                continue;
            // CPUID:RCX exception
            if (ins.id == X86_INS_CPUID && r == X86_REG_RCX)
                continue;
            reads[r] = true;
        }

        for (uint16_t _r : ins.regs_write) {
            x86_reg r = vtil::amd64::registers.extend(_r);
            if (r == X86_REG_EFLAGS || r == X86_REG_RSP)
                continue;
            writes[r] = true;
        }

        // If we write to memory OR a traced register,
        // all of the registers we read should be traced
        //
        bool should_be_tracked = mem_write;
        for (auto &p : traced) {
            if (writes[p.first])
                should_be_tracked |= p.second;
        }

        // These instructions should always be tracked
        //
        // if (ins.id == X86_INS_CALL || ins.mnemonic == "loadc") {
        //    should_be_tracked = true;
        //}

        // If instruction is tracked:
        //
        if (should_be_tracked) {
            // Stop tracing the registers we wrote to
            //
            for (auto &p : writes)
                traced[p.first] &= !p.second;

            // Start tracing the registers we read from
            //
            for (auto &p : reads)
                traced[p.first] |= p.second;

            // Log the current instruction
            //
            is_reduced.stream.push_back(is.stream[i]);
        }
    }

    // Replace input stream with the reduced stream
    //
    is.stream = is_reduced.stream;
    is.normalize();
}

// Deduces the virtual instruction stream direction from the given instruction stream
//
void update_vip_direction(vm_state *state, const instruction_stream &is) {
    // Define the filters based on the way VIP stream is read
    //
    auto fwd_filter = [&](const vtil::amd64::instruction &ins) {
        // Type #1:
        // [ add rbp, 1 ]
        //
        if (ins.is(X86_INS_ADD, {X86_OP_REG, X86_OP_IMM})) {
            return ins.operands[0].reg == state->reg_vip && ins.operands[1].imm == 1;
        }
        // Type #2:
        // [ lea rbp, [rbp+1] ]
        //
        else if (ins.is(X86_INS_LEA, {X86_OP_REG, X86_OP_MEM})) {
            return ins.operands[0].reg == state->reg_vip && ins.operands[1].mem.disp == 1 &&
                   ins.operands[1].mem.scale == 1 && ins.operands[1].mem.base == state->reg_vip &&
                   ins.operands[1].mem.index == X86_REG_INVALID;
        }
        return false;
    };
    auto bwd_filter = [&](const vtil::amd64::instruction &ins) {
        // Type #1:
        // [ sub rbp, 1 ]
        //
        if (ins.is(X86_INS_SUB, {X86_OP_REG, X86_OP_IMM})) {
            return ins.operands[0].reg == state->reg_vip && ins.operands[1].imm == 1;
        }
        // Type #2:
        // [ lea rbp, [rbp-1] ]
        //
        else if (ins.is(X86_INS_LEA, {X86_OP_REG, X86_OP_MEM})) {
            return ins.operands[0].reg == state->reg_vip && ins.operands[1].mem.disp == -1 &&
                   ins.operands[1].mem.scale == 1 && ins.operands[1].mem.base == state->reg_vip &&
                   ins.operands[1].mem.index == X86_REG_INVALID;
        }
        return false;
    };

    // Find the first instances for both where possible
    //
    auto i_fwd = is.next(fwd_filter);
    auto i_bwd = is.next(bwd_filter);

    // Deduct the way instruction stream is iterated
    //
    if (i_fwd == -1 && i_bwd != -1)
        state->dir_vip = -1;
    else if (i_fwd != -1 && i_bwd == -1)
        state->dir_vip = +1;
    else if (i_fwd != -1 && i_bwd != -1)
        state->dir_vip = i_fwd > i_bwd ? -1 : +1;
    else
        unreachable();
}

// Deduces the handler table from the given instruction stream
//
void update_handler_table(vm_state *vstate, const instruction_stream &is, int index) {
    // Find the first LEA r64, [$]
    //
    int i_handler_table = is.next(
        X86_INS_LEA, {X86_OP_REG, X86_OP_MEM},
        [&](const vtil::amd64::instruction &ins) {
            return ins.operands[1].mem.base == X86_REG_RIP &&
                   ins.operands[1].mem.index == X86_REG_INVALID;
        },
        index);

    fassert(i_handler_table != -1);

    vstate->reg_vht = is[i_handler_table].operands[0].reg;
    vstate->handler_table_rva =
        is[i_handler_table].address + is[i_handler_table].operands[1].mem.disp + 7;
}

// Parses VMENTER subroutine and extracts the vm information, entry point of the
// virtualized routine, rolling key 0 value, and describes the push order of registers.
// - Pushing reloc at last is left to the caller.
//
std::pair<std::vector<vtil::operand>, vtil::vip_t> parse_vmenter(vm_state *vstate,
                                                                 uint32_t rva_ep) {
    // Unroll the stream
    //
    auto is = deobfuscate(vstate->img, rva_ep);

    if (verbosity >= 1) {
        log<CON_BLU>("> VMENTER\n");
        log<CON_BLU>(">> INSTRUCTIONS\n");
        is.dump();
    }

    // Instruction stream should start with a 32 bit constant being pushed which is the
    // encrypted offset to the beginning of the virtual instruction stream
    //
    if (is[0].is(X86_INS_PUSHFQ, {}))
        is.erase(1);
    fassert(is[0].is(X86_INS_PUSH, {X86_OP_IMM}));
    uint32_t vip_offset_encrypted = is[0].operands[0].imm;

    // Resolve the stack composition
    //
    x86_reg reg_reloc_delta;
    std::vector<vtil::operand> stack = {
        {vip_offset_encrypted, 64},
        {vstate->img->get_real_image_base() + is[0].address + is[0].bytes.size() + 5, 64}};

    // FIXME: properly check bounds
    for (int i = 0;; i++) {
        // If PUSH R64
        if (is[i].is(X86_INS_PUSH, {X86_OP_REG}))
            stack.push_back(is[i].operands[0].reg);
        // If PUSHFQ
        if (is[i].is(X86_INS_PUSHFQ, {}))
            stack.push_back(vtil::REG_FLAGS);

        // End of pushed registers, reset stream
        if (is[i].is(X86_INS_MOVABS, {X86_OP_REG, X86_OP_IMM})) {
            reg_reloc_delta = is[i].operands[0].reg;
            is.erase(i - 1);
            break;
        }
    }
    fassert(stack.size() == (16 + 2));

    // Resolve the stack composition
    //
    uint32_t ep_vip_offset = stack.size() * 8;

    // Resolve the register mapped to be VSP
    //
    int i_save_registers_id = 0;
    while (true) {
        // Find the first MOV r64, RSP
        //
        i_save_registers_id = is.next(
            X86_INS_MOV, {X86_OP_REG, X86_OP_REG},
            [&](const vtil::amd64::instruction &ins) { return ins.operands[1].reg == X86_REG_RSP; },
            i_save_registers_id);
        fassert(i_save_registers_id != -1);
        vstate->reg_vsp = is[i_save_registers_id].operands[0].reg;

        // Check for any false positives
        //
        auto [vsp_ss, vsp_dep] = is.trace(vstate->reg_vsp, is.stream.size() - 1);
        if (vsp_ss.stream.size() != 1 || vsp_ss[0].address != is[i_save_registers_id].address) {
            i_save_registers_id++;
            continue;
        }
        break;
    }

    // Find the first stack access
    //
    int i_load_vip_id =
        is.next(X86_INS_MOV, {X86_OP_REG, X86_OP_MEM}, [&](const vtil::amd64::instruction &ins) {
            return ins.operands[1].mem.base == X86_REG_RSP &&
                   ins.operands[1].mem.disp == ep_vip_offset;
        });
    fassert(i_load_vip_id != -1);
    vstate->reg_vip = is[i_load_vip_id].operands[0].reg;

    // Find the first ADD r, x or LEA r, [r+x]
    //
    auto vip_d_epi_filter = [&](const vtil::amd64::instruction &ins) {
        if (ins.is(X86_INS_ADD, {X86_OP_REG, X86_OP_REG})) {
            return ins.operands[0].reg == vstate->reg_vip && ins.operands[1].reg == reg_reloc_delta;
        } else if (ins.is(X86_INS_LEA, {X86_OP_REG, X86_OP_MEM})) {
            return ins.operands[0].reg == vstate->reg_vip && ins.operands[1].mem.disp == 0 &&
                   ins.operands[1].mem.scale == 1 &&
                   ((ins.operands[1].mem.base == reg_reloc_delta &&
                     ins.operands[1].mem.index == vstate->reg_vip) ||
                    (ins.operands[1].mem.index == reg_reloc_delta &&
                     ins.operands[1].mem.base == vstate->reg_vip));
        }
        return false;
    };
    int i_add_base_id = is.next(vip_d_epi_filter, i_load_vip_id);
    fassert(i_add_base_id != -1);

    // Extract the VIP decryption code and wrap with a lambda
    //
    auto [vip_dec_ss, vip_dec_ss_dep] =
        is.trace(vstate->reg_vip, i_add_base_id - 1, i_load_vip_id + 1);
    fassert(vip_dec_ss_dep.empty());

    // Cleanup the stream again
    //
    is.erase(i_add_base_id);

    // Decrypt the VIP entry point
    //
    std::vector raw_stream = vip_dec_ss.to_raw();
    std::vector<uint8_t, mem::rwx_allocator<uint8_t>> exec_stream = {raw_stream.begin(),
                                                                     raw_stream.end()};
    exec_stream.push_back(0xC3);
    emulator emu = {};
    emu.set(vstate->reg_vip, vip_offset_encrypted);
    emu.invoke(exec_stream.data());
    static constexpr uint64_t default_image_base = 0x100000000;
    uint32_t rva_vip0 =
        emu.get(vstate->reg_vip) + default_image_base - vstate->img->get_real_image_base();

    // Find handler table
    //
    update_handler_table(vstate, is);

    // Update VIP direction
    //
    update_vip_direction(vstate, is);

    if (verbosity >= 1) {
        log<CON_BLU>(">> STACK\n");
        for (int i = 0; i < stack.size(); i++) {
            log<CON_GRN>("[%d] %s\n", i, stack[i].to_string());
        }
        log<CON_BLU>(">> DECRYPTION\n");
        for (int i = 0; i < vip_dec_ss.size(); i++) {
            log<CON_GRN>("%s\n", vip_dec_ss[i].to_string());
        }
        log<CON_BLU>(">> VM STATE\n");
        log<CON_GRN>("VSP -> %s\n", vtil::amd64::name(vstate->reg_vsp));
        log<CON_GRN>("VHT -> %s\n", vtil::amd64::name(vstate->reg_vht));
        log<CON_GRN>("VIP -> %s\n", vtil::amd64::name(vstate->reg_vip));
        log<CON_GRN>("VHT = %p\n", vstate->handler_table_rva);
        log<CON_GRN>("VIP = %p\n", rva_vip0);
        log<CON_GRN>("DIR = %d\n", vstate->dir_vip);
    }

    return {stack, rva_vip0};
}

// Parses the VMEXIT subroutine and extracts the order registers are pop'd from the stack.
//
std::vector<vtil::operand> parse_vmexit(vm_state *vstate, const instruction_stream &is) {
    // Resolve popped registers
    //
    std::vector<vtil::operand> stack;
    for (int i = 0;; i++) {
        // If POP R64
        if (is[i].is(X86_INS_POP, {X86_OP_REG}))
            stack.push_back(is[i].operands[0].reg);
        // If POPFW
        if (is[i].is(X86_INS_POPFQ, {}))
            stack.push_back(vtil::REG_FLAGS);
        // End of pushed registers, reset stream
        if (is[i].is(X86_INS_RET, {}))
            return stack;
    }
    unreachable();
}

// Handles the VJMP instruction
//
void handle_vjmp(vm_state *vstate, vtil::basic_block *block) {
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
    auto branch_info = vtil::optimizer::aux::analyze_branch(block_copy, &tracer, {.pack = true});
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
}

// Handles the VEXIT instruction
//
void handle_vexit(vm_state *vstate, vtil::basic_block *block, const instruction_stream &is) {
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

    // Copy the current block and pass it through optimization.
    //
    // FIXME: find a better way of cloning a block
    auto routine_copy = block->owner->clone();
    vtil::optimizer::apply_all(routine_copy);
    auto block_copy = routine_copy->get_block(block->entry_vip);

    log<CON_YLW>("JMP %s\n", jmp_dest.to_string());
    log<CON_YLW>("INS %s\n", block_copy->back().to_string());
    // for (auto &ins: *block_copy) {
    //     log<CON_YLW>("INS %s\n", ins.to_string());
    // }

    jmp_dest = block_copy->back().operands[0];
    log<CON_YLW>("jmp %s\n", jmp_dest.to_string());

    if (jmp_dest.is_immediate() && vstate->img->is_rva_in_vmp_scn(jmp_dest.imm().u64)) {
        log<CON_YLW>("INSIDE\n");
        // If return address points to a PUSH IMM32, aka VMENTER.
        //
        auto disasm = deobfuscate(vstate->img, jmp_dest.imm().u64);
        if (disasm.size() && disasm[1].is(X86_INS_PUSH, {X86_OP_IMM})) {
            // Convert into vxcall and indicate that push is implicit by
            // shifting the stack pointer.
            //
            block->wback().base = &vtil::ins::vxcall;
            block->wback().vip = vstate->vip;
            block->shift_sp(8, false, block->end());

            // Continue lifting from the linked virtual machine.
            //
            vm_state state = {vstate->img, jmp_dest.imm().u64};
            lift_il(block, &state);
        }
    }

    // vtil::tracer tracer;
    // auto stack_0 = vtil::symbolic::variable{ block->owner->entry_point->begin(), vtil::REG_SP
    // }.to_expression(); auto stack_1 = tracer.rtrace_p( { std::prev( block->end() ), vtil::REG_SP
    // } ) + block->sp_offset; auto offset = stack_1 - stack_0; if (vmp::verbosity >= 1) {
    //     log( "stack0 => %s\n", stack_0.to_string() );
    //     log( "stack1 => %s\n", stack_1.to_string() );
    //     log( "sp offset => %s\n", offset.to_string() );
    // }

    //// If stack offset is non-const or [Offset < 0]:
    ////
    // if ( !offset.is_constant() || *offset.get<true>() < 0 )
    //{
    //     // Try to read from the top of the stack.
    //     //
    //     auto continue_from = ( tracer.rtrace_p( { std::prev( block->end() ),
    //                             { tracer( { std::prev( block->end() ), vtil::REG_SP } ) +
    //                             block->sp_offset, 64 } } ) - (vstate->img->has_relocs ?
    //                             vtil::symbolic::variable{ {}, vtil::REG_IMGBASE }.to_expression()
    //                             : vtil::symbolic::expression{ vstate->img->get_real_image_base()
    //                             })).simplify( true );
    //     log( "continue => %s\n", continue_from.to_string() );
    //     log( "constant => %d\n", continue_from.is_constant() );
    //     log( "in_vmp => %d\n", vstate->img->is_rva_in_vmp_scn( *continue_from.get() ));
    //     // If constant and is in VMP section:
    //     //
    //     if ( continue_from.is_constant() && vstate->img->is_rva_in_vmp_scn( *continue_from.get()
    //     ) )
    //     {
    //         // If return address points to a PUSH IMM32, aka VMENTER.
    //         //
    //         auto disasm = deobfuscate( vstate->img, *continue_from.get() );
    //         if ( disasm.size() && disasm[ 0 ].is( X86_INS_PUSH, { X86_OP_IMM } ) )
    //         {
    //             // Convert into vxcall and indicate that push is implicit by
    //             // shifting the stack pointer.
    //             //
    //             block->wback().base = &vtil::ins::vxcall;
    //             block->wback().vip = vstate->vip;
    //             block->shift_sp( 8, false, block->end() );

    //            // Continue lifting from the linked virtual machine.
    //            //
    //            vm_state state = { vstate->img, *continue_from.get() };
    //            lift_il( block, &state );
    //        }
    //    }
    //}
}

}; // namespace vmp
