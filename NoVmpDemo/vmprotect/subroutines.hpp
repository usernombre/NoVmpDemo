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
#include "../emulator/emulator.hpp"
#include "../emulator/rwx_allocator.hpp"
#include "deobfuscator.hpp"
#include "vm_state.hpp"
#include <map>
#include <optional>
#include <variant>
#include <vector>
#include <vtil/amd64>
#include <vtil/vtil>

namespace vmp {
// Extracts the next parameter within the given instruction stream
// - On failure returns -1 as the iterator index
std::pair<int, vm_parameter> extract_next_parameter(vm_state *state, const instruction_stream &is,
                                                    int index = 0);

// Extracts all of the parameters within the given instruction stream
//
std::vector<vm_parameter> extract_parameters(vm_state *vstate, const instruction_stream &is);

// Reduces the given virtualized instruction handler to the base
// (AKA Deobfuscation + I/O based Register tracing)
//
void reduce_chunk(vm_state *vstate, instruction_stream &is,
                  const std::vector<vm_parameter> &parameters);

// Deduces the virtual instruction stream direction from the given instruction stream
//
void update_vip_direction(vm_state *state, const instruction_stream &is);

// Deduces the handler table from the given instruction stream
//
void update_handler_table(vm_state *vstate, const instruction_stream &is, int index = 0);

// Parses VMENTER subroutine and extracts the vm information, entry point of the
// virtualized routine, rolling key 0 value, and describes the push order of registers.
// - Pushing reloc at last is left to the caller.
//
std::pair<std::vector<vtil::operand>, vtil::vip_t> parse_vmenter(vm_state *vstate, uint32_t rva_ep);

// Parses the VMEXIT subroutine and extracts the order registers are pop'd from the stack.
//
std::vector<vtil::operand> parse_vmexit(vm_state *vstate, const instruction_stream &is);
}; // namespace vmp