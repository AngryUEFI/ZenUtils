#!/usr/bin/env python3
"""
Macro Assembler for Zen architectures with labels, match register handling
and automated placement of instructions.
"""
import sys
import argparse
import re
import struct
from arch.registry import Registry
from asm import assemble_single, can_parse_number

class HeaderEmitter:
    """Emit object header fields by walking spec.object_format.header.fields."""
    def __init__(self, spec, header_values):
        hdr = spec._raw['object_format']['header']
        self.fields   = hdr.get('fields', [])
        self.defaults = hdr.get('defaults', {})
        self.values   = header_values

    def emit(self, out_stream, debug):
        if debug:
            self.emit_ascii(out_stream)
        else:
            self.emit_binary(out_stream)

    def emit_ascii(self, out_stream):
        out_stream.write(bytes(f"; Header\n", 'ascii'))

        for field in self.fields:
            name   = field['name']
            ftype  = field['type']
            # priority: directive → default → zero
            val = self.values.get(name, self.defaults.get(name, 0))

            if ftype == 'uint32':
                out_stream.write(bytes(f".{name} 0x{val:08x}\n", 'ascii'))
            elif ftype == 'uint16':
                out_stream.write(bytes(f".{name} 0x{val:04x}\n", 'ascii'))
            elif ftype == 'uint8':
                out_stream.write(bytes(f".{name} 0x{val:02x}\n", 'ascii'))
            elif ftype in ('bytes', 'bytearray'):
                length = field['length']
                arr = val if isinstance(val, (bytes, bytearray)) else bytes(val)
                if len(arr) == 0:
                    arr = [0] * length
                if len(arr) != length:
                    raise ValueError(f"Length of bytes field {name} is {len(arr)}, expected {length}.")
                hex = ' '.join([f"{b:02x}" for b in arr])
                out_stream.write(bytes(f".{name} {hex}\n", 'ascii'))
            else:
                raise NotImplementedError(f"Unsupported header field type: {ftype}")

    def emit_binary(self, out_stream):
        for field in self.fields:
            name   = field['name']
            ftype  = field['type']
            # priority: directive → default → zero
            val = self.values.get(name, self.defaults.get(name, 0))

            if ftype == 'uint32':
                out_stream.write(struct.pack('<I', val))
            elif ftype == 'uint16':
                out_stream.write(struct.pack('<H', val))
            elif ftype == 'uint8':
                out_stream.write(struct.pack('<B', val))
            elif ftype in ('bytes', 'bytearray'):
                length = field['length']
                arr = val if isinstance(val, (bytes, bytearray)) else bytes(val)
                # pad or truncate to exactly `length`
                out_stream.write(arr.ljust(length, b'\0')[:length])
            else:
                raise NotImplementedError(f"Unsupported header field type: {ftype}")


class MacroAssembler:
    def __init__(self, spec):
        self.spec = spec
        self.header_values = {}
        self.start_address = spec.packages['start_address']
        self.match_regs = {}       # idx → value
        self.N              = spec.packages['count']
        self.slot_state     = ['free'] * self.N
        self.remaining_fill = {}
        self.current_slot   = None
        self.packages       = {i: [] for i in range(self.N)}  # list of instr words
        self.instructions   = {i: [] for i in range(self.N)}  # list of instr texts
        self.sequence_words = {}  # slot → (action, target)
        self.label_addrs    = {}
        self.branch_ph      = []
        self.uc_branch_ph   = []

    def discovery_pass(self, lines):
        for ln, line in enumerate(lines, 1):
            text = line.split(';', 1)[0].strip()
            m = re.match(r'\.match_reg\s+(\d+)\s*,\s*(0x[0-9A-Fa-f]+|\d+)', text)
            if m:
                idx = int(m.group(1)); val = int(m.group(2), 0)
                if idx in self.match_regs or val in self.match_regs.values():
                    sys.exit(f"Error (line {ln}): duplicate .match_reg")
                slot = idx * 2
                if not (0 <= slot < self.N):
                    sys.exit(f"Error (line {ln}): slot {slot} out of range")
                self.match_regs[idx]    = val
                self.slot_state[slot]   = 'blocked'

    def placement_pass(self, lines):
        for ln, raw in enumerate(lines, 1):
            text = raw.split(';',1)[0].strip()
            if not text:
                continue

            # --- header directives ---
            if text.startswith('.arch'):
                continue
            if text.startswith('.date'):
                self.header_values['date'] = int(text.split()[1], 0)
                continue
            if text.startswith('.revision') or text.startswith('.rev'):
                self.header_values['revision'] = int(text.split()[1], 0)
                self.header_values['rev'] = int(text.split()[1], 0)
                continue
            if text.startswith('.format'):
                self.header_values['format'] = int(text.split()[1], 0)
                continue
            if text.startswith('.cpuid'):
                self.header_values['cpuid'] = int(text.split()[1], 0)
                continue

            # --- match_reg directives ---
            if text.startswith('.match_reg'):
                idx  = int(text.split()[1].rstrip(','))
                new_slot = idx * 2

                # Close current slot
                if self.current_slot != None:
                    self.slot_state[self.current_slot] = 'used'
                    self.remaining_fill[self.current_slot] = 0

                # Open new slot
                self.current_slot = new_slot
                self.slot_state[self.current_slot] = 'used'
                self.remaining_fill[self.current_slot] = 4
                self.sequence_words[self.current_slot] = ('CONTINUE', None)
                continue

            # --- sw_branch / sw_complete ---
            m = re.match(r'\.sw_branch\s+(\w+)', text)
            if m:
                branch_target = m.group(1)
                if self.current_slot == None:
                    sys.exit(f"Error (line {ln}): Slot not set for sw_branch")

                # Close current slot
                self.slot_state[self.current_slot] = 'used'
                self.remaining_fill[self.current_slot] = 0
                if can_parse_number(branch_target):
                    # Branch target is absolute address
                    self.sequence_words[self.current_slot] = ('BRANCH', int(branch_target, 0))
                else:
                    # Branch target is label
                    self.sequence_words[self.current_slot] = ('BRANCH', branch_target)
                    self.branch_ph.append(self.current_slot)
                self.current_slot = None
                continue

            if text.startswith('.sw_complete'):
                if self.current_slot == None:
                    sys.exit(f"Error (line {ln}): Slot not set for sw_complete")

                # Close current slot
                self.slot_state[self.current_slot] = 'used'
                self.remaining_fill[self.current_slot] = 0
                self.sequence_words[self.current_slot] = ('COMPLETE', None)
                self.current_slot = None
                continue

            # --- label definition ---
            m = re.match(r'^(\w+):$', text)
            if m:
                label = m.group(1)
                # Get new slot
                preferred_slot = None
                if self.current_slot is not None:
                    preferred_slot = self.current_slot + 1
                new_slot = self._next_slot(prefer=preferred_slot)
                if new_slot is None:
                    sys.exit(f"Error (line {ln}): out of slots for label")

                # Close current slot
                if self.current_slot != None:
                    self.slot_state[self.current_slot] = 'used'
                    self.remaining_fill[self.current_slot] = 0
                    if self.sequence_words[self.current_slot] == ('CONTINUE', None):
                        if new_slot != self.current_slot + 1:
                            self.sequence_words[self.current_slot] = ('BRANCH', self.start_address + new_slot)

                # Open new slot
                self.current_slot = new_slot
                self.slot_state[self.current_slot] = 'used'
                self.remaining_fill[self.current_slot] = 4
                self.sequence_words[self.current_slot] = ('CONTINUE', None)
                self.label_addrs[label] = self.start_address + self.current_slot
                continue

            # --- normal instruction line ---
            if self.current_slot == None:
                sys.exit(f"Error (line {ln}): no slot selected to place instruction")
            
            # Allocate new slot if current slot full
            if self.remaining_fill[self.current_slot] == 0:
                # Get new slot
                new_slot = self._next_slot(prefer=self.current_slot + 1)
                if new_slot is None:
                    sys.exit(f"Error (line {ln}): out of slots for label")
                
                # Close current slot
                self.slot_state[self.current_slot] = 'used'
                if self.sequence_words[self.current_slot] == ('CONTINUE', None):
                    if new_slot != self.current_slot + 1:
                        self.sequence_words[self.current_slot] = ('BRANCH', self.start_address + new_slot)
                
                # Open new slot
                self.current_slot = new_slot
                self.slot_state[self.current_slot] = 'used'
                self.remaining_fill[self.current_slot] = 4
                self.sequence_words[self.current_slot] = ('CONTINUE', None)

            # Place instruction in current block
            self.instructions[self.current_slot].append(text)
            self.remaining_fill[self.current_slot] -= 1
            self.slot_state[self.current_slot] = 'used'

    def fixup_pass(self):
        # assemble instructions
        for slot, insn_texts in self.instructions.items():
            for insn_text in insn_texts:
                word = assemble_single(self.spec, insn_text, self.label_addrs)
                self.packages[slot].append(word)

        # branch placeholders → real slot indices
        for slot in self.branch_ph:
            action, target = self.sequence_words[slot]
            if action != 'BRANCH':
                continue
            if target not in self.label_addrs:
                sys.exit(f"Error: undefined label {target}")
            self.sequence_words[slot] = ('BRANCH', self.label_addrs[target])
        # ensure no blocked slots remain
        for idx in self.match_regs:
            s = idx*2
            if self.slot_state[s] != 'used':
                sys.exit(f"Error: blocked slot {s} unfilled")

    def emit(self, out_stream, err_stream=sys.stderr, debug=False):
        # 1) header
        he = HeaderEmitter(self.spec, self.header_values)
        he.emit(out_stream, debug)

        # 2) match registers (in index order)
        if debug:
            mcount = self.spec.match_registers['entry_count'] * self.spec.match_registers['regs_per_entry']
            out_stream.write(bytes(f"\n; Match Register\n", 'ascii'))
            for i in range(mcount):
                val = self.match_regs.get(i, 0)
                out_stream.write(bytes(f".match_reg {i}, 0x{val:08x}\n", 'ascii'))
        else:
            for match_t_word in self.spec.encode_match_registers(self.match_regs):
                out_stream.write(struct.pack('<I', match_t_word))

        # 3) instruction packages
        if debug:
            out_stream.write(bytes(f"\n; Instruction Packages\n", 'ascii'))
            for slot, insn_texts in self.instructions.items():
                # pad to 4
                while len(insn_texts) < self.spec.packages['instructions_per_package']:
                    insn_texts.append("NOP")
                # debug print
                labels_str = ""
                labels = [label for label, addr in self.label_addrs.items() if addr == self.start_address + slot]
                if len(labels) > 0:
                    labels_str = " (" + ", ".join(labels) + ")"
                out_stream.write(bytes(f"; Slot {slot} @ 0x{self.start_address + slot:x}{labels_str}\n", 'ascii'))
                out_stream.write(bytes("\n".join(insn_texts), 'ascii'))
                if slot not in self.sequence_words or self.sequence_words[slot][0] == 'CONTINUE':
                    out_stream.write(bytes(f"\n.sw_continue\n\n", 'ascii'))
                elif self.sequence_words[slot][0] == 'BRANCH':
                    out_stream.write(bytes(f"\n.sw_branch 0x{self.sequence_words[slot][1]:x}\n\n", 'ascii'))
                elif self.sequence_words[slot][0] == 'COMPLETE':
                    out_stream.write(bytes(f"\n.sw_complete\n\n", 'ascii'))
                else:
                    raise NotImplementedError(f"Unknown sw: {self.sequence_words[slot]}")

        else:
            for slot, words in self.packages.items():
                # pad to 4
                while len(words) < self.spec.packages['instructions_per_package']:
                    words.append(assemble_single(self.spec, 'nop'))
                # emit instrs
                for w in words:
                    out_stream.write(w.to_bytes(self.spec.packages['instruction_size']//8,
                                                byteorder=self.spec.endianness))
                # sequence word
                action, tgt = self.sequence_words.get(slot, ('CONTINUE', None))
                ft   = self.spec.encode_sequence_word(action, tgt or 0)
                out_stream.write(ft.to_bytes(self.spec.packages['sequence_word_size']//8,
                                            byteorder=self.spec.endianness))

        # summary
        used = len([b for b in self.slot_state if b == 'used'])
        total = self.N
        err_stream.write(f"; Packages used: {used} of {total}\n")

    # ——— helper methods ———

    def _next_slot(self, prefer=None):
        if prefer is not None:
            if self.slot_state[prefer] == 'free':
                return prefer

        for new_slot in range(self.N):
            if self.slot_state[new_slot] == 'free':
                return new_slot
        return None

def main():
    p = argparse.ArgumentParser(description="Macro assembler for Zen microcode updates")
    p.add_argument('--arch', help='Architecture name')
    p.add_argument('infile', nargs='?', help='Assembly file (stdin if omitted)')
    p.add_argument('-o', '--output',    help='Write output to file instead of stdout')
    p.add_argument('-d', '--debug', action='store_true', help='Instead writes readable debug output')
    args = p.parse_args()

    src = sys.stdin.read() if not args.infile else open(args.infile).read()
    lines = src.splitlines()

    # --- Determine architecture from directive (.arch) if present ---
    src = sys.stdin.read() if not args.infile else open(args.infile).read()
    lines = src.splitlines()

    arch_directive = None
    for ln, raw in enumerate(lines, 1):
        text = raw.split(';',1)[0].strip()
        if text.startswith('.arch'):
            parts = text.split()
            if len(parts) >= 2:
                name = parts[1]
                if arch_directive and name != arch_directive:
                    sys.exit(f"Error (line {ln}): conflicting .arch directives: "
                             f"{arch_directive} vs {name}")
                arch_directive = name

    # At least one of --arch or .arch must be provided; if both, they must match
    if args.arch and arch_directive:
        if args.arch != arch_directive:
            sys.exit(f"Error: --arch '{args.arch}' disagrees with .arch '{arch_directive}'")
        arch_name = args.arch
    elif args.arch:
        arch_name = args.arch
    elif arch_directive:
        arch_name = arch_directive
    else:
        sys.exit("Error: Architecture must be specified via --arch or .arch directive")

    try:
        spec = Registry().get(arch_name)
    except KeyError:
        sys.exit(f"Error: unknown arch {arch_name}")

    masm = MacroAssembler(spec)
    masm.discovery_pass(lines)
    masm.placement_pass(lines)
    masm.fixup_pass()
    
    # Determine output stream
    if args.output:
        try:
            out_fd = open(args.output, 'wb')
        except OSError as e:
            sys.exit(f"Error: cannot open output file '{args.output}': {e}")
    else:
        out_fd = sys.stdout.buffer

    masm.emit(out_fd, sys.stderr, debug=args.debug)

    if args.output:
        out_fd.close()

if __name__ == '__main__':
    main()
