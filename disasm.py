#!/usr/bin/env python3
import sys
import argparse
import re
from arch.registry import Registry

def disassemble_single(spec, word: int) -> str:
    # Decode fields
    fields = spec.decode_instruction(word)

    # Get disassembly template
    insn = spec.get_instruction_spec(fields)
    assembly = insn['template']
    parts = [p for p in re.split(r' |\t|:|\[|\]|\+|-|,', assembly) if p != '']

    # Insert operands
    # Iterate operands from right to left, replace only first occurrence
    # Todo: str.replace could go terribly wrong, find + splice is better
    # Todo: Register custom types in a yaml structure making special handling superfluous
    for part in reversed(parts[1:]):
        field = fields[part]
        if field['type'] == 'register':
            new_part = spec.registers[field.get('value', 0)]
        elif part == 'segment':
            segment_index = field.get('value', 0)
            new_part = spec.code_to_segment.get(segment_index, hex(segment_index))
        elif field['type'] == 'immediate':
            new_part = hex(field.get('value', 0))
        else:
            raise ValueError("Unknown field type {} in {}".format(field['type'], assembly))
        assembly = assembly.replace(part, new_part, 1)
    
    # Insert flags, in disassembly .q is optional
    flags = spec.get_flags(fields)
    if 'q' in flags:
        del flags['q']
    if len(flags):
        assembly = assembly.replace(parts[0], parts[0] + '.' + ''.join(flags.keys()))

    return assembly

def main():
    parser = argparse.ArgumentParser(description="Disassemble instruction into assembly.")
    parser.add_argument('--arch', required=True, help="Architecture spec name (e.g., Zen1, Zen2)")
    parser.add_argument('-i','--inspect', action='store_true', help="Verbose field breakdown")
    parser.add_argument("instr", help="Instruction word in hex (0x...) or binary (0b...)")
    args = parser.parse_args()

    # Load architecture spec
    reg = Registry()
    try:
        spec = reg.get(args.arch)
    except KeyError:
        sys.exit(f"Error: Unknown architecture '{args.arch}'")

    # Read instruction word
    try:
        word = int(args.instr, 0)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Inspect fields
    if args.inspect:
        print(f"; 0x{word:016X} {word:064b}")
        fields = spec.decode_instruction(word)
        for name, field in sorted(fields.items(), key=lambda kv: kv[1]['bits'][0]):
            lo, hi = field['bits']
            width = hi - lo + 1
            val = field.get('value', 0)
            bin_str = f"{val:0{width}b}".rjust(64 - lo)
            print(f"; {name:<12s}:{val:>5d} {bin_str}")

    # Disassemble instruction
    asm = disassemble_single(spec, word)
    print(asm)

if __name__ == '__main__':
    main()
