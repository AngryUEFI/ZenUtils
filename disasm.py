#!/usr/bin/env python3
import sys
import argparse
import re
import struct
from arch.registry import Registry

def disassemble_single(spec, word: int) -> str:
    # Decode fields
    fields = spec.decode_instruction(word)
    if fields is None:
        return None

    # Get disassembly template
    insn = spec.get_instruction_spec(fields)
    if insn is None:
        return None
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

def disassemble_object(spec, data: bytes) -> str:
    result = []
    offset = 0

    # Print object header
    result.append("; Header")
    fields = spec.object_format['header']['fields']
    for field in fields:
        name = field['name']
        ftype = field['type']
        if ftype == 'uint32':
            val, = struct.unpack_from('<I', data, offset)
            result.append(f".{name} 0x{val:08x}")
            offset += 4
        elif ftype == 'uint16':
            val, = struct.unpack_from('<H', data, offset)
            result.append(f".{name} 0x{val:04x}")
            offset += 2
        elif ftype == 'uint8':
            val = data[offset]
            result.append(f".{name} 0x{val:02x}")
            offset += 1
        elif ftype in ('bytes', 'bytearray'):
            length = field['length']
            hex = ' '.join([f"{b:02x}" for b in data[offset:offset+length]])
            result.append(f".{name} {hex}")
            offset += length
        else:
            raise ValueError(f"Unsupported header field type: {ftype}")
    
    # Print match registers
    result.append("\n; Match Register")
    entry_count = spec.match_registers['entry_count']
    match_reg_entries = spec.decode_match_registers(data[offset:offset+entry_count*4])
    for i, entry in enumerate(match_reg_entries):
        result.append(f".match_reg {i*2} 0x{entry['m1']['value']:08x}")
        result.append(f".match_reg {i*2+1} 0x{entry['m2']['value']:08x}")
    offset += entry_count * 4

    # Print instruction packages
    result.append("\n; Instruction Packages")
    start_address = spec.packages['start_address']
    count = spec.packages['count']
    instructions_per_package = spec.packages['instructions_per_package']
    instruction_size = spec.packages['instruction_size']
    sequence_word_size = spec.packages['sequence_word_size']

    package_byte_len = instructions_per_package * instruction_size // 8 + sequence_word_size // 8
    if len(data[offset:]) != package_byte_len * count:
        raise ValueError(f"Got file len {len(data)} byte, expected {offset + package_byte_len * count} byte.")
    
    for slot in range(count):
        insn_words = []
        for i in range(instructions_per_package):
            insn_words.append(int.from_bytes(data[offset:offset+instruction_size//8], 'little'))
            offset += instruction_size // 8
        sequence_word = int.from_bytes(data[offset:offset+sequence_word_size//8], 'little')
        offset += sequence_word_size // 8

        hex_words = [f"0x{word:016x}" for word in insn_words]
        hex_words.append(f"0x{sequence_word:08x}")
        result.append(f"; Slot {slot} @ 0x{start_address + slot:x} ({' '.join(hex_words)})")

        for word in insn_words:
            disassembly = disassemble_single(spec, word)
            if disassembly is not None:
                result.append(disassembly)
            else:
                result.append("; unknown instruction")
        
        result.append(spec.decode_sequence_word(sequence_word))
        result.append("")

    return '\n'.join(result)

def main():
    parser = argparse.ArgumentParser(description="Zen Microcode Disassembler.")
    parser.add_argument('--arch', required=True, help="Architecture spec name (e.g., Zen1, Zen2)")
    parser.add_argument('-i','--inspect', action='store_true', help="Verbose field breakdown")
    parser.add_argument('instr', nargs='?', help="Instruction word in hex (0x...) or binary (0b...)")
    parser.add_argument('-u', '--update_file', help="Microcode update file")
    args = parser.parse_args()

    if args.instr and args.update_file:
        sys.exit(f"Got instr and update_file, only one allowed.")
    if not args.instr and not args.update_file:
        sys.exit(f"One of instr or update_file required.")

    # Load architecture spec
    reg = Registry()
    try:
        spec = reg.get(args.arch)
    except KeyError:
        sys.exit(f"Error: Unknown architecture '{args.arch}'")

    ### Microcode update mode
    if args.update_file:
        data = open(args.update_file, 'rb').read()
        print(disassemble_object(spec, data))
        return

    ### Single instruction mode
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
        if fields == None:
            fields = spec.get_common_field_values(word)
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
