#!/usr/bin/env python3
import sys
import argparse
import re
from arch.registry import Registry

# Parse instruction or template into mnemonic and operands
# Preserves memory operands as one operand (e.g., `msr2:[reg15 + 8]`)
def parse_instruction(assembly: str) -> tuple:
    parts = assembly.strip().split(None, 1)
    mnemonic = parts[0]
    mnemonic = mnemonic.split('.', 1)[0].lower()
    operands = parts[1] if len(parts) > 1 else ""
    operands = [op.strip() for op in operands.split(',')] if operands else []
    return (mnemonic, operands)

# Parses memory operand into sub operands
def parse_memory_operand(operand: str) -> list:
    parts = [p for p in re.split(r' |\t|:|\[|\]|\+|-', operand) if p != '']
    return parts

# Checks if string parses to a number
def can_parse_number(string: str) -> bool:
    try:
        int(string, 0)
    except Exception as e:
        return False
    return True

# Get types for instruction operands
def get_op_types_from_inst(spec, instr_ops: list) -> list:
    types = []
    for op in instr_ops:
        if '[' in op and ']' in op:
            types.append('memory')
        elif op in spec.registers:
            types.append('register')
        elif can_parse_number(op):
            types.append('immediate')
        elif op in spec.segment_to_code:
            types.append('immediate')
        elif re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', op):
            types.append('immediate') # mark labels as immediate for now
        else:
            raise ValueError("Unknown type for operand: {}".format(op))
    return types

# Get types for operands from template
def get_op_types_from_template(spec, class_name:str, ops: list) -> list:
    types = []
    for op in ops:
        if '[' in op and ']' in op:
            types.append('memory')
            continue
        
        if op in spec.common_fields:
            types.append(spec.common_fields[op]['type'])
        elif op in spec.instruction_classes[class_name]['fields']:
            types.append(spec.instruction_classes[class_name]['fields'][op]['type'])
        else:
            raise ValueError("Unknown type for operand: {}".format(op))
    return types

# Check if instruction memory op matches template memory op
def memory_operand_matching_template(spec, class_name:str, tpl_mem_op: str, instr_mem_op: str) -> bool:
    tpl_sub_ops = parse_memory_operand(tpl_mem_op)
    instr_sub_ops = parse_memory_operand(instr_mem_op)
    if len(tpl_sub_ops) != len(instr_sub_ops):
        return False
    
    tpl_sub_ops_types = get_op_types_from_template(spec, class_name, tpl_sub_ops)
    instr_sub_ops_types = get_op_types_from_inst(spec, instr_sub_ops)
    return tpl_sub_ops_types == instr_sub_ops_types

# Search matching template for instruction
def find_instr_spec(spec, assembly: str) -> tuple:
    instr_mnem, instr_ops = parse_instruction(assembly)
    instr_op_types = get_op_types_from_inst(spec, instr_ops)

    for class_name, instr_specs in spec.instructions.items():
        for instr_spec in instr_specs:
            tpl_mnem, tpl_ops = parse_instruction(instr_spec['template'])
            if tpl_mnem != instr_mnem or len(tpl_ops) != len(instr_ops):
                continue
            
            tpl_op_types = get_op_types_from_template(spec, class_name, tpl_ops)
            if tpl_op_types != instr_op_types:
                continue
            
            if 'memory' in instr_op_types:
                # Todo: expand to consider multiple memory operands
                index = instr_op_types.index('memory')
                if not memory_operand_matching_template(spec, class_name, tpl_ops[index], instr_ops[index]):
                    continue

            return (class_name, instr_spec)
    raise ValueError("No inst spec found for instruction: {}".format(assembly))

def insert_operand_values(spec, fields: dict, instr_ops: list, field_names: list, assembly: str, label_addrs: dict):
    for op, field_name in zip(instr_ops, field_names):
        # Handle memory operand
        if '[' in op and ']' in op:
            sub_ops = parse_memory_operand(op)
            sub_field_names = parse_memory_operand(field_name)
            insert_operand_values(spec, fields, sub_ops, sub_field_names, assembly, label_addrs)
            continue

        field = fields[field_name]
        if field['type'] == 'register':
            field['value'] = spec.register_to_idx[op]
        # Todo: Register custom types in a yaml structure making special handling superfluous
        elif field_name == 'segment':
            segment_code = spec.segment_to_code.get(op, None)
            if segment_code == None:
                segment_code = int(op, 0)
            field['value'] = segment_code
        elif field['type'] == 'immediate' and can_parse_number(op):
            field['value'] = int(op, 0)
        elif field['type'] == 'immediate' and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', op):
            if op not in label_addrs:
                raise ValueError("Use of undefined label '{}' in '{}'.".format(op, assembly))
            field['value'] = label_addrs[op]
        else:
            raise ValueError("Unknown field type '{}' in '{}'.".format(field['type'], assembly))

def assemble_single(spec, assembly: str, label_addrs: dict = {}) -> int:
    # Get matching instruction spec and default field values
    class_name, instr_spec = find_instr_spec(spec, assembly)
    fields = spec.get_default_fields_for_instruction(instr_spec, class_name)

    # Insert values for operands
    _, instr_ops = parse_instruction(assembly)
    _, field_names = parse_instruction(instr_spec['template'])
    insert_operand_values(spec, fields, instr_ops, field_names, assembly, label_addrs)

    # Insert values for flags
    parts = assembly.split(None, 1)[0].split('.', 1)
    if len(parts) == 2:
        flags = parts[1]
        for flag in flags:
            flag_spec = spec.instruction_flags[flag]
            fields[flag_spec['field']]['value'] = flag_spec['value']

    return spec.encode_instruction(fields)

def main():
    parser = argparse.ArgumentParser(description="Assemble instruction to word.")
    parser.add_argument('--arch', required=True, help='Architecture spec name (e.g., Zen1, Zen2)')
    parser.add_argument('-i','--inspect', action='store_true', help="Verbose field breakdown")
    parser.add_argument('instr', help='Instruction text (in quotes)')
    args = parser.parse_args()

    # Load architecture spec
    reg = Registry()
    try:
        spec = reg.get(args.arch)
    except KeyError:
        sys.exit(f"Error: Unknown architecture '{args.arch}'")

     # Assemble instruction
    try:
        word = assemble_single(spec, args.instr)
    except Exception as e:
        sys.exit(f"Error: {e}")
    print(f"; 0x{word:016X} {word:064b}")

    # Inspect fields
    if args.inspect:
        fields = spec.decode_instruction(word)
        for name, field in sorted(fields.items(), key=lambda kv: kv[1]['bits'][0]):
            lo, hi = field['bits']
            width = hi - lo + 1
            val = field.get('value', 0)
            bin_str = f"{val:0{width}b}".rjust(64 - lo)
            print(f"; {name:<12s}:{val:>5d} {bin_str}")

if __name__ == '__main__':
    main()
