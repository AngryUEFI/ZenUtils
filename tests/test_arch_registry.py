import pytest
from arch.registry import Registry, ArchSpec


def test_registry_loads_all_arch_specs():
    # Load registry from default arch/specs directory
    reg = Registry()

    # Check that Zen and Zen1 are present
    specs = set(reg._specs.keys())
    assert 'ZenBase' in specs, "Base spec 'Zen' should be loaded"
    assert 'Zen1' in specs, "Derived spec 'Zen1' should be loaded"

    # Validate properties of base 'Zen' spec
    zen = reg.get('ZenBase')
    assert zen.name == 'ZenBase'
    assert isinstance(zen.word_size, int) and zen.word_size == 64
    # Verify register list is non-empty
    assert hasattr(zen, 'registers') and isinstance(zen.registers, list)
    assert 'reg0' in zen.registers

    # Validate package configuration
    pkg = zen.packages
    assert isinstance(pkg.get('instructions_per_package'), int) and pkg['instructions_per_package'] == 4
    seq = pkg.get('sequence_word_encoding', {})
    # Sequence word encoding should define continue, branch, complete
    for action in ['continue', 'branch', 'complete']:
        assert action in seq, f"'{action}' must be defined in sequence_word_encoding"

    # Validate 'Zen1' spec inherits defaults and overrides counts
    zen1 = reg.get('Zen1')
    assert zen1.name == 'Zen1'
    # Inherited: word_size
    assert zen1.word_size == zen.word_size
    # Inherited package size but overridden count
    assert zen1.packages.get('instructions_per_package') == 4
    assert zen.packages.get('instructions_per_package') == 4
    assert zen1.packages.get('count') == 64
    # Overridden match register count
    assert zen1.match_registers.get('entry_count') == 22
    assert zen1.match_registers.get('regs_per_entry') == 2

def test_spec_get_field_values():
    reg = Registry()
    zen2 = reg.get('Zen2')

    # Test instruction: add.n reg1, reg3, reg7
    common_fields = zen2.get_field_values(0x382F9E108CE00000, zen2.common_fields)
    assert common_fields['operation']['value'] == 0x5f
    assert common_fields['native_flags']['value'] == 1
    assert common_fields['rd']['value'] == 1
    assert common_fields['rs']['value'] == 3
    assert common_fields['rt']['value'] == 7

def test_instruction_class():
    reg = Registry()
    zen2 = reg.get('Zen2')

    # Test instruction: add reg1, reg3, 0x42
    word = 0x382F9C108E280042
    fields = zen2.get_common_field_values(word)
    class_name = zen2.get_class(fields)
    assert class_name == 'regop'

    class_fields = zen2.get_class_field_values(word, class_name)
    fields.update(class_fields)
    assert fields['imm16']['value'] == 0x42

    class_fields2 = zen2.decode_instruction(word)
    assert fields['imm16']['value'] == 0x42

def test_get_instruction_spec():
    reg = Registry()
    zen2 = reg.get('Zen2')

    # Test instruction: add reg1, reg3, 0x42
    word = 0x382F9C108E280042

    fields = zen2.decode_instruction(word)
    insn = zen2.get_instruction_spec(fields)
    assert insn['assembly'].startswith('add')

def test_get_flags():
    reg = Registry()
    zen2 = reg.get('Zen2')

    # Test instruction: add.n reg1, reg3, reg7
    word = 0x382F9E108CE00000

    fields = zen2.decode_instruction(word)
    flags = zen2.get_flags(fields)
    assert len(flags) == 2
    assert 'n' in flags
    assert 'q' in flags

def test_encode_instruction():
    reg = Registry()
    zen2 = reg.get('Zen2')

    # Test instruction: add reg1, reg3, 0x42
    word = 0x382F9C108E280042
    fields = zen2.decode_instruction(word)

    word_out = zen2.encode_instruction(fields)
    assert word_out == word

def test_get_default_fields_for_instruction():
    reg = Registry()
    zen2 = reg.get('Zen2')

    insn_spec = {
        'assembly': 'add rd, rs, rt',
        'condition': 'operation == 0x5f && imm_mode == 0'
    }

    fields = zen2.get_default_fields_for_instruction(insn_spec, 'regop')
    word = zen2.encode_instruction(fields)

    # Test instruction: add reg0, reg0, reg0
    expected = 0x382F9C1000000000

    assert word == expected