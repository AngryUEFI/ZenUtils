import yaml
from pathlib import Path
from copy import deepcopy
from .eval import ConditionEvaluator

def deep_merge(base: dict, override: dict) -> dict:
    """
    Recursively merge override into base, returning a new dict.
    Values in override take precedence. Nested dicts are merged.
    """
    merged = deepcopy(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = deep_merge(merged[key], val)
        else:
            merged[key] = deepcopy(val)
    return merged


class ArchSpec:
    """
    Represents a fully-resolved architecture specification.
    """
    def __init__(self, raw: dict):
        # Store raw merged dict for introspection
        self._raw = raw
        # Basic fields
        self.name = raw.get('name')
        self.word_size = raw.get('word_size')
        self.endianness = raw.get('endianness')
        # Registers
        self.registers = [r for r in raw.get('registers', [])]
        self.register_to_idx = {r: i for i, r in enumerate(self.registers)}
        # Size flags
        self.size_flag_to_code = raw.get('size_flags', {})
        self.code_to_size_flag = {v: k for k, v in self.size_flag_to_code.items()}
        # Segments
        self.code_to_segment = raw.get('segments', {})
        self.segment_to_code = {v: k for k, v in self.code_to_segment.items()}
        # Common fields
        self.common_fields = raw.get('common_fields', {})
        # Instruction classes
        self.instruction_classes = raw.get('instruction_classes', {})
        # Instruction flags
        self.instruction_flags = raw.get('instruction_flags', {})
        # Instructions
        self.instructions = raw.get('instructions', {})
        # Object format
        self.object_format = raw.get('object_format', {})
        # Match registers
        self.match_registers = raw.get('match_registers', {})
        # Instruction packages
        self.packages = raw.get('packages', {})

    @staticmethod
    def get_field_values(word: int, field_spec: dict) -> dict:
        result = deepcopy(field_spec)
        for field in result.values():
            lo, hi = field['bits']
            width = hi - lo + 1
            mask = (1 << width) - 1
            field['value'] = (word >> lo) & mask
        return result

    def get_common_field_values(self, word: int) -> dict:
        return self.get_field_values(word, self.common_fields)

    def get_class_field_values(self, word: int, class_name: str) -> dict:
        return self.get_field_values(word, self.instruction_classes[class_name]['fields'])

    def get_class(self, fields: dict) -> str:
        evaluator = ConditionEvaluator(fields)
        for name, insn_class in self.instruction_classes.items():
            if evaluator.evaluate(insn_class['condition']):
                return name
        return None

    def decode_instruction(self, word: int) -> dict:
        fields = self.get_common_field_values(word)
        class_name = self.get_class(fields)
        fields.update(self.get_class_field_values(word, class_name))
        return fields

    def get_instruction_spec(self, fields: dict, class_name: str = None) -> dict:
        if class_name == None:
            class_name = self.get_class(fields)
        evaluator = ConditionEvaluator(fields)
        for insn in self.instructions[class_name]:
            if evaluator.evaluate(insn['condition']):
                return insn
        return None

    def get_flags(self, fields: dict) -> dict:
        flags = {}
        for flag, spec in self.instruction_flags.items():
            if spec['field'] in fields:
                if fields[spec['field']].get('value', 0) == spec['value']:
                    flags[flag] = spec
        return flags

    @staticmethod
    def encode_instruction(fields: dict) -> int:
        word = 0
        for field in fields.values():
            lo, hi = field['bits']
            width = hi - lo + 1
            mask = (1 << width) - 1
            word |= (field.get('value', 0) & mask) << lo
        return word

    def get_default_fields_for_instruction(self, instruction: dict, class_name: str) -> dict:
        fields = deepcopy(self.common_fields)
        fields.update(deepcopy(self.instruction_classes[class_name]['fields']))
        defaults = deepcopy(self.instruction_classes[class_name]['defaults'])
        defaults.update(ConditionEvaluator.extract_defs_from_condition(instruction['condition']))
        for field, val in defaults.items():
            fields[field]['value'] = val
        return fields

    # def encode_footer(self, action: str, target: int = 0) -> int:
    #     seq = self.package.get('sequence_word_encoding', {})
    #     enc = seq.get(action.lower())
    #     if enc is None:
    #         raise KeyError(f"Unknown footer action: {action}")
    #     if isinstance(enc, int):
    #         return enc
    #     prefix = enc.get('prefix', 0)
    #     lo, hi = enc.get('target_address_bits', [0, 0])
    #     mask = (1 << (hi - lo + 1)) - 1
    #     return prefix | ((target & mask) << lo)


class Registry:
    """
    Loads architecture specs from default 'arch/specs' relative path or a custom directory.
    Resolves inheritance and provides ArchSpec objects.
    """
    def __init__(self, spec_dir: Path = None):
        # Default to 'specs' directory next to this file
        if spec_dir is None:
            spec_dir = Path(__file__).parent
        self._load_specs(spec_dir)

    def _load_specs(self, spec_dir: Path):
        raw_specs = {}
        for path in spec_dir.glob('*.yaml'):
            data = yaml.safe_load(path.read_text())
            name = data.get('name')
            if not name:
                raise ValueError(f"Spec file {path} missing 'name'")
            raw_specs[name] = data
        # Resolve inheritance
        self._specs = {}

        def resolve(name: str) -> ArchSpec:
            if name in self._specs:
                return self._specs[name]
            data = raw_specs.get(name)
            if data is None:
                raise KeyError(f"Spec '{name}' not found in {spec_dir}")
            parent_name = data.get('inherits')
            if parent_name:
                parent = resolve(parent_name)
                merged = deep_merge(parent._raw, data)
            else:
                merged = data
            spec = ArchSpec(merged)
            self._specs[name] = spec
            return spec

        for spec_name in raw_specs:
            resolve(spec_name)

    def get(self, name: str) -> ArchSpec:
        """
        Retrieve a resolved ArchSpec by name. Example:
            spec = Registry().get('Zen2')
        """
        spec = self._specs.get(name)
        if spec is None:
            raise KeyError(f"Spec '{name}' not loaded. Available: {list(self._specs)}")
        return spec
