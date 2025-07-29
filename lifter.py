from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprOp, ExprAssign, LocKey, ExprMem, ExprCond
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.ir.analysis import LifterModelCall
from collections import namedtuple
from arch.registry import Registry  
from disasm import disassemble_single

# Структуры данных для инструкций Zen
ZenOperand = namedtuple('ZenOperand', ['type', 'value', 'size'])
ZenInstruction = namedtuple('ZenInstruction', [
    'name', 'operands', 'fields', 'size_flags', 'flags'
])

class ArchZen(object):
    """Полная архитектура Zen для Miasm на базе спецификации"""
    name = "ZenMicrocode"
    bits = 64
    
    def __init__(self, loc_db: LocationDB, spec_name: str = "ZenBase"):
        self.loc_db = loc_db
        self.spec = self.load_spec(spec_name)
        
        # Создание регистров и сегментов
        self.all_regs_ids = []
        self.all_regs_ids_byname = {}
        self.segments = {}
        
        self._create_registers()
        self._create_segments()
        
        # PC и SP
        self.pc = self.all_regs_ids_byname['PC']
        self.sp = self.all_regs_ids_byname['RSP']
        
        # Размеры операций
        self.size_map = {
            0b000: 8,   # byte
            0b001: 16,  # word  
            0b011: 32,  # doubleword
            0b111: 64,  # quadword
        }
        
        # Операции ALU
        self.alu_operations = {
            0xa0: 'mov',
            0x5f: 'add', 0x5d: 'adc',
            0x50: 'sub', 0x52: 'sbb',
            0x60: 'mul',
            0xb0: 'and', 0xb5: 'xor', 0xbe: 'or',
            0x40: 'shl', 0x41: 'scl', 0x42: 'rol', 0x44: 'rcl',
            0x48: 'shr', 0x49: 'scr', 0x4a: 'ror', 0x4c: 'rcr', 0x4e: 'sar',
            0xff: 'nop'
        }
        
        # Условия переходов
        self.branch_conditions = {
            1: 'jmp', 2: 'jb', 3: 'jnb', 4: 'jz', 5: 'jnz',
            6: 'jbe', 7: 'ja', 8: 'jl', 9: 'jge',
            10: 'jle', 11: 'jg', 12: 'js', 13: 'jns'
        }
        
        self.instr_size = 64  # bits
    
    def _create_registers(self):
        """Создание всех регистров согласно спецификации"""
        # Микрокодовые регистры
        microcode_regs = [f'reg{i}' for i in range(16)]
        
        # x86-64 регистры
        x86_regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
        x86_regs.extend([f'r{i}' for i in range(8, 16)])
        
        # Все регистры + специальные
        all_reg_names = microcode_regs + x86_regs + ['PC']
        
        for reg_name in all_reg_names:
            reg_upper = reg_name.upper()
            reg_expr = ExprId(reg_upper, 64)
            self.all_regs_ids.append(reg_expr)
            self.all_regs_ids_byname[reg_upper] = reg_expr
        
        # Флаги
        flag_names = ['CF', 'ZF', 'NCF', 'NZF']  # NCF/NZF = native flags
        for flag_name in flag_names:
            flag_expr = ExprId(flag_name, 1)
            self.all_regs_ids.append(flag_expr)
            self.all_regs_ids_byname[flag_name] = flag_expr
        
        # Создаем regs namespace
        self.regs = type("regs", (object,), self.all_regs_ids_byname.copy())
    
    def _create_segments(self):
        """Создание сегментов согласно спецификации"""
        segment_map = {
            0: 'vs', 1: 'cpuid', 5: 'msr1', 
            6: 'ls', 9: 'ucode', 12: 'msr2'
        }
        
        for code, name in segment_map.items():
            self.segments[code] = ExprId(name.upper(), 16)
    
    def load_spec(self, spec_name: str):
        reg = Registry()
        spec = reg.get(spec_name)
        return spec
    
    def getpc(self, attrib=None):
        return self.pc
    
    def getsp(self, attrib=None):
        return self.sp
    
    def get_ir(self, loc_db):
        return IRAZen(self, loc_db)
    
    def decode_instr(self, data, offset):
        instr_bytes = data
        if len(instr_bytes) < 8:
            return None
            
        word = int.from_bytes(instr_bytes, 'big')
        insn = disassemble_single(self.spec, word)
        return ZenInstructionWrapper(offset, insn, self.spec, self)


class ZenInstructionWrapper:
    def __init__(self, offset, decoded, spec, arch):
        self.offset = offset
        self.spec = spec
        self.arch = arch
        self.l = 8
        self.size = self.l
        
        print(f"Decoding instruction: {decoded}")
        
        if isinstance(decoded, str):
            self.name = decoded.split()[0]
            self.decoded = self._parse_instruction_string(decoded)
        else:
            self.decoded = decoded
            self.name = decoded.name if hasattr(decoded, 'name') else str(decoded)
    
    def _parse_instruction_string(self, instr_str):
        """Полный парсинг инструкции согласно спецификации Zen"""
        parts = instr_str.strip().split()
        if not parts:
            return None
            
        name = parts[0]
        operands = []
        fields = {}
        
        # Определяем тип инструкции по имени
        instr_type = self._classify_instruction(name)
        
        if len(parts) > 1:
            operand_str = ' '.join(parts[1:])
            operands = self._parse_operands(operand_str, instr_type)
        
        # Извлекаем флаги из имени (например, add.n -> native_flags=True)
        flags_str = ""
        if '.' in name:
            base_name, flags_str = name.split('.', 1)
        else:
            base_name = name
        
        fields = self._extract_flags(flags_str)
        fields['instr_type'] = instr_type
        
        return ZenInstruction(base_name, operands, fields, 0b111, {})
    
    def _classify_instruction(self, name):
        """Классификация инструкции по спецификации"""
        base_name = name.split('.')[0].lower()
        
        # RegOp - ALU операции
        alu_ops = ['mov', 'add', 'adc', 'sub', 'sbb', 'mul', 'and', 'xor', 'or',
                   'shl', 'scl', 'rol', 'rcl', 'shr', 'scr', 'ror', 'rcr', 'sar', 'nop']
        
        # BrOp - условные переходы
        branch_ops = ['jmp', 'jb', 'jnb', 'jz', 'jnz', 'je', 'jne', 'jbe', 'ja',
                      'jl', 'jge', 'jle', 'jg', 'js', 'jns']
        
        if base_name in alu_ops:
            return 'regop'
        elif base_name in branch_ops:
            return 'brop'
        elif 'mov' in base_name and ('[' in name or 'segment:' in name):
            # Определяем load/store по позиции операндов
            return 'ldop' if name.endswith(']') else 'stop'
        else:
            return 'regop'  # По умолчанию
    
    def _parse_operands(self, operand_str, instr_type):
        """Парсинг операндов с учетом типа инструкции и единого размера"""
        operands = []
        
        # Определяем размер операндов (по умолчанию 64 бита для всех)
        default_size = 64
        
        # Убираем лишние пробелы и разделяем по запятым
        ops = [op.strip() for op in operand_str.split(',')]
        
        for op in ops:
            if not op:
                continue
                
            # Регистр
            if op.lower().startswith(('reg', 'r')) or op.lower() in ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']:
                operands.append(ZenOperand('register', op.upper(), default_size))
            
            # Память с сегментом: segment:[base + index + offset]
            elif ':' in op and '[' in op:
                operands.append(self._parse_memory_operand(op))
            
            # Непосредственное значение - используем тот же размер что и регистры
            elif op.isdigit() or (op.startswith('-') and op[1:].isdigit()):
                operands.append(ZenOperand('immediate', int(op), default_size))
            elif op.startswith('0x'):
                operands.append(ZenOperand('immediate', int(op, 16), default_size))
            
            # Адрес перехода
            elif instr_type == 'brop':
                if op.startswith('0x'):
                    addr = int(op, 16)
                else:
                    addr = int(op)
                operands.append(ZenOperand('address', addr, 13))
            
            else:
                # Неизвестный операнд - сохраняем как есть
                operands.append(ZenOperand('unknown', op, default_size))
        
        return operands
    
    def _parse_memory_operand(self, mem_str):
        """Парсинг операнда памяти: segment:[base + index + offset]"""
        # Пример: vs:[rax + rbx + 10]
        if ':' not in mem_str or '[' not in mem_str:
            return ZenOperand('memory', mem_str, 64)
        
        segment_part, addr_part = mem_str.split(':', 1)
        segment = segment_part.strip()
        
        # Убираем скобки
        addr_part = addr_part.strip()[1:-1]  # Убираем [ и ]
        
        # Парсим адресную часть
        addr_components = {'segment': segment, 'base': None, 'index': None, 'offset': 0}
        
        # Простой парсинг для demo - в реальности нужен более сложный
        parts = addr_part.replace('+', ' + ').replace('-', ' - ').split()
        
        for i, part in enumerate(parts):
            part = part.strip()
            if part in ['+', '-']:
                continue
            elif part.lower().startswith(('reg', 'r')) or part.lower() in ['rax', 'rcx', 'rdx']:
                if addr_components['base'] is None:
                    addr_components['base'] = part.upper()
                else:
                    addr_components['index'] = part.upper()
            elif part.isdigit():
                addr_components['offset'] = int(part)
        
        return ZenOperand('memory', addr_components, 64)
    
    def _extract_flags(self, flags_str):
        """Извлечение флагов из суффикса инструкции"""
        fields = {
            'size_flags': 0b111,  # По умолчанию 64-bit
            'read_cf': False, 'read_zf': False,
            'write_cf': False, 'write_zf': False,
            'native_flags': False
        }
        
        if not flags_str:
            return fields
        
        # Флаги размера
        if 'b' in flags_str:
            fields['size_flags'] = 0b000
        elif 'w' in flags_str:
            fields['size_flags'] = 0b001  
        elif 'd' in flags_str:
            fields['size_flags'] = 0b011
        elif 'q' in flags_str:
            fields['size_flags'] = 0b111
        
        # Флаги чтения/записи
        if 'c' in flags_str:
            fields['read_cf'] = True
        if 'z' in flags_str:
            fields['read_zf'] = True
        if 'C' in flags_str:
            fields['write_cf'] = True
        if 'Z' in flags_str:
            fields['write_zf'] = True
        if 'n' in flags_str:
            fields['native_flags'] = True
        
        return fields
    
    def to_string(self, loc_db=None):
        """Строковое представление инструкции"""
        if not hasattr(self.decoded, 'operands') or not self.decoded.operands:
            return self.name
        
        operand_strs = []
        for op in self.decoded.operands:
            if op.type == 'register':
                operand_strs.append(op.value.lower())
            elif op.type == 'immediate':
                operand_strs.append(str(op.value))
            elif op.type == 'address':
                operand_strs.append(f"0x{op.value:x}")
            elif op.type == 'memory':
                if isinstance(op.value, dict):
                    addr_str = op.value['segment'] + ':['
                    parts = []
                    if op.value['base']:
                        parts.append(op.value['base'].lower())
                    if op.value['index']:
                        parts.append(op.value['index'].lower())
                    if op.value['offset']:
                        parts.append(str(op.value['offset']))
                    addr_str += ' + '.join(parts) + ']'
                    operand_strs.append(addr_str)
                else:
                    operand_strs.append(str(op.value))
            else:
                operand_strs.append(str(op.value))
        
        return f"{self.name} {', '.join(operand_strs)}"
    
    def __str__(self):
        return self.to_string()
    
    def get_name(self):
        return self.name
    
    def get_operands(self):
        return getattr(self.decoded, 'operands', [])
    
    def get_length(self):
        return self.l
    
    def is_subcall(self):
        return False
    
    def splitflow(self):
        # Только условные переходы влияют на поток
        return hasattr(self.decoded, 'fields') and self.decoded.fields.get('instr_type') == 'brop'


class IRAZen(LifterModelCall):
    def __init__(self, arch, loc_db):
        super().__init__(arch=arch, loc_db=loc_db, attrib=None)
        self.arch = arch
        self.IRDst = arch.pc
        
        print(f"IRAZen initialized with IRDst: {self.IRDst}")

    def get_ir(self, instr):
        """Генерация IR для всех типов инструкций Zen"""
        print(f"Processing instruction: {instr.name}")
        
        if not hasattr(instr.decoded, 'fields'):
            return [ExprAssign(self.IRDst, ExprInt(instr.offset + instr.size, 64))], []
        
        instr_type = instr.decoded.fields.get('instr_type', 'regop')
        
        # Выбираем обработчик по типу инструкции
        if instr_type == 'regop':
            exprs = self._lift_regop(instr)
        elif instr_type == 'ldop':
            exprs = self._lift_ldop(instr)
        elif instr_type == 'stop':
            exprs = self._lift_stop(instr)
        elif instr_type == 'brop':
            exprs = self._lift_brop(instr)
        else:
            exprs = []
        
        # Добавляем обновление PC (если не было условного перехода)
        if instr_type != 'brop':
            next_addr = ExprInt(instr.offset + instr.size, 64)
            exprs.append(ExprAssign(self.IRDst, next_addr))
        
        print(f"Generated {len(exprs)} expressions")
        for i, expr in enumerate(exprs):
            print(f"  {i}: {expr}")
        
        return exprs, []

    def _create_expr_with_size(self, expr, target_size):
        """Создание выражения с заданным размером"""
        if expr is None:
            return None
        
        if expr.size == target_size:
            return expr
        
        if isinstance(expr, ExprId):
            return ExprId(expr.name, target_size)
        elif isinstance(expr, ExprInt):
            return ExprInt(expr.arg, target_size)
        else:
            # Для других типов выражений - просто возвращаем как есть
            return expr

    def _lift_regop(self, instr):
        """Обработка RegOp инструкций с единым размером операндов"""
        operands = instr.decoded.operands
        fields = instr.decoded.fields
        name = instr.decoded.name.lower()
        
        # Определяем размер операндов из флагов инструкции
        op_size = self._get_size_from_flags(fields.get('size_flags', 0b111))
        
        exprs = []
        
        if name == 'nop':
            return exprs
        
        # MOV операции
        elif name == 'mov':
            if len(operands) >= 2:
                dst = self._get_operand_expr(operands[0], op_size)
                src = self._get_operand_expr(operands[1], op_size)
                if dst and src:
                    print(f"MOV sizes: dst={dst.size}, src={src.size}")
                    exprs.append(ExprAssign(dst, src))
        
        # Арифметические операции
        elif name in ['add', 'adc', 'sub', 'sbb', 'mul']:
            if len(operands) >= 3:
                dst = self._get_operand_expr(operands[0], op_size)
                src1 = self._get_operand_expr(operands[1], op_size)
                src2 = self._get_operand_expr(operands[2], op_size)
                
                if dst and src1 and src2:
                    print(f"Arithmetic sizes: dst={dst.size}, src1={src1.size}, src2={src2.size}")
                    
                    if name == 'add':
                        result = ExprOp('+', src1, src2)
                    elif name == 'adc':
                        cf_reg = self._get_flag_reg('cf', fields.get('native_flags', False))
                        # Вместо resize создаем новый ExprId
                        if cf_reg and cf_reg.size != op_size:
                            cf_resized = ExprId(cf_reg.name, op_size)
                        else:
                            cf_resized = cf_reg
                        result = ExprOp('+', ExprOp('+', src1, src2), cf_resized)
                    elif name == 'sub':
                        result = ExprOp('-', src1, src2)
                    elif name == 'sbb':
                        cf_reg = self._get_flag_reg('cf', fields.get('native_flags', False))
                        # Вместо resize создаем новый ExprId
                        if cf_reg and cf_reg.size != op_size:
                            cf_resized = ExprId(cf_reg.name, op_size)
                        else:
                            cf_resized = cf_reg
                        result = ExprOp('-', ExprOp('-', src1, src2), cf_resized)
                    elif name == 'mul':
                        result = ExprOp('*', src1, src2)
                    
                    exprs.append(ExprAssign(dst, result))
                    
                    # Обработка флагов
                    exprs.extend(self._handle_flags(result, src1, src2, name, fields))
        
        # Логические операции
        elif name in ['and', 'xor', 'or']:
            if len(operands) >= 3:
                dst = self._get_operand_expr(operands[0], op_size)
                src1 = self._get_operand_expr(operands[1], op_size)
                src2 = self._get_operand_expr(operands[2], op_size)
                
                if dst and src1 and src2:
                    print(f"Logic sizes: dst={dst.size}, src1={src1.size}, src2={src2.size}")
                    
                    if name == 'and':
                        result = ExprOp('&', src1, src2)
                    elif name == 'xor':
                        result = ExprOp('^', src1, src2)
                    elif name == 'or':
                        result = ExprOp('|', src1, src2)
                    
                    exprs.append(ExprAssign(dst, result))
                    exprs.extend(self._handle_flags(result, src1, src2, name, fields))
        
        # Операции сдвига
        elif name in ['shl', 'shr', 'sar', 'rol', 'ror', 'scl', 'scr', 'rcl', 'rcr']:
            if len(operands) >= 3:
                dst = self._get_operand_expr(operands[0], op_size)
                src1 = self._get_operand_expr(operands[1], op_size)
                src2 = self._get_operand_expr(operands[2], op_size)
                
                if dst and src1 and src2:
                    print(f"Shift sizes: dst={dst.size}, src1={src1.size}, src2={src2.size}")
                    
                    # Упрощенная обработка сдвигов
                    if name in ['shl', 'scl']:
                        result = ExprOp('<<', src1, src2)
                    elif name in ['shr', 'scr']:
                        result = ExprOp('>>', src1, src2)
                    elif name == 'sar':
                        result = ExprOp('a>>', src1, src2)  # Арифметический сдвиг
                    else:
                        # Для rotate операций используем специальные выражения
                        result = ExprOp(f'{name}', src1, src2)
                    
                    exprs.append(ExprAssign(dst, result))
                    exprs.extend(self._handle_flags(result, src1, src2, name, fields))
        
        return exprs

    def _lift_ldop(self, instr):
        """Обработка LdOp инструкций (загрузка из памяти)"""
        operands = instr.decoded.operands
        exprs = []
        
        if len(operands) >= 2:
            op_size = self._get_size_from_flags(instr.decoded.fields.get('size_flags', 0b111))
            dst = self._get_operand_expr(operands[0], op_size)
            mem_op = operands[1]
            
            if dst and mem_op.type == 'memory':
                mem_addr = self._build_memory_address(mem_op.value)
                if mem_addr:
                    mem_expr = ExprMem(mem_addr, op_size)
                    exprs.append(ExprAssign(dst, mem_expr))
        
        return exprs

    def _lift_stop(self, instr):
        """Обработка StOp инструкций (сохранение в память)"""
        operands = instr.decoded.operands
        exprs = []
        
        if len(operands) >= 2:
            op_size = self._get_size_from_flags(instr.decoded.fields.get('size_flags', 0b111))
            mem_op = operands[0]
            src = self._get_operand_expr(operands[1], op_size)
            
            if src and mem_op.type == 'memory':
                mem_addr = self._build_memory_address(mem_op.value)
                if mem_addr:
                    mem_expr = ExprMem(mem_addr, op_size)
                    exprs.append(ExprAssign(mem_expr, src))
        
        return exprs

    def _lift_brop(self, instr):
        """Обработка BrOp инструкций (условные переходы)"""
        operands = instr.decoded.operands
        name = instr.decoded.name.lower()
        exprs = []
        
        if operands and operands[0].type == 'address':
            target_addr = ExprInt(operands[0].value, 64)
            next_addr = ExprInt(instr.offset + instr.size, 64)
            
            if name == 'jmp':
                # Безусловный переход
                exprs.append(ExprAssign(self.IRDst, target_addr))
            else:
                # Условный переход
                condition = self._build_branch_condition(name)
                if condition:
                    cond_expr = ExprCond(condition, target_addr, next_addr)
                    exprs.append(ExprAssign(self.IRDst, cond_expr))
                else:
                    # Fallback - безусловный переход к следующей инструкции
                    exprs.append(ExprAssign(self.IRDst, next_addr))
        
        return exprs

    def _get_operand_expr(self, operand, target_size=None):
        """Создание выражения для операнда с приведением к целевому размеру"""
        if operand.type == 'register':
            reg_name = operand.value.upper()
            reg_expr = self.arch.all_regs_ids_byname.get(reg_name, ExprId(reg_name, 64))
            
            # Вместо resize создаем новый ExprId с нужным размером
            if target_size and reg_expr.size != target_size:
                return ExprId(reg_name, target_size)
            return reg_expr
            
        elif operand.type == 'immediate':
            # Используем целевой размер если задан, иначе размер операнда
            size = target_size if target_size else operand.size
            return ExprInt(operand.value, size)
        else:
            return None

    def _build_memory_address(self, mem_info):
        """Построение адреса памяти из компонентов"""
        if not isinstance(mem_info, dict):
            return None
        
        # Базовый адрес
        addr_parts = []
        
        if mem_info.get('base'):
            base_reg = self.arch.all_regs_ids_byname.get(mem_info['base'], ExprId(mem_info['base'], 64))
            addr_parts.append(base_reg)
        
        if mem_info.get('index'):
            index_reg = self.arch.all_regs_ids_byname.get(mem_info['index'], ExprId(mem_info['index'], 64))
            addr_parts.append(index_reg)
        
        if mem_info.get('offset') and mem_info['offset'] != 0:
            addr_parts.append(ExprInt(mem_info['offset'], 64))
        
        if not addr_parts:
            return ExprInt(0, 64)
        elif len(addr_parts) == 1:
            return addr_parts[0]
        else:
            # Складываем все компоненты
            result = addr_parts[0]
            for part in addr_parts[1:]:
                result = ExprOp('+', result, part)
            return result

    def _get_flag_reg(self, flag_name, is_native):
        """Получение регистра флага (native или microcode)"""
        if flag_name.lower() == 'cf':
            return self.arch.all_regs_ids_byname.get('NCF' if is_native else 'CF')
        elif flag_name.lower() == 'zf':
            return self.arch.all_regs_ids_byname.get('NZF' if is_native else 'ZF')
        return None

    def _handle_flags(self, result_expr, src1, src2, op_name, fields):
        """Обработка флагов состояния"""
        exprs = []
        
        # Флаг переноса
        if fields.get('write_cf'):
            cf_reg = self._get_flag_reg('cf', fields.get('native_flags', False))
            if cf_reg:
                if op_name in ['add', 'adc']:
                    cf_expr = ExprOp('carry_add', src1, src2)
                elif op_name in ['sub', 'sbb']:
                    cf_expr = ExprOp('carry_sub', src1, src2)
                else:
                    cf_expr = ExprInt(0, 1)  # Для логических операций CF=0
                exprs.append(ExprAssign(cf_reg, cf_expr))
        
        # Флаг нуля
        if fields.get('write_zf'):
            zf_reg = self._get_flag_reg('zf', fields.get('native_flags', False))
            if zf_reg:
                zf_expr = ExprOp('==', result_expr, ExprInt(0, result_expr.size))
                exprs.append(ExprAssign(zf_reg, zf_expr))
        
        return exprs

    def _build_branch_condition(self, branch_name):
        """Построение условия для условного перехода"""
        conditions = {
            'jb': self.arch.all_regs_ids_byname.get('CF'),  # CF=1
            'jnb': ExprOp('==', self.arch.all_regs_ids_byname.get('CF'), ExprInt(0, 1)),  # CF=0
            'jz': self.arch.all_regs_ids_byname.get('ZF'),  # ZF=1
            'jnz': ExprOp('==', self.arch.all_regs_ids_byname.get('ZF'), ExprInt(0, 1)),  # ZF=0
            'je': self.arch.all_regs_ids_byname.get('ZF'),  # ZF=1
            'jne': ExprOp('==', self.arch.all_regs_ids_byname.get('ZF'), ExprInt(0, 1)),  # ZF=0
            'jge': ExprOp('==', self.arch.all_regs_ids_byname.get('CF'), ExprInt(0, 1)),  # CF=0 для unsigned
            # Добавить остальные условия по необходимости
        }
        
        return conditions.get(branch_name)

    def _get_size_from_flags(self, size_flags):
        """Получение размера в битах из флагов размера"""
        return self.arch.size_map.get(size_flags, 64)


class ZenIRCFG:
    """Кастомный IRCFG builder для Zen архитектуры"""
    
    def __init__(self, arch, loc_db):
        self.arch = arch
        self.loc_db = loc_db
        self.ira = arch.get_ir(loc_db)
        self.blocks = {}
    
    def add_instruction(self, instr):
        """Добавление одной инструкции"""
        if hasattr(instr.decoded, 'fields'):
            instr_type = instr.decoded.fields.get('instr_type', 'unknown')
        else:
            instr_type = 'unknown'
            
        print(f"\n=== Processing {instr_type} instruction: {instr.name} at 0x{instr.offset:x} ===")
        
        # Генерируем IR
        ir_exprs, _ = self.ira.get_ir(instr)
        
        if ir_exprs:
            # Создаем AssignBlock
            assign_block = AssignBlock(ir_exprs)
            
            # Создаем IRBlock
            loc_key = LocKey(instr.offset)
            ir_block = IRBlock(self.loc_db, loc_key, [assign_block])
            
            # Сохраняем блок
            self.blocks[loc_key] = ir_block
            
            print(f"✓ Created IR block for {instr.name}")
            return ir_block
        else:
            print(f"✗ No IR expressions generated")
            return None
    
    def add_instruction_sequence(self, instructions):
        """Добавление последовательности инструкций"""
        for instr in instructions:
            self.add_instruction(instr)
    
    def get_blocks(self):
        """Получение всех IR блоков"""
        return self.blocks
    
    def print_ir(self):
        """Печать всего IR"""
        print("\n" + "="*50)
        print("Generated Zen Microcode IR")
        print("="*50)
        
        for loc_key, ir_block in self.blocks.items():
            print(f"\nBlock at {loc_key}:")
            for i, assign_block in enumerate(ir_block):
                print(f"  AssignBlock {i}:")
                for j, assign in enumerate(assign_block):
                    print(f"    {assign}")


# Пример использования с различными типами инструкций
if __name__ == "__main__":
    try:
        print("=== Zen Microcode Lifter v2.0 ===")
        print("Based on full Zen architecture specification")
        
        loc_db = LocationDB()
        arch = ArchZen(loc_db, "Zen1")
        
        print(f"\nArchitecture initialized:")
        print(f"  Registers: {len(arch.all_regs_ids_byname)} total")
        print(f"  Segments: {len(arch.segments)}")
        print(f"  PC: {arch.pc}")
        
        # Примеры различных типов инструкций
        test_cases = [
            # RegOp инструкции
            (bytes.fromhex('382F9E108CE00000'), "add.n reg1, reg3, reg7"),
            (bytes.fromhex('382F9C1000000000'), "add reg0, reg0, reg0"),
            (bytes.fromhex('382F9C108C080042'), "add reg1, reg3, 0x42"),
            (bytes.fromhex('382F9E108C080042'), "add.n reg1, reg3, 0x42"),
            (bytes.fromhex('385A8FF08C080042'), "xor.zcZCnd reg1, reg3, 0x42"),
            (bytes.fromhex('20021C2000081FC0'), "jz.z 0x1fc0"),
            (bytes.fromhex('20049C0000081FE2'), "jge 0x1fe2"),
            (bytes.fromhex('286F3C1EF0008400'), "mov r13, cpuid:[r12]"),
            (bytes.fromhex('18505C073C07B000'), "mov msr2:[reg15], reg14"),
            (bytes.fromhex('286F20173DC09820'), "mov.b reg14, ls:[reg15 + reg14 + 0x20]"),
            (bytes.fromhex('38501C1080E00000'), "mov reg1, reg7"),
            (bytes.fromhex('38501C1080084242'), "mov reg1, 0x4242"),
        ]
        
        instructions = []
        for i, (instr_bytes, description) in enumerate(test_cases):
            offset = i * 8
            print(f"\n--- Decoding: {description} ---")
            instr = arch.decode_instr(instr_bytes, offset)
            if instr:
                instructions.append(instr)
                print(f"✓ Decoded as: {instr}")
            else:
                print(f"✗ Failed to decode")
        
        if instructions:
            print(f"\nSuccessfully decoded {len(instructions)} instructions")
            
            # Создаем IR
            ircfg_builder = ZenIRCFG(arch, loc_db)
            ircfg_builder.add_instruction_sequence(instructions)
            
            # Выводим результат
            ircfg_builder.print_ir()
            
            # Статистика
            ir_blocks = ircfg_builder.get_blocks()
            total_assigns = sum(len(list(block)) for block in ir_blocks.values())
            
            print(f"\n" + "="*50)
            print("SUMMARY")
            print("="*50)
            print(f"✓ Instructions processed: {len(instructions)}")
            print(f"✓ IR blocks created: {len(ir_blocks)}")
            print(f"✓ Total IR assignments: {total_assigns}")
            print(f"✓ Lifter completed successfully!")
            
        else:
            print("No instructions to process")
        
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
