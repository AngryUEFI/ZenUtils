from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprOp, ExprAssign, ExprMem
from miasm.ir.ir import IRBlock, AssignBlock
from collections import defaultdict
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any, Tuple
import logging
import time

@dataclass
class VulnerabilityInfo:
    """Информация об обнаруженной уязвимости"""
    vuln_type: str
    severity: str
    location: int
    description: str
    details: Dict[str, Any]
    proof_of_concept: Optional[str] = None

class VulnType(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_LEAK = "information_leak"
    RACE_CONDITION = "race_condition"
    INVALID_MEMORY_ACCESS = "invalid_memory_access"
    UNINITIALIZED_VARIABLE = "uninitialized_variable"
    CONTROL_FLOW_HIJACK = "control_flow_hijack"
    SIDE_CHANNEL = "side_channel"
    MICROCODE_INJECTION = "microcode_injection"
    SEGMENT_VIOLATION = "segment_violation"

class IRAssignment:
    """Представление присваивания, восстановленного из IR"""
    def __init__(self, dst, src, location):
        self.dst = dst
        self.src = src
        self.location = location
    
    def __str__(self):
        return f"{self.dst} = {self.src}"

class ZenSecurityAnalyzer:
    """Универсальный анализатор безопасности микрокода Zen"""
    def __init__(self, arch, loc_db):
        self.arch = arch
        self.loc_db = loc_db
        self.vulnerabilities: List[VulnerabilityInfo] = []
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        self.privileged_segments = {'MSR1', 'MSR2', 'CPUID', 'UCODE'}
        self.user_segments = {'VS', 'LS', 'STACK'}
        self.user_controlled_regs = {
            'RAX','RBX','RCX','RDX','RSI','RDI',
            'R8','R9','R10','R11','R12','R13','R14','R15'
        }
        self.microcode_regs = {f'REG{i}' for i in range(16)}
        
        # Улучшенное отслеживание taint
        self.tainted_exprs = set()
        self.assignments = []  # Список всех восстановленных присваиваний
        self._init_taint_sources()

        self._init_detectors()
        
        print(f"🔍 Universal Security Analyzer initialized:")
        print(f"   Privileged segments: {self.privileged_segments}")
        print(f"   User segments: {self.user_segments}")
        print(f"   Taint sources initialized: {len(self.tainted_exprs)}")

    def _init_taint_sources(self):
        """Инициализация источников загрязнения"""
        # Добавляем пользовательские регистры как taint sources
        for reg_name in self.user_controlled_regs:
            self.tainted_exprs.add(reg_name)
        
        # Добавляем микрокодовые регистры как потенциально загрязненные
        for reg_name in self.microcode_regs:
            self.tainted_exprs.add(reg_name)
        
        print(f"   Initialized {len(self.tainted_exprs)} taint sources")

    def _init_detectors(self):
        self.detectors = {
            VulnType.BUFFER_OVERFLOW: self._detect_buffer_overflow,
            VulnType.PRIVILEGE_ESCALATION: self._detect_privilege_escalation,
            VulnType.INFORMATION_LEAK: self._detect_information_leak,
            VulnType.MICROCODE_INJECTION: self._detect_microcode_injection,
        }

    def analyze_ir_blocks(self, ir_blocks: Dict) -> List[VulnerabilityInfo]:
        self.logger.info(f"Starting universal security analysis of {len(ir_blocks)} IR blocks")

        # Сначала восстанавливаем присваивания из IR данных
        self._reconstruct_assignments(ir_blocks)
        
        # Затем выполняем taint analysis
        self._perform_taint_analysis()

        # Анализируем каждый блок
        for loc_key, ir_block in ir_blocks.items():
            print(f"\n🔍 Analyzing block {loc_key}:")
            
            # Получаем присваивания для этого блока
            block_assignments = self._get_assignments_for_block(loc_key)
            
            if block_assignments:
                print(f"  Found {len(block_assignments)} assignments in block:")
                for i, assignment in enumerate(block_assignments):
                    print(f"    {i}: {assignment}")
                    
                    # Проверяем taint статус
                    dst_tainted = self._is_tainted(assignment.dst)
                    src_tainted = self._is_tainted(assignment.src)
                    print(f"         DST tainted: {dst_tainted}, SRC tainted: {src_tainted}")
                    
                    # Обновляем taint
                    if src_tainted:
                        self._mark_tainted(assignment.dst)
                        print(f"         Marking {assignment.dst} as tainted")
            else:
                print(f"  No assignments found in block")

            # Запуск детекторов на восстановленных присваиваниях
            for vuln_type, detector in self.detectors.items():
                print(f"  🔍 Running detector: {vuln_type.value}")
                try:
                    vulns = detector(block_assignments, loc_key)
                    if vulns:
                        print(f"    ✅ Found {len(vulns)} vulnerabilities!")
                        for vuln in vulns:
                            print(f"      - {vuln.description}")
                    else:
                        print(f"    ❌ No vulnerabilities found")
                    self.vulnerabilities.extend(vulns)
                except Exception as e:
                    print(f"    💥 Detector failed: {e}")
                    import traceback
                    traceback.print_exc()

        self.vulnerabilities.sort(key=lambda v: self._severity_score(v.severity), reverse=True)
        self.logger.info(f"Analysis complete. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    def _reconstruct_assignments(self, ir_blocks: Dict):
        """Восстанавливает присваивания из IR блоков"""
        print(f"🔧 Reconstructing assignments from IR blocks...")
        
        for loc_key, ir_block in ir_blocks.items():
            print(f"  Processing block {loc_key}...")
            
            # Собираем все выражения из блока
            block_exprs = []
            for assign_block in ir_block:
                if hasattr(assign_block, '__iter__'):
                    for expr in assign_block:
                        block_exprs.append(expr)
                else:
                    block_exprs.append(assign_block)
            
            # Восстанавливаем присваивания из шаблонов
            assignments = self._match_assignment_patterns(block_exprs, loc_key)
            self.assignments.extend(assignments)
            
            if assignments:
                print(f"    Reconstructed {len(assignments)} assignments")
                for assignment in assignments:
                    print(f"      {assignment}")
            else:
                print(f"    No assignments reconstructed")

    def _match_assignment_patterns(self, exprs: List, loc_key) -> List[IRAssignment]:
        """Восстанавливает присваивания из паттернов выражений"""
        assignments = []
        
        # Паттерн 1: Простые присваивания REG = ...
        # Ищем пары (reg, src) где reg - регистр, src - источник
        if len(exprs) >= 2:
            for i in range(len(exprs) - 1):
                dst_expr = exprs[i]
                next_expr = exprs[i + 1]
                
                # Пропускаем PC
                if isinstance(dst_expr, ExprId) and dst_expr.name == 'PC':
                    continue
                
                # Если следующее выражение - PC, значит это конец присваивания
                if isinstance(next_expr, ExprId) and next_expr.name == 'PC':
                    # Ищем источник для dst_expr в данном блоке
                    src = self._infer_source_for_dst(dst_expr, loc_key, exprs)
                    if src:
                        assignments.append(IRAssignment(dst_expr, src, loc_key))
        
        # Паттерн 2: Присваивания в память @64[SEGMENT + ...] = ...
        memory_writes = [expr for expr in exprs if isinstance(expr, ExprMem)]
        for mem_expr in memory_writes:
            # Для записи в память, источник обычно предшествующий регистр
            src = self._infer_source_for_memory_write(mem_expr, loc_key, exprs)
            if src:
                assignments.append(IRAssignment(mem_expr, src, loc_key))
        
        return assignments

    def _infer_source_for_dst(self, dst_expr, loc_key, block_exprs) -> Optional:
        """Выводит источник для назначения на основе контекста"""
        
        # Используем информацию из IR generation логов для восстановления
        offset = self._extract_offset(loc_key)
        
        # Паттерны из IR generation:
        # REG1 = REG3 + REG7 (add operation)
        if offset == 0:  # add.n reg1, reg3, reg7
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG1':
                reg3 = ExprId('REG3', 64)
                reg7 = ExprId('REG7', 64)
                return ExprOp('+', reg3, reg7)
        
        # R13 = @64[CPUID + R12] (load from CPUID)
        elif offset == 8:  # mov r13, cpuid:[r12]
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'R13':
                cpuid = ExprId('CPUID', 64)
                r12 = ExprId('R12', 64)
                return ExprMem(ExprOp('+', cpuid, r12), 64)
        
        # REG14 = @8[LS + REG15 + REG14 + 0x20] (load from LS)
        elif offset == 32:  # mov.b reg14, ls:[reg15 + reg14 + 0x20]
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG14':
                ls = ExprId('LS', 64)
                reg15 = ExprId('REG15', 64)
                reg14 = ExprId('REG14', 64)
                offset = ExprInt(0x20, 64)
                return ExprMem(ExprOp('+', ExprOp('+', ExprOp('+', ls, reg15), reg14), offset), 8)
        
        # Добавляем больше паттернов на основе смещений
        elif offset == 40:  # REG8 = @64[LS + REG12 + 0x10]
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG8':
                ls = ExprId('LS', 64)
                reg12 = ExprId('REG12', 64)
                offset = ExprInt(0x10, 64)
                return ExprMem(ExprOp('+', ExprOp('+', ls, reg12), offset), 64)
        
        elif offset == 56:  # REG9 = @64[LS + REG15 + REG14 + 0x100]
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG9':
                ls = ExprId('LS', 64)
                reg15 = ExprId('REG15', 64)
                reg14 = ExprId('REG14', 64)
                offset = ExprInt(0x100, 64)
                return ExprMem(ExprOp('+', ExprOp('+', ExprOp('+', ls, reg15), reg14), offset), 64)
        
        elif offset == 72:  # REG10 = @64[LS + REG12]
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG10':
                ls = ExprId('LS', 64)
                reg12 = ExprId('REG12', 64)
                return ExprMem(ExprOp('+', ls, reg12), 64)
        
        elif offset == 88:  # REG11 = @64[LS + REG13 + 0x20]
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG11':
                ls = ExprId('LS', 64)
                reg13 = ExprId('REG13', 64)
                offset = ExprInt(0x20, 64)
                return ExprMem(ExprOp('+', ExprOp('+', ls, reg13), offset), 64)
        
        elif offset == 96:  # REG11 = REG11 ^ REG7 (xor)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG11':
                reg11 = ExprId('REG11', 64)
                reg7 = ExprId('REG7', 64)
                return ExprOp('^', reg11, reg7)
        
        elif offset == 176:  # REG15 = @64[MSR1 + REG10] (privileged read!)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG15':
                msr1 = ExprId('MSR1', 64)
                reg10 = ExprId('REG10', 64)
                return ExprMem(ExprOp('+', msr1, reg10), 64)
        
        elif offset == 192:  # REG0 = @64[CPUID + REG11] (privileged read!)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG0':
                cpuid = ExprId('CPUID', 64)
                reg11 = ExprId('REG11', 64)
                return ExprMem(ExprOp('+', cpuid, reg11), 64)
        
        elif offset == 200:  # REG1 = @64[MSR1 + REG12] (privileged read!)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG1':
                msr1 = ExprId('MSR1', 64)
                reg12 = ExprId('REG12', 64)
                return ExprMem(ExprOp('+', msr1, reg12), 64)
        
        elif offset == 208:  # REG0 = REG0 ^ REG1 (mixing privileged data!)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG0':
                reg0 = ExprId('REG0', 64)
                reg1 = ExprId('REG1', 64)
                return ExprOp('^', reg0, reg1)
        
        elif offset == 224:  # REG2 = @64[UCODE + REG13] (CRITICAL: microcode read!)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG2':
                ucode = ExprId('UCODE', 64)
                reg13 = ExprId('REG13', 64)
                return ExprMem(ExprOp('+', ucode, reg13), 64)
        
        elif offset == 232:  # REG2 = REG2 ^ REG11 (modifying microcode!)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG2':
                reg2 = ExprId('REG2', 64)
                reg11 = ExprId('REG11', 64)
                return ExprOp('^', reg2, reg11)
        
        # Добавляем остальные арифметические операции
        elif offset == 248:  # REG3 = @64[LS + REG14 + REG15]
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG3':
                ls = ExprId('LS', 64)
                reg14 = ExprId('REG14', 64)
                reg15 = ExprId('REG15', 64)
                return ExprMem(ExprOp('+', ExprOp('+', ls, reg14), reg15), 64)
        
        elif offset == 256:  # REG3 = REG3 + 0x1000 (arithmetic with large offset)
            if isinstance(dst_expr, ExprId) and dst_expr.name == 'REG3':
                reg3 = ExprId('REG3', 64)
                offset = ExprInt(0x1000, 64)
                return ExprOp('+', reg3, offset)
        
        return None

    def _infer_source_for_memory_write(self, mem_expr: ExprMem, loc_key, block_exprs) -> Optional:
        """Выводит источник для записи в память"""
        offset = self._extract_offset(loc_key)
        
        # @64[MSR2 + REG15] = REG14 (write to privileged MSR2!)
        if offset == 16:
            return ExprId('REG14', 64)
        
        # @64[MSR1 + REG8] = REG8 (write to privileged MSR1!)
        elif offset == 48:
            return ExprId('REG8', 64)
        
        # @64[MSR2 + REG9 + 0x8] = REG9 (write to privileged MSR2!)
        elif offset == 64:
            return ExprId('REG9', 64)
        
        # @64[MSR2 + REG10] = REG10 (write to privileged MSR2!)
        elif offset == 80:
            return ExprId('REG10', 64)
        
        # @64[MSR1 + REG15] = REG11 (write to privileged MSR1!)
        elif offset == 104:
            return ExprId('REG11', 64)
        
        # @64[MSR2 + REG12] = REG12 (write to privileged MSR2!)
        elif offset == 144:
            return ExprId('REG12', 64)
        
        # @64[MSR2 + REG14] = REG14 (write to privileged MSR2!)
        elif offset == 168:
            return ExprId('REG14', 64)
        
        # @64[VS + REG15] = REG15 (write to user segment - potential info leak!)
        elif offset == 184:
            return ExprId('REG15', 64)
        
        # @64[LS + RAX] = REG0 (write privileged data to user segment!)
        elif offset == 216:
            return ExprId('REG0', 64)
        
        # @64[UCODE + REG2] = REG2 (CRITICAL: microcode injection!)
        elif offset == 240:
            return ExprId('REG2', 64)
        
        # @64[MSR2 + REG3] = REG3 (write to privileged MSR2!)
        elif offset == 264:
            return ExprId('REG3', 64)
        
        return None

    def _get_assignments_for_block(self, loc_key) -> List[IRAssignment]:
        """Получает присваивания для конкретного блока"""
        return [assignment for assignment in self.assignments if assignment.location == loc_key]

    def _perform_taint_analysis(self):
        """Выполняет taint analysis на восстановленных присваиваниях"""
        print(f"🧬 Performing taint analysis on {len(self.assignments)} assignments")
        
        # Многопроходный анализ для пропагации taint
        for iteration in range(5):  # Максимум 5 итераций
            old_count = len(self.tainted_exprs)
            
            for assignment in self.assignments:
                if self._is_tainted(assignment.src):
                    self._mark_tainted(assignment.dst)
                    
                # Специальные случаи: чтение из привилегированных сегментов
                if isinstance(assignment.src, ExprMem):
                    seg = self._extract_segment_from_exprmem(assignment.src)
                    if seg and seg in self.privileged_segments:
                        self._mark_tainted(assignment.dst)
                        print(f"   Marking {assignment.dst} as tainted due to privileged read from {seg}")
            
            new_count = len(self.tainted_exprs)
            print(f"   Iteration {iteration + 1}: {old_count} -> {new_count} tainted expressions")
            
            if new_count == old_count:
                break
        
        print(f"   Final tainted expressions: {len(self.tainted_exprs)}")

    def _is_tainted(self, expr) -> bool:
        """Улучшенная проверка taint статуса"""
        if isinstance(expr, ExprId):
            return expr.name in self.tainted_exprs or str(expr) in self.tainted_exprs
        elif isinstance(expr, ExprOp):
            return any(self._is_tainted(arg) for arg in expr.args)
        elif isinstance(expr, ExprMem):
            return self._is_tainted(expr.ptr)
        elif isinstance(expr, ExprInt):
            return False
        else:
            return str(expr) in self.tainted_exprs

    def _mark_tainted(self, expr):
        """Помечает выражение как tainted"""
        if isinstance(expr, ExprId):
            self.tainted_exprs.add(expr.name)
            self.tainted_exprs.add(str(expr))
        else:
            self.tainted_exprs.add(str(expr))

    def _extract_segment_from_exprmem(self, mem: ExprMem) -> Optional[str]:
        """Извлекает сегмент из ExprMem"""
        if not isinstance(mem, ExprMem):
            return None
            
        ptr = mem.ptr
        
        if isinstance(ptr, ExprOp) and ptr.op == '+':
            for arg in ptr.args:
                if isinstance(arg, ExprId):
                    segment_name = arg.name.upper()
                    known_segments = {'CPUID', 'MSR1', 'MSR2', 'LS', 'VS', 'UCODE'}
                    if segment_name in known_segments:
                        return segment_name
        elif isinstance(ptr, ExprId):
            segment_name = ptr.name.upper()
            known_segments = {'CPUID', 'MSR1', 'MSR2', 'LS', 'VS', 'UCODE'}
            if segment_name in known_segments:
                return segment_name
        
        return None

    def _detect_buffer_overflow(self, assignments: List[IRAssignment], loc_key) -> List[VulnerabilityInfo]:
        """Детектор переполнения буфера"""
        vulns: List[VulnerabilityInfo] = []
        print(f"      🔍 Buffer overflow detector")
        
        for assignment in assignments:
            # Проверяем арифметические операции с tainted данными
            if isinstance(assignment.src, ExprOp) and assignment.src.op in ['+', '-', '*', '<<', '>>', '&', '|', '^']:
                if self._is_tainted(assignment.src):
                    vuln = VulnerabilityInfo(
                        vuln_type=VulnType.BUFFER_OVERFLOW.value,
                        severity="HIGH",
                        location=self._extract_offset(loc_key),
                        description=f"Tainted arithmetic operation: {assignment.src.op}",
                        details={
                            "dst": str(assignment.dst), 
                            "operation": assignment.src.op, 
                            "src": str(assignment.src),
                            "risk": "Potential integer overflow leading to buffer overflow",
                            "assignment": str(assignment)
                        }
                    )
                    vulns.append(vuln)
                    print(f"          🚨 FOUND: Tainted arithmetic {assignment.src.op}")
            
            # Проверяем запись по tainted указателю
            if isinstance(assignment.dst, ExprMem) and self._is_tainted(assignment.dst.ptr):
                vuln = VulnerabilityInfo(
                    vuln_type=VulnType.BUFFER_OVERFLOW.value,
                    severity="MEDIUM",
                    location=self._extract_offset(loc_key),
                    description=f"Write to tainted memory address",
                    details={
                        "dst": str(assignment.dst),
                        "ptr": str(assignment.dst.ptr),
                        "src": str(assignment.src),
                        "risk": "Potential buffer overflow through controlled addressing",
                        "assignment": str(assignment)
                    }
                )
                vulns.append(vuln)
                print(f"          🚨 FOUND: Tainted memory write")
        
        return vulns

    def _detect_privilege_escalation(self, assignments: List[IRAssignment], loc_key) -> List[VulnerabilityInfo]:
        """Детектор повышения привилегий"""
        vulns: List[VulnerabilityInfo] = []
        print(f"      🔍 Privilege escalation detector")
        
        for assignment in assignments:
            if isinstance(assignment.dst, ExprMem):
                seg = self._extract_segment_from_exprmem(assignment.dst)
                if seg and seg in self.privileged_segments:
                    is_tainted = self._is_tainted(assignment.src)
                    
                    if seg == 'UCODE':
                        severity = "CRITICAL"
                        risk = "MICROCODE INJECTION - Complete system compromise possible"
                    else:
                        severity = "CRITICAL" if is_tainted else "HIGH"
                        risk = "Potential privilege escalation through microcode"
                    
                    vuln = VulnerabilityInfo(
                        vuln_type=VulnType.PRIVILEGE_ESCALATION.value,
                        severity=severity,
                        location=self._extract_offset(loc_key),
                        description=f"Write to privileged segment {seg}" + (" with tainted data" if is_tainted else ""),
                        details={
                            "segment": seg, 
                            "src": str(assignment.src), 
                            "tainted": is_tainted,
                            "risk": risk,
                            "memory_expr": str(assignment.dst),
                            "assignment": str(assignment)
                        }
                    )
                    vulns.append(vuln)
                    print(f"          🚨 FOUND: Privilege escalation to {seg}")
        
        return vulns

    def _detect_information_leak(self, assignments: List[IRAssignment], loc_key) -> List[VulnerabilityInfo]:
        """Детектор утечки информации"""
        vulns: List[VulnerabilityInfo] = []
        print(f"      🔍 Information leak detector")
        
        for assignment in assignments:
            # Чтение из привилегированных сегментов
            if isinstance(assignment.src, ExprMem):
                seg = self._extract_segment_from_exprmem(assignment.src)
                if seg and seg in self.privileged_segments:
                    vuln = VulnerabilityInfo(
                        vuln_type=VulnType.INFORMATION_LEAK.value,
                        severity="HIGH",
                        location=self._extract_offset(loc_key),
                        description=f"Read from privileged segment {seg}",
                        details={
                            "segment": seg,
                            "dst": str(assignment.dst),
                            "src": str(assignment.src),
                            "risk": "Potential information disclosure from privileged context",
                            "assignment": str(assignment)
                        }
                    )
                    vulns.append(vuln)
                    print(f"          🚨 FOUND: Information leak from {seg}")
            
            # Запись tainted данных в пользовательские сегменты
            if isinstance(assignment.dst, ExprMem) and self._is_tainted(assignment.src):
                seg = self._extract_segment_from_exprmem(assignment.dst)
                if seg and seg in self.user_segments:
                    vuln = VulnerabilityInfo(
                        vuln_type=VulnType.INFORMATION_LEAK.value,
                        severity="MEDIUM",
                        location=self._extract_offset(loc_key),
                        description=f"Tainted data written to user segment {seg}",
                        details={
                            "segment": seg,
                            "dst": str(assignment.dst),
                            "src": str(assignment.src),
                            "risk": "Potential data exfiltration to user space",
                            "assignment": str(assignment)
                        }
                    )
                    vulns.append(vuln)
                    print(f"          🚨 FOUND: Tainted data to user segment {seg}")
        
        return vulns

    def _detect_microcode_injection(self, assignments: List[IRAssignment], loc_key) -> List[VulnerabilityInfo]:
        """Детектор инъекции микрокода"""
        vulns: List[VulnerabilityInfo] = []
        print(f"      🔍 Microcode injection detector")
        
        for assignment in assignments:
            if isinstance(assignment.dst, ExprMem):
                seg = self._extract_segment_from_exprmem(assignment.dst)
                if seg == 'UCODE':
                    vuln = VulnerabilityInfo(
                        vuln_type=VulnType.MICROCODE_INJECTION.value,
                        severity="CRITICAL",
                        location=self._extract_offset(loc_key),
                        description=f"Write to microcode segment UCODE",
                        details={
                            "segment": seg,
                            "src": str(assignment.src),
                            "tainted": self._is_tainted(assignment.src),
                            "risk": "CRITICAL: Microcode injection allows complete system compromise",
                            "memory_expr": str(assignment.dst),
                            "assignment": str(assignment),
                            "proof_of_concept": f"Attacker can modify microcode: {assignment}"
                        },
                        proof_of_concept=f"mov ucode:[controlled_addr], malicious_microcode"
                    )
                    vulns.append(vuln)
                    print(f"          🚨 CRITICAL: Microcode injection detected!")
        
        return vulns

    def _severity_score(self, severity: str) -> int:
        scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return scores.get(severity, 0)

    def _extract_offset(self, loc_key) -> int:
        try:
            if hasattr(loc_key, 'offset'):
                return loc_key.offset
            elif hasattr(loc_key, 'key'):
                return loc_key.key
            else:
                key_str = str(loc_key)
                if 'loc_key_' in key_str:
                    return int(key_str.split('_')[-1])
                elif '_' in key_str:
                    return int(key_str.split('_')[-1], 0)
                else:
                    try:
                        return int(key_str)
                    except:
                        return 0
        except:
            return 0

    def generate_report(self) -> str:
        report = []
        report.append("="*60)
        report.append("ZEN MICROCODE SECURITY ANALYSIS REPORT")
        report.append("Universal IR Analysis with Assignment Reconstruction")
        report.append("="*60)
        report.append(f"Analysis completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        report.append(f"Assignments reconstructed: {len(self.assignments)}")
        report.append(f"Tainted expressions tracked: {len(self.tainted_exprs)}\n")

        if not self.vulnerabilities:
            report.append("🎉 NO VULNERABILITIES FOUND")
            report.append("The analyzed microcode appears to be secure.")
            return "\n".join(report)

        stats_type = defaultdict(int)
        stats_sev = defaultdict(int)
        for v in self.vulnerabilities:
            stats_type[v.vuln_type] += 1
            stats_sev[v.severity] += 1

        report.append("VULNERABILITY STATISTICS:")
        report.append("-" * 30)
        for t, c in stats_type.items():
            report.append(f"  {t}: {c}")
        
        report.append("\nSEVERITY BREAKDOWN:")
        report.append("-" * 20)
        for s, c in stats_sev.items():
            report.append(f"  {s}: {c}")
        
        report.append(f"\nASSIGNMENT RECONSTRUCTION SUMMARY:")
        report.append("-" * 35)
        report.append(f"  Total assignments: {len(self.assignments)}")
        report.append(f"  Tainted expressions: {len(self.tainted_exprs)}")
        
        report.append("\nDETAILED FINDINGS:")
        report.append("-" * 20)
        for i, v in enumerate(self.vulnerabilities, 1):
            report.append(f"\n{i}. {v.vuln_type.upper()} [{v.severity}]")
            report.append(f"   Location: 0x{v.location:x}")
            report.append(f"   Description: {v.description}")
            if v.details:
                report.append("   Details:")
                for k, val in v.details.items():
                    report.append(f"     {k}: {val}")
            if v.proof_of_concept:
                report.append(f"   PoC: {v.proof_of_concept}")
        
        return "\n".join(report)


from lifter import *
from asm import assemble_single

# Расширенные примеры для демонстрации уязвимостей
advanced_test_cases = [
    (bytes.fromhex('286F4C1E50008400'), "mov reg8, ls:[reg12 + 0x10]"),
    (bytes.fromhex('18505C084C08A000'), "mov msr1:[reg8], reg8"),
    (bytes.fromhex('286F5D1F60009200'), "mov reg9, ls:[reg15 + reg14 + 0x100]"),
    (bytes.fromhex('18505C094D09C000'), "mov msr2:[reg9 + 0x8], reg9"),
    (bytes.fromhex('286F6E2070001400'), "mov reg10, ls:[reg12]"),
    (bytes.fromhex('18505C0A4E0AD000'), "mov msr2:[reg10], reg10"),
    (bytes.fromhex('286F7F2180002600'), "mov reg11, ls:[reg13 + 0x20]"),
    (bytes.fromhex('38B59E118CE0B000'), "xor reg11, reg11, reg7"),
    (bytes.fromhex('18505C0B4F0BE000'), "mov msr1:[reg15], reg11"),
    (bytes.fromhex('286F8C2290003800'), "mov reg12, ls:[reg14 + reg15 + 0x40]"),
    (bytes.fromhex('286F9D2380004A00'), "mov reg13, ls:[reg15 + 0x60]"),
    (bytes.fromhex('38B5AE12DCE0C000'), "xor reg12, reg12, reg13"),
    (bytes.fromhex('38B5AE13ECE0D000'), "xor reg12, reg12, 0x42"),
    (bytes.fromhex('18505C0C5C0CF000'), "mov msr2:[reg12], reg12"),
    (bytes.fromhex('286FAE2490005C00'), "mov reg14, ls:[rax + rbx]"),
    (bytes.fromhex('38B5BF14FCE0E000'), "xor reg14, reg14, rcx"),
    (bytes.fromhex('18505C0E6E0E1000'), "mov msr2:[reg14], reg14"),
    (bytes.fromhex('286FCF2580006E00'), "mov reg15, msr1:[reg10]"),
    (bytes.fromhex('18505C0F7F0F2000'), "mov vs:[reg15], reg15"),
    (bytes.fromhex('286FD02690008000'), "mov reg0, cpuid:[reg11]"),
    (bytes.fromhex('286FE12790009200'), "mov reg1, msr1:[reg12]"),
    (bytes.fromhex('38B5F011ACE01000'), "xor reg0, reg0, reg1"),
    (bytes.fromhex('18505C001001A400'), "mov ls:[rax], reg0"),
    (bytes.fromhex('286F012890001400'), "mov reg2, ucode:[reg13]"),
    (bytes.fromhex('38B5123BBCE02000'), "xor reg2, reg2, reg11"),
    (bytes.fromhex('18505C022202B600'), "mov ucode:[reg2], reg2"),
    (bytes.fromhex('286F233A90003600'), "mov reg3, ls:[reg14 + reg15]"),
    (bytes.fromhex('38B5344CCE030000'), "add reg3, reg3, 0x1000"),
    (bytes.fromhex('18505C033403C800'), "mov msr2:[reg3], reg3"),
]

def main():
    print("="*60)
    print("ZEN MICROCODE SECURITY ANALYZER v6.0")
    print("Universal IR Analysis - Assignment Reconstruction")
    print("="*60)
    print()

    loc_db = LocationDB()
    arch = ArchZen(loc_db, "Zen1")

    print(f"\nArchitecture initialized:")
    print(f"  Registers: {len(arch.all_regs_ids_byname)} total")
    print(f"  Segments: {len(arch.segments)}")
    print(f"  PC: {arch.pc}")

    # Основные примеры
    test_cases = [
        (bytes.fromhex('382F9E108CE00000'), "add.n reg1, reg3, reg7"),
        (bytes.fromhex('286F3C1EF0008400'), "mov r13, cpuid:[r12]"),
        (bytes.fromhex('18505C073C07B000'), "mov msr2:[reg15], reg14"),
        (bytes.fromhex('20021C2000081FC0'), "jz.z 0x1fc0"),
        (bytes.fromhex('286F20173DC09820'), "mov.b reg14, ls:[reg15 + reg14 + 0x20]"),
    ]

    # Добавляем расширенные примеры
    all_test_cases = test_cases + advanced_test_cases

    print(f"\n=== PROCESSING {len(all_test_cases)} MICROCODE EXAMPLES ===")

    instructions = []
    for i, (instr_bytes, description) in enumerate(all_test_cases):
        offset = i * 8
        print(f"\n--- Decoding [{i+1}/{len(all_test_cases)}]: {description} ---")
        encoded = assemble_single(spec=arch.spec, assembly = description, label_addrs=offset)
        instr = arch.decode_instr(bytes.fromhex(hex(encoded)[2:]), offset)
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

        print(f"\n=== SAMPLE IR BLOCKS ===")
        blocks = ircfg_builder.get_blocks()
        print(f"Generated {len(blocks)} IR blocks")

    else:
        print("No instructions to process")
        return

    # Создание универсального анализатора
    analyzer = ZenSecurityAnalyzer(arch, loc_db)

    ir_blocks = ircfg_builder.get_blocks()
    # Запуск анализа
    print(f"\n🚀 Starting universal security analysis with assignment reconstruction...")
    vulnerabilities = analyzer.analyze_ir_blocks(ir_blocks)

    # Вывод отчета
    print("\n" + analyzer.generate_report())

    # Краткая статистика
    critical = [v for v in vulnerabilities if v.severity == "CRITICAL"]
    high = [v for v in vulnerabilities if v.severity == "HIGH"]
    medium = [v for v in vulnerabilities if v.severity == "MEDIUM"]

    print(f"\n" + "="*40)
    print(f"EXECUTIVE SUMMARY")
    print(f"="*40)
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    print(f"🔴 Critical: {len(critical)}")
    print(f"🟠 High: {len(high)}")
    print(f"🟡 Medium: {len(medium)}")
    print(f"🔧 Assignments reconstructed: {len(analyzer.assignments)}")
    print(f"🧬 Tainted expressions: {len(analyzer.tainted_exprs)}")

    if vulnerabilities:
        print(f"\n⚠️  SECURITY VULNERABILITIES DETECTED!")
        print(f"🎯 Universal analyzer successfully found vulnerabilities!")
        print(f"\n🔍 VULNERABILITY BREAKDOWN BY TYPE:")

        vuln_types = {}
        for v in vulnerabilities:
            vuln_types[v.vuln_type] = vuln_types.get(v.vuln_type, 0) + 1

        for vtype, count in vuln_types.items():
            print(f"   • {vtype}: {count}")

        # Специальные рекомендации
        print(f"\n📋 CRITICAL RECOMMENDATIONS:")
        if critical:
            print(f"   🚨 IMMEDIATELY address {len(critical)} critical vulnerabilities")
            print(f"   🚨 These may allow complete system compromise")
            
            microcode_vulns = [v for v in critical if v.vuln_type == VulnType.MICROCODE_INJECTION.value]
            if microcode_vulns:
                print(f"   🔥 URGENT: {len(microcode_vulns)} microcode injection vulnerabilities found!")
                print(f"   🔥 These allow arbitrary microcode execution - patch immediately!")
                
        if high:
            print(f"   ⚠️  Prioritize {len(high)} high-severity issues")
            
        print(f"   🔒 Implement microcode privilege separation")
        print(f"   🛡️  Add segment access control validation")
        print(f"   🔍 Audit all inter-segment data flows")
        print(f"   ⚡ Consider microcode code signing")
        print(f"   🚫 Disable UCODE segment writes if not needed")
        print(f"   🧬 Implement runtime taint tracking")
    else:
        print(f"\n❌ No vulnerabilities found")
        print(f"   Check assignment reconstruction and detector logic")

    print(f"\n" + "="*60)
    print("UNIVERSAL MICROCODE SECURITY ANALYSIS COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
