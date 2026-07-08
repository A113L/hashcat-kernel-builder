#!/usr/bin/env python3
"""
KernelBuilder - Auto-generate Hashcat OpenCL kernels and modules.
Python port of the C# tool.
Auto-generate Hashcat kernels and modules.
"""

import argparse
import os
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Endianness(Enum):
    LittleEndian = auto()
    BigEndian = auto()


class OutputFormat(Enum):
    Binary = 1
    Hex = 2


class Conversion(Enum):
    LE2LE = auto()
    LE2BE = auto()
    BE2LE = auto()
    BE2BE = auto()


class KernelType(Enum):
    SingleHash = auto()
    MultiHash = auto()


class AttackVector(Enum):
    a0 = auto()
    a1 = auto()
    a3 = auto()


# ---------------------------------------------------------------------------
# CodeList
# ---------------------------------------------------------------------------
class CodeList(list):
    def __init__(self):
        super().__init__()
        self.spacing = 0

    def add(self, element, spacing=None):
        if spacing is not None:
            self.spacing = spacing
        if isinstance(element, str):
            lines = element.split("\n")
        else:
            lines = list(element)
        for item in lines:
            super().append(" " * (self.spacing * 2) + item.strip())

    def add_range(self, other):
        self.extend(other)


# ---------------------------------------------------------------------------
# IAlgorithm
# ---------------------------------------------------------------------------
class IAlgorithm(ABC):
    byteLength: int = 16
    context: str = ""

    @property
    @abstractmethod
    def endianness(self) -> Endianness:
        ...

    @property
    @abstractmethod
    def outputFormat(self) -> OutputFormat:
        ...

    @property
    def length(self) -> int:
        return self.byteLength * self.outputFormat.value

    @property
    @abstractmethod
    def opts_types(self) -> str:
        ...

    @property
    @abstractmethod
    def initialValues(self) -> str:
        ...

    @property
    @abstractmethod
    def contextType(self) -> str:
        ...

    @property
    @abstractmethod
    def initFunction(self) -> str:
        ...

    @property
    @abstractmethod
    def updateFunction(self) -> str:
        ...

    @property
    @abstractmethod
    def updateGlobalFunction(self) -> str:
        ...

    @property
    @abstractmethod
    def updateSwapFunction(self) -> str:
        ...

    @property
    @abstractmethod
    def updateVectorSwapFunction(self) -> str:
        ...

    @property
    @abstractmethod
    def updateGlobalSwapFunction(self) -> str:
        ...

    @property
    @abstractmethod
    def update64Function(self) -> str:
        ...

    @property
    @abstractmethod
    def update64VectorFunction(self) -> str:
        ...

    @property
    @abstractmethod
    def finalFunction(self) -> str:
        ...


# ---------------------------------------------------------------------------
# Algorithm implementations
# ---------------------------------------------------------------------------
class MD5(IAlgorithm):
    def __init__(self):
        self.byteLength = 16
        self.context = ""

    @property
    def endianness(self): return Endianness.LittleEndian
    @property
    def outputFormat(self): return OutputFormat.Hex
    @property
    def opts_types(self): return "OPTS_TYPE_PT_GENERATE_LE | OPTS_TYPE_ST_ADD80 | OPTS_TYPE_ST_ADDBITS14"
    @property
    def initialValues(self): return "MD5M_"
    @property
    def contextType(self): return "md5_ctx_t"
    @property
    def initFunction(self): return "md5_init"
    @property
    def updateFunction(self): return "md5_update"
    @property
    def updateGlobalFunction(self): return "md5_update_global"
    @property
    def updateSwapFunction(self): return "md5_update_swap"
    @property
    def updateVectorSwapFunction(self): return "md5_update_vector_swap"
    @property
    def updateGlobalSwapFunction(self): return "md5_update_global_swap"
    @property
    def update64Function(self): return "md5_update_64"
    @property
    def update64VectorFunction(self): return "md5_update_vector_64"
    @property
    def finalFunction(self): return "md5_final"


class SHA1(IAlgorithm):
    def __init__(self):
        self.byteLength = 20
        self.context = ""

    @property
    def endianness(self): return Endianness.BigEndian
    @property
    def outputFormat(self): return OutputFormat.Hex
    @property
    def opts_types(self): return "OPTS_TYPE_PT_GENERATE_BE | OPTS_TYPE_ST_ADD80 | OPTS_TYPE_ST_ADDBITS15"
    @property
    def initialValues(self): return "SHA1M_"
    @property
    def contextType(self): return "sha1_ctx_t"
    @property
    def initFunction(self): return "sha1_init"
    @property
    def updateFunction(self): return "sha1_update"
    @property
    def updateGlobalFunction(self): return "sha1_update_global"
    @property
    def updateSwapFunction(self): return "sha1_update_swap"
    @property
    def updateVectorSwapFunction(self): return "sha1_update_vector_swap"
    @property
    def updateGlobalSwapFunction(self): return "sha1_update_global_swap"
    @property
    def update64Function(self): return "sha1_update_64"
    @property
    def update64VectorFunction(self): return "sha1_update_vector_64"
    @property
    def finalFunction(self): return "sha1_final"


class SHA224(IAlgorithm):
    def __init__(self):
        self.byteLength = 28
        self.context = ""

    @property
    def endianness(self): return Endianness.BigEndian
    @property
    def outputFormat(self): return OutputFormat.Hex
    @property
    def opts_types(self): return "OPTS_TYPE_PT_GENERATE_BE | OPTS_TYPE_ST_ADD80 | OPTS_TYPE_ST_ADDBITS15"
    @property
    def initialValues(self): return "SHA224M_"
    @property
    def contextType(self): return "sha224_ctx_t"
    @property
    def initFunction(self): return "sha224_init"
    @property
    def updateFunction(self): return "sha224_update"
    @property
    def updateGlobalFunction(self): return "sha224_update_global"
    @property
    def updateSwapFunction(self): return "sha224_update_swap"
    @property
    def updateVectorSwapFunction(self): return "sha224_update_vector_swap"
    @property
    def updateGlobalSwapFunction(self): return "sha224_update_global_swap"
    @property
    def update64Function(self): return "sha224_update_64"
    @property
    def update64VectorFunction(self): return "sha224_update_vector_64"
    @property
    def finalFunction(self): return "sha224_final"


class SHA256(IAlgorithm):
    def __init__(self):
        self.byteLength = 32
        self.context = ""

    @property
    def endianness(self): return Endianness.BigEndian
    @property
    def outputFormat(self): return OutputFormat.Hex
    @property
    def opts_types(self): return "OPTS_TYPE_PT_GENERATE_BE | OPTS_TYPE_ST_ADD80 | OPTS_TYPE_ST_ADDBITS15"
    @property
    def initialValues(self): return "SHA256M_"
    @property
    def contextType(self): return "sha256_ctx_t"
    @property
    def initFunction(self): return "sha256_init"
    @property
    def updateFunction(self): return "sha256_update"
    @property
    def updateGlobalFunction(self): return "sha256_update_global"
    @property
    def updateSwapFunction(self): return "sha256_update_swap"
    @property
    def updateVectorSwapFunction(self): return "sha256_update_vector_swap"
    @property
    def updateGlobalSwapFunction(self): return "sha256_update_global_swap"
    @property
    def update64Function(self): return "sha256_update_64"
    @property
    def update64VectorFunction(self): return "sha256_update_vector_64"
    @property
    def finalFunction(self): return "sha256_final"


SUPPORTED_ALGORITHMS = {
    "MD5": MD5,
    "SHA1": SHA1,
    "SHA224": SHA224,
    "SHA256": SHA256,
}


def parse_algorithm_name(algorithm: str) -> IAlgorithm:
    if algorithm == "MD5":
        return MD5()
    elif algorithm == "SHA1":
        return SHA1()
    elif algorithm == "SHA224":
        return SHA224()
    elif algorithm == "SHA256":
        return SHA256()
    raise NotImplementedError("The hash function you specified is not supported!")


# ---------------------------------------------------------------------------
# Interpreter / Parser
# ---------------------------------------------------------------------------
class IExpression:
    pass


@dataclass
class Variable(IExpression):
    Name: str
    def __str__(self): return "$" + self.Name


@dataclass
class FunctionCall(IExpression):
    FunctionName: str
    Arguments: List[IExpression] = field(default_factory=list)
    OutputId: str = ""
    def __str__(self):
        return f"{self.FunctionName}({', '.join(str(a) for a in self.Arguments)})"


@dataclass
class Concat(IExpression):
    Parts: List[IExpression] = field(default_factory=list)
    def __str__(self):
        return " . ".join(str(p) for p in self.Parts)


class Parser:
    def __init__(self, input_str: str):
        self.input = input_str
        self.pos = 0

    def parse_expression(self):
        return self.parse_concat()

    def parse_concat(self):
        expr = self.parse_term()
        parts = [expr]
        while self.match('.'):
            nxt = self.parse_term()
            parts.append(nxt)
        if len(parts) == 1:
            return parts[0]
        return Concat(Parts=parts)

    def parse_term(self):
        self.skip_whitespace()
        if self.pos >= len(self.input):
            raise Exception("Unexpected end of input.")
        current = self.current()
        if current == '$':
            return self.parse_variable()
        elif current.isalpha():
            return self.parse_function_call()
        elif current == '(':
            self.consume('(')
            expr = self.parse_expression()
            self.consume(')')
            return expr
        raise Exception(f"Unexpected character '{current}' at position {self.pos}")

    def parse_variable(self):
        self.consume('$')
        sb = []
        while self.pos < len(self.input) and (self.input[self.pos].isalnum() or self.input[self.pos] == '_'):
            sb.append(self.input[self.pos])
            self.pos += 1
        return Variable(Name=''.join(sb))

    def parse_function_call(self):
        sb = []
        while self.pos < len(self.input) and (self.input[self.pos].isalnum() or self.input[self.pos] == '_'):
            sb.append(self.input[self.pos])
            self.pos += 1
        func_name = ''.join(sb)
        fc = FunctionCall(FunctionName=func_name)
        self.skip_whitespace()
        if self.pos < len(self.input) and self.current() == '(':
            self.consume('(')
            arg = self.parse_expression()
            fc.Arguments.append(arg)
            self.consume(')')
        return fc

    def skip_whitespace(self):
        while self.pos < len(self.input) and self.input[self.pos].isspace():
            self.pos += 1

    def current(self):
        return self.input[self.pos]

    def match(self, expected):
        self.skip_whitespace()
        if self.pos < len(self.input) and self.input[self.pos] == expected:
            self.pos += 1
            return True
        return False

    def consume(self, expected):
        self.skip_whitespace()
        if self.pos < len(self.input) and self.input[self.pos] == expected:
            self.pos += 1
        else:
            raise Exception(f"Expected '{expected}' at position {self.pos}")


class InstructionGenerator:
    def __init__(self):
        self.id_counter = 1
        self.instructions = []

    def generate(self, expr: IExpression) -> str:
        if isinstance(expr, Variable):
            return expr.Name
        elif isinstance(expr, Concat):
            parts = [self.generate(part) for part in expr.Parts]
            return ", ".join(parts)
        elif isinstance(expr, FunctionCall):
            arg_outputs = []
            for arg in expr.Arguments:
                if isinstance(arg, Concat):
                    for part in arg.Parts:
                        arg_outputs.append(self.generate(part))
                else:
                    arg_outputs.append(self.generate(arg))

            current_id = f"{expr.FunctionName.upper()}-{self.id_counter}"
            self.id_counter += 1
            expr.OutputId = current_id

            for argument in arg_outputs:
                self.instructions.append(f"{current_id} - {argument}")
            return current_id
        return ""

    def get_instructions(self) -> List[str]:
        return self.instructions


class Interpreter:
    @staticmethod
    def generate_instructions(algorithm: str) -> List[str]:
        parser = Parser(algorithm)
        expr = parser.parse_expression()
        generator = InstructionGenerator()
        generator.generate(expr)
        return generator.get_instructions()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_presalted_contexts(instructions: List[str]) -> List[str]:
    """Return contexts whose very first input is salt (eligible for presalt hoisting)."""
    presalted = []
    seen = set()
    for inst in instructions:
        parts = inst.split(" - ")
        ctx = parts[0].replace("-", "").replace(" ", "")
        input_ = parts[1].replace("-", "")
        if ctx not in seen:
            seen.add(ctx)
            if input_ == "salt":
                presalted.append(ctx)
    return presalted


def resolve_algorithm_from_context(ctx: str) -> str:
    """Extract algorithm name from context id, e.g. SHA2561 -> SHA256."""
    m = re.match(r"([A-Za-z]+)\d*", ctx)
    if m:
        return m.group(1).upper()
    return ""


def needs_chained_buffers(instructions: List[str]) -> bool:
    """True if any instruction feeds a previous hash context into another (needs w0-w3 arrays)."""
    for inst in instructions:
        input_ = inst.split(" - ")[1].replace("-", "")
        if input_ not in ("plain", "salt"):
            return True
    return False


# ---------------------------------------------------------------------------
# KernelCodeGenerator
# ---------------------------------------------------------------------------
class KernelCodeGenerator:
    @staticmethod
    def generate_imports(attack_vector: AttackVector, optimized: bool = False) -> CodeList:
        code = CodeList()

        code.add("""
/**
 * Plugin has been auto-generated by https://github.com/PenguinKeeper7/KernelBuilder
 * DO NOT PR into hashcat master
 */

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
""")

        if attack_vector == AttackVector.a3:
            code.add("#define NEW_SIMD_CODE")

        code.add("""
#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
""")

        if attack_vector == AttackVector.a3:
            code.add("#include M2S(INCLUDE_PATH/inc_simd.cl)")
        else:
            code.add("""
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
""")

        code.add("""
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha224.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc_le[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc_le[(i).s0], l_bin2asc_le[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc_le[(i).s0], l_bin2asc_le[(i).s1], l_bin2asc_le[(i).s2], l_bin2asc_le[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc_le[(i).s0], l_bin2asc_le[(i).s1], l_bin2asc_le[(i).s2], l_bin2asc_le[(i).s3], l_bin2asc_le[(i).s4], l_bin2asc_le[(i).s5], l_bin2asc_le[(i).s6], l_bin2asc_le[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc_le[(i).s0], l_bin2asc_le[(i).s1], l_bin2asc_le[(i).s2], l_bin2asc_le[(i).s3], l_bin2asc_le[(i).s4], l_bin2asc_le[(i).s5], l_bin2asc_le[(i).s6], l_bin2asc_le[(i).s7], l_bin2asc_le[(i).s8], l_bin2asc_le[(i).s9], l_bin2asc_le[(i).sa], l_bin2asc_le[(i).sb], l_bin2asc_le[(i).sc], l_bin2asc_le[(i).sd], l_bin2asc_le[(i).se], l_bin2asc_le[(i).sf])
#endif
""")

        code.add("")
        return code

    @staticmethod
    def generate_header(instructions: List[str], kernel_type: KernelType, attack_vector: AttackVector, hash_mode: str,
                        optimized: bool = False, tier: str = None, presalted_contexts: List[str] = None) -> CodeList:
        if presalted_contexts is None:
            presalted_contexts = []

        code = CodeList()

        if kernel_type == KernelType.SingleHash:
            function_name_suffix = "s"
        else:
            function_name_suffix = "m"

        if tier is not None:
            function_name_suffix = function_name_suffix + tier
        else:
            function_name_suffix = function_name_suffix + "xx"

        if attack_vector == AttackVector.a0:
            argument = "KERN_ATTR_RULES ()"
        elif attack_vector == AttackVector.a1:
            argument = "KERN_ATTR_BASIC ()"
        elif attack_vector == AttackVector.a3:
            argument = "KERN_ATTR_VECTOR ()"
        else:
            raise NotImplementedError("Unknown -a mode")

        code.add(f"KERNEL_FQ KERNEL_FA void m{hash_mode}_{function_name_suffix} ({argument})", 0)

        code.add("""
{
/**
    * modifier
    */

const u64 gid = get_global_id (0);
const u64 lid = get_local_id (0);
const u64 lsz = get_local_size (0);

/**
    * both encoding bin2asc tables
    */

LOCAL_VK u32 l_bin2asc[256];
LOCAL_VK u32 l_bin2asc_le[256];

for (u32 i = lid; i < 256; i += lsz)
{
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
    l_bin2asc_le[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
}

SYNC_THREADS ();

if (gid >= GID_CNT) return;

/**
    * digest
    */

const u32 search[4] =
{
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
};

/**
    * base
    */
""", 1)

        if attack_vector == AttackVector.a0:
            code.add("COPY_PW (pws[gid]);", 1)
        else:
            code.add("""
const u32 pw_len = pws[gid].pw_len;
u32x w[64] = { 0 };
for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
{
  w[idx] = pws[gid].i[idx];
}

u32x w0l = w[0];
""")

        # Handle optional salts
        for instruction in instructions:
            if "salt" in instruction:
                code.add("""
const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

u32 s[64] = { 0 };

for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
{
  s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
}
""", 1)

                # Presalt hoisting: for optimized a0/a1, pre-initialize contexts that start with salt
                if optimized and attack_vector in (AttackVector.a0, AttackVector.a1):
                    for ctx_name in presalted_contexts:
                        algo_name = resolve_algorithm_from_context(ctx_name)
                        if algo_name in SUPPORTED_ALGORITHMS:
                            algo = parse_algorithm_name(algo_name)
                            code.add(f"{algo.contextType} {ctx_name}_presalt;")
                            code.add(f"{algo.initFunction} (&{ctx_name}_presalt);")
                            if algo.endianness == Endianness.LittleEndian:
                                code.add(f"{algo.updateFunction}(&{ctx_name}_presalt, s, salt_len);")
                            else:
                                code.add(f"{algo.updateSwapFunction}(&{ctx_name}_presalt, s, salt_len);")
                break

        # Determine if we need w0-w3 arrays for chained hash loading
        needs_buffers = needs_chained_buffers(instructions)

        code.add("""

/**
 * loop
 */

""", 1)

        if needs_buffers:
            code.add("""  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

""", 1)

        if attack_vector == AttackVector.a3:
            code.add("for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)")
        else:
            code.add("for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)")

        code.add("{")
        code.spacing += 1

        if attack_vector == AttackVector.a0:
            code.add("""
pw_t tmp = PASTE_PW;

tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);
""", 1)
        elif attack_vector == AttackVector.a3:
            code.add("""
                                    	
const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

const u32x wStart = w0l | w0r;

w[0] = wStart;
""")

        code.add("")
        return code

    @staticmethod
    def generate_compute(instructions: List[str], attack_vector: AttackVector, optimized: bool = False,
                         presalted_contexts: List[str] = None) -> CodeList:
        if presalted_contexts is None:
            presalted_contexts = []

        code = CodeList()
        code.spacing = 2

        context_algorithms: Dict[str, IAlgorithm] = {}
        context_input_counts: Dict[str, int] = {}

        for instruction in instructions:
            ctx = instruction.split(" - ")[0].replace("-", "").replace(" ", "")
            if ctx in context_input_counts:
                context_input_counts[ctx] += 1
            else:
                context_input_counts[ctx] = 1

        for idx in range(len(instructions)):
            instruction = instructions[idx]
            context = instruction.split(" - ")[0].replace(" ", "").replace("-", "")
            input_ = instruction.split(" - ")[1].replace("-", "")
            algorithm_name = instruction.split("-")[0]

            if algorithm_name.startswith("CUT"):
                cut_length = int(context.split("_")[0].replace("CUT", "")) // 2
                algorithm_name = instruction.split("_")[-1].split("-")[0]
                instruction = instruction.replace(f"CUT{cut_length}_", "")
                current_algorithm = parse_algorithm_name(algorithm_name)
                context = context.split("_")[-1]
            else:
                current_algorithm = parse_algorithm_name(algorithm_name)

            current_algorithm.context = context

            if context not in context_algorithms:
                context_algorithms[context] = current_algorithm

                is_presalted = (optimized and attack_vector in (AttackVector.a0, AttackVector.a1) and
                                context in presalted_contexts and input_ == "salt")

                if is_presalted:
                    code.add(f"{current_algorithm.contextType} {context};")
                    code.add(f"{context} = {context}_presalt;")
                else:
                    if attack_vector != AttackVector.a3:
                        code.add(f"{current_algorithm.contextType} {context};")
                        code.add(f"{current_algorithm.initFunction} (&{context});")
                    else:
                        code.add(f"{current_algorithm.contextType.replace('_t', '_vector_t')} {context};")
                        code.add(f"{current_algorithm.initFunction}_vector (&{context});")

                code.add("")

            # Re-parse CUTs for inputs
            if input_.startswith("CUT"):
                cut_length = int(input_.split("_")[0].replace("CUT", "")) // 2
                if cut_length % 4 != 0:
                    raise NotImplementedError("CUT is not supported for values that are not multiples of 4.")

                context_to_cut = instruction.split("_")[-1].split(" - ")[0].replace("-", "")
                if context_to_cut not in context_algorithms:
                    raise NotImplementedError("CUT is not supported on raw values such as $plain or $salt.")

                context_algorithms[context_to_cut].byteLength = cut_length
                input_ = input_.split("_")[-1]

            if input_ == "plain":
                if current_algorithm.endianness == Endianness.LittleEndian:
                    if attack_vector == AttackVector.a0:
                        code.add(f"{current_algorithm.updateFunction}(&{context}, tmp.i, tmp.pw_len);")
                    elif attack_vector == AttackVector.a1:
                        code.add(f"""
{current_algorithm.updateGlobalFunction}(&{context}, pws[gid].i, pws[gid].pw_len);
{current_algorithm.updateGlobalFunction}(&{context}, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
""")
                    else:
                        code.add(f"""
{current_algorithm.updateFunction}_vector (&{context}, w, pw_len);
""")
                else:  # Big-endian algorithm
                    if attack_vector == AttackVector.a0:
                        code.add(f"{current_algorithm.updateSwapFunction}(&{context}, tmp.i, tmp.pw_len);")
                    elif attack_vector == AttackVector.a1:
                        code.add(f"""
{current_algorithm.updateGlobalSwapFunction}(&{context}, pws[gid].i, pws[gid].pw_len);
{current_algorithm.updateGlobalSwapFunction}(&{context}, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
""")
                    else:
                        code.add(f"""
{current_algorithm.updateFunction}_vector_swap (&{context}, w, pw_len);
""")
            elif input_ == "salt":
                is_first_occurrence = True
                for j in range(idx):
                    if instructions[j].split(" - ")[0].replace(" ", "").replace("-", "") == context:
                        is_first_occurrence = False
                        break

                is_first_salt_presalted = (optimized and attack_vector in (AttackVector.a0, AttackVector.a1) and
                                           context in presalted_contexts and input_ == "salt" and is_first_occurrence)

                if not is_first_salt_presalted:
                    if current_algorithm.endianness == Endianness.LittleEndian:
                        if attack_vector != AttackVector.a3:
                            code.add(f"{current_algorithm.updateFunction}(&{context}, s, salt_len);")
                        else:
                            code.add(f"{current_algorithm.updateFunction}_vector(&{context}, s, salt_len);")
                    else:
                        if attack_vector != AttackVector.a3:
                            code.add(f"{current_algorithm.updateSwapFunction}(&{context}, s, salt_len);")
                        else:
                            code.add(f"{current_algorithm.updateVectorSwapFunction}(&{context}, s, salt_len);")
            elif input_ in context_algorithms:
                input_algorithm = context_algorithms[input_]

                if context not in context_input_counts:
                    raise NotImplementedError("Cannot CUT the outer hash.")

                code.add_range(KernelCodeGenerator.load_buffers(input_algorithm, current_algorithm, context_input_counts[context], optimized))

                if input_algorithm.length >= 56 or context_input_counts[context] != 1:
                    if attack_vector != AttackVector.a3:
                        code.add(f"{current_algorithm.update64Function}(&{context}, w0, w1, w2, w3, {input_algorithm.length});")
                    else:
                        code.add(f"{current_algorithm.update64VectorFunction}(&{context}, w0, w1, w2, w3, {input_algorithm.length});")
                else:
                    code.add(f"{context}.len = {input_algorithm.length};")
            else:
                raise Exception(f"ERROR: Input parameter {input_} not supported!")

            code.add("")

            if idx == len(instructions) - 1 or instructions[idx + 1].split(" - ")[0].replace(" ", "").replace("-", "") != context:
                if attack_vector != AttackVector.a3:
                    code.add(f"{current_algorithm.finalFunction}(&{context});")
                else:
                    code.add(f"{current_algorithm.finalFunction}_vector (&{context});")
                code.add("")

        return code

    @staticmethod
    def generate_footer(final_context: str, attack_vector: AttackVector, kernel_type: KernelType, optimized: bool = False) -> CodeList:
        code = CodeList()

        final_context = final_context.split(" - ")[0].replace("-", "")

        type_ = "M" if kernel_type == KernelType.MultiHash else "S"

        # PATCH: the comparer macro must match whether the hash *context* is
        # vectorized, not whether -O/optimized was requested. Only -a3
        # kernels declare NEW_SIMD_CODE (see generate_imports) and use
        # `_vector_t` contexts / `_final_vector` finalizers; -a0/-a1 kernels
        # stay scalar (`md5_ctx_t`, `md5_final`) even when optimized, so
        # COMPARE_*_SIMD is undefined for them and only COMPARE_*_SCALAR
        # exists. Forcing SIMD for "a3 or optimized" was wrong and caused
        # "identifier COMPARE_M_SIMD is undefined" build errors on
        # -a0/-a1 optimized kernels.
        comparer = "SIMD" if attack_vector == AttackVector.a3 else "SCALAR"

        code.add(f"COMPARE_{type_}_{comparer} ({final_context}.h[DGST_R0], {final_context}.h[DGST_R1], {final_context}.h[DGST_R2], {final_context}.h[DGST_R3]);", 2)

        code.add("}", 1)
        code.add("}", 0)

        return code

    @staticmethod
    def generate_stub_kernel(kernel_type: KernelType, attack_vector: AttackVector, hash_mode: str, tier: str) -> CodeList:
        code = CodeList()

        function_name_suffix = ("s" if kernel_type == KernelType.SingleHash else "m") + tier

        if attack_vector == AttackVector.a0:
            argument = "KERN_ATTR_RULES ()"
        elif attack_vector == AttackVector.a1:
            argument = "KERN_ATTR_BASIC ()"
        elif attack_vector == AttackVector.a3:
            argument = "KERN_ATTR_VECTOR ()"
        else:
            raise NotImplementedError("Unknown -a mode")

        code.add(f"KERNEL_FQ KERNEL_FA void m{hash_mode}_{function_name_suffix} ({argument})", 0)
        code.add("{")
        code.add("}", 0)
        code.add("")

        return code

    @staticmethod
    def load_buffers(source: IAlgorithm, target: IAlgorithm, inputs: int, optimized: bool = False) -> CodeList:
        code = CodeList()
        code.spacing = 2

        previous_context_idx = 0
        bytes_processed = 0

        mask_idx = 0
        mask_offsets = [0, 0, 0, 0]

        buffer_target = ""
        if source.length <= 56 and inputs == 1:
            buffer_target = f"{target.context}."

        if source.endianness == target.endianness:
            if source.endianness == Endianness.LittleEndian:
                conversion = Conversion.LE2LE
                mask_offsets = [0, 8, 16, 24]
            else:
                conversion = Conversion.BE2BE
                mask_offsets = [16, 24, 0, 8]
        else:
            if source.endianness == Endianness.LittleEndian:
                conversion = Conversion.LE2BE
                mask_offsets = [8, 0, 24, 16]
            else:
                conversion = Conversion.BE2LE
                mask_offsets = [24, 16, 8, 0]

        a = 0
        while a < source.byteLength:
            b = 0
            while b < 4:
                suffix = ""
                if conversion == Conversion.LE2LE or conversion == Conversion.BE2LE:
                    suffix = ""
                else:
                    suffix = "_le"

                shift_str = str(mask_offsets[mask_idx]).rjust(2)
                code.add(f"{buffer_target}w{a}[{b}] =  uint_to_hex_lower8{suffix} (({source.context}.h[{previous_context_idx}] >>  {shift_str}) & 255) <<  0")

                mask_idx = (mask_idx + 1) % 4

                shift_str = str(mask_offsets[mask_idx]).rjust(2)
                last_len = len(code[-1])
                line = f"| uint_to_hex_lower8{suffix} (({source.context}.h[{previous_context_idx}] >>  {shift_str}) & 255) << 16;"
                code.add(line.rjust(last_len + 1))

                mask_idx = (mask_idx + 1) % 4

                bytes_processed += 2

                if bytes_processed == source.byteLength:
                    if buffer_target == "":
                        b += 1
                        while a < 4:
                            while b < 4:
                                code.add(f"w{a}[{b}] = 0;")
                                b += 1
                            b = 0
                            a += 1
                    a = sys.maxsize
                    break

                if b % 2 == 1:
                    previous_context_idx += 1

                b += 1
            a += 1

        return code


# ---------------------------------------------------------------------------
# ModuleCodeGenerator
# ---------------------------------------------------------------------------
class ModuleCodeGenerator:
    @staticmethod
    def generate_module(algorithm: str, instructions: List[str], ID: str) -> CodeList:
        code = CodeList()

        algorithm_name = instructions[-1].split("-")[0]
        final_algorithm = parse_algorithm_name(algorithm_name)

        code.add("""
/**
 * Plugin has been auto-generated by https://github.com/PenguinKeeper7/KernelBuilder
 * DO NOT PR into hashcat master
 */

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
""")

        code.add(f"static const u32   DGST_SIZE      = DGST_SIZE_4_{final_algorithm.byteLength // 4};")

        salted = False
        for instruction in instructions:
            if "salt" in instruction:
                salted = True
                code.add("static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH_SALTED;")

        if not salted:
            code.add("static const u32 HASH_CATEGORY = HASH_CATEGORY_RAW_HASH;")

        code.add(f'static const char *HASH_NAME      = "{algorithm}";')
        code.add(f"static const u64   KERN_TYPE      = {ID.lstrip('0')};")

        code.add("""
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_RAW_HASH;
""")

        code.add(f"static const u64   OPTS_TYPE      = {final_algorithm.opts_types} | OPTS_TYPE_SELF_TEST_DISABLE;")

        if salted:
            code.add("static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;")
        else:
            code.add("static const u32   SALT_TYPE      = SALT_TYPE_NONE;")

        code.add('static const char *ST_PASS        = "NOT_IMPLEMENTED";')

        if salted:
            code.add(f'static const char *ST_HASH        = "{"0" * final_algorithm.length}:NOT_IMPLEMENTED";')
        else:
            code.add(f'static const char *ST_HASH        = "{"0" * final_algorithm.length}";')

        code.add("""
u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    return 31;
  }

  return PW_MAX;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
""")

        code.spacing = 1

        code.add("""
u32 *digest = (u32 *) digest_buf;

hc_token_t token;

memset (&token, 0, sizeof (hc_token_t));
""")

        if salted:
            code.add("token.token_cnt = 2;")
            code.add("token.sep[0] = hashconfig->separator;")
        else:
            code.add("token.token_cnt = 1;")

        code.add(f"""
token.len[0]     = {final_algorithm.length};
token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_HEX;
""")

        if salted:
            code.add("""
token.len_min[1] = SALT_MIN;
token.len_max[1] = SALT_MAX;
token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
{
  token.len_min[1] *= 2;
  token.len_max[1] *= 2;

  token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
}
""")

        code.add("""
const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

const u8 *hash_pos = token.buf[0];
""")

        code.spacing = 2

        for i in range(final_algorithm.byteLength // 4):
            if final_algorithm.endianness == Endianness.LittleEndian:
                code.add(f"digest[{i}] = hex_to_u32 (hash_pos + {i * 8});")
            else:
                code.add(f"digest[{i}] = byte_swap_32 (hex_to_u32 (hash_pos + {i * 8}));")

        code.spacing = 1

        code.add("""
if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
{
""")

        code.spacing = 2

        for i in range(final_algorithm.byteLength // 4):
            code.add(f"digest[{i}] -= {final_algorithm.initialValues}{chr(65 + i)};")

        code.spacing = 1

        code.add("}")

        if salted:
            code.add("""
const u8 *salt_pos = token.buf[1];
const int salt_len = token.len[1];

const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

if (parse_rc == false) return (PARSER_SALT_LENGTH);
""")

        code.add("return (PARSER_OK);")

        code.spacing = 0

        code.add("""
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
""")

        code.spacing = 1

        code.add("""
const u32 *digest = (const u32 *) digest_buf;

""")

        code.add(f"u32 tmp[{final_algorithm.byteLength // 4}];")

        for i in range(final_algorithm.byteLength // 4):
            code.add(f"tmp[{i}] = digest[{i}];")

        code.add("""
if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
{
""")

        code.spacing = 2

        for i in range(final_algorithm.byteLength // 4):
            code.add(f"tmp[{i}] += {final_algorithm.initialValues}{chr(65 + i)};")

        code.spacing = 1

        code.add("""
}

u8 *out_buf = (u8 *) line_buf;
""")

        for i in range(final_algorithm.byteLength // 4):
            if final_algorithm.endianness == Endianness.BigEndian:
                code.add(f"tmp[{i}] = byte_swap_32 (tmp[{i}]);")
            code.add(f"u32_to_hex (tmp[{i}], out_buf +  {i * 8});")

        code.add(f"int out_len = {final_algorithm.length};")

        if salted:
            code.add("""
out_buf[out_len] = hashconfig->separator;

out_len += 1;

out_len += generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, out_buf + out_len);
""")

        code.add("return out_len;")

        code.spacing = 0

        code.add("""
}

void module_init (module_ctx_t *module_ctx)
{
""")

        code.spacing = 1

        code.add("""
module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

module_ctx->module_attack_exec              = module_attack_exec;
module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
module_ctx->module_bridge_name              = MODULE_DEFAULT;
module_ctx->module_bridge_type              = MODULE_DEFAULT;
module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
module_ctx->module_dgst_pos0                = module_dgst_pos0;
module_ctx->module_dgst_pos1                = module_dgst_pos1;
module_ctx->module_dgst_pos2                = module_dgst_pos2;
module_ctx->module_dgst_pos3                = module_dgst_pos3;
module_ctx->module_dgst_size                = module_dgst_size;
module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
module_ctx->module_esalt_size               = MODULE_DEFAULT;
module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
module_ctx->module_hash_decode              = module_hash_decode;
module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
module_ctx->module_hash_encode              = module_hash_encode;
module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
module_ctx->module_hash_mode                = MODULE_DEFAULT;
module_ctx->module_hash_category            = module_hash_category;
module_ctx->module_hash_name                = module_hash_name;
module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
module_ctx->module_hook12                   = MODULE_DEFAULT;
module_ctx->module_hook23                   = MODULE_DEFAULT;
module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
module_ctx->module_hook_size                = MODULE_DEFAULT;
module_ctx->module_jit_build_options        = MODULE_DEFAULT;
module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
module_ctx->module_kern_type                = module_kern_type;
module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
module_ctx->module_opti_type                = module_opti_type;
module_ctx->module_opts_type                = module_opts_type;
module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
module_ctx->module_potfile_disable          = MODULE_DEFAULT;
module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
module_ctx->module_pwdump_column            = MODULE_DEFAULT;
module_ctx->module_pw_max                   = module_pw_max;
module_ctx->module_pw_min                   = MODULE_DEFAULT;
module_ctx->module_salt_max                 = MODULE_DEFAULT;
module_ctx->module_salt_min                 = MODULE_DEFAULT;
module_ctx->module_salt_type                = module_salt_type;
module_ctx->module_separator                = MODULE_DEFAULT;
module_ctx->module_st_hash                  = module_st_hash;
module_ctx->module_st_pass                  = module_st_pass;
module_ctx->module_tmp_size                 = MODULE_DEFAULT;
module_ctx->module_unstable_warning         = MODULE_DEFAULT;
module_ctx->module_warmup_disable           = MODULE_DEFAULT;
""")

        code.add("}", 0)

        return code


# ---------------------------------------------------------------------------
# Program
# ---------------------------------------------------------------------------
def create_folder_structure(ID: str, overwrite: bool, hashcat: bool):
    if os.path.exists(f"plugins/{ID}") and not overwrite and not hashcat:
        print(f"{ID} has already been used!", file=sys.stderr)
        sys.exit(0)

    prefix = ""
    if not hashcat:
        prefix = f"plugins/{ID}/"
        os.makedirs(prefix, exist_ok=True)

    os.makedirs(f"{prefix}src/modules", exist_ok=True)
    os.makedirs(f"{prefix}OpenCL", exist_ok=True)


def generate_kernels(instructions: List[str], ID: str, hashcat: bool, build_optimized: bool = True):
    prefix = ""
    if not hashcat:
        prefix = f"plugins/{ID}/"

    attack_vectors = [AttackVector.a0, AttackVector.a1, AttackVector.a3]

    presalted = get_presalted_contexts(instructions) if build_optimized else []

    for attack_vector in attack_vectors:
        # Generate pure kernel
        kernel_code = CodeList()

        kernel_code.add_range(KernelCodeGenerator.generate_imports(attack_vector, optimized=False))

        kernel_code.add_range(KernelCodeGenerator.generate_header(instructions, KernelType.MultiHash, attack_vector, ID, optimized=False))
        kernel_code.add_range(KernelCodeGenerator.generate_compute(instructions, attack_vector, optimized=False))
        kernel_code.add_range(KernelCodeGenerator.generate_footer(instructions[-1], attack_vector, KernelType.MultiHash, optimized=False))

        kernel_code.add_range(KernelCodeGenerator.generate_header(instructions, KernelType.SingleHash, attack_vector, ID, optimized=False))
        kernel_code.add_range(KernelCodeGenerator.generate_compute(instructions, attack_vector, optimized=False))
        kernel_code.add_range(KernelCodeGenerator.generate_footer(instructions[-1], attack_vector, KernelType.SingleHash, optimized=False))

        path = f"{prefix}OpenCL/m{ID}_{attack_vector.name}-pure.cl"
        with open(path, "w") as f:
            f.write("\n".join(kernel_code) + "\n")

        if build_optimized:
            opt_code = CodeList()

            opt_code.add_range(KernelCodeGenerator.generate_imports(attack_vector, optimized=True))

            for kernel_type in (KernelType.MultiHash, KernelType.SingleHash):
                opt_code.add_range(KernelCodeGenerator.generate_header(instructions, kernel_type, attack_vector, ID, optimized=True, tier="04", presalted_contexts=presalted))
                opt_code.add_range(KernelCodeGenerator.generate_compute(instructions, attack_vector, optimized=True, presalted_contexts=presalted))
                opt_code.add_range(KernelCodeGenerator.generate_footer(instructions[-1], attack_vector, kernel_type, optimized=True))

                for tier in ("08", "16"):
                    opt_code.add_range(KernelCodeGenerator.generate_stub_kernel(kernel_type, attack_vector, ID, tier))

            opt_path = f"{prefix}OpenCL/m{ID}_{attack_vector.name}-optimized.cl"
            with open(opt_path, "w") as f:
                f.write("\n".join(opt_code) + "\n")


def generate_module(algorithm: str, instructions: List[str], ID: str, hashcat: bool):
    prefix = ""
    if not hashcat:
        prefix = f"plugins/{ID}/"

    module_code = CodeList()
    module_code.add_range(ModuleCodeGenerator.generate_module(algorithm, instructions, ID))

    path = f"{prefix}src/modules/module_{ID}.c"
    with open(path, "w") as f:
        f.write("\n".join(module_code) + "\n")


def print_supported():
    print("Supported hash algorithms:")
    for name in sorted(SUPPORTED_ALGORITHMS.keys()):
        print(f"  {name}")
    print()
    print("Supported input variables:")
    print("  $plain  - password candidate")
    print("  $salt   - salt value")
    print()
    print("Syntax examples:")
    print("  md5($plain)")
    print("  sha1($plain.$salt)")
    print("  sha256($salt.$plain)")
    print("  sha224($plain)")
    print("  md5(sha1($plain))")
    print("  sha256($plain.$salt)")


def main():
    epilog_text = """examples:
  python3 kernel_builder.py 'md5($plain)' 98000
  python3 kernel_builder.py 'sha1($plain.$salt)' 98001
  python3 kernel_builder.py 'sha224($plain)' 98002
  python3 kernel_builder.py 'sha256($salt.$plain)' 98003
  python3 kernel_builder.py 'md5(sha1($plain))' 98004 --hashcat
  python3 kernel_builder.py 'sha256($plain)' 98005 --no-optimized
"""

    parser = argparse.ArgumentParser(
        description="KernelBuilder - Generate hashcat OpenCL kernels and C modules from PHP-like expressions.",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("algorithm", nargs="?", help="Algorithm expression, e.g. 'md5($plain)' or 'sha1($plain.$salt)'")
    parser.add_argument("ID", nargs="?", help="Kernel ID / -m number (1-5 digits)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite previously created kernels")
    parser.add_argument("--hashcat", action="store_true", help="Output directly to Hashcat directories")
    parser.add_argument("--optimized", dest="optimized", action="store_true",
                         help="Force generation of -optimized.cl kernels (a0/a1/a3). WARNING: these kernels "
                              "are currently just the -pure.cl body relabeled under optimized-kernel filenames, "
                              "not real hashcat-style vectorized/inlined transforms, and have caused GPU "
                              "'illegal memory access' crashes under -O for both salted and unsalted hashes. "
                              "Off by default; use at your own risk.")
    parser.add_argument("--no-optimized", dest="optimized", action="store_false",
                         help="Skip generating -optimized.cl kernels; only the -pure.cl kernels are produced. "
                              "This is already the default.")
    parser.set_defaults(optimized=None)
    parser.add_argument("-l", "--list", action="store_true", help="List supported algorithms and exit")
    args = parser.parse_args()

    if args.list:
        print_supported()
        sys.exit(0)

    if not args.algorithm or not args.ID:
        parser.print_help()
        sys.exit(1)

    algorithm = args.algorithm
    ID = args.ID
    overwrite = args.overwrite
    hashcat = args.hashcat

    if not ID.isdigit() or len(ID) > 5 or len(ID) == 0:
        print(f'The ID "{ID}" must be a 1-5 digit number. ex: 98000')
        sys.exit(0)

    ID = ID.zfill(5)

    instructions = Interpreter.generate_instructions(algorithm)
    
    if args.optimized is None:
        build_optimized = False
    else:
        build_optimized = args.optimized

    create_folder_structure(ID, overwrite, hashcat)

    generate_kernels(instructions, ID, hashcat, build_optimized)
    generate_module(algorithm, instructions, ID, hashcat)

    if hashcat:
        print("Plugin has been stored in the Hashcat folders")
        print("")
        print("Compile Hashcat using: https://github.com/hashcat/hashcat/blob/master/BUILD.md")
    else:
        print(f"Plugin has been stored in plugins/{ID}")
        print("")
        print(f"1) Copy and paste the 2 folders inside plugins/{ID} into Hashcat")
        print(f"2) Compile Hashcat using: https://github.com/hashcat/hashcat/blob/master/BUILD.md")


if __name__ == "__main__":
    main()
