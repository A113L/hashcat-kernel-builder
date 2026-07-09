#!/usr/bin/env python3
"""
KernelBuilder - Auto-generate Hashcat OpenCL kernels and modules.
Python port of the C# tool.

This script takes a simple, PHP-like hash expression (e.g. "md5($salt.$plain)")
and generates a full Hashcat plugin from it:
  - OpenCL kernel source files (.cl) for attack modes -a0 (rules), -a1
    (combinator) and -a3 (mask/brute-force), in "pure" form (works for any
    password length, no -O flag support).
  - A C module file (module_<ID>.c) that tells Hashcat how to parse/encode
    hashes of this type on the CPU side (hash format, salt handling, etc).

High-level flow:
  1. Parser/Interpreter: turns the PHP-like expression string into a flat
     list of "instructions" describing which hash algorithm consumes which
     input (plain, salt, or the output of another hash step).
  2. KernelCodeGenerator: turns those instructions into actual OpenCL C code
     (the GPU kernel).
  3. ModuleCodeGenerator: turns them into the C module Hashcat uses on the
     host side.
"""

import argparse
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

# Byte order of the hash algorithm's internal words.
# MD5 is little-endian; the SHA-family (SHA1/224/256) is big-endian.
# This matters because when we feed one hash's raw digest into another hash
# as input, we may need to byte-swap the words depending on both algorithms'
# endianness.
class Endianness(Enum):
    LittleEndian = auto()
    BigEndian = auto()


# How the final hash is represented in the hash file:
# Hex = lowercase hex string (e.g. "5d41402abc4b2a76b9719d911017c59")
# Binary = raw bytes (not really used by this generator, kept for completeness)
class OutputFormat(Enum):
    Binary = 1
    Hex = 2


# Which direction a byte-swap conversion needs to go when packing one
# algorithm's digest into another algorithm's input buffer.
class Conversion(Enum):
    LE2LE = auto()
    LE2BE = auto()
    BE2LE = auto()
    BE2BE = auto()


# A kernel can process either:
# - MultiHash: many target hashes at once (used when cracking a hash *list*)
# - SingleHash: just one target hash (used when cracking a single hash,
#   allows some extra shortcuts in the comparison step)
class KernelType(Enum):
    SingleHash = auto()
    MultiHash = auto()


# Hashcat attack modes this generator supports:
# a0 = straight/rules-based dictionary attack
# a1 = combinator attack (two wordlists combined)
# a3 = mask attack / brute-force (vectorized kernel)
class AttackVector(Enum):
    a0 = auto()
    a1 = auto()
    a3 = auto()


# ---------------------------------------------------------------------------
# CodeList
# ---------------------------------------------------------------------------
class CodeList(list):
    """
    A thin helper around a plain Python list that acts as a growable buffer
    of source-code lines. It auto-indents every line added according to the
    current `spacing` level (in units of 2 spaces), so the generated OpenCL/C
    code stays readable without having to manually prefix every string with
    spaces.
    """
    def __init__(self):
        super().__init__()
        self.spacing = 0  # current indentation level (multiplied by 2 spaces)

    def add(self, element, spacing=None):
        """
        Append one or more lines of code.
        `element` can be a single multi-line string (split on '\n') or an
        iterable of pre-split lines (e.g. another CodeList).
        If `spacing` is given, it updates the indentation level used for
        this call (and all subsequent calls) before adding the lines.
        """
        if spacing is not None:
            self.spacing = spacing
        if isinstance(element, str):
            lines = element.split("\n")
        else:
            lines = list(element)
        for item in lines:
            super().append(" " * (self.spacing * 2) + item.strip())

    def add_range(self, other):
        """Append all lines from another CodeList/iterable as-is (no reformatting)."""
        self.extend(other)


# ---------------------------------------------------------------------------
# IAlgorithm
# ---------------------------------------------------------------------------
class IAlgorithm(ABC):
    """
    Abstract description of a single hash algorithm (MD5, SHA1, SHA224,
    SHA256, ...). Each concrete subclass just returns the algorithm-specific
    metadata and the exact names of the OpenCL helper functions Hashcat's
    inc_hash_*.cl headers provide for that algorithm (init/update/final,
    plus endianness-aware variants).

    `context` holds the name of the local OpenCL variable instance of this
    algorithm's context struct used in the generated kernel (e.g. "MD51" for
    the first MD5 step) - it's assigned dynamically while generating code,
    not a fixed property of the algorithm itself.
    """
    byteLength: int = 16   # raw digest size in bytes (e.g. 16 for MD5, 32 for SHA256)
    context: str = ""      # OpenCL variable name assigned to this instance during codegen

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
        """Length of the hash's *textual* representation (hex chars), used when sizing buffers."""
        return self.byteLength * self.outputFormat.value

    @property
    @abstractmethod
    def opts_types(self) -> str:
        """The OPTS_TYPE_* flags Hashcat needs for this algorithm's password-generation mode."""
        ...

    @property
    @abstractmethod
    def initialValues(self) -> str:
        """Prefix of the algorithm's IV constant macros (e.g. "MD5M_" -> MD5M_A/B/C/D)."""
        ...

    @property
    @abstractmethod
    def contextType(self) -> str:
        """Name of the OpenCL struct type holding this algorithm's running hash state."""
        ...

    @property
    @abstractmethod
    def initFunction(self) -> str:
        """OpenCL function that initializes a fresh context struct."""
        ...

    @property
    @abstractmethod
    def updateFunction(self) -> str:
        """OpenCL function that feeds arbitrary-length little-endian-ordered data into the context."""
        ...

    @property
    @abstractmethod
    def updateGlobalFunction(self) -> str:
        """Same as updateFunction, but reads its input from __global memory (used for -a1)."""
        ...

    @property
    @abstractmethod
    def updateSwapFunction(self) -> str:
        """Like updateFunction, but byte-swaps the input first (used for big-endian algorithms)."""
        ...

    @property
    @abstractmethod
    def updateVectorSwapFunction(self) -> str:
        """Vectorized (u32x, used in -a3 SIMD kernels) variant of updateSwapFunction."""
        ...

    @property
    @abstractmethod
    def updateGlobalSwapFunction(self) -> str:
        """Global-memory + byte-swapping update variant (used for -a1 with big-endian algorithms)."""
        ...

    @property
    @abstractmethod
    def update64Function(self) -> str:
        """Fast-path update function that consumes exactly one 64-byte block, pre-split into 4 words."""
        ...

    @property
    @abstractmethod
    def update64VectorFunction(self) -> str:
        """Vectorized variant of update64Function, used in -a3 kernels."""
        ...

    @property
    @abstractmethod
    def finalFunction(self) -> str:
        """OpenCL function that finalizes the context and produces the digest."""
        ...


# ---------------------------------------------------------------------------
# Algorithm implementations
# ---------------------------------------------------------------------------
# Each class below is just a lookup table: it maps the abstract IAlgorithm
# properties to the concrete names hashcat's OpenCL/inc_hash_<algo>.cl headers
# actually use, plus the algorithm's byte length and endianness.

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


# Registry of all algorithm names this generator understands, used for
# validation/listing (see print_supported()).
SUPPORTED_ALGORITHMS = {
    "MD5": MD5,
    "SHA1": SHA1,
    "SHA224": SHA224,
    "SHA256": SHA256,
}


def parse_algorithm_name(algorithm: str) -> IAlgorithm:
    """Instantiate the IAlgorithm subclass matching a given algorithm name string."""
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
# This section implements a tiny hand-written parser for the PHP-like
# expression syntax, e.g.:
#   md5($plain)
#   sha1($salt.$plain)
#   md5(sha1($plain))
# It builds an expression tree (Variable / FunctionCall / Concat nodes), then
# walks that tree to produce a flat "instruction list" describing, in
# execution order, which hash algorithm needs to absorb which input.

class IExpression:
    """Marker base class for all expression-tree node types."""
    pass


@dataclass
class Variable(IExpression):
    """A leaf node representing a raw input value: $plain or $salt."""
    Name: str
    def __str__(self): return "$" + self.Name


@dataclass
class FunctionCall(IExpression):
    """
    A hash function call node, e.g. md5(...) or sha1(...).
    `Arguments` holds the single expression passed to it (this simple grammar
    only supports one argument, itself possibly a Concat).
    `OutputId` is filled in later during instruction generation and
    identifies which "context" (OpenCL variable) this call's result maps to.
    """
    FunctionName: str
    Arguments: List[IExpression] = field(default_factory=list)
    OutputId: str = ""
    def __str__(self):
        return f"{self.FunctionName}({', '.join(str(a) for a in self.Arguments)})"


@dataclass
class Concat(IExpression):
    """String concatenation node, e.g. $salt.$plain -> Concat([$salt, $plain])."""
    Parts: List[IExpression] = field(default_factory=list)
    def __str__(self):
        return " . ".join(str(p) for p in self.Parts)


class Parser:
    """
    A minimal recursive-descent parser for the algorithm expression grammar:

        expression := concat
        concat     := term ('.' term)*
        term       := variable | function_call | '(' expression ')'
        variable   := '$' identifier
        function_call := identifier '(' expression ')'

    `self.input` is the raw expression string, `self.pos` is the current
    read cursor into it.
    """
    def __init__(self, input_str: str):
        self.input = input_str
        self.pos = 0

    def parse_expression(self):
        return self.parse_concat()

    def parse_concat(self):
        """Parse one or more terms joined by '.', producing a Concat node if there's more than one."""
        expr = self.parse_term()
        parts = [expr]
        while self.match('.'):
            nxt = self.parse_term()
            parts.append(nxt)
        if len(parts) == 1:
            return parts[0]
        return Concat(Parts=parts)

    def parse_term(self):
        """Parse a single term: a $variable, a function call, or a parenthesized sub-expression."""
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
        """Parse a $name token into a Variable node."""
        self.consume('$')
        sb = []
        while self.pos < len(self.input) and (self.input[self.pos].isalnum() or self.input[self.pos] == '_'):
            sb.append(self.input[self.pos])
            self.pos += 1
        return Variable(Name=''.join(sb))

    def parse_function_call(self):
        """Parse a name(...) token into a FunctionCall node (with its single argument, if any)."""
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
        """If the next non-whitespace char equals `expected`, consume it and return True."""
        self.skip_whitespace()
        if self.pos < len(self.input) and self.input[self.pos] == expected:
            self.pos += 1
            return True
        return False

    def consume(self, expected):
        """Consume the next non-whitespace char, raising if it doesn't match `expected`."""
        self.skip_whitespace()
        if self.pos < len(self.input) and self.input[self.pos] == expected:
            self.pos += 1
        else:
            raise Exception(f"Expected '{expected}' at position {self.pos}")


class InstructionGenerator:
    """
    Walks the parsed expression tree (post-order) and flattens it into a
    linear list of "instructions". Each instruction is a string of the form:

        "<CONTEXT_ID> - <input>"

    where <CONTEXT_ID> identifies one hash-algorithm invocation (e.g.
    "MD5-1", "SHA256-2") and <input> is either "plain", "salt", or another
    context's id (meaning: feed that inner hash's digest into this one).

    Example: for md5(sha1($plain)), the generated instructions are:
        ["SHA1-1 - plain", "MD5-2 - SHA1-1"]
    i.e. first SHA1 absorbs $plain, then MD5 absorbs SHA1's output.
    """
    def __init__(self):
        self.id_counter = 1
        self.instructions = []

    def generate(self, expr: IExpression) -> str:
        """
        Recursively process an expression node, emitting instructions as a
        side effect, and returning a string token representing this node's
        "value" (a variable name, or the context id of a function call) so
        the parent node can reference it as an input.
        """
        if isinstance(expr, Variable):
            return expr.Name
        elif isinstance(expr, Concat):
            # For concatenation, just resolve each part and join their
            # tokens; the caller (a FunctionCall) is the one that will turn
            # this into multiple separate "update" instructions.
            parts = [self.generate(part) for part in expr.Parts]
            return ", ".join(parts)
        elif isinstance(expr, FunctionCall):
            # First, recursively resolve all of this call's inputs. If the
            # argument was a Concat, expand it into its individual parts so
            # each one becomes its own instruction (absorbed in sequence).
            arg_outputs = []
            for arg in expr.Arguments:
                if isinstance(arg, Concat):
                    for part in arg.Parts:
                        arg_outputs.append(self.generate(part))
                else:
                    arg_outputs.append(self.generate(arg))

            # Assign a unique id for this hash step, e.g. "MD5-1".
            current_id = f"{expr.FunctionName.upper()}-{self.id_counter}"
            self.id_counter += 1
            expr.OutputId = current_id

            # Emit one instruction per input this call absorbs, in order.
            for argument in arg_outputs:
                self.instructions.append(f"{current_id} - {argument}")
            return current_id
        return ""

    def get_instructions(self) -> List[str]:
        return self.instructions


class Interpreter:
    @staticmethod
    def generate_instructions(algorithm: str) -> List[str]:
        """Parse a PHP-like algorithm expression string and return its flat instruction list."""
        parser = Parser(algorithm)
        expr = parser.parse_expression()
        generator = InstructionGenerator()
        generator.generate(expr)
        return generator.get_instructions()


# ---------------------------------------------------------------------------
# KernelCodeGenerator
# ---------------------------------------------------------------------------
# This class turns the instruction list into actual OpenCL kernel source
# code. A generated kernel file has 4 sections, each produced by one of the
# methods below, concatenated in this order:
#   generate_imports()  -> #include headers, helper macros
#   generate_header()   -> function signature + per-candidate loop setup
#   generate_compute()  -> the actual hashing logic inside the loop
#   generate_footer()   -> compares the computed digest against the target hash(es)
class KernelCodeGenerator:
    @staticmethod
    def generate_imports(attack_vector: AttackVector) -> CodeList:
        """
        Emit the top of the kernel file: the auto-generated banner, the
        conditional #include block (different includes are needed for a3's
        SIMD/mask kernels vs a0/a1's rule/combinator kernels), and the
        uint_to_hex_lower8[/_le] helper macros used later to convert a raw
        hash digest into its lowercase-hex ASCII representation (needed when
        chaining one hash's output as another hash's text input).
        """
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
            # a3 (mask attack) uses SIMD-vectorized helper routines.
            code.add("#include M2S(INCLUDE_PATH/inc_simd.cl)")
        else:
            # a0/a1 need the rule-engine and scalar hashing headers.
            code.add("""
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
""")

        # Include every supported algorithm's hash implementation
        # unconditionally; the unused ones are simply not called.
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
    def generate_header(instructions: List[str], kernel_type: KernelType, attack_vector: AttackVector, hash_mode: str) -> CodeList:
        """
        Emit the kernel function signature plus everything that needs to run
        ONCE per GPU thread (i.e. once per target password-candidate "slot"),
        before entering the per-rule/per-mask candidate loop:
          - the local bin2asc lookup tables used for hex conversion
          - the target digest to compare against
          - the base password bytes (for a0: full copy; for a1/a3: raw words)
          - the salt bytes, if this algorithm uses one
          - scratch buffers (w0-w3) used later for chaining hash outputs
          - the opening of the "for each candidate" loop itself
        """
        code = CodeList()

        # Hashcat's naming convention: functions ending in _sxx are the
        # "single hash" kernel variant, _mxx the "multi hash" variant. The
        # literal "xx" here is Hashcat's own placeholder/convention for pure
        # kernels (as opposed to the tiered s04/s08/... names optimized
        # kernels use - not relevant here since this script only emits pure
        # kernels).
        if kernel_type == KernelType.SingleHash:
            function_name_suffix = "s"
        else:
            function_name_suffix = "m"

        # Each attack mode expects a different macro that expands to the
        # kernel's parameter list (buffers for passwords/rules/salts/etc).
        if attack_vector == AttackVector.a0:
            argument = "KERN_ATTR_RULES ()"
        elif attack_vector == AttackVector.a1:
            argument = "KERN_ATTR_BASIC ()"
        elif attack_vector == AttackVector.a3:
            argument = "KERN_ATTR_VECTOR ()"
        else:
            raise NotImplementedError("Unknown -a mode")

        code.add(f"KERNEL_FQ KERNEL_FA void m{hash_mode}_{function_name_suffix}xx ({argument})", 0)

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
            # a0 (rules attack): just copy the base password word into the
            # per-thread working buffer; rules are applied later, per candidate.
            code.add("COPY_PW (pws[gid]);", 1)
        else:
            # a1/a3: load the raw base password words into a local u32x
            # array `w`, and remember its first word (w0l) for a3's later
            # mask-combination step.
            code.add("""
const u32 pw_len = pws[gid].pw_len;
u32x w[64] = { 0 };
for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
{
  w[idx] = pws[gid].i[idx];
}

u32x w0l = w[0];
""")

        # If any instruction consumes $salt, load the salt bytes once here
        # (the salt is identical for every candidate within this kernel
        # invocation, so this only needs to happen once, before the loop).
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
                break

        # Scratch buffers used later (in generate_compute/load_buffers) when
        # chaining one hash's hex-encoded digest into another hash as input
        # (e.g. md5(sha1($plain))). Declared once, outside the loop, and
        # overwritten fresh on each iteration.
        code.add("""

/**
 * loop
 */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

""", 1)

        # a3 processes VECT_SIZE candidates per loop iteration (SIMD); a0/a1
        # process exactly one candidate per iteration.
        if attack_vector == AttackVector.a3:
            code.add("for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)")
        else:
            code.add("for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)")

        code.add("{")
        code.spacing += 1

        if attack_vector == AttackVector.a0:
            # Apply the current rule (from the rules file) to the base
            # password to produce this iteration's actual candidate.
            code.add("""
pw_t tmp = PASTE_PW;
tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);
""", 1)
        elif attack_vector == AttackVector.a3:
            # Combine the base word with this iteration's mask-generated
            # word fragment to build the actual candidate's first word.
            code.add("""

const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

const u32x wStart = w0l | w0r;

w[0] = wStart;
""")

        code.add("")
        return code

    @staticmethod
    def generate_compute(instructions: List[str], attack_vector: AttackVector) -> CodeList:
        """
        Emit the actual hashing logic, executed once per password candidate
        (inside the loop opened by generate_header). Walks the flat
        instruction list in order and, for each instruction, emits the
        matching OpenCL call:
          - "<ctx> - plain" -> feed the password candidate into that context
          - "<ctx> - salt"  -> feed the (pre-loaded) salt into that context
          - "<ctx> - <other_ctx>" -> feed another context's finished digest
            (converted to its lowercase-hex text form) into this context
        Each context is init'd on first use and finalized once no more
        instructions reference it (i.e. once its hashing is complete).
        """
        code = CodeList()
        code.spacing = 2

        # context_algorithms: maps a context id (e.g. "MD52") to the
        # IAlgorithm instance handling it, so later instructions referencing
        # that same context can look up which algorithm it is.
        context_algorithms: Dict[str, IAlgorithm] = {}
        # context_input_counts: how many separate "update" instructions feed
        # into a given context. This matters for the CUT-hash path below,
        # since e.g. a context absorbing salt+plain has 2 inputs, which
        # affects how chained digests get packed into it.
        context_input_counts: Dict[str, int] = {}

        for instruction in instructions:
            ctx = instruction.split(" - ")[0].replace("-", "")
            if ctx in context_input_counts:
                context_input_counts[ctx] += 1
            else:
                context_input_counts[ctx] = 1

        for idx in range(len(instructions)):
            instruction = instructions[idx]
            context = instruction.split(" - ")[0].replace(" ", "").replace("-", "")
            input_ = instruction.split(" - ")[1].replace("-", "")
            algorithm_name = instruction.split("-")[0]

            # Handle CUT<n>_<ALGO> pseudo-algorithm names: these mean "use
            # only the first n/2 bytes of this context's digest" (truncated
            # hash). Strip the CUT prefix and re-resolve the real algorithm
            # name/context underneath it.
            if algorithm_name.startswith("CUT"):
                cut_length = int(context.split("_")[0].replace("CUT", "")) // 2
                # Cleanup so the rest of the code doesn't know about the CUT and pretend nothing happened
                algorithm_name = instruction.split("_")[-1].split("-")[0]
                instruction = instruction.replace(f"CUT{cut_length}_", "")
                # Must entirely re-parse
                current_algorithm = parse_algorithm_name(algorithm_name)
                context = context.split("_")[-1]
            else:
                current_algorithm = parse_algorithm_name(algorithm_name)

            current_algorithm.context = context

            # First time we see this context: declare its state struct and
            # initialize it.
            if context not in context_algorithms:
                context_algorithms[context] = current_algorithm

                if attack_vector != AttackVector.a3:
                    code.add(f"{current_algorithm.contextType} {context};")
                    code.add(f"{current_algorithm.initFunction} (&{context});")
                else:
                    # a3 uses the vectorized (SIMD) context struct/init variant.
                    code.add(f"{current_algorithm.contextType.replace('_t', '_vector_t')} {context};")
                    code.add(f"{current_algorithm.initFunction}_vector (&{context});")

                code.add("")

            # If the *input* being fed in is itself a truncated (CUT)
            # reference to another context, resolve that too: shrink the
            # source algorithm's reported byte length so load_buffers()
            # below only packs the truncated portion.
            if input_.startswith("CUT"):
                cut_length = int(input_.split("_")[0].replace("CUT", "")) // 2
                if cut_length % 4 != 0:
                    raise NotSupportedError("CUT is not supported for values that are not multiples of 4.")

                context_to_cut = instruction.split("_")[-1].split(" - ")[0].replace("-", "")
                if context_to_cut not in context_algorithms:
                    raise NotSupportedError("CUT is not supported on raw values such as $plain or $salt.")

                context_algorithms[context_to_cut].byteLength = cut_length
                input_ = input_.split("_")[-1]

            if input_ == "plain":
                # Feed the password candidate into this context. The exact
                # call depends on: algorithm endianness (needs byte-swap or
                # not) and attack mode (different password source/shape).
                if current_algorithm.endianness == Endianness.LittleEndian:
                    if attack_vector == AttackVector.a0:
                        code.add(f"{current_algorithm.updateFunction}(&{context}, tmp.i, tmp.pw_len);")
                    elif attack_vector == AttackVector.a1:
                        # -a1 candidates are built from two separate word buffers
                        # (left wordlist + right wordlist), so absorb both in sequence.
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
                # Feed the (already loaded) salt bytes into this context.
                # a3 uses the vectorized update variant since its context is
                # itself a vector context.
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
                # Chained hashing: this instruction's input is another
                # context's finished digest. We need to convert that raw
                # binary digest into its lowercase-hex ASCII representation
                # (since that's what e.g. md5(sha1($plain)) actually hashes
                # — the *text* of the inner hash, not its raw bytes), then
                # feed those hex bytes into the current context.
                input_algorithm = context_algorithms[input_]

                # TODO: allow this
                if context not in context_input_counts:
                    raise NotImplementedError("Cannot CUT the outer hash.")

                # Pack the source digest's hex representation into the w0-w3
                # scratch buffers (see load_buffers() below for the actual
                # byte-shuffling/hex-conversion logic).
                code.add_range(KernelCodeGenerator.load_buffers(input_algorithm, current_algorithm, context_input_counts[context]))

                if input_algorithm.length >= 56 or context_input_counts[context] != 1:
                    # The hex text is too long to fit directly in this
                    # context's internal buffer (or this context has more
                    # than one input already), so use the explicit
                    # "here are 4 pre-packed words, absorb them as one
                    # 64-byte block" fast-path update function instead.
                    if attack_vector != AttackVector.a3:
                        code.add(f"{current_algorithm.update64Function}(&{context}, w0, w1, w2, w3, {input_algorithm.length});")
                    else:
                        code.add(f"{current_algorithm.update64VectorFunction}(&{context}, w0, w1, w2, w3, {input_algorithm.length});")
                else:
                    # Short enough and the only input: load_buffers() already
                    # wrote directly into the context's own buffer, so we
                    # just need to record how many bytes were written.
                    code.add(f"{context}.len = {input_algorithm.length};")
            else:
                raise Exception(f"ERROR: Input parameter {input_} not supported!")

            code.add("")

            # Once we've processed the last instruction feeding this
            # context (i.e. the next instruction belongs to a different
            # context, or there are no more instructions), finalize it to
            # produce its digest.
            if idx == len(instructions) - 1 or instructions[idx + 1].split(" - ")[0].replace(" ", "").replace("-", "") != context:
                if attack_vector != AttackVector.a3:
                    code.add(f"{current_algorithm.finalFunction}(&{context});")
                else:
                    code.add(f"{current_algorithm.finalFunction}_vector (&{context});")
                code.add("")

        return code

    @staticmethod
    def generate_footer(final_context: str, attack_vector: AttackVector, kernel_type: KernelType) -> CodeList:
        """
        Emit the end of the kernel: compare the outermost (last) context's
        finished digest against the target hash(es), then close the
        candidate loop and the kernel function itself.
        COMPARE_{M|S}_{SIMD|SCALAR} is a Hashcat macro that, on a match,
        records the found candidate.
        """
        code = CodeList()

        final_context = final_context.split(" - ")[0].replace("-", "")

        type_ = "M" if kernel_type == KernelType.MultiHash else "S"
        comparer = "SIMD" if attack_vector == AttackVector.a3 else "SCALAR"

        code.add(f"COMPARE_{type_}_{comparer} ({final_context}.h[DGST_R0], {final_context}.h[DGST_R1], {final_context}.h[DGST_R2], {final_context}.h[DGST_R3]);", 2)

        code.add("}", 1)  # close the candidate loop
        code.add("}", 0)  # close the kernel function

        return code

    @staticmethod
    def load_buffers(source: IAlgorithm, target: IAlgorithm, inputs: int) -> CodeList:
        """
        Convert `source`'s raw binary digest into its lowercase-hex ASCII
        text form, and write that text into the w0[4]/w1[4]/w2[4]/w3[4]
        scratch word arrays (or, if it's short enough and the only input,
        directly into `target`'s own internal buffer) so it can then be fed
        into `target`'s hashing context as its "plaintext" input.

        This has to account for:
          - both algorithms' endianness (may need `_le` hex-conversion
            variant and different mask offsets to end up with the correct
            byte order in the destination buffer)
          - `source`'s digest length (byteLength), which may have been
            shrunk by a CUT truncation
          - whether `target` already has other inputs too (`inputs`), which
            determines whether we can write straight into target's own
            buffer or must use the generic w0-w3 scratch arrays instead
        """
        code = CodeList()
        code.spacing = 2

        previous_context_idx = 0  # which 32-bit word of source's digest we're currently reading
        bytes_processed = 0

        mask_idx = 0
        mask_offsets = [0, 0, 0, 0]

        # If the source digest is short enough (<=56 bytes of hex) and it's
        # the *only* input this target context receives, we can hex-encode
        # directly into the target's own small buffer instead of the
        # generic scratch arrays - saves an extra copy/update call later.
        buffer_target = ""
        if source.length <= 56 and inputs == 1:
            buffer_target = f"{target.context}."

        # Work out which byte-swap conversion (if any) is needed, and in
        # which order to pull bytes out of each source word, based on
        # whether source and target algorithms share the same endianness.
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

        a = 0  # index into the destination w0/w1/w2/w3 array selection
        while a < source.byteLength:
            b = 0  # index within the current destination word's 4 slots
            while b < 4:
                # Whether to use the plain or "_le" hex-lookup macro,
                # depending on the conversion direction determined above.
                suffix = ""
                if conversion == Conversion.LE2LE or conversion == Conversion.BE2LE:
                    suffix = ""
                else:
                    suffix = "_le"

                # Emit two hex-nibble lookups packed into one 16-bit slot of
                # the destination word (this is written as two half-lines:
                # the assignment, then the second term appended on the next
                # source line but right-justified to visually align with it).
                shift_str = str(mask_offsets[mask_idx]).rjust(2)
                code.add(f"{buffer_target}w{a}[{b}] =  uint_to_hex_lower8{suffix} (({source.context}.h[{previous_context_idx}] >>  {shift_str}) & 255) <<  0")

                mask_idx = (mask_idx + 1) % 4

                shift_str = str(mask_offsets[mask_idx]).rjust(2)
                last_len = len(code[-1])
                line = f"| uint_to_hex_lower8{suffix} (({source.context}.h[{previous_context_idx}] >>  {shift_str}) & 255) << 16;"
                code.add(line.rjust(last_len + 1))

                mask_idx = (mask_idx + 1) % 4

                bytes_processed += 2

                # Once we've converted the whole source digest to hex...
                if bytes_processed == source.byteLength:
                    # ...zero out any remaining, unused w0-w3 slots for
                    # safety (only relevant when writing into the generic
                    # scratch arrays, not target's own small buffer).
                    # This shouldn't be necessary but CUDA is annoying
                    # Just continues using the previous loops for ease. Janky but works
                    if buffer_target == "":
                        b += 1
                        while a < 4:
                            while b < 4:
                                code.add(f"w{a}[{b}] = 0;")
                                b += 1
                            b = 0
                            a += 1
                    a = sys.maxsize  # sentinel to break out of the outer while loop too
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
    """
    Generates the Hashcat C "module" file for this hash mode. This is the
    CPU-side code Hashcat uses to:
      - know basic metadata about the hash mode (name, digest size, whether
        it's salted, which OPTS_TYPE/OPTI_TYPE flags apply)
      - parse a line from the user's hash file into a binary digest (+ salt)
      - re-encode a binary digest back into the same text format, for
        printing cracked results / potfile entries
      - register all of the above with Hashcat's module_ctx callback table
    """
    @staticmethod
    def generate_module(algorithm: str, instructions: List[str], ID: str) -> CodeList:
        code = CodeList()

        # The outermost (last) instruction's algorithm determines the
        # module's overall digest format/size (e.g. for md5(sha1($plain)),
        # that's MD5 - the final visible hash).
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

        # Digest size, expressed in Hashcat's DGST_SIZE_4_<n> unit (n = number
        # of 32-bit words in the digest).
        code.add(f"static const u32   DGST_SIZE      = DGST_SIZE_4_{final_algorithm.byteLength // 4};")

        # Detect whether any step in the chain consumes $salt, to decide the
        # hash category and salt-related module behavior below.
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

        # Self-test hash/pass placeholders (disabled via OPTS_TYPE_SELF_TEST_DISABLE
        # above, so these values are never actually verified against).
        if salted:
            code.add(f'static const char *ST_HASH        = "{"0" * final_algorithm.length}:NOT_IMPLEMENTED";')
        else:
            code.add(f'static const char *ST_HASH        = "{"0" * final_algorithm.length}";')

        # Boilerplate trivial getter functions Hashcat calls to read each of
        # the constants defined above at runtime.
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

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
""")

        code.spacing = 1

        # module_hash_decode(): parses one line of the user-supplied hash
        # file (format "hexhash" or "hexhash:salt") into a binary digest
        # (and salt, if applicable) that the kernel can compare against.
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

        # Convert each 8-hex-char chunk of the hash string into a u32,
        # byte-swapping if the final algorithm is big-endian.
        for i in range(final_algorithm.byteLength // 4):
            if final_algorithm.endianness == Endianness.LittleEndian:
                code.add(f"digest[{i}] = hex_to_u32 (hash_pos + {i * 8});")
            else:
                code.add(f"digest[{i}] = byte_swap_32 (hex_to_u32 (hash_pos + {i * 8}));")

        code.spacing = 1

        # NOTE: this OPTI_TYPE_OPTIMIZED_KERNEL branch (subtracting the IV
        # constants) only matters if an optimized kernel is used with -O.
        # This script only generates pure kernels, so this branch is
        # effectively dead code at runtime, but kept for structural parity
        # with Hashcat's own modules / in case optimized kernels are added
        # back later.
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

        # module_hash_encode(): the reverse of decode - turns a cracked
        # binary digest back into its textual hash:salt representation, used
        # when printing results.
        code.add("""
const u32 *digest = (const u32 *) digest_buf;

// we can not change anything in the original buffer, otherwise destroying sorting
// therefore create some local buffer

""")

        code.add(f"u32 tmp[{final_algorithm.byteLength // 4}];")

        for i in range(final_algorithm.byteLength // 4):
            code.add(f"tmp[{i}] = digest[{i}];")

        # See note above re: OPTI_TYPE_OPTIMIZED_KERNEL - unreachable for
        # this pure-kernel-only build, kept for structural parity.
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

        # module_init(): registers every callback/constant above (plus
        # Hashcat's own MODULE_DEFAULT fallbacks for everything this plugin
        # doesn't customize) into the module_ctx struct Hashcat uses to
        # drive this hash mode.
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
module_ctx->module_pw_max                   = MODULE_DEFAULT;
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
    """
    Create the output directory layout for the generated plugin:
      plugins/<ID>/OpenCL/       (kernel .cl files)
      plugins/<ID>/src/modules/  (module .c file)
    Or, if --hashcat was passed, write directly into the current directory's
    OpenCL/ and src/modules/ (i.e. straight into a Hashcat source checkout).
    Refuses to overwrite an existing plugins/<ID> folder unless --overwrite
    or --hashcat is given.
    """
    if os.path.exists(f"plugins/{ID}") and not overwrite and not hashcat:
        print(f"{ID} has already been used!", file=sys.stderr)
        sys.exit(0)

    prefix = ""
    if not hashcat:
        prefix = f"plugins/{ID}/"
        os.makedirs(prefix, exist_ok=True)

    os.makedirs(f"{prefix}src/modules", exist_ok=True)
    os.makedirs(f"{prefix}OpenCL", exist_ok=True)


def generate_kernels(instructions: List[str], ID: str, hashcat: bool):
    """
    For each supported attack vector (a0, a1, a3), generate one pure kernel
    file containing both the multi-hash and single-hash kernel functions
    back-to-back, and write it to OpenCL/m<ID>_<a0|a1|a3>-pure.cl.
    """
    prefix = ""
    if not hashcat:
        prefix = f"plugins/{ID}/"

    attack_vectors = [AttackVector.a0, AttackVector.a1, AttackVector.a3]
    for attack_vector in attack_vectors:
        # Generate pure kernel
        kernel_code = CodeList()

        kernel_code.add_range(KernelCodeGenerator.generate_imports(attack_vector))

        # Multi-hash kernel function (mXXXXX_mxx): used when cracking a list
        # of hashes at once.
        kernel_code.add_range(KernelCodeGenerator.generate_header(instructions, KernelType.MultiHash, attack_vector, ID))
        kernel_code.add_range(KernelCodeGenerator.generate_compute(instructions, attack_vector))
        kernel_code.add_range(KernelCodeGenerator.generate_footer(instructions[-1], attack_vector, KernelType.MultiHash))

        # Single-hash kernel function (mXXXXX_sxx): used when cracking just
        # one target hash, allows a slightly cheaper comparison path.
        kernel_code.add_range(KernelCodeGenerator.generate_header(instructions, KernelType.SingleHash, attack_vector, ID))
        kernel_code.add_range(KernelCodeGenerator.generate_compute(instructions, attack_vector))
        kernel_code.add_range(KernelCodeGenerator.generate_footer(instructions[-1], attack_vector, KernelType.SingleHash))

        path = f"{prefix}OpenCL/m{ID}_{attack_vector.name}-pure.cl"
        with open(path, "w") as f:
            f.write("\n".join(kernel_code) + "\n")


def generate_module(algorithm: str, instructions: List[str], ID: str, hashcat: bool):
    """Generate and write the module_<ID>.c file described by ModuleCodeGenerator."""
    prefix = ""
    if not hashcat:
        prefix = f"plugins/{ID}/"

    module_code = CodeList()
    module_code.add_range(ModuleCodeGenerator.generate_module(algorithm, instructions, ID))

    path = f"{prefix}src/modules/module_{ID}.c"
    with open(path, "w") as f:
        f.write("\n".join(module_code) + "\n")


def print_supported():
    """Print the list of supported hash algorithms and example expression syntax (for -l/--list)."""
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
    """CLI entry point: parse arguments, parse the hash expression, and generate the plugin files."""
    epilog_text = """examples:
  python3 kernel_builder.py 'md5($plain)' 98000
  python3 kernel_builder.py 'sha1($plain.$salt)' 98001
  python3 kernel_builder.py 'sha224($plain)' 98002
  python3 kernel_builder.py 'sha256($salt.$plain)' 98003
  python3 kernel_builder.py 'md5(sha1($plain))' 98004 --hashcat
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

    # Hashcat -m mode numbers must be a plain 1-5 digit numeric string.
    if not ID.isdigit() or len(ID) > 5 or len(ID) == 0:
        print(f'The ID "{ID}" must be a 1-5 digit number. ex: 98000')
        sys.exit(0)

    # Zero-pad the ID so file/function names are consistent (e.g. "2" -> "00002").
    ID = ID.zfill(5)

    # Parse the PHP-like expression into the flat instruction list every
    # downstream generator consumes.
    instructions = Interpreter.generate_instructions(algorithm)

    create_folder_structure(ID, overwrite, hashcat)

    generate_kernels(instructions, ID, hashcat)
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
