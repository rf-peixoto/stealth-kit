#!/usr/bin/env python3
"""
cobfuscate.py  -  C source string obfuscator

Takes a .c file, finds string literals that sit in safe (callable) positions
inside function bodies, and rewrites them so that no clear text remains in the
source OR the compiled binary. Each literal is replaced by a call to one of N
runtime deobfuscation functions, fed an obfuscated byte blob.

Design goals (see conversation):
  * Must still compile.  We skip every position where a function-call expression
    is not a legal substitute for a string literal.
  * No clear text anywhere.  Blobs are emitted as unsigned-char arrays, not
    string literals, so `strings` finds nothing.
  * Low entropy.  Only distribution-preserving transforms are used
    (position add, bit-rotate, affine byte map, byte reordering). No XOR with a
    random stream, no stored key tables -> section entropy stays close to the
    original, so the result does not look like a packed/encrypted blob.
  * Multi-layer.  Each of the N deob functions chains 3-5 transforms, so every
    decode runs several passes, and different strings route through different
    functions.
  * Safe memory.  Default ("static") gives each obfuscated string its own
    persistent output buffer: a stable address safe to stash in tables, no
    shared pool to clobber, and the caller never frees. ("malloc" mode returns
    a fresh buffer per call that the caller must free.)

This stops `strings`/casual inspection. It does NOT stop a determined analyst
with a debugger, and does not claim to.

Usage:
    python3 cobfuscate.py input.c -o output.c [options]

Options:
    -o, --output PATH     Output file (default: <input>.obf.c)
    --n-deob N            Number of distinct deob functions (default 5)
    --seed S              RNG seed for reproducible builds
    --alloc {static,malloc}
                          Buffer strategy (default static: one persistent
                          buffer per string, drop-in. malloc => caller frees.)
    --prefix P            Identifier prefix for injected symbols (default __cbf_)
    --verify              Run `cc -fsyntax-only` on the output and report
    --stats               Print how many literals were obfuscated / skipped
"""

import argparse
import os
import random
import sys

# ----------------------------------------------------------------------------
# Byte-level transform layers.
#
# Each layer is (name, params). We derive both the Python encoder and the
# emitted C decoder from the same description so they can never drift.
# Encoding applies layers L1..Lm to plaintext; decoding applies the inverse
# of Lm..L1 (reverse order).
# ----------------------------------------------------------------------------


def _rol8(x, r):
    return ((x << r) | (x >> (8 - r))) & 0xFF


def _modinv(a, m=256):
    # a is odd => invertible mod 256
    return pow(a, -1, m)


def encode_layer(data, layer):
    """Apply one layer (encode direction) to a list of ints, return new list."""
    name = layer[0]
    n = len(data)
    if name == "add":
        # Pure constant byte-shift (Caesar). Position-independent so the byte
        # histogram is preserved exactly -> Shannon entropy is unchanged.
        s = layer[1]
        return [(data[i] + s) & 0xFF for i in range(n)]
    if name == "rol":
        r = layer[1]
        return [_rol8(data[i], r) for i in range(n)]
    if name == "affine":
        a, b = layer[1], layer[2]
        return [(a * data[i] + b) & 0xFF for i in range(n)]
    if name == "reverse":
        return data[::-1]
    if name == "swap":
        out = list(data)
        for i in range(0, n - 1, 2):
            out[i], out[i + 1] = out[i + 1], out[i]
        return out
    if name == "rotl":
        if n == 0:
            return list(data)
        amt = layer[1] % n
        return data[amt:] + data[:amt]
    raise ValueError("unknown layer " + name)


def encode_pipeline(data, pipeline):
    for layer in pipeline:
        data = encode_layer(data, layer)
    return data


def c_decode_stmt(layer, prefix):
    """C statements that invert one layer in place over buffer `b`, length `len`."""
    name = layer[0]
    P = prefix
    if name == "add":
        s = layer[1]
        return f"for(int i=0;i<len;i++) b[i]=(unsigned char)(b[i]-({s}));"
    if name == "rol":
        r = layer[1]
        return f"for(int i=0;i<len;i++) b[i]={P}ror(b[i],{r});"
    if name == "affine":
        a, b = layer[1], layer[2]
        ainv = _modinv(a)
        return (f"for(int i=0;i<len;i++) "
                f"b[i]=(unsigned char)(({ainv})*(int)((int)b[i]-({b})));")
    if name == "reverse":
        return ("for(int i=0,j=len-1;i<j;i++,j--)"
                "{unsigned char t=b[i];b[i]=b[j];b[j]=t;}")
    if name == "swap":
        return ("for(int i=0;i+1<len;i+=2)"
                "{unsigned char t=b[i];b[i]=b[i+1];b[i+1]=t;}")
    if name == "rotl":
        # encode = left-rotate by amt; invert = left-rotate by m=(len-amt).
        # left-rotate-by-m via three reversals: rev(0,m-1);rev(m,len-1);rev(0,len-1)
        amt = layer[1]
        return (f"if(len>0){{int m=(({amt})%len);m=(len-m)%len;"
                f"{P}rev(b,0,m-1);{P}rev(b,m,len-1);{P}rev(b,0,len-1);}}")
    raise ValueError("unknown layer " + name)


LAYER_BUILDERS = [
    lambda rng: ("add", rng.randint(1, 255)),
    lambda rng: ("rol", rng.randint(1, 7)),
    lambda rng: ("affine", rng.choice(range(3, 256, 2)), rng.randint(1, 255)),
    lambda rng: ("reverse",),
    lambda rng: ("swap",),
    lambda rng: ("rotl", rng.randint(1, 251)),
]


def make_pipelines(n, rng):
    pipelines = []
    for _ in range(n):
        length = rng.randint(3, 5)
        pl = [rng.choice(LAYER_BUILDERS)(rng) for _ in range(length)]
        pipelines.append(pl)
    return pipelines


# ----------------------------------------------------------------------------
# C lexer / scanner.
#
# Single pass over the source (read as latin-1 so 1 char == 1 byte). We copy
# everything through verbatim and only rewrite string literals that pass the
# safety gate. We track just enough context to avoid emitting a function call
# where a string literal is required.
# ----------------------------------------------------------------------------

PUNCT_MULTI = ("<<=", ">>=", "...", "->", "++", "--", "<<", ">>", "<=", ">=",
               "==", "!=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=",
               "|=", "^=", "::")

ID_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
ID_CONT = ID_START | set("0123456789")

STRING_PREFIXES = ("u8", "u", "U", "L")  # wide/unicode -> skipped


class Scanner:
    def __init__(self, src, prefix, alloc="static"):
        self.s = src
        self.n = len(src)
        self.i = 0
        self.prefix = prefix
        self.alloc = alloc       # "static" (per-blob buffer) | "malloc"
        self.out = []            # output pieces
        self.blobs = []          # (blob_name, encoded_bytes)
        # context
        self.brace_stack = []    # frames: (kind, static_flag); kind 'code'|'init'
        self.paren_stack = []    # tag per open paren
        self.prev_sig = ""       # last significant token text
        self.prev_sig2 = ""      # the one before that
        # declaration qualifiers seen since last statement boundary
        self.decl_bad = False    # static / extern / _Thread_local present
        self.asm_armed = False   # saw asm/__asm__, waiting (through qualifiers) for '('
        self.obf_count = 0
        self.skip_count = 0

    # -- significant token bookkeeping ------------------------------------
    def push_sig(self, tok):
        self.prev_sig2 = self.prev_sig
        self.prev_sig = tok

    def reset_decl(self):
        self.decl_bad = False

    # -- main ------------------------------------------------------------
    def run(self, pipelines, blob_prefix):
        self.pipelines = pipelines
        self.blob_prefix = blob_prefix
        self.route = 0
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]

            # line continuation: copy backslash-newline verbatim
            if c == "\\" and self.i + 1 < n and s[self.i + 1] == "\n":
                self.out.append(s[self.i:self.i + 2])
                self.i += 2
                continue

            # whitespace (significant: newline may end a directive, handled there)
            if c in " \t\r\n":
                self.out.append(c)
                self.i += 1
                continue

            # preprocessor directive: '#' as first significant char on a line.
            if c == "#" and self._at_line_start():
                self._consume_directive()
                continue

            # comments
            if c == "/" and self.i + 1 < n and s[self.i + 1] == "/":
                self._consume_line_comment()
                continue
            if c == "/" and self.i + 1 < n and s[self.i + 1] == "*":
                self._consume_block_comment()
                continue

            # char literal
            if c == "'":
                self._consume_char()
                self.push_sig("'char'")
                continue

            # string literal (possibly with a prefix just scanned as an ident)
            if c == '"':
                self._handle_string()
                continue

            # identifier / keyword (may be a string prefix like L"...")
            if c in ID_START:
                self._consume_ident()
                continue

            # number
            if c.isdigit() or (c == "." and self.i + 1 < n and s[self.i + 1].isdigit()):
                self._consume_number()
                continue

            # punctuation
            self._consume_punct()

        return "".join(self.out)

    # -- helpers ---------------------------------------------------------
    def _at_line_start(self):
        # look back over spaces/tabs to a newline or start of file
        j = self.i - 1
        while j >= 0 and self.s[j] in " \t":
            j -= 1
        return j < 0 or self.s[j] == "\n"

    def _consume_directive(self):
        s, n = self.s, self.n
        start = self.i
        while self.i < n:
            c = s[self.i]
            if c == "\\" and self.i + 1 < n and s[self.i + 1] == "\n":
                self.i += 2
                continue
            if c == "\n":
                break
            self.i += 1
        self.out.append(s[start:self.i])
        # directive does not change expression context meaningfully

    def _consume_line_comment(self):
        s, n = self.s, self.n
        start = self.i
        while self.i < n and s[self.i] != "\n":
            if s[self.i] == "\\" and self.i + 1 < n and s[self.i + 1] == "\n":
                self.i += 2
                continue
            self.i += 1
        self.out.append(s[start:self.i])

    def _consume_block_comment(self):
        s, n = self.s, self.n
        start = self.i
        self.i += 2
        while self.i < n and not (s[self.i] == "*" and self.i + 1 < n and s[self.i + 1] == "/"):
            self.i += 1
        self.i = min(self.i + 2, n)
        self.out.append(s[start:self.i])

    def _consume_char(self):
        s, n = self.s, self.n
        start = self.i
        self.i += 1
        while self.i < n:
            c = s[self.i]
            if c == "\\":
                self.i += 2
                continue
            self.i += 1
            if c == "'":
                break
        self.out.append(s[start:self.i])

    def _consume_ident(self):
        s, n = self.s, self.n
        start = self.i
        while self.i < n and s[self.i] in ID_CONT:
            self.i += 1
        tok = s[start:self.i]

        # Is this a string prefix immediately followed by a quote?  e.g. L"..."
        if tok in STRING_PREFIXES and self.i < n and s[self.i] == '"':
            # wide/unicode string -> skip obfuscation, copy prefix + string raw
            self.out.append(tok)
            self._handle_string(wide=True)
            return

        self.out.append(tok)

        if tok in ("static", "extern", "_Thread_local"):
            self.decl_bad = True

        # asm template / operand constraints must stay literals. asm may be
        # written `asm volatile (...)` / `__asm__ __volatile__ (...)`, so arm
        # on the asm keyword and stay armed across the asm qualifiers until '('.
        if tok in ("asm", "__asm__", "__asm"):
            self.asm_armed = True
        elif tok in ("volatile", "__volatile__", "__volatile",
                     "goto", "inline", "__inline", "__inline__"):
            pass  # qualifier allowed between asm and '(' -> keep armed
        else:
            self.asm_armed = False

        self.push_sig(tok)

    def _consume_number(self):
        s, n = self.s, self.n
        start = self.i
        # crude but sufficient: consume ident-ish + . + exponent signs
        while self.i < n and (s[self.i] in ID_CONT or s[self.i] == "."):
            # handle exponent sign
            if s[self.i] in "eEpP" and self.i + 1 < n and s[self.i + 1] in "+-":
                self.i += 2
                continue
            self.i += 1
        self.out.append(s[start:self.i])
        self.push_sig("0")

    def _consume_punct(self):
        s, n = self.s, self.n
        tok = None
        for m in PUNCT_MULTI:
            if s.startswith(m, self.i):
                tok = m
                break
        if tok is None:
            tok = s[self.i]
        self.out.append(tok)
        self.i += len(tok)

        if tok == "{":
            ctx = "init" if self.prev_sig in ("=", "{", ",") else "code"
            if ctx == "init":
                parent = self.brace_stack[-1] if self.brace_stack else None
                # A frame is "static storage" if the declaration carried
                # static/extern/_Thread_local, or it is nested in one that did.
                sflag = self.decl_bad or (parent is not None
                                          and parent[0] == "init" and parent[1])
            else:
                sflag = False
            self.brace_stack.append((ctx, sflag))
            self.reset_decl()
        elif tok == "}":
            if self.brace_stack:
                self.brace_stack.pop()
            self.reset_decl()
        elif tok == ";":
            self.reset_decl()
        elif tok == "(":
            tag = "plain"
            if (self.asm_armed
                    or self.prev_sig in ("sizeof", "_Alignof", "alignof",
                                         "_Static_assert", "static_assert",
                                         "asm", "__asm__", "__asm", "_Pragma",
                                         "__attribute__", "__attribute")):
                tag = "noarg"
            self.paren_stack.append(tag)
        elif tok == ")":
            if self.paren_stack:
                self.paren_stack.pop()

        if tok != "(":
            self.asm_armed = False
        self.push_sig(tok)

    # -- string handling -------------------------------------------------
    def _read_one_string(self):
        """Read a single "..." literal starting at self.i, return (raw, content)."""
        s, n = self.s, self.n
        start = self.i
        self.i += 1  # opening quote
        content_chars = []
        while self.i < n:
            c = s[self.i]
            if c == "\\":
                # keep escape as-is for re-decode; also for raw copy
                content_chars.append(s[self.i:self.i + 2])
                self.i += 2
                continue
            if c == '"':
                self.i += 1
                break
            content_chars.append(c)
            self.i += 1
        raw = s[start:self.i]
        return raw, "".join(content_chars)

    def _skip_ws_and_comments_peek(self):
        """Return index of next significant char without consuming."""
        s, n = self.s, self.n
        j = self.i
        while j < n:
            c = s[j]
            if c == "\\" and j + 1 < n and s[j + 1] == "\n":
                j += 2
                continue
            if c in " \t\r\n":
                j += 1
                continue
            if c == "/" and j + 1 < n and s[j + 1] == "/":
                while j < n and s[j] != "\n":
                    j += 1
                continue
            if c == "/" and j + 1 < n and s[j + 1] == "*":
                j += 2
                while j < n and not (s[j] == "*" and j + 1 < n and s[j + 1] == "/"):
                    j += 1
                j = min(j + 2, n)
                continue
            break
        return j

    def _handle_string(self, wide=False):
        """At a '"'. Gather an adjacent-concatenated run, then obfuscate or copy."""
        # Decide safety BEFORE consuming (uses current context / prev tokens).
        safe = (not wide) and self._string_is_safe()

        # Gather the full concatenation run.
        pieces_raw = []
        contents = []
        wide_run = wide
        while True:
            raw, content = self._read_one_string()
            pieces_raw.append(raw)
            contents.append(content)
            j = self._skip_ws_and_comments_peek()
            # Check for an adjacent string (optionally with a prefix) OR /*noobf*/
            # A following prefix+quote or bare quote continues the run.
            nxt = self._peek_string_start(j)
            if nxt is None:
                break
            self.i = nxt[0]
            if nxt[1]:  # had a prefix
                self.out.append("")  # prefix already accounted below
            # emit any skipped ws/comment between pieces verbatim
            # (we advanced self.i to the quote; the gap was ws/comments only)
            # copy the gap:
            gap_start = self._gap_start
            # nothing: handled by copying below
            if nxt[2]:
                wide_run = True

        full_raw = "".join(pieces_raw)

        # Opt-out marker: /*noobf*/ immediately after the string run.
        jrun = self._skip_ws_and_comments_peek()
        optout = self.s.startswith("/*noobf*/", self._first_nonws_after(self.i))

        if (not safe) or wide_run or optout:
            self.out.append(full_raw)
            self.skip_count += 1
            self.push_sig('"str"')
            return

        # Decode C-escapes in the concatenated content to raw bytes.
        data = decode_c_escapes("".join(contents))
        pipeline_id = self.route % len(self.pipelines)
        self.route += 1
        encoded = encode_pipeline(list(data), self.pipelines[pipeline_id])
        idx = len(self.blobs)
        blob_name = f"{self.blob_prefix}{idx}"
        self.blobs.append((blob_name, encoded))
        if self.alloc == "static":
            # each string gets its own persistent output buffer -> stable
            # address, safe to stash, no pool, no clobbering, no free()
            oname = f"{self.prefix}o{idx}"
            call = f"{self.prefix}d{pipeline_id}({blob_name},{len(data)},{oname})"
        else:  # malloc
            call = f"{self.prefix}d{pipeline_id}({blob_name},{len(data)})"
        self.out.append(call)
        self.obf_count += 1
        self.push_sig('"str"')

    def _first_nonws_after(self, idx):
        s, n = self.s, self.n
        j = idx
        while j < n and s[j] in " \t":
            j += 1
        return j

    def _peek_string_start(self, j):
        """If a string literal begins at/after j (skipping ws already done),
        return (quote_index, had_prefix, is_wide). Else None."""
        s, n = self.s, self.n
        self._gap_start = self.i
        if j >= n:
            return None
        # optional prefix
        k = j
        prefix = ""
        if s[k] in ID_START:
            m = k
            while m < n and s[m] in ID_CONT:
                m += 1
            cand = s[k:m]
            if cand in STRING_PREFIXES and m < n and s[m] == '"':
                prefix = cand
                k = m
            else:
                return None
        if k < n and s[k] == '"':
            # copy gap (ws/comments/prefix) verbatim into output
            self.out.append(s[self.i:k])
            return (k, bool(prefix), prefix in ("L", "u", "U", "u8"))
        return None

    def _string_is_safe(self):
        # file scope -> never (needs a constant; a call won't compile there)
        if not self.brace_stack:
            return False
        # not anywhere inside sizeof/_Static_assert/asm/__attribute__ parens
        # (inherited through nesting, e.g. __attribute__((section("x"))) )
        if "noarg" in self.paren_stack:
            return False
        # not the operand of sizeof/_Alignof written without parens
        if self.prev_sig in ("sizeof", "_Alignof", "alignof"):
            return False
        # not a char-array initializer: `... ] = "..."`  (also catches
        # designated array-element init `[i] = "..."`, which we skip to be safe)
        if self.prev_sig == "=" and self.prev_sig2 == "]":
            return False

        top = self.brace_stack[-1]
        if top[0] == "code":
            # ordinary statement/expression position: fine unless the current
            # declaration carries static/extern/_Thread_local storage.
            if self.decl_bad:
                return False
            return True
        if top[0] == "init":
            # Aggregate initializer. Legal to use a function call ONLY for
            # automatic storage: we must be inside a function body (a 'code'
            # frame exists below) and the declaration must not be static.
            if top[1]:                                   # static/extern storage
                return False
            if not any(f[0] == "code" for f in self.brace_stack):
                return False                             # file-scope aggregate
            return True
        return False


# ----------------------------------------------------------------------------
# C escape decoding (literal content -> raw bytes).
# ----------------------------------------------------------------------------

_SIMPLE_ESC = {
    "n": 10, "t": 9, "r": 13, "\\": 92, '"': 34, "'": 39, "?": 63,
    "a": 7, "b": 8, "f": 12, "v": 11, "0": 0,
}


def decode_c_escapes(text):
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c != "\\":
            out.append(ord(c) & 0xFF)
            i += 1
            continue
        i += 1
        if i >= n:
            out.append(92)
            break
        e = text[i]
        if e == "x":
            i += 1
            h = ""
            while i < n and text[i] in "0123456789abcdefABCDEF":
                h += text[i]
                i += 1
            out.append(int(h, 16) & 0xFF if h else ord("x"))
            continue
        if e in "01234567":
            o = ""
            while i < n and len(o) < 3 and text[i] in "01234567":
                o += text[i]
                i += 1
            out.append(int(o, 8) & 0xFF)
            continue
        if e in _SIMPLE_ESC:
            out.append(_SIMPLE_ESC[e])
            i += 1
            continue
        # unknown escape: keep the char
        out.append(ord(e) & 0xFF)
        i += 1
    return bytes(out)


# ----------------------------------------------------------------------------
# Runtime C code generation.
# ----------------------------------------------------------------------------


def gen_runtime(prefix, pipelines, alloc):
    """Emit the deob helpers and the N deob functions.

    alloc == "static":  each call site passes its own persistent output buffer
                        (see gen_blobs). Signature: d(c,len,o). Stable address,
                        safe to stash, no free, no shared state.
    alloc == "malloc":  each call mallocs a fresh buffer the CALLER must free.
                        Signature: d(c,len).
    """
    P = prefix
    L = []
    L.append("/* ==== injected by cobfuscate.py : runtime string deobfuscator ==== */")
    L.append("#include <string.h>")
    if alloc == "malloc":
        L.append("#include <stdlib.h>")

    # bit / reorder helpers
    L.append(f"static unsigned char {P}ror(unsigned char x,int r)"
             f"{{return (unsigned char)((x>>r)|(x<<(8-r)));}}")
    L.append(f"static void {P}rev(unsigned char*b,int lo,int hi)"
             f"{{while(lo<hi){{unsigned char t=b[lo];b[lo]=b[hi];b[hi]=t;lo++;hi--;}}}}")

    for idx, pl in enumerate(pipelines):
        if alloc == "malloc":
            L.append(f"static char* {P}d{idx}(const unsigned char*c,int len){{")
            L.append(f"  unsigned char*b=(unsigned char*)malloc((size_t)len+1);")
            L.append(f"  if(!b) return (char*)0;")
        else:  # static: caller supplies the output buffer `o`
            L.append(f"static char* {P}d{idx}(const unsigned char*c,int len,unsigned char*b){{")
        L.append(f"  if(len>0) memcpy(b,c,(size_t)len);")
        for layer in reversed(pl):
            L.append("  " + c_decode_stmt(layer, P))
        L.append(f"  b[len]=0; return (char*)b;")
        L.append(f"}}")

    L.append("/* ==== end injected runtime ==== */")
    return "\n".join(L) + "\n"


def splice_injection(body, inject):
    """Place `inject` right before the first top-level #include in `body`
    (so it lands after leading feature-test macros like _GNU_SOURCE), or at
    the very top if there is no #include."""
    lines = body.split("\n")
    for idx, line in enumerate(lines):
        if line.lstrip().startswith("#") and line.lstrip()[1:].lstrip().startswith("include"):
            before = "\n".join(lines[:idx])
            after = "\n".join(lines[idx:])
            sep = "\n" if before else ""
            return before + sep + inject + after
    return inject + body


def gen_blobs(blobs, alloc, prefix):
    if not blobs:
        return ""
    L = ["/* ==== injected obfuscated string blobs ==== */"]
    for idx, (name, data) in enumerate(blobs):
        body = ",".join(str(x) for x in data) if data else "0"
        L.append(f"static const unsigned char {name}[]={{{body}}};")
        if alloc == "static":
            # one persistent output buffer per string (len+1 for the NUL).
            # Zero-initialised in .bss; the plaintext only appears here at
            # runtime, never in the file, so `strings` on the binary sees nothing.
            L.append(f"static unsigned char {prefix}o{idx}[{len(data) + 1}];")
    L.append("/* ==== end blobs ==== */")
    return "\n".join(L) + "\n"


# ----------------------------------------------------------------------------
# Driver.
# ----------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(description="Obfuscate string literals in a C source file.")
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    ap.add_argument("--n-deob", type=int, default=5)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--alloc", choices=["static", "malloc"], default="static",
                    help="static: one persistent buffer per string (default, "
                         "drop-in, safe to stash). malloc: fresh buffer per "
                         "call that the caller must free().")
    ap.add_argument("--prefix", default="__cbf_")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args(argv)

    if args.n_deob < 1:
        ap.error("--n-deob must be >= 1")

    with open(args.input, "r", encoding="latin-1") as f:
        src = f.read()

    rng = random.Random(args.seed)
    pipelines = make_pipelines(args.n_deob, rng)
    blob_prefix = args.prefix + "b"

    sc = Scanner(src, args.prefix, args.alloc)
    body = sc.run(pipelines, blob_prefix)

    runtime = gen_runtime(args.prefix, pipelines, args.alloc)
    blobs = gen_blobs(sc.blobs, args.alloc, args.prefix)

    # Inject the runtime AFTER any leading feature-test macros (e.g.
    # `#define _GNU_SOURCE`) but before the file's first #include, so our
    # injected includes do not get pulled in ahead of those macros. If the
    # file has no #include, prepend at the very top.
    inject = runtime + blobs
    output = splice_injection(body, inject)

    out_path = args.output or (os.path.splitext(args.input)[0] + ".obf.c")
    with open(out_path, "w", encoding="latin-1") as f:
        f.write(output)

    if args.stats or args.verify:
        sys.stderr.write(
            f"[cobfuscate] obfuscated={sc.obf_count} skipped={sc.skip_count} "
            f"deob_funcs={args.n_deob} alloc={args.alloc} -> {out_path}\n")

    if args.verify:
        import subprocess
        cc = os.environ.get("CC", "cc")
        r = subprocess.run([cc, "-fsyntax-only", "-x", "c", out_path],
                           capture_output=True, text=True)
        if r.returncode == 0:
            sys.stderr.write("[cobfuscate] verify: OK (syntax check passed)\n")
        else:
            sys.stderr.write("[cobfuscate] verify: FAILED\n" + r.stderr + "\n")
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
