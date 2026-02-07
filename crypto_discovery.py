"""
Step 1: Crypto Discovery Engine (Optimized V2)
===============================================
对齐需求:
  1) 加密算法识别: YARA + 常量签名 + S-Box表匹配 + MLIL结构指纹 + AES-NI检测
  2) 数据流准备:   函数级 source/sink 标注 + taint_anchors 填充
  3) 对抗行为链:   Source->Crypto->Sink 攻击链发现 + 行为场景分类

相比原版改进:
  - [需求1] 新增 S-Box/T-Table 全表匹配 (16字节前缀)，关联到引用函数
  - [需求1] 算法识别增加 RC4/Feistel/Custom 启发式规则
  - [需求1] taint_anchors 真正填充 source/sink 信息
  - [需求2] analyze_function 输出完整的 caller/callee 调用链
  - [需求3] 攻击链增加行为场景分类 (Payload/C2/Exfil/Ransomware)
  - [Bug]  logger -> logging, _norm_api 安全裁剪, BFS 队列限制, IO seed 补全字段
"""

import sys
import os
import logging
import yara
import json
import glob
import hashlib
import time
import math
import re
import traceback
from collections import Counter, defaultdict, deque
from tqdm import tqdm
from openai import OpenAI

# ==============================================================================
# 0. 日志配置
# ==============================================================================
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.handlers = []

try:
    import binaryninja
    from binaryninja.enums import MediumLevelILOperation, SymbolType
except ImportError:
    print("❌ BinaryNinja API not found.")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIRECTORY = r"D:\Experimental data\ori100\malicious"
RULES_DIRECTORY = os.path.join(BASE_DIR, "rules")
KEY_FILE = os.path.join(BASE_DIR, "keys", "deepseek_key.txt")

OUTPUT_DIR = os.path.join(BASE_DIR, "output")
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

OUTPUT_JSONL = os.path.join(OUTPUT_DIR, "step1_crypto_candidates.jsonl")
LOG_FILE = os.path.join(OUTPUT_DIR, "scan_history.log")

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8', mode='w')
file_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
root_logger.addHandler(file_handler)


def log_dual(msg, level="info"):
    getattr(logging, level, logging.info)(msg)
    if level != "debug":
        prefix = {"warning": "⚠️ ", "error": "❌ "}.get(level, "")
        tqdm.write(f"{prefix}{msg}")


# ==============================================================================
# 1. 全局配置
# ==============================================================================
MAX_TOTAL_NODES = 3000
MAX_EXPANSION_DEPTH = 2
MAX_BFS_QUEUE = 10000
DEBUG_MODE = True

ENABLE_LLM_REFINEMENT = True
LLM_TRIGGER_MIN_CONF = 35
LLM_TRIGGER_MAX_CONF = 85

FUNC_ANALYSIS_CACHE = {}
REF_CACHE = {}

# ==============================================================================
# 2. [需求1] 加密算法特征库 (大幅扩展)
# ==============================================================================

# 2.1 单值常量签名库 (用于 MLIL 常量匹配)
SIG_DB = {
    # TEA / XTEA — 对齐 crypto_signatures.yar TEAN
    0x9E3779B9: ("TEA/XTEA", 8, "BLOCK"), 0x61C88647: ("TEA/XTEA", 8, "BLOCK"),
    # RC5 / RC6 — 对齐 crypto_signatures.yar RC6_Constants
    0xB7E15163: ("RC5/RC6", 5, "BLOCK"), 0x9E3779B1: ("RC6", 5, "BLOCK"),
    # Blowfish (P-array 初始值) — 对齐 crypto_signatures.yar BLOWFISH_Constants
    0x243F6A88: ("Blowfish", 5, "BLOCK"), 0x85A308D3: ("Blowfish", 5, "BLOCK"),
    0x13198A2E: ("Blowfish", 3, "BLOCK"), 0x03707344: ("Blowfish", 3, "BLOCK"),
    # SM4 (国密 FK 参数) — 对齐 block_cipher.yar SM4_FK
    0xA3B1BAC6: ("SM4", 5, "BLOCK"), 0x56AA3350: ("SM4", 5, "BLOCK"),
    0x677D9197: ("SM4", 5, "BLOCK"), 0xB27022DC: ("SM4", 5, "BLOCK"),
    # ChaCha20 / Salsa20 — 对齐 stream_cipher.yar + crypto_signatures.yar
    0x61707865: ("ChaCha/Salsa", 8, "STREAM"), 0x3320646E: ("ChaCha/Salsa", 8, "STREAM"),
    0x79622D32: ("ChaCha/Salsa", 8, "STREAM"), 0x6B206574: ("ChaCha/Salsa", 8, "STREAM"),
    # Sosemanuk — 对齐 stream_cipher.yar Sosemanuk_constants
    0x54657307: ("Sosemanuk", 5, "STREAM"),
    # SHA-1 Round Constants — 对齐 crypto_signatures.yar SHA1_Constants
    0x5A827999: ("SHA1", 5, "HASH"), 0x6ED9EBA1: ("SHA1", 5, "HASH"),
    0x8F1BBCDC: ("SHA1", 5, "HASH"), 0xCA62C1D6: ("SHA1", 5, "HASH"),
    0xC3D2E1F0: ("SHA1", 3, "HASH"),
    # MD5 Init — 对齐 crypto_signatures.yar MD5_Constants
    0x67452301: ("MD5/SHA1", 3, "HASH"), 0xEFCDAB89: ("MD5/SHA1", 3, "HASH"),
    0x98BADCFE: ("MD5", 3, "HASH"), 0x10325476: ("MD5", 3, "HASH"),
    # SHA-256 Init + K[0] — 对齐 crypto_signatures.yar SHA2_BLAKE2_IVs
    0x6A09E667: ("SHA256", 5, "HASH"), 0xBB67AE85: ("SHA256", 5, "HASH"),
    0x3C6EF372: ("SHA256", 5, "HASH"), 0xA54FF53A: ("SHA256", 5, "HASH"),
    0x428A2F98: ("SHA256", 5, "HASH"),
    # SHA-512 Init — 对齐 crypto_signatures.yar SHA512_Constants (64-bit常量)
    0x6A09E667F3BCC908: ("SHA512", 5, "HASH"),
    0xBB67AE8584CAA73B: ("SHA512", 5, "HASH"),
    # SHA-3 / Keccak Round Constants — 对齐 crypto_signatures.yar SHA3_constants
    0x8000000080008000: ("SHA3/Keccak", 5, "HASH"),
    0x800000000000808B: ("SHA3/Keccak", 5, "HASH"),
    0x8000000080008081: ("SHA3/Keccak", 5, "HASH"),
    # RIPEMD-160 — 对齐 crypto_signatures.yar RIPEMD160_Constants
    0xA953FD4E: ("RIPEMD160", 5, "HASH"), 0x50A28BE6: ("RIPEMD160", 5, "HASH"),
    # CRC32 — 对齐 crypto_signatures.yar CRC32_poly_Constant
    0xEDB88320: ("CRC32", 5, "HASH"),
    # MurmurHash
    0x5BD1E995: ("MurmurHash", 3, "HASH"),
    # Whirlpool — 对齐 crypto_signatures.yar WHIRLPOOL_Constants
    0x18186018: ("Whirlpool", 5, "HASH"),
    # SipHash — 对齐 crypto_signatures.yar SipHash_big_endian_constants
    0x736F6D65: ("SipHash", 5, "HASH"),  # "some" = 'somepseu...'
    0x646F7261: ("SipHash", 5, "HASH"),  # "dora" = 'dorandom'
    # ARIA SB2 首字节 — 对齐 crypto_signatures.yar ARIA_SB2
    0xE24E54FC: ("ARIA", 5, "BLOCK"),
    # DES — 对齐 crypto_signatures.yar DES_Long (IP 表特征)
    0x3A32223A: ("DES", 3, "BLOCK"),
}

# 2.2 [需求1新增] S-Box / T-Table 全表特征 (16字节前缀匹配)
# 与 YARA 规则相互补充：YARA 做文件级字节匹配，此处做 BinaryNinja 内存段级匹配 + 交叉引用关联
SBOX_SIGNATURES = {
    # AES — 对齐 crypto_signatures.yar RijnDael_AES / RijnDael_AES_CHAR
    "AES_SBOX":     bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
    "AES_INV_SBOX": bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
    "AES_TE0":      bytes.fromhex("c66363a5f87c7c84ee777799f67b7b8d"),
    "AES_TD0":      bytes.fromhex("51f4a75098445706a235b609f04fc6a0"),
    # CRC32 — 对齐 crypto_signatures.yar CRC32_table
    "CRC32_TABLE":  bytes.fromhex("0000000077073096ee0e612c990951ba"),
    "CRC32_BZIP":   bytes.fromhex("00000000049c2577e4ee4c0509721906"),
    # MD5 T 表 — 对齐 crypto_signatures.yar MD5_Constants
    "MD5_SINIT":    bytes.fromhex("d76aa478e8c7b756242070db"),
    # DES — 对齐 crypto_signatures.yar DES_sbox + DES_pbox_long
    "DES_SBOX1":    bytes.fromhex("0e040d0102060f0b08030a0c05090007"),
    "DES_PBOX":     bytes.fromhex("1080104000000000008010000000104010000040108000000080004000801000"),
    # Blowfish — 对齐 crypto_signatures.yar BLOWFISH_Constants
    "BLOWFISH_SBOX":bytes.fromhex("d1310ba698dfb5ac2ffd72dbd01adfb7"),
    # SM4 — 对齐 block_cipher.yar SM4_SBox
    "SM4_SBOX":     bytes.fromhex("d690e9fecce13db716b614c228fb2c05"),
    # SM4 CK — 对齐 block_cipher.yar SM4_CK
    "SM4_CK":       bytes.fromhex("150e070031 2a231c4d463f386962 5b54".replace(" ", "")),
    # ARIA SB2 — 对齐 crypto_signatures.yar ARIA_SB2
    "ARIA_SB2":     bytes.fromhex("e24e54fc94c24acc620d6a463c4d8bd1"),
    # Sosemanuk mul_a table — 对齐 stream_cipher.yar Sosemanuk_encrypt_tables
    "SOSEMANUK_MUL_A": bytes.fromhex("00000000e19fcf136b973726"),
    # Whirlpool — 对齐 crypto_signatures.yar WHIRLPOOL_Constants
    "WHIRLPOOL_C0": bytes.fromhex("18186018c07830d8"),
}

# 2.3 API 角色映射
API_ROLES_EXACT = {
    # Network Sources
    "recv": ("net", "src"), "wsarecv": ("net", "src"), "recvfrom": ("net", "src"),
    "wsarecvfrom": ("net", "src"),
    "internetreadfile": ("net", "src"), "internetreadfileex": ("net", "src"),
    "httpqueryinfo": ("net", "src"), "internetquerydataavailable": ("net", "src"),
    "winhttpreaddata": ("net", "src"), "winhttpreceiveresponse": ("net", "src"),
    "urldownloadtofile": ("net", "src"),
    # Network Sinks
    "send": ("net", "sink"), "wsasend": ("net", "sink"), "sendto": ("net", "sink"),
    "wsasendto": ("net", "sink"),
    "httpsendrequest": ("net", "sink"), "httpsendrequestex": ("net", "sink"),
    "winhttpsendrequest": ("net", "sink"),
    # Network Context
    "connect": ("net", "io"), "bind": ("net", "io"), "listen": ("net", "io"),
    "accept": ("net", "io"),
    "internetopen": ("net", "ctx"), "internetopenurl": ("net", "ctx"),
    "internetconnect": ("net", "ctx"),
    "winhttpopen": ("net", "ctx"), "winhttpconnect": ("net", "ctx"),
    # File Sources
    "readfile": ("file", "src"), "fread": ("file", "src"), "readfileex": ("file", "src"),
    # File Sinks
    "writefile": ("file", "sink"), "fwrite": ("file", "sink"), "writefileex": ("file", "sink"),
    # File Context
    "createfile": ("file", "ctx"), "fopen": ("file", "ctx"),
    # Registry
    "regqueryvalueex": ("registry", "src"), "regsetvalueex": ("registry", "sink"),
    # Exec/Inject Sinks
    "createprocess": ("exec", "sink"), "createprocessinternal": ("exec", "sink"),
    "shellexecute": ("exec", "sink"), "shellexecuteex": ("exec", "sink"),
    "winexec": ("exec", "sink"),
    "createremotethread": ("exec", "sink"),
    "writeprocessmemory": ("exec", "sink"),
    # Memory
    "virtualalloc": ("mem", "alloc"), "virtualallocex": ("mem", "alloc"),
    # Loader
    "loadlibrary": ("loader", "src"), "loadlibraryex": ("loader", "src"),
    "getprocaddress": ("loader", "src"), "getmodulehandle": ("loader", "src"),
    # Crypto API
    "cryptdecrypt": ("crypto", "api"), "bcryptdecrypt": ("crypto", "api"),
    "cryptencrypt": ("crypto", "api"), "bcryptencrypt": ("crypto", "api"),
    "aes_encrypt": ("crypto", "api"), "evp_encrypt": ("crypto", "api"),
    "evp_decryptfinal": ("crypto", "api"), "evp_encryptfinal": ("crypto", "api"),
    # Crypto Context
    "cryptacquirecontext": ("crypto", "ctx"), "cryptcreatehash": ("crypto", "ctx"),
    "cryptderivekey": ("crypto", "ctx"), "bcryptopenalgorithmprovider": ("crypto", "ctx"),
    "cryptimportkey": ("crypto", "ctx"), "cryptgenkey": ("crypto", "ctx"),
}

DYNAMIC_RES_APIS = {"getprocaddress", "loadlibrary", "ldrgetprocedureaddress", "ldrloaddll", "freelibrary"}
RULE_BLACKLIST = ["Microsoft", "Visual", "RichHeader", "Manifest", "Linker", "Compiler", "Library", "Runtime"]
MATH_LIB_FILTER = ["exp", "log", "pow", "sqrt", "sin", "cos", "operator new"]

# [需求3] 攻击行为场景分类规则
BEHAVIOR_SCENARIOS = [
    # (source_cat, sink_cat) -> scenario_label
    ({"net"}, {"exec", "mem"}, "Payload_Decryption_Loading"),
    ({"net"}, {"exec"}, "C2_Command_Execution"),
    ({"file", "registry"}, {"net"}, "Data_Exfiltration"),
    ({"file"}, {"file"}, "Ransomware_Encryption"),
    ({"net"}, {"file"}, "Payload_Drop_To_Disk"),
    ({"loader"}, {"exec"}, "Reflective_Loading"),
]

# [需求1] YARA 规则名 -> 算法标签映射 (将 YARA 命中转化为结构化的算法标签)
YARA_ALGO_MAP = {
    # AES
    "RijnDael_AES": "AES", "RijnDael_AES_CHAR": "AES", "RijnDael_AES_CHAR_inv": "AES",
    "DCP_RIJNDAEL_Init": "AES", "DCP_RIJNDAEL_EncryptECB": "AES",
    # DES
    "DES_Long": "DES", "DES_sbox": "DES", "DES_pbox_long": "DES",
    "FlyUtilsCnDES_ECB_Encrypt": "DES", "FlyUtilsCnDES_ECB_Decrypt": "DES",
    "DCP_DES_Init": "DES", "DCP_DES_EncryptECB": "DES",
    # Blowfish
    "BLOWFISH_Constants": "Blowfish", "DCP_BLOWFISH_Init": "Blowfish",
    "DCP_BLOWFISH_EncryptCBC": "Blowfish",
    # SM4
    "SM4_SBox": "SM4", "SM4_FK": "SM4", "SM4_CK": "SM4",
    # ChaCha/Salsa
    "Chacha_128_constant": "ChaCha/Salsa", "Chacha_256_constant": "ChaCha/Salsa",
    # Sosemanuk
    "Sosemanuk_constants": "Sosemanuk", "Sosemanuk_encrypt_tables": "Sosemanuk",
    # RC5/RC6
    "RC6_Constants": "RC5/RC6",
    # TEA
    "TEAN": "TEA/XTEA",
    # MD5
    "MD5_Constants": "MD5", "MD5_API": "MD5",
    # SHA
    "SHA1_Constants": "SHA1", "SHA512_Constants": "SHA512",
    "SHA2_BLAKE2_IVs": "SHA256", "SHA3_constants": "SHA3/Keccak",
    "SHA3_interleaved": "SHA3/Keccak",
    # Other Hash
    "RIPEMD160_Constants": "RIPEMD160", "WHIRLPOOL_Constants": "Whirlpool",
    "CRC32_poly_Constant": "CRC32", "CRC32_table": "CRC32", "CRC32_table_lookup": "CRC32",
    "CRC32b_poly_Constant": "CRC32", "CRC32c_poly_Constant": "CRC32", "CRC16_table": "CRC16",
    "SipHash_big_endian_constants": "SipHash", "Elf_Hash": "Elf_Hash",
    # ARIA
    "ARIA_SB2": "ARIA",
    # ECC
    "Curve25519": "Curve25519", "ecc_order": "ECC",
    # RSA (多库)
    "CryptoPP_RsaFunction": "RSA", "CryptoPP_ApplyFunction": "RSA",
    "FGint_RSAEncrypt": "RSA", "FGint_RsaDecrypt": "RSA", "FGint_RsaSign": "RSA",
    "FGint_RSAVerify": "RSA",
    "RsaRef2_RsaPublicEncrypt": "RSA", "RsaRef2_RsaPrivateDecrypt": "RSA",
    "RsaRef2_RsaPublicDecrypt": "RSA", "RsaRef2_RsaPrivateEncrypt": "RSA",
    "LockBox_EncryptRsaEx": "RSA", "LockBox_DecryptRsaEx": "RSA",
    "LockBox_RsaEncryptFile": "RSA",
    # DSA
    "OpenSSL_DSA": "DSA", "FGint_DSASign": "DSA", "FGint_DSAVerify": "DSA",
    # Encoding
    "BASE64_table": "BASE64",
    # Packer/Cryptor
    "DarkEYEv3_Cryptor": "DarkEYE_Cryptor",
    # WinCrypto API
    "Advapi_Hash_API": "WinCryptoAPI",
    "Crypt32_CryptBinaryToString_API": "WinCryptoAPI",
}


# ==============================================================================
# 3. 辅助类
# ==============================================================================

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set): return list(obj)
        return super().default(obj)


class LLMRefiner:
    def __init__(self, key_path):
        self.client = None
        if not ENABLE_LLM_REFINEMENT: return
        if os.path.exists(key_path):
            try:
                with open(key_path, 'r') as f:
                    self.client = OpenAI(api_key=f.read().strip(), base_url="https://api.deepseek.com")
            except Exception as e:
                log_dual(f"LLM Init Failed: {e}", "warning")

    def refine(self, func_name, code_snippet, static_conf):
        if not self.client: return None
        try:
            resp = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[{
                    "role": "user",
                    "content": (
                        f"Analyze function '{func_name}'. Heuristic Score: {static_conf}.\n"
                        f"Code snippet:\n```\n{code_snippet[:800]}\n```\n"
                        f"Is this Encryption, Hashing, Compression, or Other? "
                        f"Return JSON: {{\"category\": \"...\", \"confidence\": int, \"algo_guess\": \"...\"}}"
                    )
                }],
                response_format={"type": "json_object"}
            )
            return json.loads(resp.choices[0].message.content)
        except:
            return None


# ==============================================================================
# 4. 函数验证
# ==============================================================================

def deep_validate_function(bv, func):
    if not func: return False
    if func.total_bytes < 6: return False
    try:
        head = bv.read(func.start, 4)
        if not head or len(head) < 4: return False
        if head in (b'\x00\x00\x00\x00', b'\xCC\xCC\xCC\xCC'): return False
    except:
        return False

    if func.mlil is None:
        func.reanalyze()
        if func.mlil is None: return False

    invalid_count = 0
    count = 0
    try:
        for block in func:
            for instr in block:
                count += 1
                if count > 30: break
                txt = "".join([t.text for t in instr[0]]).lower()
                if "invalid" in txt or "???" in txt or "undefined" in txt:
                    invalid_count += 1
            if count > 30: break
    except:
        return False

    if count == 0: return False
    if invalid_count / count > 0.2: return False
    return True


# ==============================================================================
# 5. 底层工具函数
# ==============================================================================

def calculate_sha256(filepath):
    try:
        s = hashlib.sha256()
        with open(filepath, "rb") as f:
            for b in iter(lambda: f.read(4096), b""): s.update(b)
        return s.hexdigest()
    except:
        return f"err_{time.time()}"


def load_yara_rules():
    files = glob.glob(os.path.join(RULES_DIRECTORY, '*.yar')) + \
            glob.glob(os.path.join(RULES_DIRECTORY, '*.rules'))
    if not files:
        log_dual("No YARA rules found in rules/ directory!", "error")
        return None
    try:
        return yara.compile(filepaths={f"r{i}": f for i, f in enumerate(files)})
    except Exception as e:
        log_dual(f"YARA Compile Error: {e}", "error")
        return None


def is_noise(rule):
    for kw in RULE_BLACKLIST:
        if kw.lower() in rule.lower() and "pack" not in rule.lower(): return True
    return False


def iter_yara_offsets(match):
    if hasattr(match, "strings"):
        for s in match.strings:
            if hasattr(s, "instances"):
                for inst in s.instances: yield inst.offset, getattr(s, "identifier", "?")
            elif isinstance(s, tuple) and len(s) >= 2:
                yield s[0], s[1]


def _norm_api(n):
    """安全的 API 名称规范化"""
    n = (n or "").lower().strip()
    if ".dll!" in n: n = n.split(".dll!", 1)[1]
    elif "!" in n: n = n.split("!", 1)[1]
    elif ".dll." in n: n = n.split(".dll.", 1)[1]
    for p in ["__imp_", "imp_", "j_", "_"]:
        if n.startswith(p): n = n[len(p):]
    if "@" in n: n = n.split("@", 1)[0]
    # 安全后缀裁剪：只有裁剪后能匹配已知 API 才生效
    for suffix in ["exa", "exw", "ex", "a", "w"]:
        if n.endswith(suffix) and len(n) > len(suffix):
            candidate = n[:-len(suffix)]
            if candidate in API_ROLES_EXACT:
                return candidate
    return n


def _is_import_name(n):
    n = (n or "").lower()
    return any(x in n for x in ["__imp_", "imp_", "iat", "j_", "!", ".dll"])


def file_offset_to_vaddr(bv, off):
    a = bv.get_address_for_data_offset(off)
    if a is not None: return a
    try:
        for seg in bv.segments:
            if seg.data_length and seg.data_offset <= off < seg.data_offset + seg.data_length:
                return seg.start + (off - seg.data_offset)
    except:
        pass
    return None


def _try_const_addr(expr):
    try:
        if expr.operation == MediumLevelILOperation.MLIL_CONST_PTR: return int(expr.constant)
        if expr.operation == MediumLevelILOperation.MLIL_CONST: return int(expr.constant)
        if expr.operation == MediumLevelILOperation.MLIL_ADD:
            ops = getattr(expr, 'operands', [])
            if len(ops) >= 2:
                a, b = _try_const_addr(ops[0]), _try_const_addr(ops[1])
                if a is not None and b is not None: return a + b
    except:
        pass
    return None


def _canonicalize_internal_target(bv, addr_hex, name=None):
    try:
        a = int(addr_hex, 16)
    except:
        return name, addr_hex, None
    f = bv.get_function_at(a)
    if not f:
        fs = bv.get_functions_containing(a)
        f = fs[0] if fs else None
    if f: return f.name, hex(f.start), f
    return name, addr_hex, None


def edge_key(e):
    return (e.get("src"), e.get("dst"), e.get("site"))


def _entropy(data):
    """计算字节序列的信息熵"""
    if not data: return 0
    e = 0
    for x in range(256):
        p = float(data.count(x)) / len(data)
        if p > 0: e -= p * math.log(p, 2)
    return e


# ==============================================================================
# 6. [需求1新增] S-Box / 查找表 扫描器
# ==============================================================================

def scan_sbox_tables(bv):
    """
    [需求1] 在 .rdata/.data 中匹配完整的 S-Box/T-Table 特征表，
    并通过交叉引用关联到引用该表的函数。
    """
    matches = []
    for section in bv.sections.values():
        if section.name not in [".rdata", ".data", ".rodata"]: continue
        try:
            size = min(section.end - section.start, 1024 * 1024)
            data = bv.read(section.start, size)
            for name, sig in SBOX_SIGNATURES.items():
                idx = 0
                while True:
                    pos = data.find(sig, idx)
                    if pos == -1: break
                    addr = section.start + pos
                    # 获取引用此数据地址的所有函数
                    ref_funcs = set()
                    # 检查表头附近多个偏移的引用（编译器可能引用表的不同位置）
                    for offset in [0, 4, 8, 16]:
                        for ref in bv.get_code_refs(addr + offset):
                            if ref.function:
                                ref_funcs.add(ref.function.start)
                        for ref in bv.get_data_refs(addr + offset):
                            ref_addr = ref if isinstance(ref, int) else getattr(ref, 'address', None)
                            if ref_addr:
                                for f in bv.get_functions_containing(ref_addr):
                                    ref_funcs.add(f.start)

                    matches.append({
                        "algo": name,
                        "addr": hex(addr),
                        "section": section.name,
                        "referencing_funcs": [hex(a) for a in ref_funcs]
                    })
                    idx = pos + len(sig)
        except:
            pass
    return matches


# ==============================================================================
# 7. 交叉引用查找
# ==============================================================================

def find_references_smart(bv, vaddr):
    key = (id(bv), int(vaddr))
    if key in REF_CACHE: return REF_CACHE[key]

    hits = []
    seen_funcs = set()

    def collect(addr):
        try:
            for r in bv.get_code_refs(addr):
                if r.function and r.function.start not in seen_funcs:
                    hits.append((r.function, r.address))
                    seen_funcs.add(r.function.start)
        except:
            pass
        try:
            for r in bv.get_data_refs(addr):
                ref_addr = r if isinstance(r, int) else getattr(r, 'address', None)
                if ref_addr:
                    for f in bv.get_functions_containing(ref_addr):
                        if f.start not in seen_funcs:
                            hits.append((f, ref_addr))
                            seen_funcs.add(f.start)
        except:
            pass

    collect(vaddr)
    if not hits:
        limit = max(bv.start, vaddr - 16)
        curr = vaddr
        while curr > limit:
            curr -= 4
            collect(curr)
            if hits: break

    REF_CACHE[key] = hits
    return hits


# ==============================================================================
# 8. [需求1] 增强的算法识别引擎
# ==============================================================================

class StaticAlgoDetector:
    @staticmethod
    def detect(imm_consts, op_profile, total_ops, struct_feats, sbox_hits=None):
        """
        综合算法识别：常量签名 + 操作码分布 + 结构特征 + S-Box表关联
        """
        hints = defaultdict(float)
        families = defaultdict(int)

        # 1. 常量签名匹配
        for val, count in imm_consts.items():
            if val in SIG_DB:
                name, weight, algo_type = SIG_DB[val]
                hints[name] += weight * count
                families[algo_type] += 1

        # 2. S-Box 表匹配（如果关联到了当前函数）
        if sbox_hits:
            for sh in sbox_hits:
                algo_name = sh["algo"].split("_")[0]  # "AES_SBOX" -> "AES"
                hints[algo_name] += 15  # 高权重
                families["SBOX_CONFIRMED"] += 1

        style = "UNKNOWN"
        confidence = 0
        hints_score = sum(hints.values())

        # 3. 操作码分布分析
        if total_ops > 10:
            xor_r = op_profile.get("xor", 0) / total_ops
            shift_r = op_profile.get("shift", 0) / total_ops
            rotate_r = op_profile.get("rotate", 0) / total_ops
            add_r = op_profile.get("add", 0) / total_ops
            sub_r = op_profile.get("sub", 0) / total_ops
            aes_ops = op_profile.get("crypto_hw", 0)

            if aes_ops > 0:
                style = "AES-NI"
                confidence = 99
            elif xor_r > 0.12 and (shift_r + rotate_r) > 0.04 and add_r > 0.06:
                style = "ARX"
                confidence = max(confidence, 78)
            elif xor_r > 0.25:
                style = "XOR-Intensive"
                confidence = max(confidence, 60)
            # [需求1新增] RC4 特征: 双循环 + 少XOR + 大量ADD (swap操作)
            elif struct_feats.get("loops", 0) >= 2 and xor_r < 0.05 and add_r > 0.15:
                style = "RC4-Like"
                confidence = max(confidence, 65)
            # [需求1新增] Feistel 特征: 循环 + XOR + Shift + 中等ADD
            elif struct_feats.get("loops", 0) >= 1 and xor_r > 0.06 and shift_r > 0.03:
                style = "Feistel-Like"
                confidence = max(confidence, 55)
            # [需求1新增] 简单 XOR 加密: 循环 + 纯 XOR
            elif struct_feats.get("loops", 0) >= 1 and xor_r > 0.08 and shift_r < 0.01:
                style = "Simple-XOR-Loop"
                confidence = max(confidence, 50)

        # 4. 常量强度加成
        if hints_score >= 10 or max(families.values(), default=0) >= 2:
            confidence = max(confidence, 75)
            if style == "UNKNOWN": style = "ConstantMatch"
            else: style = f"StrongConst+{style}"

        # 5. S-Box 确认
        if "SBOX_CONFIRMED" in families:
            confidence = max(confidence, 85)
            style = f"SBOX+{style}"

        # 6. 结构加成
        if struct_feats.get("loops", 0) > 0: confidence += 10
        if struct_feats.get("table_lookups", 0) > 2:
            style += "+TableLookup"
            confidence += 10

        confidence = min(confidence, 100)

        top_hints = sorted(
            [{"algo": k, "score": round(v, 1)} for k, v in hints.items()],
            key=lambda x: x['score'], reverse=True
        )[:5]

        return {
            "algo_hints": top_hints,
            "crypto_style": style,
            "crypto_confidence_fast": confidence,
            "sbox_confirmed": bool(sbox_hits),
        }


# ==============================================================================
# 9. MLIL 遍历 (递归表达式树)
# ==============================================================================

def _collect_constants_mlil(bv, expr, imm_counter, ptr_counter, limit=512):
    if expr is None or (sum(imm_counter.values()) + sum(ptr_counter.values())) >= limit: return
    try:
        if hasattr(expr, "operation"):
            op = expr.operation.name
            if op in ("MLIL_CONST", "MLIL_CONST_PTR"):
                raw_val = int(expr.constant)
                val32 = raw_val & 0xFFFFFFFF
                is_ptr = False
                if val32 in SIG_DB:
                    imm_counter[val32] += 1
                elif 0x100 < val32 < 0xFFFF0000:
                    if bv.start <= raw_val < bv.end:
                        try:
                            if hasattr(bv, 'get_sections_at') and bv.get_sections_at(raw_val):
                                is_ptr = True
                        except:
                            pass
                    if is_ptr:
                        ptr_counter[raw_val] += 1
                    else:
                        imm_counter[val32] += 1
    except:
        pass
    try:
        for o in (getattr(expr, "operands", []) or []):
            if hasattr(o, "operation"):
                _collect_constants_mlil(bv, o, imm_counter, ptr_counter, limit)
            elif isinstance(o, list):
                for it in o:
                    if hasattr(it, "operation"):
                        _collect_constants_mlil(bv, it, imm_counter, ptr_counter, limit)
    except:
        pass


def _collect_ops_mlil(expr, op_counter, limit=2048):
    """递归遍历 MLIL 表达式树统计操作码"""
    if expr is None or op_counter.get("total", 0) >= limit: return
    try:
        if hasattr(expr, "operation"):
            op_counter["total"] += 1
            name = expr.operation.name
            if "XOR" in name: op_counter["xor"] += 1
            elif "SHL" in name or "SHR" in name or "LSL" in name or "LSR" in name:
                op_counter["shift"] += 1
            elif "ROL" in name or "ROR" in name: op_counter["rotate"] += 1
            elif "ADD" in name: op_counter["add"] += 1
            elif "SUB" in name: op_counter["sub"] += 1
            elif "MUL" in name: op_counter["mul"] += 1
            elif "INTRINSIC" in name and any(k in str(expr).lower() for k in ("aes", "sha")):
                op_counter["crypto_hw"] += 1

            for o in (getattr(expr, "operands", []) or []):
                if hasattr(o, "operation"):
                    _collect_ops_mlil(o, op_counter, limit)
                elif isinstance(o, list):
                    for it in o:
                        if hasattr(it, "operation"): _collect_ops_mlil(it, op_counter, limit)
    except:
        pass


def _count_table_lookups(bv, expr, struct, limit=256):
    if expr is None or struct.get("table_lookups", 0) >= limit: return
    try:
        if hasattr(expr, "operation"):
            if expr.operation == MediumLevelILOperation.MLIL_LOAD:
                ptr = _try_const_addr(expr.src)
                if ptr is not None and bv.start <= ptr < bv.end:
                    struct["table_lookups"] += 1
            for o in (getattr(expr, "operands", []) or []):
                if hasattr(o, "operation"):
                    _count_table_lookups(bv, o, struct, limit)
                elif isinstance(o, list):
                    for it in o:
                        if hasattr(it, "operation"): _count_table_lookups(bv, it, struct, limit)
    except:
        pass


# ==============================================================================
# 10. 调用目标解析
# ==============================================================================

def resolve_call_target(bv, func, instr):
    try:
        dest = instr.dest
        if dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            addr = dest.constant
            f = bv.get_function_at(addr)
            if f:
                try:
                    if getattr(f, "is_thunk", False):
                        tf = getattr(f, "thunked_function", None)
                        if tf:
                            return tf.name, hex(tf.start), "import" if _is_import_name(tf.name) else "internal", True
                except:
                    pass
                sym = bv.get_symbol_at(f.start)
                if sym and (sym.type == SymbolType.ImportedFunctionSymbol or _is_import_name(sym.name)):
                    return sym.name, hex(f.start), "import", True
                return f.name, hex(addr), "internal", False

            sym = bv.get_symbol_at(addr)
            if sym:
                is_imp = sym.type == SymbolType.ImportedFunctionSymbol or _is_import_name(sym.name)
                return sym.name, hex(addr), "import" if is_imp else "internal", is_imp

        if dest.operation == MediumLevelILOperation.MLIL_IMPORT:
            sym = bv.get_symbol_by_address(dest.constant)
            if sym: return sym.name, hex(dest.constant), "import", True

        if dest.operation == MediumLevelILOperation.MLIL_LOAD:
            ptr = _try_const_addr(dest.src)
            if ptr:
                sym = bv.get_symbol_at(ptr)
                if sym and sym.type in (SymbolType.ImportAddressSymbol, SymbolType.ImportedFunctionSymbol):
                    return sym.name, hex(ptr), "import", True
                try:
                    val = bv.read_pointer(ptr)
                    sym_t = bv.get_symbol_at(val)
                    if sym_t and (_is_import_name(sym_t.name) or sym_t.type == SymbolType.ImportedFunctionSymbol):
                        return sym_t.name, hex(val), "import", True
                except:
                    pass

        m = re.search(r'call\(\s*([a-zA-Z0-9_@\.\!\-]+)\s*\)', str(instr))
        if m:
            name = m.group(1)
            base = _norm_api(name)
            if base in API_ROLES_EXACT: return name, None, "import", True
            return name, None, "indirect", True

        return None, None, None, True
    except:
        return None, None, None, True


# ==============================================================================
# 11. [需求1+2] 核心函数分析 (增强版)
# ==============================================================================

def analyze_function_cached(bv, func):
    key = (id(bv), int(func.start))
    if key in FUNC_ANALYSIS_CACHE: return FUNC_ANALYSIS_CACHE[key]
    res = analyze_function(bv, func)
    FUNC_ANALYSIS_CACHE[key] = res
    return res


def analyze_function(bv, func, sbox_table_hits=None):
    """
    综合分析一个函数，提取:
    - stats: 操作码分布、常量、API调用
    - topo: 调用边（caller/callee）
    - behavior: IO事件、taint锚点 (source/sink)
    - algo: 加密算法识别结果
    - instr_logic: MLIL 代码文本
    """
    stats = {
        "op_profile": Counter(), "api_calls": [], "imm_consts": Counter(),
        "complexity": {"blocks": len(func.basic_blocks), "total_bytes": func.total_bytes}
    }
    topo = {"call_edges": [], "callers": [], "callees": []}
    behavior = {
        "io_events": [],
        "taint_anchors": {"sources": [], "sinks": []},
        "templates": set()
    }
    struct = {"loops": 0, "table_lookups": 0}
    imm_counter = Counter()
    ptr_counter = Counter()

    # [需求1] 收集 caller 信息
    for ref in bv.get_code_refs(func.start):
        if ref.function:
            caller_info = {"addr": hex(ref.function.start), "name": ref.function.name,
                           "site": hex(ref.address)}
            topo["callers"].append(caller_info)
            topo["call_edges"].append({
                "src": hex(ref.function.start), "dst": hex(func.start),
                "dst_name": func.name, "site": hex(ref.address), "dst_kind": "internal"
            })

    try:
        if func.mlil:
            for block in func.mlil:
                for edge in block.outgoing_edges:
                    if edge.target.start < block.start: struct["loops"] += 1

                for instr in block:
                    _collect_ops_mlil(instr, stats["op_profile"])
                    _collect_constants_mlil(bv, instr, imm_counter, ptr_counter)
                    _count_table_lookups(bv, instr, struct)

                    if instr.operation.name in ("MLIL_CALL", "MLIL_TAILCALL", "MLIL_CALL_UNTYPED"):
                        t_name, t_addr, t_kind, is_indir = resolve_call_target(bv, func, instr)
                        site = hex(instr.address)
                        if t_name:
                            if t_kind == "internal" and t_addr and t_addr.startswith("0x"):
                                t_name, t_addr, _ = _canonicalize_internal_target(bv, t_addr, t_name)

                            topo["call_edges"].append({
                                "src": hex(func.start), "dst": t_addr, "dst_name": t_name,
                                "site": site, "dst_kind": t_kind
                            })
                            # [需求1] 收集 callee 信息
                            topo["callees"].append({
                                "addr": t_addr, "name": t_name, "kind": t_kind, "site": site
                            })
                            stats["api_calls"].append({"name": t_name, "kind": t_kind})

                            base = _norm_api(t_name)
                            if base in API_ROLES_EXACT:
                                cat, kind = API_ROLES_EXACT[base]
                                io_event = {"cat": cat, "kind": kind, "api": t_name, "site": site}
                                behavior["io_events"].append(io_event)

                                # [需求2] 填充 taint_anchors
                                if kind == "src":
                                    behavior["taint_anchors"]["sources"].append({
                                        "api": t_name, "category": cat, "site": site
                                    })
                                elif kind == "sink":
                                    behavior["taint_anchors"]["sinks"].append({
                                        "api": t_name, "category": cat, "site": site
                                    })
    except Exception as e:
        logging.debug(f"Err analyzing {func.name}: {e}")

    # [需求1] 确定当前函数关联的 S-Box 命中
    func_sbox_hits = []
    if sbox_table_hits:
        func_addr_hex = hex(func.start)
        for sh in sbox_table_hits:
            if func_addr_hex in sh.get("referencing_funcs", []):
                func_sbox_hits.append(sh)

    op_total = max(1, stats["op_profile"].get("total", 1))
    algo = StaticAlgoDetector.detect(imm_counter, stats["op_profile"], op_total, struct, func_sbox_hits)

    # 去重边
    ded = {}
    for e in topo["call_edges"]:
        if e.get("dst"): ded[edge_key(e)] = e
    topo["call_edges"] = list(ded.values())

    stats["imm_consts"] = dict(imm_counter.most_common(16))
    stats["ptr_consts"] = dict(ptr_counter.most_common(8))
    behavior["templates"] = list(behavior["templates"])
    stats["op_profile"] = dict(stats["op_profile"])

    instr_logic = "\n".join([str(i) for b in func.mlil for i in b][:300]) if func.mlil else ""

    return stats, topo, behavior, algo, instr_logic


# ==============================================================================
# 12. [需求3] 污点传播 + 攻击链分析 (增强版)
# ==============================================================================

def _propagate_taint_attributes(results, all_edges_dict, sources, sinks):
    adj = defaultdict(list)
    rev_adj = defaultdict(list)
    addr_map = {v["addr"]: k for k, v in results.items()}
    for e in all_edges_dict.values():
        src, dst = e.get("src"), e.get("dst")
        if src and dst and src in addr_map and dst in addr_map:
            adj[src].append(dst)
            rev_adj[dst].append(src)

    def bfs(start_nodes, direction="fwd"):
        reached = set(start_nodes)
        q = deque(start_nodes)
        while q:
            curr = q.popleft()
            neighbors = adj[curr] if direction == "fwd" else rev_adj[curr]
            for n in neighbors:
                if n not in reached:
                    reached.add(n)
                    q.append(n)
        return reached

    reach_src = bfs(sources, "fwd")
    reach_sink = bfs(sinks, "bwd")

    cryptos = set()
    for v in results.values():
        io = v.get("behavior", {}).get("io_events", [])
        algo = v.get("static_algo", {})

        has_api = any(x.get("cat") == "crypto" and x.get("kind") == "api" for x in io)
        strong_static = algo.get("crypto_confidence_fast", 0) >= 60
        has_yara = len(v.get("trigger_rules", [])) > 0 or len(v.get("yara_hits", [])) > 0
        has_sbox = algo.get("sbox_confirmed", False)
        ver = str(v.get("llm_verdict", {})).lower()
        is_llm = any(k in ver for k in ("encrypt", "hash", "cipher", "aes", "rc4", "md5", "tea", "chacha"))

        if has_api or strong_static or has_yara or has_sbox or is_llm:
            cryptos.add(v["addr"])

    reach_crypto = bfs(cryptos, "bwd")
    return reach_src, reach_sink, reach_crypto, cryptos


def _classify_chain_scenario(src_cats, sink_cats):
    """[需求3] 根据源/汇类别判断攻击行为场景"""
    for rule_src, rule_sink, label in BEHAVIOR_SCENARIOS:
        if src_cats & rule_src and sink_cats & rule_sink:
            return label
    return "Unknown_Crypto_Operation"


def analyze_sample_chain(results, all_edges_dict, max_chains=50):
    """
    [需求3增强] 攻击链分析:
    1. Loader Chain: Source -> Crypto
    2. Linear Attack Chain: Source -> Crypto -> Sink (含行为场景分类)
    3. Crypto Bridge: 加密函数连接两端的桥接模式
    """
    addr2node = {v["addr"]: v for v in results.values()}
    addr2name = {v["addr"]: v.get("func_name", v["addr"]) for v in results.values()}

    sources = {v["addr"] for v in results.values() if
               any(x.get("kind") == "src" for x in v.get("behavior", {}).get("io_events", []))}
    sinks = {v["addr"] for v in results.values() if
             any(x.get("kind") == "sink" for x in v.get("behavior", {}).get("io_events", []))}

    reach_src, reach_sink, reach_crypto, cryptos = _propagate_taint_attributes(
        results, all_edges_dict, sources, sinks
    )

    for v in results.values():
        v["analysis_flags"] = {
            "source_reachable": v["addr"] in reach_src,
            "sink_reachable": v["addr"] in reach_sink,
            "crypto_reachable": v["addr"] in reach_crypto,
            "is_crypto": v["addr"] in cryptos
        }

    chains = []
    seen = set()
    adj = defaultdict(list)
    for e in all_edges_dict.values():
        if e.get("src") and e.get("dst"):
            adj[e["src"]].append(e["dst"])

    # --- Loader Chain: Source -> ... -> Crypto ---
    for src in sources:
        q = deque([(src, [src])])
        while q:
            if len(q) > MAX_BFS_QUEUE: break
            curr, path = q.popleft()
            if len(path) > 4: continue
            if curr in cryptos and curr != src:
                t = tuple(path)
                if t not in seen:
                    seen.add(t)
                    chains.append({
                        "type": "Loader Chain",
                        "src_func": addr2name.get(src),
                        "crypto_func": addr2name.get(curr),
                        "sink_func": "Implicit",
                        "path_addrs": path,
                        "path_names": [addr2name.get(p) for p in path],
                    })
                    log_dual(f"  🔗 Loader: {addr2name.get(src)} -> {addr2name.get(curr)}")

            for child in adj[curr]:
                if child not in path:
                    q.append((child, path + [child]))

    # --- Linear Attack Chain: Source -> Crypto -> Sink (含行为分类) ---
    for src in sources:
        if src not in reach_sink: continue
        q = deque([(src, [src], src in cryptos)])
        while q and len(chains) < max_chains:
            if len(q) > MAX_BFS_QUEUE: break
            curr, path, has_crypto = q.popleft()
            if len(path) > 6: continue
            if curr in cryptos: has_crypto = True

            if curr in sinks and has_crypto:
                t = tuple(path)
                if t not in seen:
                    seen.add(t)
                    c_node = next((x for x in path if x in cryptos), None)

                    # [需求3] 收集源端和汇端的 API 类别
                    src_node = addr2node.get(src, {})
                    sink_node = addr2node.get(curr, {})
                    src_cats = {e.get("cat") for e in src_node.get("behavior", {}).get("io_events", [])
                                if e.get("kind") == "src"}
                    sink_cats = {e.get("cat") for e in sink_node.get("behavior", {}).get("io_events", [])
                                 if e.get("kind") == "sink"}
                    scenario = _classify_chain_scenario(src_cats, sink_cats)

                    chains.append({
                        "type": "Linear Attack Chain",
                        "scenario": scenario,
                        "src_func": addr2name.get(src),
                        "crypto_func": addr2name.get(c_node),
                        "sink_func": addr2name.get(curr),
                        "path_addrs": path,
                        "path_names": [addr2name.get(p) for p in path],
                    })
                    log_dual(f"  🔗 Chain [{scenario}]: {addr2name.get(src)} -> {addr2name.get(c_node)} -> {addr2name.get(curr)}")

            for child in adj[curr]:
                if child in reach_sink or child in cryptos or child in sinks:
                    q.append((child, path + [child], has_crypto))

    return chains


# ==============================================================================
# 13. IO 种子发现
# ==============================================================================

def seed_io_funcs_from_imports(bv):
    seeds = set()
    for sym in bv.get_symbols():
        if sym.type in (SymbolType.ImportedFunctionSymbol, SymbolType.ImportAddressSymbol):
            base = _norm_api(sym.name)
            if base in API_ROLES_EXACT or base in DYNAMIC_RES_APIS:
                for r in bv.get_code_refs(sym.address):
                    if r.function: seeds.add(r.function)
                if hasattr(bv, "get_code_refs_from_const"):
                    for r in bv.get_code_refs_from_const(sym.address):
                        if r.function: seeds.add(r.function)
    return list(seeds)


# ==============================================================================
# 14. JSONL 输出
# ==============================================================================

def append_jsonl(data):
    try:
        with open(OUTPUT_JSONL, 'a', encoding='utf-8') as f:
            for v in data.values():
                f.write(json.dumps(v, cls=SetEncoder, ensure_ascii=False) + "\n")
                f.flush()
    except Exception as e:
        log_dual(f"JSONL Write Failed: {e}", "error")


# ==============================================================================
# 15. 样本处理主函数
# ==============================================================================

def process_sample(binary_path, rules, llm_refiner):
    filename = os.path.basename(binary_path)
    file_hash = calculate_sha256(binary_path)
    results = {}
    all_edges_dict = {}
    bv = None

    FUNC_ANALYSIS_CACHE.clear()
    REF_CACHE.clear()

    try:
        bv = binaryninja.load(binary_path)
        if not bv:
            if DEBUG_MODE: log_dual(f"[{filename}] BN Load Failed", "warning")
            return None, "LOAD_ERR"

        bv.update_analysis_and_wait()

        # [需求1] S-Box 全表扫描
        sbox_hits = scan_sbox_tables(bv)
        if sbox_hits:
            algos_found = list(set(m['algo'] for m in sbox_hits))
            log_dual(f"  📋 S-Box Tables Found: {algos_found}")

        # --- 1. YARA 候选 ---
        matches = rules.match(binary_path)
        for match in matches:
            if is_noise(match.rule): continue
            log_dual(f"  🔥 YARA Hit: {match.rule}")

            for offset, ident in iter_yara_offsets(match):
                vaddr = file_offset_to_vaddr(bv, offset)
                if not vaddr: continue

                refs = find_references_smart(bv, vaddr)
                for func, xref_addr in refs:
                    if not deep_validate_function(bv, func): continue
                    if any(k in func.name.lower() for k in MATH_LIB_FILTER): continue

                    key = f"{file_hash[:12]}_{hex(func.start)}"
                    if key not in results:
                        s, t, b, a, code = analyze_function(bv, func, sbox_hits)
                        FUNC_ANALYSIS_CACHE[(id(bv), int(func.start))] = (s, t, b, a, code)
                        for e in t['call_edges']:
                            if e.get("dst"): all_edges_dict[edge_key(e)] = e
                        results[key] = {
                            "id": key, "sample": filename, "sample_hash": file_hash,
                            "addr": hex(func.start), "func_name": func.name,
                            "trigger_rules": [match.rule], "yara_hits": [],
                            "yara_algo_tags": [],  # [需求1] 结构化算法标签
                            "features": s, "topology": t, "behavior": b, "static_algo": a,
                            "instruction_logic": code
                        }
                    if match.rule not in results[key]["trigger_rules"]:
                        results[key]["trigger_rules"].append(match.rule)
                    results[key]["yara_hits"].append(
                        {"rule": match.rule, "offset": hex(offset), "xref": hex(xref_addr)})
                    # [需求1] 映射 YARA 规则名到算法标签
                    algo_tag = YARA_ALGO_MAP.get(match.rule)
                    if algo_tag and algo_tag not in results[key].get("yara_algo_tags", []):
                        results[key].setdefault("yara_algo_tags", []).append(algo_tag)

        # --- 2. IO 种子 ---
        io_seeds = seed_io_funcs_from_imports(bv)
        for f in io_seeds:
            if not deep_validate_function(bv, f): continue
            k = f"{file_hash[:12]}_{hex(f.start)}"
            if k not in results:
                s, t, b, a, code = analyze_function(bv, f, sbox_hits)
                FUNC_ANALYSIS_CACHE[(id(bv), int(f.start))] = (s, t, b, a, code)
                for e in t['call_edges']: all_edges_dict[edge_key(e)] = e
                results[k] = {
                    "id": k, "sample": filename, "sample_hash": file_hash,
                    "addr": hex(f.start), "func_name": f.name,
                    "static_algo": a, "behavior": b, "is_seed": True,
                    "features": s, "topology": t, "instruction_logic": code,
                    "trigger_rules": [], "yara_hits": []
                }

        # --- 3. S-Box 引用函数直接加入候选 ---
        for sh in sbox_hits:
            for ref_addr_str in sh.get("referencing_funcs", []):
                try:
                    ref_addr = int(ref_addr_str, 16)
                    func = bv.get_function_at(ref_addr)
                    if not func or not deep_validate_function(bv, func): continue
                    k = f"{file_hash[:12]}_{hex(func.start)}"
                    if k not in results:
                        s, t, b, a, code = analyze_function(bv, func, sbox_hits)
                        FUNC_ANALYSIS_CACHE[(id(bv), int(func.start))] = (s, t, b, a, code)
                        for e in t['call_edges']: all_edges_dict[edge_key(e)] = e
                        results[k] = {
                            "id": k, "sample": filename, "sample_hash": file_hash,
                            "addr": hex(func.start), "func_name": func.name,
                            "static_algo": a, "behavior": b,
                            "is_sbox_ref": True, "sbox_algo": sh["algo"],
                            "features": s, "topology": t, "instruction_logic": code,
                            "trigger_rules": [], "yara_hits": []
                        }
                        log_dual(f"  📋 S-Box Ref: {func.name} <- {sh['algo']}")
                except:
                    pass

        # --- 4. BFS 扩展 ---
        candidate_addrs = set()
        for v in results.values():
            try:
                candidate_addrs.add(int(v["addr"], 16))
            except:
                pass

        queue = deque([(a, 0) for a in candidate_addrs])
        visited_context = candidate_addrs.copy()

        while queue:
            if len(results) >= MAX_TOTAL_NODES: break
            curr, depth = queue.popleft()
            if depth >= MAX_EXPANSION_DEPTH: continue

            f = bv.get_function_at(curr)
            if not f: continue

            # Upward
            for ref in bv.get_code_refs(f.start):
                caller = ref.function
                if caller and caller.start not in visited_context:
                    if not deep_validate_function(bv, caller): continue
                    visited_context.add(caller.start)
                    s, t, b, a, code = analyze_function(bv, caller, sbox_hits)
                    FUNC_ANALYSIS_CACHE[(id(bv), int(caller.start))] = (s, t, b, a, code)
                    for e in t['call_edges']: all_edges_dict[edge_key(e)] = e

                    k = f"{file_hash[:12]}_{hex(caller.start)}"
                    results[k] = {
                        "id": k, "sample": filename, "sample_hash": file_hash,
                        "addr": hex(caller.start), "func_name": caller.name,
                        "behavior": b, "static_algo": a,
                        "features": s, "topology": t, "is_context": True,
                        "instruction_logic": code,
                        "trigger_rules": [], "yara_hits": []
                    }
                    queue.append((caller.start, depth + 1))

            # Downward
            if f.mlil:
                budget = 0
                for block in f.mlil:
                    for instr in block:
                        budget += 1
                        if budget > 200: break
                        if instr.operation.name in ("MLIL_CALL", "MLIL_TAILCALL"):
                            _, t_addr, kind, _ = resolve_call_target(bv, f, instr)
                            if kind == "internal" and t_addr:
                                try:
                                    ta = int(t_addr, 16)
                                    if ta not in visited_context:
                                        tf = bv.get_function_at(ta)
                                        if not deep_validate_function(bv, tf): continue
                                        visited_context.add(ta)
                                        s, t, b, a, code = analyze_function(bv, tf, sbox_hits)
                                        FUNC_ANALYSIS_CACHE[(id(bv), int(ta))] = (s, t, b, a, code)
                                        for e in t['call_edges']: all_edges_dict[edge_key(e)] = e

                                        if a["crypto_confidence_fast"] >= 60:
                                            log_dual(f"  🧮 Heuristic Hit: {tf.name} ({a['crypto_style']})")

                                        k = f"{file_hash[:12]}_{hex(ta)}"
                                        results[k] = {
                                            "id": k, "sample": filename, "sample_hash": file_hash,
                                            "addr": hex(ta), "func_name": tf.name,
                                            "behavior": b, "static_algo": a,
                                            "features": s, "topology": t, "is_context": True,
                                            "instruction_logic": code,
                                            "trigger_rules": [], "yara_hits": []
                                        }
                                        queue.append((ta, depth + 1))
                                except:
                                    pass

        # --- 5. LLM 精炼 ---
        if llm_refiner:
            candidates = [
                v for v in results.values()
                if LLM_TRIGGER_MIN_CONF <= v.get("static_algo", {}).get("crypto_confidence_fast", 0) <= LLM_TRIGGER_MAX_CONF
            ]
            candidates.sort(key=lambda x: x.get("static_algo", {}).get("crypto_confidence_fast", 0), reverse=True)
            for v in candidates[:5]:
                code = v.get("instruction_logic")
                if code:
                    res = llm_refiner.refine(
                        v.get("func_name", ""), code,
                        v.get("static_algo", {}).get("crypto_confidence_fast", 0)
                    )
                    if res:
                        v["llm_verdict"] = res
                        log_dual(f"  🧠 LLM: {v['func_name']} -> {res.get('category')} ({res.get('confidence')}%)")
                        ver = str(res.get("category", "")).lower()
                        if "encrypt" in ver or "hash" in ver:
                            v["static_algo"]["crypto_confidence_fast"] = 90

        # --- 6. 攻击链分析 ---
        chains = analyze_sample_chain(results, all_edges_dict)

        # --- 7. 输出 ---
        final_res = {}
        for k, v in results.items():
            v["sample"] = filename
            v["sample_hash"] = file_hash
            final_res[k] = v

        if final_res:
            induced_edges = []
            node_addrs = {v["addr"] for v in final_res.values()}
            for e in all_edges_dict.values():
                if e.get("src") in node_addrs and e.get("dst") in node_addrs:
                    induced_edges.append(e)

            # 构建 chain_targets 供 Step2 直接使用
            chain_targets = []
            for ch in chains:
                addrs = ch.get("path_addrs", [])
                if addrs:
                    chain_targets.append({
                        "type": ch.get("type"),
                        "scenario": ch.get("scenario", "Unknown"),
                        "path_addrs": addrs,
                        "crypto_func": ch.get("crypto_func"),
                        "src_func": ch.get("src_func"),
                        "sink_func": ch.get("sink_func"),
                    })

            final_res[f"{file_hash[:12]}__GRAPH_META"] = {
                "type": "graph_meta", "sample": filename, "sample_hash": file_hash,
                "all_edges_raw": list(all_edges_dict.values()),
                "edges_induced": induced_edges,
                "global_chains": chains,
                "chain_targets": chain_targets,
                "sbox_tables": sbox_hits,
            }
            log_dual(f"  ✅ Saved {len(final_res)} funcs, {len(chains)} chains, {len(sbox_hits)} sbox tables")
        else:
            log_dual(f"  ⚠️ No valid functions found", "warning")

        return final_res, f"HIT {len(final_res)}"

    except Exception as e:
        log_dual(f"[{filename}] Crash: {e}", "error")
        if DEBUG_MODE: traceback.print_exc()
        return None, f"ERR: {e}"
    finally:
        if bv: bv.file.close()


# ==============================================================================
# 16. 主入口
# ==============================================================================

def main():
    if not os.path.exists(TARGET_DIRECTORY):
        print(f"Target not found: {TARGET_DIRECTORY}")
        return

    rules = load_yara_rules()
    llm = LLMRefiner(KEY_FILE)

    files = glob.glob(os.path.join(TARGET_DIRECTORY, "*"))
    files = [f for f in files if os.path.isfile(f) and not f.endswith('.json')]

    if os.path.exists(OUTPUT_JSONL): os.remove(OUTPUT_JSONL)
    print(f"🚀 Step 1 Optimized V2 | {len(files)} files")
    print(f"   Features: S-Box Table Matching, Enhanced Algo ID, Behavior Scenario Classification")
    print(f"📝 Logs: {LOG_FILE}")

    with tqdm(total=len(files)) as pbar:
        for path in files:
            pbar.set_description(os.path.basename(path)[:15])
            res, status = process_sample(path, rules, llm)
            if res: append_jsonl(res)
            pbar.update(1)

    print("\n🎉 Done.")


if __name__ == "__main__":
    main()