"""
Step 2: Hybrid Dataflow / Taint Analysis Engine (V3 — Enhanced)
================================================================
对齐需求:
  1) 加密算法识别: 消费 Step1 的 YARA/SBox/常量识别结果，
     通过 SSA 数据流追踪密码参数（密钥/IV/明文）的来源与去向。
     [V3-增强] 新增 Opcode Histogram 结构指纹：统计 XOR/SHIFT/ROTATE/ADD 等
     IL 指令分布，匹配 TEA/RC4/ChaCha20 等无常量加密实现的特征模板。
  2) 数据流分析: 基于 MLIL SSA def-use 链实现跨基本块、跨函数
     的前后向污点传播，替代原版单 BB BFS 逻辑。
     [V3-增强] 新增内存污点追踪：启发式匹配 MLIL_STORE→MLIL_LOAD 的
     非栈内存流动（全局变量/堆内存），解决解密 Payload 存入全局 Buffer
     后被 CreateThread 使用的场景。
     [V3-增强] 上下文敏感 Caller 优先级：按交叉引用数排序，优先分析
     xref 少的 Caller（具体业务逻辑），而非 main 等通用入口。
  3) 加密类对抗行为分析: 识别 Source→Crypto→Sink 攻击链，
     生成 Step3 所需的 angr blueprint（含污点锚点、密钥位置、行为场景）。
     [V3-增强] 数据流验证攻击链：只有当 Source 和 Sink 之间存在实际的
     数据流路径（在 backward_trace/forward_trace 中被验证）时才确诊为
     该行为，避免日志函数等场景的误报。未验证时降低 confidence。

相比 V2 改进:
  [需求1-增强] Opcode Histogram 加密指纹 (TEA/RC4/ChaCha20/XOR/Feistel/AES 模板)
  [需求1-增强] 常量检测: TEA delta (0x9E3779B9) / mod 256 (AND 0xFF) / 大表索引
  [需求2-增强] MLIL_STORE→MLIL_LOAD 内存污点传播 (启发式地址匹配)
  [需求2-增强] Caller 按 xref 少→多排序 (优先业务逻辑, 跳过 main/entry)
  [需求3-增强] 数据流验证攻击链: chain_verified 标志 + trace 连通性检查
  [需求3-增强] 未验证场景降低 confidence (-10 分), 已验证场景加分 (+10 分)
"""

import gc
import faulthandler
import hashlib
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from heapq import heapify, heappush, heappushpop

from openai import OpenAI
from tqdm import tqdm


# ==============================================================================
# 0. BinaryNinja 静音加载
# ==============================================================================

def suppress_stdout_stderr():
    try:
        out_fd = sys.stdout.fileno()
        err_fd = sys.stderr.fileno()
        saved_out = os.dup(out_fd)
        saved_err = os.dup(err_fd)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, out_fd)
        os.dup2(devnull, err_fd)
        os.close(devnull)
        return saved_out, saved_err
    except Exception:
        return None, None


def restore_stdout_stderr(saved_fds):
    saved_out, saved_err = saved_fds
    if saved_out is None or saved_err is None:
        return
    try:
        os.dup2(saved_out, sys.stdout.fileno())
        os.dup2(saved_err, sys.stderr.fileno())
        os.close(saved_out)
        os.close(saved_err)
    except Exception:
        pass


saved_fds = suppress_stdout_stderr()
try:
    import binaryninja
    from binaryninja import MediumLevelILOperation, SSAVariable, Variable

    try:
        if hasattr(binaryninja, "disable_default_log"):
            binaryninja.disable_default_log()
        else:
            binaryninja.log_to_stdout(binaryninja.LogLevel.ErrorLog)
            if hasattr(binaryninja, "log_to_stderr"):
                binaryninja.log_to_stderr(binaryninja.LogLevel.ErrorLog)
    except Exception:
        pass
except ImportError:
    restore_stdout_stderr(saved_fds)
    print("BinaryNinja API not found. Please ensure it is installed.")
    sys.exit(1)
finally:
    restore_stdout_stderr(saved_fds)


def _safe_op(name):
    return getattr(MediumLevelILOperation, name, None)


MLIL_CALL_OPS = {
    op for op in (
        _safe_op("MLIL_CALL"), _safe_op("MLIL_CALL_UNTYPED"),
        _safe_op("MLIL_TAILCALL"), _safe_op("MLIL_CALL_SSA"),
        _safe_op("MLIL_CALL_UNTYPED_SSA"), _safe_op("MLIL_TAILCALL_SSA"),
    ) if op is not None
}
MLIL_SET_VAR_OPS = {
    op for op in (
        _safe_op("MLIL_SET_VAR"), _safe_op("MLIL_SET_VAR_SSA"),
        _safe_op("MLIL_SET_VAR_ALIASED"), _safe_op("MLIL_SET_VAR_SPLIT"),
        _safe_op("MLIL_SET_VAR_SPLIT_SSA"),
    ) if op is not None
}
MLIL_RET_OPS = {op for op in (_safe_op("MLIL_RET"),) if op is not None}
MLIL_STORE_OPS = {
    op for op in (_safe_op("MLIL_STORE"), _safe_op("MLIL_STORE_SSA"),)
    if op is not None
}
MLIL_LOAD_OPS = {
    op for op in (_safe_op("MLIL_LOAD"), _safe_op("MLIL_LOAD_SSA"),
                  _safe_op("MLIL_LOAD_STRUCT"), _safe_op("MLIL_LOAD_STRUCT_SSA"),)
    if op is not None
}

# ---- [需求1-增强] 加密特征指令集 (用于 Opcode Histogram) ----
MLIL_XOR_OPS = {op for op in (_safe_op("MLIL_XOR"), _safe_op("MLIL_XOR_SSA"),) if op is not None}
MLIL_SHIFT_OPS = {
    op for op in (
        _safe_op("MLIL_LSL"), _safe_op("MLIL_LSR"), _safe_op("MLIL_ASR"),
        _safe_op("MLIL_ROL"), _safe_op("MLIL_ROR"),
        _safe_op("MLIL_LSL_SSA"), _safe_op("MLIL_LSR_SSA"), _safe_op("MLIL_ASR_SSA"),
        _safe_op("MLIL_ROL_SSA"), _safe_op("MLIL_ROR_SSA"),
    ) if op is not None
}
MLIL_ROTATE_OPS = {
    op for op in (
        _safe_op("MLIL_ROL"), _safe_op("MLIL_ROR"),
        _safe_op("MLIL_ROL_SSA"), _safe_op("MLIL_ROR_SSA"),
    ) if op is not None
}
MLIL_ADD_OPS = {op for op in (_safe_op("MLIL_ADD"), _safe_op("MLIL_ADD_SSA"),) if op is not None}
MLIL_SUB_OPS = {op for op in (_safe_op("MLIL_SUB"), _safe_op("MLIL_SUB_SSA"),) if op is not None}
MLIL_AND_OPS = {op for op in (_safe_op("MLIL_AND"), _safe_op("MLIL_AND_SSA"),) if op is not None}
MLIL_OR_OPS  = {op for op in (_safe_op("MLIL_OR"),  _safe_op("MLIL_OR_SSA"),) if op is not None}
MLIL_MUL_OPS = {op for op in (_safe_op("MLIL_MUL"), _safe_op("MLIL_MUL_SSA"),) if op is not None}
MLIL_MOD_OPS = {op for op in (_safe_op("MLIL_DIVU"), _safe_op("MLIL_MODU"),
                              _safe_op("MLIL_MODS"), _safe_op("MLIL_DIVS"),
                              _safe_op("MLIL_DIVU_SSA"), _safe_op("MLIL_DIVS_SSA"),) if op is not None}
MLIL_CMP_OPS = {op for op in (
    _safe_op("MLIL_CMP_E"), _safe_op("MLIL_CMP_NE"),
    _safe_op("MLIL_CMP_SLT"), _safe_op("MLIL_CMP_ULT"),
    _safe_op("MLIL_CMP_SGE"), _safe_op("MLIL_CMP_UGE"),
    _safe_op("MLIL_CMP_SLE"), _safe_op("MLIL_CMP_ULE"),
    _safe_op("MLIL_CMP_SGT"), _safe_op("MLIL_CMP_UGT"),
) if op is not None}

# ==============================================================================
# 1. 全局配置
# ==============================================================================

TARGET_DIRECTORY = r"D:\Experimental data\ori100\malicious"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

INPUT_CANDIDATES = os.path.join(OUTPUT_DIR, "step1_crypto_candidates.jsonl")
OUTPUT_BLUEPRINT_L = os.path.join(OUTPUT_DIR, "step2_angr_blueprint.jsonl")
OUTPUT_REPORT_L = os.path.join(OUTPUT_DIR, "step2_behavior_report.jsonl")
KEY_FILE = os.path.join(BASE_DIR, "keys", "deepseek_key.txt")
LOG_FILE = os.path.join(OUTPUT_DIR, "step2_analysis.log")
FATAL_LOG_FILE = os.path.join(OUTPUT_DIR, "step2_fatal.log")

MAX_TARGETS_PER_SAMPLE = 12
MAX_FALLBACK_POOL = 30
MAX_CALLER_REFS = 25
MAX_TRACE_LINES = 60

LLM_MAX_RETRIES = 2
LLM_TIMEOUT = 45
MIN_SEMANTIC_CONF = 55

# ---------- Step3 API 行为映射 (必须与 Step3 symbolic_execution.py 完全对齐) ----------
# [V4-对齐] 36 个 API — 与 Step3 V4 API_BEHAVIOR_MAP 逐项一致
STEP3_API_BEHAVIOR_MAP = {
    "virtualalloc": {"tag": "Payload_Mem_Alloc", "arg": -1, "check": "return"},
    "virtualallocex": {"tag": "Payload_Mem_Alloc", "arg": -1, "check": "return"},
    "virtualprotect": {"tag": "Payload_Mem_Alloc", "arg": 2, "check": "pointer"},
    "heapalloc": {"tag": "Payload_Mem_Alloc", "arg": -1, "check": "return"},
    "writeprocessmemory": {"tag": "Payload_Injection", "arg": 2, "check": "pointer"},
    "ntwritevirtualmemory": {"tag": "Payload_Injection", "arg": 2, "check": "pointer"},
    "createremotethread": {"tag": "Payload_Execution", "arg": -1, "check": "return"},
    "createremotethreadex": {"tag": "Payload_Execution", "arg": -1, "check": "return"},
    "ntcreatethreadex": {"tag": "Payload_Execution", "arg": -1, "check": "return"},
    "createprocess": {"tag": "Command_Execution", "arg": 1, "check": "pointer"},
    "createprocessa": {"tag": "Command_Execution", "arg": 1, "check": "pointer"},
    "createprocessw": {"tag": "Command_Execution", "arg": 1, "check": "pointer"},
    "winexec": {"tag": "Command_Execution", "arg": 0, "check": "pointer"},
    "shellexecute": {"tag": "Command_Execution", "arg": 2, "check": "pointer"},
    "shellexecutea": {"tag": "Command_Execution", "arg": 2, "check": "pointer"},
    "shellexecutew": {"tag": "Command_Execution", "arg": 2, "check": "pointer"},
    "shellexecuteex": {"tag": "Command_Execution", "arg": 2, "check": "pointer"},
    "system": {"tag": "Command_Execution", "arg": 0, "check": "pointer"},
    "recv": {"tag": "C2_Recv", "arg": 1, "check": "pointer"},
    "recvfrom": {"tag": "C2_Recv", "arg": 1, "check": "pointer"},
    "wsarecv": {"tag": "C2_Recv", "arg": 1, "check": "pointer"},
    "send": {"tag": "Data_Exfiltration", "arg": 1, "check": "pointer"},
    "sendto": {"tag": "Data_Exfiltration", "arg": 1, "check": "pointer"},
    "wsasend": {"tag": "Data_Exfiltration", "arg": 1, "check": "pointer"},
    "connect": {"tag": "C2_Recv", "arg": 1, "check": "pointer"},
    "socket": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "wsastartup": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "internetopen": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "internetopena": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "internetopenw": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "internetconnect": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "internetconnecta": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "httpopenrequest": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "httpopenrequesta": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "httpsendrequest": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "httpssendrequesta": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "internetreadfile": {"tag": "Payload_Download", "arg": 1, "check": "pointer"},
    "winhttpopen": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "winhttpreaddata": {"tag": "Payload_Download", "arg": 1, "check": "pointer"},
    "winhttpconnect": {"tag": "C2_Recv", "arg": -1, "check": "return"},
    "urldownloadtofile": {"tag": "Payload_Download", "arg": 1, "check": "pointer"},
    "urldownloadtofilea": {"tag": "Payload_Download", "arg": 1, "check": "pointer"},
    "urldownloadtofilew": {"tag": "Payload_Download", "arg": 1, "check": "pointer"},
    "writefile": {"tag": "File_Write", "arg": 1, "check": "pointer"},
    "readfile": {"tag": "File_Read", "arg": 1, "check": "pointer"},
    "createfilea": {"tag": "File_Write", "arg": 0, "check": "pointer"},
    "createfilew": {"tag": "File_Write", "arg": 0, "check": "pointer"},
    "fread": {"tag": "File_Read", "arg": 0, "check": "pointer"},
    "fwrite": {"tag": "File_Write", "arg": 0, "check": "pointer"},
    "fopen": {"tag": "File_Read", "arg": 0, "check": "pointer"},
    "deletefilea": {"tag": "File_Write", "arg": 0, "check": "pointer"},
    "deletefilew": {"tag": "File_Write", "arg": 0, "check": "pointer"},
    "movefileex": {"tag": "File_Write", "arg": 0, "check": "pointer"},
    "cryptdecrypt": {"tag": "Crypto_API_Decrypt", "arg": 4, "check": "pointer"},
    "cryptencrypt": {"tag": "Crypto_API_Encrypt", "arg": 4, "check": "pointer"},
    "bcryptdecrypt": {"tag": "Crypto_API_Decrypt", "arg": 4, "check": "pointer"},
    "bcryptencrypt": {"tag": "Crypto_API_Encrypt", "arg": 4, "check": "pointer"},
    "cryptimportkey": {"tag": "Crypto_API_Key", "arg": 2, "check": "pointer"},
    "cryptgenkey": {"tag": "Crypto_API_Key", "arg": -1, "check": "return"},
    "bcryptgeneratesymmetrickey": {"tag": "Crypto_API_Key", "arg": 2, "check": "pointer"},
    "cryptacquirecontext": {"tag": "Crypto_API_Key", "arg": -1, "check": "return"},
    "cryptacquirecontexta": {"tag": "Crypto_API_Key", "arg": -1, "check": "return"},
    "regqueryvalueex": {"tag": "Registry_Read", "arg": 4, "check": "pointer"},
    "regqueryvalueexa": {"tag": "Registry_Read", "arg": 4, "check": "pointer"},
    "regsetvalueex": {"tag": "Registry_Write", "arg": 4, "check": "pointer"},
    "regsetvalueexa": {"tag": "Registry_Write", "arg": 4, "check": "pointer"},
    "regopenkey": {"tag": "Registry_Read", "arg": 1, "check": "pointer"},
    "regopenkeyexa": {"tag": "Registry_Read", "arg": 1, "check": "pointer"},
    "getmodulehandlea": {"tag": "Module_Resolve", "arg": 0, "check": "pointer"},
    "getmodulehandlew": {"tag": "Module_Resolve", "arg": 0, "check": "pointer"},
    "getmodulehandleexa": {"tag": "Module_Resolve", "arg": 0, "check": "pointer"},
    "getmodulehandleexw": {"tag": "Module_Resolve", "arg": 0, "check": "pointer"},
    "loadlibrary": {"tag": "Module_Resolve", "arg": 0, "check": "pointer"},
    "loadlibrarya": {"tag": "Module_Resolve", "arg": 0, "check": "pointer"},
    "loadlibraryw": {"tag": "Module_Resolve", "arg": 0, "check": "pointer"},
    "getprocaddress": {"tag": "Module_Resolve", "arg": 1, "check": "pointer"},
}

# ---- 密码密钥管理 API: 追踪 key material 流向 ----
CRYPTO_KEY_APIS = {
    "cryptimportkey":       {"key_arg": 2, "key_len_arg": 3, "desc": "CryptoAPI import key blob"},
    "cryptderivekey":       {"key_arg": -1, "key_len_arg": -1, "desc": "CryptoAPI derive key from hash"},
    "cryptgenkey":          {"key_arg": -1, "key_len_arg": -1, "desc": "CryptoAPI generate random key"},
    "bcryptgeneratesymmetrickey": {"key_arg": 2, "key_len_arg": 4, "desc": "BCrypt generate symmetric key"},
    "bcryptimportkey":      {"key_arg": 4, "key_len_arg": 5, "desc": "BCrypt import key blob"},
    "cryptacquirecontext":  {"key_arg": -1, "key_len_arg": -1, "desc": "CryptoAPI acquire context"},
    "bcryptopenalgorithmprovider": {"key_arg": -1, "key_len_arg": -1, "desc": "BCrypt open algo provider"},
    "evp_cipherinit_ex":    {"key_arg": 2, "key_len_arg": -1, "desc": "OpenSSL EVP cipher init + key"},
    "aes_set_encrypt_key":  {"key_arg": 0, "key_len_arg": 1, "desc": "OpenSSL AES set encrypt key"},
    "aes_set_decrypt_key":  {"key_arg": 0, "key_len_arg": 1, "desc": "OpenSSL AES set decrypt key"},
}


def _derive_api_sets_from_step3_map(api_map):
    source_set = set()
    sink_set = set()
    for api, meta in api_map.items():
        tag = str((meta or {}).get("tag", "")).lower()
        if any(k in tag for k in ("recv", "read", "download")):
            source_set.add(api)
        else:
            sink_set.add(api)
    return source_set, sink_set


API_SOURCES, API_SINKS = _derive_api_sets_from_step3_map(STEP3_API_BEHAVIOR_MAP)
STEP3_MONITORED_APIS = set(STEP3_API_BEHAVIOR_MAP.keys())

CRYPTO_HINT_APIS = {
    "cryptencrypt", "cryptdecrypt", "bcryptencrypt", "bcryptdecrypt",
    "bcryptimportkey", "bcryptexportkey", "cryptimportkey", "cryptexportkey",
    "aes_encrypt", "aes_decrypt", "evp_encryptfinal", "evp_decryptfinal",
    "evp_cipherinit_ex", "cryptcreatehash", "crypthashdata",
    "bcrypthash", "md5_init", "sha1_init", "sha256_init",
}

SCENARIO_CLASSES = (
    "Payload_Decryption_Loading",
    "C2_Command_Execution",
    "Data_Exfiltration",
    "Ransomware_Encryption",
)

# ---- [需求1-增强] 加密算法 Opcode 指纹模板 ----
# 基于 IL 指令分布特征识别无常量的加密实现
# 每个模板: min_total_ops, min_xor_ratio, min_shift_ratio, has_rotate, has_loop
CRYPTO_OPCODE_FINGERPRINTS = {
    "TEA/XTEA": {
        "min_total_ops": 20,
        "min_xor_ratio": 0.15,       # TEA: 大量 XOR
        "min_shift_ratio": 0.10,      # TEA: 大量 SHIFT (<<4, >>5)
        "min_add_ratio": 0.10,        # TEA: 大量 ADD
        "require_rotate": False,
        "require_loop": True,
        "max_total_ops": 300,         # TEA 通常很紧凑
        "bonus_conditions": ["delta_constant"],  # 0x9E3779B9
    },
    "RC4": {
        "min_total_ops": 15,
        "min_xor_ratio": 0.05,       # RC4: 至少有 XOR
        "min_shift_ratio": 0.0,
        "min_add_ratio": 0.05,
        "require_rotate": False,
        "require_loop": True,
        "max_total_ops": 200,
        "bonus_conditions": ["mod_256_pattern"],  # AND 0xFF 或 MOD 256
    },
    "ChaCha20/Salsa20": {
        "min_total_ops": 40,
        "min_xor_ratio": 0.15,
        "min_shift_ratio": 0.05,
        "min_add_ratio": 0.15,
        "require_rotate": True,       # 核心: ROL 操作
        "require_loop": True,
        "max_total_ops": 800,
        "bonus_conditions": [],
    },
    "Custom_XOR_Cipher": {
        "min_total_ops": 5,
        "min_xor_ratio": 0.20,       # 高 XOR 占比
        "min_shift_ratio": 0.0,
        "min_add_ratio": 0.0,
        "require_rotate": False,
        "require_loop": True,
        "max_total_ops": 150,
        "bonus_conditions": [],
    },
    "Feistel_Cipher": {
        "min_total_ops": 30,
        "min_xor_ratio": 0.12,
        "min_shift_ratio": 0.05,
        "min_add_ratio": 0.05,
        "require_rotate": False,
        "require_loop": True,
        "max_total_ops": 600,
        "bonus_conditions": [],
    },
    "AES_Manual": {
        "min_total_ops": 50,
        "min_xor_ratio": 0.15,
        "min_shift_ratio": 0.08,
        "min_add_ratio": 0.0,
        "require_rotate": False,
        "require_loop": True,
        "max_total_ops": 1500,
        "bonus_conditions": ["sbox_table_access"],
    },
}

LLM_SYSTEM_PROMPT = (
    "You are a malware dataflow triage assistant. "
    "You are given MLIL code from a malware binary and taint analysis evidence. "
    "Output strict JSON only (no markdown). "
    "Scenario must be exactly one of: "
    "Payload_Decryption_Loading, C2_Command_Execution, "
    "Data_Exfiltration, Ransomware_Encryption. "
    "Never output Unknown scenario — choose the closest match and lower confidence if unsure. "
    "For algo, use standard names: AES, DES, RC4, ChaCha20, Salsa20, TEA, XTEA, "
    "Blowfish, SM4, RC5, RC6, XOR, Custom, API_Crypto, Unknown."
)

SKIP_FUNC_NAMES = {
    "__scrt", "__except", "printf", "sprintf", "fprintf", "malloc", "free",
    "memset", "memcpy", "memmove", "strlen", "strcpy", "strcat", "strcmp",
    "operator new", "operator delete", "_start", "__libc", "_init", "_fini",
    "security_check_cookie", "dllmain", "std::", "boost::", "concurrency::",
    "microsoft::", "platform::", "??", "?", "winmain", "wwinmain",
    "start", "entry", "maincrtstartup", "__tmaincrtstartup",
}

API_NAME_SPLIT_RE = re.compile(r"[!:@`]")

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")],
)

_FATAL_FH = None
try:
    _FATAL_FH = open(FATAL_LOG_FILE, "a", encoding="utf-8")
    faulthandler.enable(file=_FATAL_FH, all_threads=True)
except Exception:
    _FATAL_FH = None


def safe_tqdm_write(msg):
    try:
        tqdm.write(msg)
    except Exception:
        try:
            print(msg)
        except Exception:
            pass


# ==============================================================================
# 2. 地址与 API 名规范化
# ==============================================================================

def normalize_addr_text(addr):
    if addr is None:
        return None
    if isinstance(addr, int):
        return hex(addr)
    text = str(addr).strip().lower()
    if not text:
        return None
    if text.startswith("0x"):
        return text
    try:
        return hex(int(text, 16))
    except Exception:
        return None


def normalize_api_name(name):
    """安全的 API 名规范化 — 优先精确匹配, 仅在无精确匹配时裁剪后缀"""
    if not name:
        return None
    n = str(name).strip().lower()
    if not n:
        return None
    if "." in n:
        n = n.split(".")[-1]
    n = API_NAME_SPLIT_RE.split(n)[-1]
    n = n.strip("_").replace("__imp_", "")
    if n.startswith("j_"):
        n = n[2:]
    n = re.sub(r"@\d+$", "", n)
    # [V4-对齐] 精确匹配优先: 如果当前名字已经在已知 API 集中, 直接返回
    # 这样 createprocessa / shellexecutew 等后缀变体不会被误裁剪
    all_known = API_SOURCES | API_SINKS | CRYPTO_HINT_APIS | set(CRYPTO_KEY_APIS.keys())
    if n in all_known:
        return n
    # 安全后缀裁剪: 只有裁剪后能匹配已知 API 才生效
    for suffix in ["exa", "exw", "ex", "a", "w"]:
        if n.endswith(suffix) and len(n) > len(suffix):
            candidate = n[:-len(suffix)]
            if candidate in all_known:
                return candidate
    return n


# ==============================================================================
# 3. Step1 输出索引器 (修复 graph_meta 丢失 + 评分系统)
# ==============================================================================

class Step1Index:
    """[Bug-Fix] 正确消费 Step1 输出，包括 graph_meta 和 chain_targets"""

    def __init__(self):
        self.graph_meta = {}
        self.sample_hash = {}
        self.fallback_heap = defaultdict(list)
        self.crypto_addrs = defaultdict(set)
        self.anchor_map = defaultdict(lambda: defaultdict(lambda: {"sources": set(), "sinks": set()}))
        # [需求1] 保存 Step1 的算法识别结果
        self.algo_info = defaultdict(dict)      # sample -> {addr: {algo_hints, yara_algo_tags, ...}}
        self.bad_lines = 0
        self.total_lines = 0

    def _score_candidate(self, record):
        """基于 Step1 字段评分候选节点的优先级"""
        flags = record.get("analysis_flags", {}) or {}
        behavior = record.get("behavior", {}) or {}
        anchors = behavior.get("taint_anchors", {}) or {}
        static_algo = record.get("static_algo", {}) or {}
        trigger_rules = record.get("trigger_rules", []) or []

        score = 0
        reasons = []
        if flags.get("is_crypto"):
            score += 90
            reasons.append("is_crypto")
        if flags.get("crypto_reachable"):
            score += 25
            reasons.append("crypto_reachable")
        if flags.get("source_reachable"):
            score += 20
            reasons.append("source_reachable")
        if flags.get("sink_reachable"):
            score += 20
            reasons.append("sink_reachable")

        static_conf = int(static_algo.get("crypto_confidence_fast", 0) or 0)
        if static_conf > 0:
            score += min(20, static_conf // 5)
            reasons.append(f"static_conf={static_conf}")

        if anchors.get("sources"):
            score += 15
            reasons.append("taint_src")
        if anchors.get("sinks"):
            score += 15
            reasons.append("taint_sink")
        if trigger_rules:
            score += min(10, len(trigger_rules))
            reasons.append(f"yara={len(trigger_rules)}")
        # [需求1] yara_algo_tags 加分
        yara_tags = record.get("yara_algo_tags", []) or []
        if yara_tags:
            score += 15
            reasons.append(f"algo_tags={'|'.join(yara_tags[:3])}")
        # sbox_confirmed 加分
        if static_algo.get("sbox_confirmed"):
            score += 20
            reasons.append("sbox")

        return score, "|".join(reasons) if reasons else "none"

    def _push_fallback(self, sample, addr, score, reason):
        heap = self.fallback_heap[sample]
        for idx, (old_score, old_addr, old_reason) in enumerate(heap):
            if old_addr == addr:
                if score > old_score:
                    heap[idx] = (score, addr, reason or old_reason)
                    heapify(heap)
                return
        item = (score, addr, reason)
        if len(heap) < MAX_FALLBACK_POOL:
            heappush(heap, item)
        elif score > heap[0][0]:
            heappushpop(heap, item)

    def load(self, path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                self.total_lines += 1
                if not line.strip():
                    continue
                try:
                    j = json.loads(line)
                except Exception:
                    self.bad_lines += 1
                    continue

                sample = j.get("sample")
                if not sample:
                    continue

                # [Bug-Fix] 正确保存 graph_meta (不再过滤掉)
                if j.get("type") == "graph_meta":
                    self.graph_meta[sample] = j
                    continue

                if j.get("sample_hash") and sample not in self.sample_hash:
                    self.sample_hash[sample] = j.get("sample_hash")

                addr = normalize_addr_text(j.get("addr"))
                if not addr:
                    continue

                # 标记加密函数地址
                flags = j.get("analysis_flags", {}) or {}
                static_algo = j.get("static_algo", {}) or {}
                static_conf = int(static_algo.get("crypto_confidence_fast", 0) or 0)
                if flags.get("is_crypto") or static_conf >= 70:
                    self.crypto_addrs[sample].add(addr)

                # [需求1] 保存算法识别信息供 Step2 使用
                algo_record = {}
                if static_algo:
                    algo_record["static_algo"] = static_algo
                yara_tags = j.get("yara_algo_tags", [])
                if yara_tags:
                    algo_record["yara_algo_tags"] = yara_tags
                trigger_rules = j.get("trigger_rules", [])
                if trigger_rules:
                    algo_record["trigger_rules"] = trigger_rules
                if algo_record:
                    self.algo_info[sample][addr] = algo_record

                # 收集 taint anchors
                anchors = (j.get("behavior", {}) or {}).get("taint_anchors", {}) or {}
                src_apis = [normalize_api_name(x.get("api")) for x in (anchors.get("sources", []) or []) if x.get("api")]
                sink_apis = [normalize_api_name(x.get("api")) for x in (anchors.get("sinks", []) or []) if x.get("api")]
                src_apis = [x for x in src_apis if x]
                sink_apis = [x for x in sink_apis if x]
                if src_apis or sink_apis:
                    bucket = self.anchor_map[sample][addr]
                    bucket["sources"].update(src_apis)
                    bucket["sinks"].update(sink_apis)

                score, reason = self._score_candidate(j)
                if score >= 25:
                    self._push_fallback(sample, addr, score, reason)

        logging.info(
            "Step1 parsed: total=%d graph_meta=%d bad_json=%d algo_info_samples=%d",
            self.total_lines, len(self.graph_meta), self.bad_lines, len(self.algo_info),
        )

    def build_contexts(self):
        samples = set()
        samples.update(self.graph_meta.keys())
        samples.update(self.sample_hash.keys())
        samples.update(self.fallback_heap.keys())
        samples.update(self.crypto_addrs.keys())
        samples.update(self.anchor_map.keys())

        contexts = {}
        for sample in sorted(samples):
            meta = self.graph_meta.get(sample, {})
            chain_targets = meta.get("chain_targets") or meta.get("global_chains") or []
            fallback_sorted = sorted(
                self.fallback_heap.get(sample, []), key=lambda x: x[0], reverse=True
            )
            fallback_targets = [
                {"addr": addr, "score": score, "reason": reason}
                for score, addr, reason in fallback_sorted
            ]
            anchors = {}
            for addr, raw in self.anchor_map.get(sample, {}).items():
                anchors[addr] = {
                    "sources": sorted(raw["sources"]),
                    "sinks": sorted(raw["sinks"]),
                }

            contexts[sample] = {
                "sample_hash": self.sample_hash.get(sample),
                "chain_targets": chain_targets,
                "fallback_targets": fallback_targets,
                "crypto_addrs": set(self.crypto_addrs.get(sample, set())),
                "anchors": anchors,
                "algo_info": self.algo_info.get(sample, {}),
            }
        return contexts


# ==============================================================================
# 4. 目标规划 (从 Step1 chain_targets + fallback 中选取分析目标)
# ==============================================================================

def build_target_plan(sample_ctx):
    targets = []
    seen = set()
    crypto_addrs = sample_ctx.get("crypto_addrs", set())

    # 优先从 chain_targets 选取
    for chain in sample_ctx.get("chain_targets", []):
        path = [normalize_addr_text(x) for x in (chain.get("path_addrs") or [])]
        path = [x for x in path if x]
        if not path:
            continue
        chain_type = str(chain.get("type") or "Unknown")
        chain_scenario = str(chain.get("scenario") or "Unknown")

        selected = []
        crypto_nodes = [addr for addr in path if addr in crypto_addrs]
        if crypto_nodes:
            selected.append((crypto_nodes[-1], "chain_crypto"))
        if chain_type.lower().startswith("linear") and path[-1] not in [x[0] for x in selected]:
            selected.append((path[-1], "chain_sink_tail"))
        if not selected:
            selected.append((path[-1], "chain_tail"))

        for target_addr, reason in selected:
            key = (target_addr, tuple(path))
            if key in seen:
                continue
            seen.add(key)
            targets.append({
                "path_addrs": path,
                "target_addr": target_addr,
                "chain_type": chain_type,
                "chain_scenario": chain_scenario,
                "reason": reason,
            })
            if len(targets) >= MAX_TARGETS_PER_SAMPLE:
                return targets

    # fallback: 按评分排序的候选节点
    for fb in sample_ctx.get("fallback_targets", []):
        target_addr = normalize_addr_text(fb.get("addr"))
        if not target_addr:
            continue
        key = (target_addr, (target_addr,))
        if key in seen:
            continue
        seen.add(key)
        targets.append({
            "path_addrs": [target_addr],
            "target_addr": target_addr,
            "chain_type": "Fallback",
            "chain_scenario": "Unknown",
            "reason": fb.get("reason", "fallback"),
        })
        if len(targets) >= MAX_TARGETS_PER_SAMPLE:
            break

    return targets


def collect_seed_anchors(sample_ctx, path_addrs, target_addr):
    anchors = sample_ctx.get("anchors", {})
    src = set()
    sink = set()
    nodes = list(path_addrs or [])
    if target_addr and target_addr not in nodes:
        nodes.append(target_addr)
    for addr in nodes:
        entry = anchors.get(addr)
        if not entry:
            continue
        src.update(entry.get("sources", []))
        sink.update(entry.get("sinks", []))
    return sorted(src), sorted(sink)


def collect_algo_context(sample_ctx, target_addr, path_addrs):
    """[需求1] 从 Step1 收集目标函数及路径上的算法识别上下文"""
    algo_info = sample_ctx.get("algo_info", {})
    result = {
        "step1_algo_hints": [],
        "step1_yara_tags": [],
        "step1_trigger_rules": [],
        "step1_sbox_confirmed": False,
        "step1_crypto_confidence": 0,
    }
    addrs_to_check = list(path_addrs or [])
    if target_addr and target_addr not in addrs_to_check:
        addrs_to_check.append(target_addr)

    for addr in addrs_to_check:
        info = algo_info.get(addr, {})
        sa = info.get("static_algo", {})
        if sa:
            for h in sa.get("algo_hints", []):
                if h not in result["step1_algo_hints"]:
                    result["step1_algo_hints"].append(h)
            if sa.get("sbox_confirmed"):
                result["step1_sbox_confirmed"] = True
            conf = int(sa.get("crypto_confidence_fast", 0) or 0)
            result["step1_crypto_confidence"] = max(result["step1_crypto_confidence"], conf)
        for tag in info.get("yara_algo_tags", []):
            if tag not in result["step1_yara_tags"]:
                result["step1_yara_tags"].append(tag)
        for rule in info.get("trigger_rules", []):
            if rule not in result["step1_trigger_rules"]:
                result["step1_trigger_rules"].append(rule)

    return result


# ==============================================================================
# 5. SSA 级污点分析引擎 (完全重写，跨基本块)
# ==============================================================================

class StaticTaintEngine:
    """
    [Bug-Fix + 需求2] 基于 MLIL SSA def-use 链的污点分析引擎。
    替代原版的单基本块 BFS，天然支持跨基本块追踪。
    """

    def __init__(self, bv):
        self.bv = bv
        self._ssa_cache = {}
        self._callsite_cache = {}

    @staticmethod
    def _is_call_op(op):
        return op in MLIL_CALL_OPS

    @staticmethod
    def _is_set_var_op(op):
        return op in MLIL_SET_VAR_OPS

    @staticmethod
    def _is_ret_op(op):
        return op in MLIL_RET_OPS

    def _get_mlil_ssa(self, func):
        if func is None:
            return None
        key = int(getattr(func, "start", 0))
        if key in self._ssa_cache:
            return self._ssa_cache[key]
        try:
            mlil = getattr(func, "mlil", None)
            ssa = mlil.ssa_form if mlil is not None else None
        except Exception:
            ssa = None
        self._ssa_cache[key] = ssa
        return ssa

    @staticmethod
    def _iter_ssa_instructions(ssa_func):
        if ssa_func is None:
            return []
        instructions = []
        try:
            instructions.extend(list(ssa_func.instructions))
        except Exception:
            try:
                for block in ssa_func:
                    for instr in block:
                        instructions.append(instr)
            except Exception:
                return []
        instructions.sort(key=lambda x: getattr(x, "instr_index", 0))
        return instructions

    @staticmethod
    def _ssa_var_key(ssa_var):
        try:
            return (int(ssa_var.var.identifier), int(ssa_var.version))
        except Exception:
            return str(ssa_var)

    @staticmethod
    def _coerce_int(value, default=None):
        try:
            return int(value)
        except Exception:
            return default

    def _coerce_ssa_instruction(self, ssa, ref):
        if ssa is None or ref is None:
            return None
        if hasattr(ref, "operation") and hasattr(ref, "instr_index"):
            return ref
        idx = self._coerce_int(ref, None)
        if idx is None and hasattr(ref, "instr_index"):
            idx = self._coerce_int(getattr(ref, "instr_index", None), None)
        if idx is None or idx < 0:
            return None
        try:
            return ssa[idx]
        except Exception:
            return None

    def _add_ssa_var(self, bucket, maybe_var):
        if isinstance(maybe_var, SSAVariable):
            bucket[self._ssa_var_key(maybe_var)] = maybe_var

    def _extract_ssa_vars(self, expr):
        vars_map = {}
        stack = [expr]
        seen = set()
        while stack and len(seen) < 1200:
            node = stack.pop()
            if node is None:
                continue
            if isinstance(node, SSAVariable):
                self._add_ssa_var(vars_map, node)
                continue
            if isinstance(node, (list, tuple, set)):
                stack.extend(node)
                continue
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            for attr in ("src", "dest", "var", "output", "params", "operands"):
                try:
                    val = getattr(node, attr, None)
                    if val is None:
                        continue
                    if isinstance(val, SSAVariable):
                        self._add_ssa_var(vars_map, val)
                    elif isinstance(val, (list, tuple)):
                        stack.extend(val)
                    elif hasattr(val, "operation"):
                        stack.append(val)
                except Exception:
                    pass
        return list(vars_map.values())

    def _extract_call_node(self, instr):
        if instr is None:
            return None
        op = getattr(instr, "operation", None)
        if self._is_call_op(op):
            return instr
        if self._is_set_var_op(op):
            src = getattr(instr, "src", None)
            if self._is_call_op(getattr(src, "operation", None)):
                return src
        return None

    def _get_callee_addr(self, instr):
        call_node = self._extract_call_node(instr)
        if call_node is None:
            return None
        try:
            dest = getattr(call_node, "dest", None)
            if hasattr(dest, "constant"):
                return int(dest.constant)
        except Exception:
            pass
        return None

    def _get_callee_name(self, instr):
        call_node = self._extract_call_node(instr)
        if call_node is None:
            return None
        addr = self._get_callee_addr(instr)
        if addr is not None:
            try:
                sym = self.bv.get_symbol_at(addr)
                if sym and sym.name:
                    return sym.name
            except Exception:
                pass
        text = str(call_node)
        m = re.search(r"([A-Za-z_?$@][\w?$@.]*)\s*\(", text)
        return m.group(1) if m else None

    def _get_call_params(self, instr):
        call_node = self._extract_call_node(instr)
        if call_node is None:
            return []
        try:
            return list(getattr(call_node, "params", []) or [])
        except Exception:
            return []

    def _get_call_output_ssa_vars(self, instr):
        out = {}
        if self._is_set_var_op(getattr(instr, "operation", None)):
            for sv in self._extract_ssa_vars(getattr(instr, "dest", None)):
                out[self._ssa_var_key(sv)] = sv
        call_node = self._extract_call_node(instr)
        if call_node is not None:
            for v in getattr(call_node, "output", []) or []:
                for sv in self._extract_ssa_vars(v):
                    out[self._ssa_var_key(sv)] = sv
        return list(out.values())

    def _append_trace(self, traces, func, instr, label):
        if len(traces) >= MAX_TRACE_LINES:
            return
        try:
            f_addr = hex(func.start)
            i_addr = hex(getattr(instr, "address", 0))
            text = str(instr)
            if len(text) > 180:
                text = text[:177] + "..."
            traces.append(f"{label} {f_addr}@{i_addr}: {text}")
        except Exception:
            pass

    def _build_callsite_index(self, caller):
        if caller is None:
            return {"by_addr": defaultdict(list), "by_callee": defaultdict(list), "all_calls": []}
        key = int(getattr(caller, "start", 0))
        if key in self._callsite_cache:
            return self._callsite_cache[key]
        index = {
            "by_addr": defaultdict(list),
            "by_callee": defaultdict(list),
            "all_calls": [],
        }
        ssa = self._get_mlil_ssa(caller)
        for instr in self._iter_ssa_instructions(ssa):
            if self._extract_call_node(instr) is None:
                continue
            addr = int(getattr(instr, "address", -1))
            index["all_calls"].append((addr, instr))
            if addr >= 0:
                index["by_addr"][addr].append(instr)
            callee_addr = self._get_callee_addr(instr)
            if callee_addr is not None:
                index["by_callee"][int(callee_addr)].append((addr, instr))
        self._callsite_cache[key] = index
        return index

    def _find_call_instruction(self, caller, ref_addr, target_addr):
        index = self._build_callsite_index(caller)
        ref_addr = int(ref_addr)
        target_addr = int(target_addr)

        for instr in index["by_addr"].get(ref_addr, []):
            callee_addr = self._get_callee_addr(instr)
            if callee_addr is None or int(callee_addr) == target_addr:
                return instr
        same_addr = index["by_addr"].get(ref_addr, [])
        if same_addr:
            return same_addr[0]
        by_callee = index["by_callee"].get(target_addr, [])
        if by_callee:
            by_callee.sort(key=lambda x: abs(x[0] - ref_addr))
            return by_callee[0][1]
        if index["all_calls"]:
            return min(index["all_calls"], key=lambda x: abs(x[0] - ref_addr))[1]
        return None

    def _scan_internal_calls(self, func, evidence):
        ssa = self._get_mlil_ssa(func)
        for instr in self._iter_ssa_instructions(ssa):
            callee = normalize_api_name(self._get_callee_name(instr))
            if callee in STEP3_MONITORED_APIS:
                evidence["internal_calls"].add(callee)
            if callee in CRYPTO_HINT_APIS:
                evidence["internal_calls"].add(callee)

    # ---- [需求2] 密钥参数追踪 ----
    def _scan_key_material(self, func, evidence):
        """[需求3] 扫描加密密钥管理 API 调用，定位密钥 buffer 位置"""
        ssa = self._get_mlil_ssa(func)
        for instr in self._iter_ssa_instructions(ssa):
            callee = normalize_api_name(self._get_callee_name(instr))
            if callee not in CRYPTO_KEY_APIS:
                continue
            key_meta = CRYPTO_KEY_APIS[callee]
            params = self._get_call_params(instr)
            key_info = {
                "api": callee,
                "desc": key_meta["desc"],
                "site": hex(getattr(instr, "address", 0)),
                "key_param_expr": None,
                "key_len_param_expr": None,
            }
            key_arg_idx = key_meta["key_arg"]
            if key_arg_idx >= 0 and key_arg_idx < len(params):
                key_info["key_param_expr"] = str(params[key_arg_idx])
            key_len_idx = key_meta["key_len_arg"]
            if key_len_idx >= 0 and key_len_idx < len(params):
                key_info["key_len_param_expr"] = str(params[key_len_idx])
            # 返回值也可能是 key handle
            if key_arg_idx == -1:
                out_vars = self._get_call_output_ssa_vars(instr)
                if out_vars:
                    key_info["key_param_expr"] = f"return({str(out_vars[0])})"
            evidence["key_material"].append(key_info)

    # ---- [需求1-增强] Opcode Histogram — 加密结构指纹 ----
    def _compute_opcode_histogram(self, func):
        """统计函数中加密相关 IL 指令的分布特征"""
        ssa = self._get_mlil_ssa(func)
        if ssa is None:
            return None

        hist = {
            "total_ops": 0,
            "xor": 0, "shift": 0, "rotate": 0,
            "add": 0, "sub": 0,
            "and_op": 0, "or_op": 0,
            "mul": 0, "mod_div": 0,
            "cmp": 0,
            "store": 0, "load": 0,
            "call": 0,
            "has_loop": False,
            "basic_block_count": 0,
            "back_edge_count": 0,
            "mod_256_pattern": False,   # AND 0xFF — RC4 特征
            "delta_constant": False,    # 0x9E3779B9 — TEA 特征
            "sbox_table_access": False, # 大表索引访问 — AES/DES 特征
            "large_const_count": 0,     # 非标准大常量数
        }

        # 收集基本块信息用于回边检测
        bb_starts = set()
        bb_map = {}
        try:
            for bb in ssa.basic_blocks:
                bb_starts.add(bb.start)
                bb_map[bb.start] = bb
                hist["basic_block_count"] += 1
        except Exception:
            pass

        # 回边检测: 后继块的 start <= 当前块 start → 回边 (循环)
        for bb_start, bb in bb_map.items():
            try:
                for edge in bb.outgoing_edges:
                    target_bb = edge.target
                    if hasattr(target_bb, "start") and target_bb.start <= bb_start:
                        hist["back_edge_count"] += 1
                        hist["has_loop"] = True
            except Exception:
                pass

        # 遍历所有指令统计 opcode
        large_consts = set()
        for instr in self._iter_ssa_instructions(ssa):
            op = getattr(instr, "operation", None)
            if op is None:
                continue
            hist["total_ops"] += 1

            if op in MLIL_XOR_OPS:
                hist["xor"] += 1
            if op in MLIL_SHIFT_OPS:
                hist["shift"] += 1
            if op in MLIL_ROTATE_OPS:
                hist["rotate"] += 1
            if op in MLIL_ADD_OPS:
                hist["add"] += 1
            if op in MLIL_SUB_OPS:
                hist["sub"] += 1
            if op in MLIL_AND_OPS:
                hist["and_op"] += 1
                # 检测 AND 0xFF (mod 256) — RC4 特征
                self._check_and_0xff(instr, hist)
            if op in MLIL_OR_OPS:
                hist["or_op"] += 1
            if op in MLIL_MUL_OPS:
                hist["mul"] += 1
            if op in MLIL_MOD_OPS:
                hist["mod_div"] += 1
            if op in MLIL_CMP_OPS:
                hist["cmp"] += 1
            if op in MLIL_STORE_OPS:
                hist["store"] += 1
            if op in MLIL_LOAD_OPS:
                hist["load"] += 1
            if self._is_call_op(op):
                hist["call"] += 1

            # 收集常量值 (检测 TEA delta, 大表索引等)
            self._collect_constants(instr, large_consts, hist)

        hist["large_const_count"] = len(large_consts)
        return hist

    @staticmethod
    def _check_and_0xff(instr, hist):
        """检测 AND 0xFF 模式 (RC4 的 mod 256)"""
        try:
            for attr in ("src", "right", "operands"):
                val = getattr(instr, attr, None)
                if val is None:
                    continue
                if isinstance(val, (list, tuple)):
                    for v in val:
                        if hasattr(v, "constant") and int(v.constant) == 0xFF:
                            hist["mod_256_pattern"] = True
                            return
                elif hasattr(val, "constant") and int(val.constant) == 0xFF:
                    hist["mod_256_pattern"] = True
                    return
        except Exception:
            pass

    @staticmethod
    def _collect_constants(instr, large_consts, hist):
        """收集指令中的常量值，检测 TEA delta 和大表访问"""
        try:
            stack = [instr]
            seen = set()
            while stack and len(seen) < 20:
                node = stack.pop()
                if node is None:
                    continue
                nid = id(node)
                if nid in seen:
                    continue
                seen.add(nid)
                if hasattr(node, "constant"):
                    c = int(node.constant)
                    # TEA delta: 0x9E3779B9
                    if c in (0x9E3779B9, 0x61C88647, 0xC6EF3720):
                        hist["delta_constant"] = True
                    # 大表索引: 常量地址 + LOAD 组合
                    if c > 0x1000 and c not in (0xFFFF, 0xFFFFFFFF, 0xFF):
                        large_consts.add(c)
                for attr in ("src", "dest", "left", "right", "operands"):
                    val = getattr(node, attr, None)
                    if val is not None:
                        if isinstance(val, (list, tuple)):
                            stack.extend(val)
                        elif hasattr(val, "operation"):
                            stack.append(val)
        except Exception:
            pass

    @staticmethod
    def match_crypto_fingerprint(hist):
        """[需求1-增强] 将 opcode histogram 与已知加密指纹模板匹配"""
        if hist is None or hist["total_ops"] < 5:
            return []

        total = max(1, hist["total_ops"])
        xor_r = hist["xor"] / total
        shift_r = hist["shift"] / total
        add_r = hist["add"] / total

        matches = []
        for algo_name, fp in CRYPTO_OPCODE_FINGERPRINTS.items():
            if total < fp["min_total_ops"] or total > fp["max_total_ops"]:
                continue
            if xor_r < fp["min_xor_ratio"]:
                continue
            if shift_r < fp["min_shift_ratio"]:
                continue
            if add_r < fp["min_add_ratio"]:
                continue
            if fp["require_rotate"] and hist["rotate"] == 0:
                continue
            if fp["require_loop"] and not hist["has_loop"]:
                continue

            # 基础得分
            score = 50
            # XOR 越多加分越多
            score += min(20, int(xor_r * 100))
            # 循环复杂度加分
            score += min(10, hist["back_edge_count"] * 3)
            # bonus conditions
            for cond in fp.get("bonus_conditions", []):
                if hist.get(cond, False):
                    score += 15

            matches.append({
                "algo_pattern": algo_name,
                "score": min(95, score),
                "evidence": {
                    "xor_ratio": round(xor_r, 3),
                    "shift_ratio": round(shift_r, 3),
                    "add_ratio": round(add_r, 3),
                    "rotate_count": hist["rotate"],
                    "has_loop": hist["has_loop"],
                    "back_edges": hist["back_edge_count"],
                    "total_ops": total,
                },
            })

        # 按得分排序
        matches.sort(key=lambda x: x["score"], reverse=True)
        return matches[:3]

    # ---- [需求2-增强] 全局内存/堆内存启发式追踪 ----

    def _build_memory_index(self, ssa):
        """构建函数内 STORE/LOAD 内存访问索引，用于启发式跨内存污点传播"""
        mem_index = {
            "stores": defaultdict(list),   # addr_key -> [(instr, src_vars)]
            "loads": defaultdict(list),    # addr_key -> [(instr, output_vars)]
        }
        if ssa is None:
            return mem_index

        for instr in self._iter_ssa_instructions(ssa):
            op = getattr(instr, "operation", None)

            if op in MLIL_STORE_OPS:
                addr_key = self._normalize_mem_addr_key(instr, "dest")
                if addr_key:
                    src_vars = self._extract_ssa_vars(getattr(instr, "src", None))
                    mem_index["stores"][addr_key].append((instr, src_vars))

            elif op in MLIL_LOAD_OPS:
                addr_key = self._normalize_mem_addr_key(instr, "src")
                if addr_key:
                    # LOAD 的结果是包含它的 SET_VAR 的 dest
                    out_vars = self._extract_ssa_vars(getattr(instr, "dest", None))
                    if not out_vars:
                        # 如果 LOAD 本身没有 dest，尝试从父指令获取
                        out_vars = self._extract_ssa_vars(instr)
                    mem_index["loads"][addr_key].append((instr, out_vars))

        return mem_index

    @staticmethod
    def _normalize_mem_addr_key(instr, addr_attr):
        """规范化内存访问地址为可比较的 key

        策略: 提取地址表达式的文本表示并简化
        - 常量地址: 直接用 hex 值
        - 变量 + 偏移: 用 "var_name+offset" 形式
        - 复杂表达式: 用截断的文本表示
        """
        try:
            addr_expr = getattr(instr, addr_attr, None)
            if addr_expr is None:
                return None

            # 如果是 STORE，地址在 dest 属性; 如果是 LOAD，地址在 src 属性
            # 但 BinaryNinja MLIL 中 STORE 的第一个操作数是地址
            # STORE [addr], value → addr = instr.dest, value = instr.src
            # LOAD [addr] → addr = instr.src

            # 常量地址
            if hasattr(addr_expr, "constant"):
                return f"const_{hex(int(addr_expr.constant))}"

            # 变量 + 偏移 (如 [rbp + 0x10])
            text = str(addr_expr)
            if len(text) > 120:
                text = text[:120]

            # 简化: 移除 SSA 版本号使得 var#1 和 var#2 能匹配同一内存位置
            simplified = re.sub(r"#\d+", "", text).strip()
            if simplified:
                return f"expr_{simplified}"

            return None
        except Exception:
            return None

    def _propagate_through_memory(self, ssa, tainted_keys, mem_index, visited, stack, traces, func, label_prefix):
        """当污点值被 STORE 写入内存时，找到匹配的 LOAD 并传播污点"""
        propagated = 0
        for addr_key, store_list in mem_index["stores"].items():
            # 检查是否有污点值被存储到这个地址
            has_tainted_store = False
            for store_instr, src_vars in store_list:
                for sv in src_vars:
                    if self._ssa_var_key(sv) in tainted_keys:
                        has_tainted_store = True
                        self._append_trace(traces, func, store_instr,
                                         f"[{label_prefix}-mem-store]")
                        break
                if has_tainted_store:
                    break

            if not has_tainted_store:
                continue

            # 将对应地址的 LOAD 输出变量加入污点工作列表
            load_list = mem_index["loads"].get(addr_key, [])
            for load_instr, out_vars in load_list:
                for ov in out_vars:
                    ok = self._ssa_var_key(ov)
                    if ok not in visited:
                        stack.append(ov)
                        tainted_keys.add(ok)
                        propagated += 1
                        self._append_trace(traces, func, load_instr,
                                         f"[{label_prefix}-mem-load]")
        return propagated

    def _propagate_memory_backward(self, ssa, query_keys, mem_index, visited, stack, traces, func):
        """当后向追踪遇到 LOAD 时，找到匹配的 STORE 并继续追踪其来源"""
        propagated = 0
        for addr_key, load_list in mem_index["loads"].items():
            has_queried_load = False
            for load_instr, out_vars in load_list:
                for ov in out_vars:
                    if self._ssa_var_key(ov) in query_keys:
                        has_queried_load = True
                        break
                if has_queried_load:
                    break

            if not has_queried_load:
                continue

            store_list = mem_index["stores"].get(addr_key, [])
            for store_instr, src_vars in store_list:
                for sv in src_vars:
                    sk = self._ssa_var_key(sv)
                    if sk not in visited:
                        stack.append(sv)
                        propagated += 1
                        self._append_trace(traces, func, store_instr,
                                         "[ssa-backward-mem-store]")
        return propagated

    def _get_param_seed_ssa_vars(self, func, ssa):
        param_ids = set()
        try:
            for p in list(getattr(func, "parameter_vars", []) or []):
                if isinstance(p, Variable):
                    param_ids.add(int(p.identifier))
        except Exception:
            pass
        if not param_ids:
            return []
        seeds = {}
        for instr in self._iter_ssa_instructions(ssa):
            for sv in self._extract_ssa_vars(instr):
                try:
                    if int(sv.var.identifier) not in param_ids:
                        continue
                except Exception:
                    continue
                try:
                    def_ref = ssa.get_ssa_var_definition(sv)
                except Exception:
                    def_ref = None
                def_instr = self._coerce_ssa_instruction(ssa, def_ref)
                if def_instr is None:
                    seeds[self._ssa_var_key(sv)] = sv
        return list(seeds.values())

    def _trace_backward_sources_ssa(self, caller, call_instr):
        """[Bug-Fix + 需求2-增强] SSA def-use 链后向追踪 + 内存 LOAD→STORE 传播"""
        ssa = self._get_mlil_ssa(caller)
        if ssa is None:
            return set(), [], False

        seed = {}
        for p in self._get_call_params(call_instr):
            for sv in self._extract_ssa_vars(p):
                seed[self._ssa_var_key(sv)] = sv
        if not seed:
            return set(), [], False

        # [需求2-增强] 构建内存访问索引
        mem_index = self._build_memory_index(ssa)

        hits = set()
        traces = []
        reached_func_args = False
        stack = list(seed.values())
        visited = set()

        while stack and len(visited) < 8000:
            sv = stack.pop()
            k = self._ssa_var_key(sv)
            if k in visited:
                continue
            visited.add(k)

            try:
                def_ref = ssa.get_ssa_var_definition(sv)
            except Exception:
                def_ref = None
            def_instr = self._coerce_ssa_instruction(ssa, def_ref)
            if def_instr is None:
                reached_func_args = True
                continue

            callee = normalize_api_name(self._get_callee_name(def_instr))
            if callee in API_SOURCES:
                hits.add(callee)
                self._append_trace(traces, caller, def_instr, "[ssa-backward-source]")

            # [需求2-增强] 如果定义是 LOAD，尝试通过内存索引追踪到 STORE 来源
            def_op = getattr(def_instr, "operation", None)
            if def_op in MLIL_SET_VAR_OPS:
                src_expr = getattr(def_instr, "src", None)
                if src_expr is not None and getattr(src_expr, "operation", None) in MLIL_LOAD_OPS:
                    self._propagate_memory_backward(
                        ssa, {k}, mem_index, visited, stack, traces, caller
                    )

            # 继续追踪 RHS 变量
            rhs = {}
            for rhs_var in self._extract_ssa_vars(getattr(def_instr, "src", None)):
                rhs[self._ssa_var_key(rhs_var)] = rhs_var
            for p in self._get_call_params(def_instr):
                for rhs_var in self._extract_ssa_vars(p):
                    rhs[self._ssa_var_key(rhs_var)] = rhs_var
            for r in rhs.values():
                rk = self._ssa_var_key(r)
                if rk not in visited:
                    stack.append(r)

        return hits, traces, reached_func_args

    def _trace_forward_sinks_ssa(self, func, seed_vars, label_prefix):
        """[Bug-Fix + 需求2-增强] SSA use-chain 前向追踪 + 内存 STORE→LOAD 传播"""
        ssa = self._get_mlil_ssa(func)
        if ssa is None or not seed_vars:
            return set(), [], False

        # [需求2-增强] 构建内存访问索引
        mem_index = self._build_memory_index(ssa)

        hits = set()
        traces = []
        return_tainted = False
        stack = list(seed_vars)
        visited = set()
        tainted_keys = set()  # 追踪所有被污染的变量 key

        # 初始化 tainted_keys
        for sv in seed_vars:
            tainted_keys.add(self._ssa_var_key(sv))

        mem_propagation_done = False  # 避免重复传播

        while stack and len(visited) < 8000:
            sv = stack.pop()
            sk = self._ssa_var_key(sv)
            if sk in visited:
                continue
            visited.add(sk)
            tainted_keys.add(sk)

            try:
                use_refs = list(ssa.get_ssa_var_uses(sv) or [])
            except Exception:
                use_refs = []

            for use_ref in use_refs:
                use_instr = self._coerce_ssa_instruction(ssa, use_ref)
                if use_instr is None:
                    continue

                # 检查是否调用了 sink API
                if self._extract_call_node(use_instr) is not None:
                    uses_this_arg = False
                    for p in self._get_call_params(use_instr):
                        p_vars = self._extract_ssa_vars(p)
                        if any(self._ssa_var_key(x) == sk for x in p_vars):
                            uses_this_arg = True
                            break
                    if uses_this_arg:
                        callee = normalize_api_name(self._get_callee_name(use_instr))
                        if callee in API_SINKS:
                            hits.add(callee)
                            self._append_trace(traces, func, use_instr, f"[{label_prefix}-sink]")
                        # 追踪 call 的输出
                        for ov in self._get_call_output_ssa_vars(use_instr):
                            ok = self._ssa_var_key(ov)
                            if ok not in visited:
                                stack.append(ov)

                # 赋值传播
                if self._is_set_var_op(getattr(use_instr, "operation", None)):
                    src_vars = self._extract_ssa_vars(getattr(use_instr, "src", None))
                    if any(self._ssa_var_key(x) == sk for x in src_vars):
                        for dv in self._extract_ssa_vars(getattr(use_instr, "dest", None)):
                            dk = self._ssa_var_key(dv)
                            if dk not in visited:
                                stack.append(dv)

                # 返回值污点检查
                if self._is_ret_op(getattr(use_instr, "operation", None)):
                    ret_vars = self._extract_ssa_vars(getattr(use_instr, "src", None))
                    if any(self._ssa_var_key(x) == sk for x in ret_vars):
                        return_tainted = True
                        self._append_trace(traces, func, use_instr, f"[{label_prefix}-ret]")

                # [需求2-增强] 检查 memory store + 传播到对应 LOAD
                if getattr(use_instr, "operation", None) in MLIL_STORE_OPS:
                    src_vars = self._extract_ssa_vars(getattr(use_instr, "src", None))
                    if any(self._ssa_var_key(x) == sk for x in src_vars):
                        self._append_trace(traces, func, use_instr, f"[{label_prefix}-store]")
                        # 触发内存传播 (仅执行一次以避免过度传播)
                        if not mem_propagation_done:
                            self._propagate_through_memory(
                                ssa, tainted_keys, mem_index, visited, stack,
                                traces, func, label_prefix
                            )
                            mem_propagation_done = True

        return hits, traces, return_tainted

    def _intra_function_taint_ssa(self, func, evidence):
        ssa = self._get_mlil_ssa(func)
        if ssa is None:
            return [], False

        param_seed = {}
        taint_seed = {}
        for sv in self._get_param_seed_ssa_vars(func, ssa):
            k = self._ssa_var_key(sv)
            param_seed[k] = sv
            taint_seed[k] = sv

        # 从 source API 调用收集额外 seed
        for instr in self._iter_ssa_instructions(ssa):
            if self._extract_call_node(instr) is None:
                continue
            callee = normalize_api_name(self._get_callee_name(instr))
            if callee in API_SOURCES:
                evidence["sources"].add(callee)
                self._append_trace(evidence["backward_trace"], func, instr, "[ssa-source]")
                for ov in self._get_call_output_ssa_vars(instr):
                    taint_seed[self._ssa_var_key(ov)] = ov

        sink_hits, sink_trace, ret_tainted = self._trace_forward_sinks_ssa(
            func, list(taint_seed.values()), "ssa-intra"
        )
        evidence["sinks"].update(sink_hits)
        for t in sink_trace:
            if len(evidence["forward_trace"]) < MAX_TRACE_LINES:
                evidence["forward_trace"].append(t)

        param_labels = sorted({str(x.var) for x in param_seed.values() if hasattr(x, "var")})
        return param_labels, ret_tainted

    # ---- [需求2-增强] Caller 优先级排序 ----
    def _prioritize_callers(self, caller_refs):
        """按 caller 函数的交叉引用数排序: xref 越少的 caller 越可能是具体业务逻辑,
        优先分析; 像 main/entry 这种通用入口 xref 多，放到最后。"""
        if len(caller_refs) <= 1:
            return caller_refs

        scored = []
        for ref in caller_refs:
            caller = getattr(ref, "function", None)
            if caller is None:
                scored.append((9999, ref))
                continue

            name = (caller.name or "").lower()
            # 惩罚通用入口函数
            penalty = 0
            if any(skip in name for skip in ("main", "entry", "start", "winmain", "dllmain")):
                penalty = 5000

            # 统计 caller 函数本身被引用的次数 (越少越具体)
            try:
                caller_xrefs = len(list(self.bv.get_code_refs(caller.start)))
            except Exception:
                caller_xrefs = 100

            scored.append((caller_xrefs + penalty, ref))

        scored.sort(key=lambda x: x[0])
        return [ref for _, ref in scored[:MAX_CALLER_REFS]]

    def analyze_dependency(self, target_func):
        """主入口: 分析目标函数的完整数据流依赖"""
        evidence = {
            "sources": set(),
            "sinks": set(),
            "internal_calls": set(),
            "key_material": [],
            "backward_trace": [],
            "forward_trace": [],
        }

        self._scan_internal_calls(target_func, evidence)
        self._scan_key_material(target_func, evidence)
        tainted_params, intra_ret_tainted = self._intra_function_taint_ssa(target_func, evidence)

        # [需求1-增强] 计算 opcode histogram 和加密指纹匹配
        opcode_hist = self._compute_opcode_histogram(target_func)
        opcode_fingerprint_matches = self.match_crypto_fingerprint(opcode_hist)

        # 跨函数分析: caller
        caller_refs = list(self.bv.get_code_refs(target_func.start))

        # [需求2-增强] 按交叉引用数排序: 优先分析 xref 少的 caller (更具体的业务逻辑)
        caller_refs = self._prioritize_callers(caller_refs)

        caller_scanned = 0
        caller_ret_tainted = False
        caller_args_reached = False

        for ref in caller_refs[:MAX_CALLER_REFS]:
            caller = getattr(ref, "function", None)
            if caller is None:
                continue
            if self._get_mlil_ssa(caller) is None:
                continue
            call_instr = self._find_call_instruction(caller, ref.address, target_func.start)
            if call_instr is None:
                continue
            caller_scanned += 1

            # 后向: 追踪参数来源
            b_hits, b_trace, reached_args = self._trace_backward_sources_ssa(caller, call_instr)
            caller_args_reached = caller_args_reached or reached_args
            evidence["sources"].update(b_hits)
            for t in b_trace:
                if len(evidence["backward_trace"]) < MAX_TRACE_LINES:
                    evidence["backward_trace"].append(t)

            # 前向: 追踪返回值去向
            out_vars = self._get_call_output_ssa_vars(call_instr)
            f_hits, f_trace, f_ret = self._trace_forward_sinks_ssa(caller, out_vars, "ssa-caller")
            caller_ret_tainted = caller_ret_tainted or f_ret
            evidence["sinks"].update(f_hits)
            for t in f_trace:
                if len(evidence["forward_trace"]) < MAX_TRACE_LINES:
                    evidence["forward_trace"].append(t)

            # caller 中也扫描密钥 API
            self._scan_key_material(caller, evidence)

        return {
            "input_from_source": sorted(evidence["sources"]),
            "output_to_sink": sorted(evidence["sinks"]),
            "internal_apis": sorted(evidence["internal_calls"]),
            "key_material": evidence["key_material"],
            "taint_summary": {
                "mode": "MLIL_SSA_DefUse_MemTaint",
                "tainted_params": tainted_params[:12],
                "return_tainted": bool(intra_ret_tainted or caller_ret_tainted),
                "caller_refs_total": len(caller_refs),
                "caller_refs_scanned": caller_scanned,
                "caller_args_reached": bool(caller_args_reached),
            },
            "backward_trace": evidence["backward_trace"],
            "forward_trace": evidence["forward_trace"],
            # [需求1-增强] Opcode 指纹
            "opcode_histogram": {
                "total_ops": opcode_hist["total_ops"] if opcode_hist else 0,
                "xor": opcode_hist["xor"] if opcode_hist else 0,
                "shift": opcode_hist["shift"] if opcode_hist else 0,
                "rotate": opcode_hist["rotate"] if opcode_hist else 0,
                "add": opcode_hist["add"] if opcode_hist else 0,
                "has_loop": opcode_hist["has_loop"] if opcode_hist else False,
                "back_edges": opcode_hist["back_edge_count"] if opcode_hist else 0,
                "mod_256_pattern": opcode_hist["mod_256_pattern"] if opcode_hist else False,
                "delta_constant": opcode_hist["delta_constant"] if opcode_hist else False,
            } if opcode_hist else None,
            "opcode_fingerprint_matches": opcode_fingerprint_matches,
        }


# ==============================================================================
# 6. BinaryNinja 加载器
# ==============================================================================

class BNCoreAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.bv = None
        self.taint_engine = None

    def load(self):
        if not os.path.exists(self.binary_path):
            return False
        saved_fds = suppress_stdout_stderr()
        try:
            self.bv = binaryninja.load(self.binary_path)
            if self.bv is None:
                return False
            self.bv.update_analysis_and_wait()
            self.taint_engine = StaticTaintEngine(self.bv)
            return True
        except Exception as e:
            logging.error("BN Load Error (%s): %s", self.binary_path, e)
            return False
        finally:
            restore_stdout_stderr(saved_fds)

    def close(self):
        if self.bv:
            try:
                self.bv.file.close()
            except Exception:
                pass
            self.bv = None
            self.taint_engine = None
            gc.collect()

    def _normalize_address(self, addr):
        if self.bv.start <= addr < self.bv.end:
            return addr
        for base in (0x400000, 0x10000000):
            rva = addr - base
            if rva <= 0:
                continue
            remapped = self.bv.start + rva
            if self.bv.start <= remapped < self.bv.end:
                return remapped
        return addr

    def get_func(self, addr_text):
        saved_fds = suppress_stdout_stderr()
        try:
            raw = addr_text if isinstance(addr_text, int) else int(str(addr_text), 16)
            addr = self._normalize_address(raw)
        except Exception:
            restore_stdout_stderr(saved_fds)
            return None
        try:
            func = self.bv.get_function_at(addr)
            if not func:
                self.bv.create_user_function(addr)
                self.bv.update_analysis_and_wait()
                func = self.bv.get_function_at(addr)
            if not func:
                return None
            name = (func.name or "").lower()
            if any(skip in name for skip in SKIP_FUNC_NAMES):
                return None
            if func.mlil is None:
                func.analysis_skipped = False
                self.bv.update_analysis_and_wait()
                if func.mlil is None:
                    return None
            return func
        except Exception:
            return None
        finally:
            restore_stdout_stderr(saved_fds)

    @staticmethod
    def get_code(func, max_lines=80):
        try:
            return "\n".join(str(x) for x in list(func.mlil.instructions)[:max_lines])
        except Exception:
            return ""

    @staticmethod
    def make_path_id(sample, path_addrs, target_addr, reason):
        raw = f"{sample}|{target_addr}|{'->'.join(path_addrs or [])}|{reason}"
        return f"{sample}_{hashlib.md5(raw.encode()).hexdigest()[:12]}"


# ==============================================================================
# 7. 语义分析器 (规则推断 + LLM 增强)
# ==============================================================================

class HybridSemanticAnalyzer:
    def __init__(self, key_path):
        self.client = None
        if os.path.exists(key_path):
            try:
                with open(key_path, "r", encoding="utf-8") as f:
                    key = f.read().strip()
                if key:
                    self.client = OpenAI(api_key=key, base_url="https://api.deepseek.com")
            except Exception:
                self.client = None

    @staticmethod
    def _normalize_scenario_label(raw, fallback):
        txt = str(raw or "").strip()
        if txt in SCENARIO_CLASSES:
            return txt
        s = txt.lower()
        if any(x in s for x in ("payload", "loader", "decrypt", "loading", "inject", "shellcode")):
            return "Payload_Decryption_Loading"
        if any(x in s for x in ("c2", "command", "exec", "remote thread")):
            return "C2_Command_Execution"
        if any(x in s for x in ("exfil", "steal", "transmit", "sensitive", "send")):
            return "Data_Exfiltration"
        if any(x in s for x in ("ransom", "encrypt", "locker")):
            return "Ransomware_Encryption"
        return fallback

    @staticmethod
    def _extract_trace_connected_apis(evidence):
        """[需求3-增强] 从 trace 信息中提取实际通过数据流连接的 API

        只有在 backward_trace / forward_trace 中出现的 API 才被视为
        "数据流验证过的" (dataflow-verified)，其余仅是函数内存在的 API 调用。
        """
        verified_sources = set()
        verified_sinks = set()

        # 从 backward trace 中提取验证过的 source API
        for line in (evidence.get("backward_trace") or []):
            line_lower = str(line).lower()
            if "[ssa-backward-source]" in line_lower or "[ssa-source]" in line_lower:
                for api in API_SOURCES:
                    if api in line_lower:
                        verified_sources.add(api)
            # 内存传播也算验证
            if "[ssa-backward-mem-store]" in line_lower:
                for api in API_SOURCES:
                    if api in line_lower:
                        verified_sources.add(api)

        # 从 forward trace 中提取验证过的 sink API
        for line in (evidence.get("forward_trace") or []):
            line_lower = str(line).lower()
            if "-sink]" in line_lower:
                for api in API_SINKS:
                    if api in line_lower:
                        verified_sinks.add(api)
            # 内存传播 sink 也算
            if "-mem-load]" in line_lower:
                for api in API_SINKS:
                    if api in line_lower:
                        verified_sinks.add(api)

        return verified_sources, verified_sinks

    @staticmethod
    def _infer_scenario_from_evidence(src, sink, internal, chain_scenario, evidence=None):
        """[需求3-增强] 基于数据流验证的攻击链判定

        改进: 区分 "数据流验证过的 API" 和 "仅存在于函数中的 API"。
        当 Source→Sink 存在实际数据流路径时，confidence 更高 (chain_verified=True)；
        仅靠关键词匹配时 confidence 降低。
        """
        chain_label = HybridSemanticAnalyzer._normalize_scenario_label(chain_scenario, "")
        if chain_label:
            return chain_label, 80, True  # Step1 chain → 直接信任

        all_tokens = src + sink + internal
        joined = " ".join(all_tokens)

        # [需求3-增强] 提取数据流验证过的 API
        verified_sources, verified_sinks = set(), set()
        if evidence:
            verified_sources, verified_sinks = (
                HybridSemanticAnalyzer._extract_trace_connected_apis(evidence)
            )

        # 分类检测
        # [V4-对齐] 包含所有 36 个 API 的检测模式 (子串匹配覆盖 A/W 后缀变体)
        has_network_src = any(x in joined for x in ("recv", "internetreadfile", "winhttpreaddata", "urldownloadtofile"))
        has_exec_sink = any(x in joined for x in ("createprocess", "winexec", "shellexecute", "system"))
        has_payload_sink = any(x in joined for x in ("virtualalloc", "writeprocessmemory", "createremotethread", "ntmapviewofsection"))
        has_exfil_sink = any(x in joined for x in ("send", "wsasend", "httpsendrequest", "internetwritefile"))
        has_writefile = "writefile" in joined or "fwrite" in joined
        has_readfile = "readfile" in joined or "fread" in joined
        has_crypto_enc = any(x in joined for x in ("cryptencrypt", "bcryptencrypt"))
        has_crypto_dec = any(x in joined for x in ("cryptdecrypt", "bcryptdecrypt"))
        has_credential = "cryptunprotectdata" in joined

        # [需求3-增强] 验证 Source→Sink 的数据流连通性
        def is_verified(src_apis, sink_apis):
            """检查是否 source 和 sink 都通过 trace 被验证"""
            src_ok = any(a in verified_sources for a in src_apis) if src_apis else False
            sink_ok = any(a in verified_sinks for a in sink_apis) if sink_apis else False
            # 如果有 trace 信息但两端都验证了 → 强连通
            if src_ok and sink_ok:
                return True
            # 如果 trace 里至少有一端验证了 → 弱连通
            if src_ok or sink_ok:
                return None  # 半验证
            return False

        # 场景判定 + 数据流验证
        scenario = None
        base_conf = 0
        chain_verified = False

        if has_payload_sink and (has_network_src or has_crypto_dec):
            scenario = "Payload_Decryption_Loading"
            base_conf = 78
            v = is_verified(
                {"recv", "internetreadfile", "winhttpreaddata", "urldownloadtofile", "urldownloadtofilea"},
                {"virtualalloc", "writeprocessmemory", "createremotethread", "ntmapviewofsection"}
            )
            chain_verified = (v is True)
        elif has_exec_sink and has_network_src:
            scenario = "C2_Command_Execution"
            base_conf = 75
            v = is_verified(
                {"recv", "internetreadfile", "winhttpreaddata"},
                {"createprocess", "createprocessa", "createprocessw",
                 "winexec", "shellexecute", "shellexecutea", "shellexecutew", "system"}
            )
            chain_verified = (v is True)
        elif has_exfil_sink and (has_readfile or has_crypto_enc or has_network_src or has_credential):
            scenario = "Data_Exfiltration"
            base_conf = 72
            v = is_verified(
                {"readfile", "fread", "recv", "internetreadfile", "cryptunprotectdata"},
                {"send", "wsasend", "httpsendrequesta", "httpsendrequestw", "internetwritefile"}
            )
            chain_verified = (v is True)
        elif has_crypto_enc and has_writefile:
            scenario = "Ransomware_Encryption"
            base_conf = 70
            v = is_verified(
                {"readfile", "fread"},
                {"writefile", "fwrite", "cryptencrypt", "bcryptencrypt"}
            )
            chain_verified = (v is True)
        elif has_credential:
            scenario = "Data_Exfiltration"
            base_conf = 68
        elif has_crypto_enc or (has_writefile and has_readfile):
            scenario = "Ransomware_Encryption"
            base_conf = 65
        elif has_exec_sink:
            scenario = "C2_Command_Execution"
            base_conf = 60
        elif has_payload_sink:
            scenario = "Payload_Decryption_Loading"
            base_conf = 60
        elif has_exfil_sink:
            scenario = "Data_Exfiltration"
            base_conf = 60
        else:
            scenario = "Data_Exfiltration"
            base_conf = 45

        # [需求3-增强] 调整置信度
        if chain_verified:
            # 数据流验证通过: 加分
            base_conf = min(95, base_conf + 10)
        elif evidence and (evidence.get("backward_trace") or evidence.get("forward_trace")):
            # 有 trace 但未形成完整链: 轻微降分
            if not verified_sources and not verified_sinks:
                base_conf = max(40, base_conf - 10)

        return scenario, base_conf, chain_verified

    @staticmethod
    def _infer_algo_from_step1(algo_context):
        """[需求1] 利用 Step1 的算法识别结果推断算法名"""
        yara_tags = algo_context.get("step1_yara_tags", [])
        if yara_tags:
            return yara_tags[0]  # 优先使用 YARA 标签
        algo_hints = algo_context.get("step1_algo_hints", [])
        if algo_hints:
            best = max(algo_hints, key=lambda x: x.get("score", 0))
            return best.get("algo", "Unknown")
        if algo_context.get("step1_sbox_confirmed"):
            return "SBox_Crypto"
        return None

    @staticmethod
    def _heuristic_semantic(evidence, chain_scenario, algo_context=None):
        src = [str(x).lower() for x in (evidence.get("input_from_source") or [])]
        sink = [str(x).lower() for x in (evidence.get("output_to_sink") or [])]
        internal = [str(x).lower() for x in (evidence.get("internal_apis") or [])]
        union = src + sink + internal

        # [需求1] 从 Step1 继承算法识别
        algo = "Unknown"
        if algo_context:
            step1_algo = HybridSemanticAnalyzer._infer_algo_from_step1(algo_context)
            if step1_algo:
                algo = step1_algo

        # [需求1-增强] 从 opcode fingerprint 补充算法识别
        opcode_matches = evidence.get("opcode_fingerprint_matches", [])
        if algo == "Unknown" and opcode_matches:
            best_match = opcode_matches[0]
            if best_match["score"] >= 60:
                algo = best_match["algo_pattern"]

        # [需求3-增强] 使用数据流验证的场景判定
        scenario, scenario_conf, chain_verified = (
            HybridSemanticAnalyzer._infer_scenario_from_evidence(
                src, sink, internal, chain_scenario, evidence
            )
        )
        confidence = scenario_conf

        if any(any(h in item for h in CRYPTO_HINT_APIS) for item in union):
            if algo == "Unknown":
                algo = "API_Crypto"
            confidence = max(confidence, 70)
        elif any("xor" in item for item in internal):
            if algo == "Unknown":
                algo = "Custom_XOR"
            confidence = max(confidence, 60)

        # Step1 confidence 加成
        if algo_context and algo_context.get("step1_crypto_confidence", 0) >= 70:
            confidence = max(confidence, 75)

        # [需求1-增强] opcode fingerprint 加成
        if opcode_matches and opcode_matches[0]["score"] >= 70:
            confidence = max(confidence, 68)

        return {
            "algo": algo,
            "scenario": scenario,
            "confidence": int(confidence),
            "chain_verified": chain_verified,
            "opcode_algo_match": opcode_matches[0]["algo_pattern"] if opcode_matches else None,
        }

    def analyze(self, path_addrs, chain_scenario, evidence, code, algo_context=None):
        heuristic = self._heuristic_semantic(evidence, chain_scenario, algo_context)
        if not self.client:
            return heuristic
        if heuristic["confidence"] >= 85 and heuristic["algo"] != "Unknown":
            return heuristic

        # 构造 LLM 提示 (含 Step1 上下文)
        step1_info = ""
        if algo_context:
            tags = algo_context.get("step1_yara_tags", [])
            hints = algo_context.get("step1_algo_hints", [])
            rules = algo_context.get("step1_trigger_rules", [])
            if tags or hints or rules:
                step1_info = f"""
        [Step1 Crypto Identification]
        YARA Algorithm Tags: {tags}
        Static Algo Hints: {hints}
        YARA Rules Triggered: {rules}
        SBox Confirmed: {algo_context.get('step1_sbox_confirmed', False)}
        Static Confidence: {algo_context.get('step1_crypto_confidence', 0)}
        """

        key_info = ""
        km = evidence.get("key_material", [])
        if km:
            key_info = f"\n        [Key Material Flow]\n        {json.dumps(km[:5], indent=2)}\n        "

        opcode_info = ""
        opcode_matches = evidence.get("opcode_fingerprint_matches", [])
        if opcode_matches:
            opcode_info = f"""
        [Opcode Fingerprint Analysis]
        Top matches: {json.dumps(opcode_matches[:2], indent=2)}
        Histogram summary: xor={evidence.get('opcode_histogram', {}).get('xor', 0)}, \
shift={evidence.get('opcode_histogram', {}).get('shift', 0)}, \
rotate={evidence.get('opcode_histogram', {}).get('rotate', 0)}, \
has_loop={evidence.get('opcode_histogram', {}).get('has_loop', False)}
        """

        chain_verified = heuristic.get("chain_verified", False)
        chain_info = f"\n        [Chain Verification] Dataflow verified: {chain_verified}\n" if evidence else ""

        prompt = f"""
        Analyze malware function evidence and return strict JSON.

        {step1_info}
        {key_info}
        {opcode_info}
        {chain_info}

        [Dataflow Evidence]
        Input Sources: {evidence.get('input_from_source', [])}
        Output Sinks: {evidence.get('output_to_sink', [])}
        Internal APIs: {evidence.get('internal_apis', [])}
        Return Tainted: {evidence.get('taint_summary', {}).get('return_tainted')}
        Chain Scenario Hint: {chain_scenario}
        Path: {path_addrs}

        [MLIL Code]
        ```
        {code[:1200]}
        ```

        Task:
        1) Identify crypto algorithm (AES/DES/RC4/ChaCha20/TEA/Blowfish/SM4/XOR/Custom/API_Crypto/Unknown).
           Use the Step1 identification results as strong evidence.
        2) Scenario MUST be exactly one of:
           Payload_Decryption_Loading, C2_Command_Execution,
           Data_Exfiltration, Ransomware_Encryption.
        3) Confidence 0..100.
        Return JSON: {{"algo":"...","scenario":"<one_of_4>","confidence":int}}
        """

        for _ in range(LLM_MAX_RETRIES):
            try:
                resp = self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": LLM_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                    timeout=LLM_TIMEOUT,
                )
                parsed = json.loads(resp.choices[0].message.content)
                llm_conf = max(0, min(100, int(parsed.get("confidence", 0) or 0)))
                normalized_scenario = self._normalize_scenario_label(
                    parsed.get("scenario"), heuristic["scenario"],
                )
                llm_res = {
                    "algo": parsed.get("algo", "Unknown"),
                    "scenario": normalized_scenario,
                    "confidence": llm_conf,
                    "chain_verified": heuristic.get("chain_verified", False),
                    "opcode_algo_match": heuristic.get("opcode_algo_match"),
                }
                return llm_res if llm_res["confidence"] >= heuristic["confidence"] else heuristic
            except Exception:
                time.sleep(1)
        return heuristic


# ==============================================================================
# 8. Evidence 合并与安全化
# ==============================================================================

def merge_seed_into_evidence(evidence, seed_sources, seed_sinks):
    evidence["input_from_source"] = sorted(
        set(evidence.get("input_from_source", [])) | set(seed_sources)
    )
    evidence["output_to_sink"] = sorted(
        set(evidence.get("output_to_sink", [])) | set(seed_sinks)
    )
    # [Bug-Fix] Step3 expects input_from_source[0]; never leave it empty
    if not evidence["input_from_source"]:
        evidence["input_from_source"] = ["FuncArgs"]
    evidence["step1_seed"] = {
        "sources": list(seed_sources),
        "sinks": list(seed_sinks),
    }
    return evidence


def resolve_binary_path(sample_name, sample_hash):
    path = os.path.join(TARGET_DIRECTORY, sample_name)
    if os.path.exists(path):
        return path
    if sample_hash:
        fallback = os.path.join(TARGET_DIRECTORY, sample_hash)
        if os.path.exists(fallback):
            return fallback
    return None


# ==============================================================================
# 9. 主样本处理逻辑
# ==============================================================================

def process_sample(sample_name, sample_ctx, semantic_analyzer):
    bin_path = resolve_binary_path(sample_name, sample_ctx.get("sample_hash"))
    if not bin_path:
        logging.warning("Sample binary not found: %s", sample_name)
        return [], []

    targets = build_target_plan(sample_ctx)
    if not targets:
        return [], []

    bn = BNCoreAnalyzer(bin_path)
    if not bn.load():
        return [], []

    blueprints = []
    reports = []
    scored = []

    try:
        for target in targets:
            func = bn.get_func(target["target_addr"])
            if not func:
                continue

            saved_fds = suppress_stdout_stderr()
            try:
                evidence = bn.taint_engine.analyze_dependency(func)
                code = bn.get_code(func)
            finally:
                restore_stdout_stderr(saved_fds)

            # 合并 Step1 seed anchors
            seed_sources, seed_sinks = collect_seed_anchors(
                sample_ctx, target["path_addrs"], target["target_addr"]
            )
            evidence = merge_seed_into_evidence(evidence, seed_sources, seed_sinks)

            # [需求1] 收集 Step1 算法上下文
            algo_context = collect_algo_context(
                sample_ctx, target["target_addr"], target["path_addrs"]
            )

            # 语义分析 (规则 + LLM)
            semantic = semantic_analyzer.analyze(
                target["path_addrs"], target["chain_scenario"],
                evidence, code, algo_context
            )

            has_dataflow = bool(
                evidence.get("input_from_source")
                or evidence.get("output_to_sink")
                or evidence.get("internal_apis")
            )
            keep = has_dataflow or semantic.get("confidence", 0) >= MIN_SEMANTIC_CONF
            if target["chain_scenario"] and target["chain_scenario"].lower() != "unknown":
                keep = True

            path_id = bn.make_path_id(
                sample_name, target["path_addrs"],
                target["target_addr"], target["reason"]
            )

            # [需求3] 构建完整的 blueprint
            rec_bp = {
                "path_id": path_id,
                "sample": sample_name,
                "sample_hash": sample_ctx.get("sample_hash"),
                "target_func": hex(func.start),
                "target_func_name": func.name,
                "path_addrs": target["path_addrs"],
                "chain_type": target["chain_type"],
                "chain_scenario": target["chain_scenario"],
                "target_reason": target["reason"],
                "semantic": semantic,
                "evidence": evidence,
                # [需求1] Step1 算法识别上下文传递给 Step3
                "step1_algo_context": algo_context,
            }

            rec_rep = {
                "sample": sample_name,
                "func": func.name,
                "target_func": hex(func.start),
                "chain_type": target["chain_type"],
                "chain_scenario": target["chain_scenario"],
                "algo": semantic.get("algo"),
                "scenario": semantic.get("scenario"),
                "confidence": semantic.get("confidence"),
                "chain_verified": semantic.get("chain_verified", False),
                "opcode_algo_match": semantic.get("opcode_algo_match"),
                "has_dataflow": has_dataflow,
                "key_material_found": len(evidence.get("key_material", [])),
                "sources": evidence.get("input_from_source", []),
                "sinks": evidence.get("output_to_sink", []),
                "taint_summary": evidence.get("taint_summary", {}),
                "opcode_fingerprint_matches": evidence.get("opcode_fingerprint_matches", []),
            }

            score = int(semantic.get("confidence", 0) or 0)
            if has_dataflow:
                score += 20
            if target["chain_scenario"] and target["chain_scenario"].lower() != "unknown":
                score += 10
            if evidence.get("key_material"):
                score += 15
            # [需求3-增强] 数据流验证通过: 加分
            if semantic.get("chain_verified"):
                score += 12
            # [需求1-增强] opcode 指纹匹配: 加分
            if evidence.get("opcode_fingerprint_matches"):
                score += 8
            scored.append((score, rec_bp, rec_rep))

            if keep:
                blueprints.append(rec_bp)
                reports.append(rec_rep)
                safe_tqdm_write(
                    f"   [+] {sample_name[:8]} {func.name} -> "
                    f"{semantic.get('algo')} | {semantic.get('scenario')} "
                    f"(conf={semantic.get('confidence')}"
                    f"{' ✓chain' if semantic.get('chain_verified') else ''}"
                    f"{' ◆opcode:' + semantic.get('opcode_algo_match', '') if semantic.get('opcode_algo_match') else ''})"
                )

        # 至少保留一个最高分结果
        if not blueprints and scored:
            scored.sort(key=lambda x: x[0], reverse=True)
            blueprints.append(scored[0][1])
            reports.append(scored[0][2])

    except Exception:
        logging.exception("Error while processing sample %s", sample_name)
    finally:
        bn.close()

    return blueprints, reports


# ==============================================================================
# 10. 主入口
# ==============================================================================

def main():
    print("🚀 Step 2: Hybrid Dataflow/Taint Analysis (V3 — Enhanced)")
    if not os.path.exists(INPUT_CANDIDATES):
        print("❌ Input file not found:", INPUT_CANDIDATES)
        return

    # 1. 加载 Step1 输出
    idx = Step1Index()
    idx.load(INPUT_CANDIDATES)
    contexts = idx.build_contexts()

    print(f"   - Loaded {len(contexts)} samples from Step1 index.")
    print(f"   - Graph meta records: {len(idx.graph_meta)}")
    print(f"   - Malformed lines skipped: {idx.bad_lines}")
    print(f"   - Samples with algo info: {len(idx.algo_info)}")

    # 2. 初始化语义分析器
    semantic_analyzer = HybridSemanticAnalyzer(KEY_FILE)

    # 3. 清空旧输出
    with open(OUTPUT_BLUEPRINT_L, "w", encoding="utf-8"):
        pass
    with open(OUTPUT_REPORT_L, "w", encoding="utf-8"):
        pass

    total_bp = 0
    total_rep = 0
    processed = 0

    with tqdm(total=len(contexts), desc="Processing Samples", mininterval=1.0) as pbar:
        for sample_name, sample_ctx in contexts.items():
            bps, reps = process_sample(sample_name, sample_ctx, semantic_analyzer)

            if bps:
                with open(OUTPUT_BLUEPRINT_L, "a", encoding="utf-8") as f:
                    for item in bps:
                        f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
                total_bp += len(bps)

            if reps:
                with open(OUTPUT_REPORT_L, "a", encoding="utf-8") as f:
                    for item in reps:
                        f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
                total_rep += len(reps)

            processed += 1
            pbar.update(1)
            if processed % 5 == 0:
                gc.collect()

    print(f"\n✅ Analysis complete.")
    print(f"   Samples={processed}, Blueprints={total_bp}, Reports={total_rep}")
    print(f"   Output: {OUTPUT_DIR}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.exception("Fatal error in Step2 main")
        raise