"""
Step 3: Symbolic Execution & Adversarial Behavior Analysis (V3 — Angr Enhanced)
=================================================================================
对齐需求:
  1) 加密算法识别: 三层交叉验证 —
     Layer-A: Step1 YARA + S-Box + 常量 (静态, 从 blueprint.step1_algo_context 消费)
     Layer-B: Step2 Opcode Fingerprint + SSA 数据流 (静态, 从 blueprint.evidence 消费)
     Layer-C: angr 动态常量检测 + 运行时 S-Box 访问 (动态, 本模块新增)
     三层投票 → 最终算法判定 + 综合置信度
  2) 数据流分析: 引导式符号执行 —
     使用 Step2 的 backward_trace / forward_trace / taint_summary 定位
     taint injection 点和 sink 目标函数地址;
     使用 key_material 定位密钥缓冲区, 精确提取密钥数据;
     前后向调用链重建 (_get_call_chain) 恢复完整攻击路径。
  3) 对抗行为分析: 数据流验证攻击链 —
     消费 Step2 的 chain_verified 标志区分 "已验证链" 和 "推测链";
     规则引擎基于 Source→Crypto→Sink 三段式攻击链判定;
     LLM 增强: 完整上下文 (Step1 algo + Step2 traces + Step3 dynamic);
     最终生成 step3_final_report.json 汇总所有样本分析结果。

V3 (angr 优化) 修复:
  [Bug-Fix] find_addrs 引导地址: V2 计算了但从未使用 → V3 在每步检查状态
            是否到达引导地址, 主动触发 sink 检测
  [Bug-Fix] 单状态检查: V2 只检查 active[0] 的 API 命中 → V3 遍历所有活跃
            状态, 不再遗漏其他路径上的 sink
  [优化]   状态裁剪: V2 naive 截断 active[:8] → V3 评分裁剪:
            - 即将命中 API 地址 +50
            - 在 Step2 引导集中 +40
            - 探索新路径(低访问频率) +20
            - 循环卡住(高访问频率) -30
  [优化]   循环防护: V2 纯 DFS 易陷入循环 → V3 LoopSeer(bound=8) +
            地址访问频率计数, 超过阈值移除状态
  [优化]   MAX_STATES: 8→32 (配合评分裁剪不会 OOM, 但保留更多有效路径)
  [优化]   LAZY_SOLVES: 延迟约束求解, 减少不必要的 SMT 调用
  [优化]   deadended 检查: 2→10 个, 并检查 LoopSeer 的 spinning 状态
"""

import sys
import os
import json
import logging
import time
import datetime
import math
import traceback
import gc
import re
import threading
from collections import defaultdict, deque
from tqdm import tqdm

# ==============================================================================
# 0. 平台配置
# ==============================================================================

sys.setrecursionlimit(10000)

INPUT_BLUEPRINT = r"output\step2_angr_blueprint.jsonl"
OUTPUT_FINAL_REPORT = r"output\step3_final_report.json"
OUTPUT_KEYS_L = r"output\step3_extracted_keys.jsonl"
OUTPUT_BEHAVIOR_L = r"output\step3_behavior_results.jsonl"
TEMP_DIR = r"output\temp_results"
GLOBAL_LOG_FILE = r"output\step3_debug.log"
TARGET_DIR = r"D:\Experimental data\ori100\malicious"
KEY_FILE = r"keys\deepseek_key.txt"

# angr 超时与资源限制
ANGR_TIMEOUT = 90          # 单函数符号执行最大秒数
ANGR_MAX_STEPS = 2000      # 最大步数
ANGR_MAX_STATES = 32       # 最大活跃状态数 (V3: 8→32, 配合评分裁剪)
ANGR_PRUNE_TRIGGER = 48    # 触发裁剪的状态数阈值
MAX_CALL_CHAIN_DEPTH = 10  # 调用链最大深度
MAX_KEY_CANDIDATES = 20    # 最大密钥候选数
LOOP_BOUND = 8             # LoopSeer 单循环最大展开次数
ADDR_VISIT_LIMIT = 3       # 同一基本块地址最多访问次数

for d in [os.path.dirname(OUTPUT_FINAL_REPORT), TEMP_DIR]:
    if d and not os.path.exists(d):
        os.makedirs(d)

try:
    with open(GLOBAL_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"\n{'=' * 80}\n")
        f.write(f"=== [V4] Step3 Enhanced Platform STARTED AT {datetime.datetime.now()} ===\n")
        f.write(f"{'=' * 80}\n\n")
except Exception:
    pass


# ==============================================================================
# 1. 核心引擎加载 + 全局常量
# ==============================================================================

def lazy_import():
    try:
        import binaryninja
        from binaryninja import MediumLevelILOperation, SymbolType
        import angr
        import claripy
        from openai import OpenAI
        logging.getLogger('angr').setLevel(logging.ERROR)
        logging.getLogger('claripy').setLevel(logging.CRITICAL)
        logging.getLogger('cle').setLevel(logging.CRITICAL)
        # [V4-fix] 静音 angr 内部 VEX CAS (Compare-And-Swap) 刷屏
        # 这些是 angr propagator 遇到多线程原子操作时的已知限制, 非真实错误
        logging.getLogger('angr.analyses.propagator').setLevel(logging.CRITICAL)
        logging.getLogger('angr.analyses.propagator.engine_vex').setLevel(logging.CRITICAL)
        return binaryninja, MediumLevelILOperation, SymbolType, angr, claripy, OpenAI
    except ImportError as e:
        raise ImportError(f"Critical Dependency Missing: {e}")


# ---- API 行为映射 (与 Step2 STEP3_API_BEHAVIOR_MAP 完全对齐) ----
API_BEHAVIOR_MAP = {
    # Memory allocation / Injection
    "virtualalloc":       {"tag": "Payload_Mem_Alloc",    "arg": -1, "check": "return"},
    "virtualallocex":     {"tag": "Payload_Mem_Alloc",    "arg": -1, "check": "return"},
    "virtualprotect":     {"tag": "Payload_Mem_Alloc",    "arg": 2,  "check": "pointer"},
    "heapalloc":          {"tag": "Payload_Mem_Alloc",    "arg": -1, "check": "return"},
    "writeprocessmemory": {"tag": "Payload_Injection",    "arg": 2,  "check": "pointer"},
    "ntwritevirtualmemory": {"tag": "Payload_Injection",  "arg": 2,  "check": "pointer"},
    # Process / Thread execution
    "createremotethread":    {"tag": "Payload_Execution",    "arg": -1, "check": "return"},
    "createremotethreadex":  {"tag": "Payload_Execution",    "arg": -1, "check": "return"},
    "ntcreatethreadex":      {"tag": "Payload_Execution",    "arg": -1, "check": "return"},
    "createprocess":         {"tag": "Command_Execution",    "arg": 1,  "check": "pointer"},
    "createprocessa":        {"tag": "Command_Execution",    "arg": 1,  "check": "pointer"},
    "createprocessw":        {"tag": "Command_Execution",    "arg": 1,  "check": "pointer"},
    "winexec":               {"tag": "Command_Execution",    "arg": 0,  "check": "pointer"},
    "shellexecute":          {"tag": "Command_Execution",    "arg": 2,  "check": "pointer"},
    "shellexecutea":         {"tag": "Command_Execution",    "arg": 2,  "check": "pointer"},
    "shellexecutew":         {"tag": "Command_Execution",    "arg": 2,  "check": "pointer"},
    "shellexecuteex":        {"tag": "Command_Execution",    "arg": 2,  "check": "pointer"},
    "system":                {"tag": "Command_Execution",    "arg": 0,  "check": "pointer"},
    # Network
    "recv":               {"tag": "C2_Recv",              "arg": 1,  "check": "pointer"},
    "recvfrom":           {"tag": "C2_Recv",              "arg": 1,  "check": "pointer"},
    "wsarecv":            {"tag": "C2_Recv",              "arg": 1,  "check": "pointer"},
    "send":               {"tag": "Data_Exfiltration",    "arg": 1,  "check": "pointer"},
    "sendto":             {"tag": "Data_Exfiltration",    "arg": 1,  "check": "pointer"},
    "wsasend":            {"tag": "Data_Exfiltration",    "arg": 1,  "check": "pointer"},
    "connect":            {"tag": "C2_Recv",              "arg": 1,  "check": "pointer"},
    "socket":             {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "wsastartup":         {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    # HTTP
    "internetopen":       {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "internetopena":      {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "internetopenw":      {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "internetconnect":    {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "internetconnecta":   {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "httpopenrequest":    {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "httpopenrequesta":   {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "httpsendrequest":    {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "httpssendrequesta":  {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "internetreadfile":   {"tag": "Payload_Download",     "arg": 1,  "check": "pointer"},
    "winhttpopen":        {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "winhttpreaddata":    {"tag": "Payload_Download",     "arg": 1,  "check": "pointer"},
    "winhttpconnect":     {"tag": "C2_Recv",              "arg": -1, "check": "return"},
    "urldownloadtofile":  {"tag": "Payload_Download",     "arg": 1,  "check": "pointer"},
    "urldownloadtofilea": {"tag": "Payload_Download",     "arg": 1,  "check": "pointer"},
    "urldownloadtofilew": {"tag": "Payload_Download",     "arg": 1,  "check": "pointer"},
    # File I/O
    "writefile":          {"tag": "File_Write",           "arg": 1,  "check": "pointer"},
    "readfile":           {"tag": "File_Read",            "arg": 1,  "check": "pointer"},
    "createfilea":        {"tag": "File_Write",           "arg": 0,  "check": "pointer"},
    "createfilew":        {"tag": "File_Write",           "arg": 0,  "check": "pointer"},
    "fread":              {"tag": "File_Read",            "arg": 0,  "check": "pointer"},
    "fwrite":             {"tag": "File_Write",           "arg": 0,  "check": "pointer"},
    "fopen":              {"tag": "File_Read",            "arg": 0,  "check": "pointer"},
    "deletefilea":        {"tag": "File_Write",           "arg": 0,  "check": "pointer"},
    "deletefilew":        {"tag": "File_Write",           "arg": 0,  "check": "pointer"},
    "movefileex":         {"tag": "File_Write",           "arg": 0,  "check": "pointer"},
    # Crypto API
    "cryptdecrypt":       {"tag": "Crypto_API_Decrypt",   "arg": 4,  "check": "pointer"},
    "cryptencrypt":       {"tag": "Crypto_API_Encrypt",   "arg": 4,  "check": "pointer"},
    "bcryptdecrypt":      {"tag": "Crypto_API_Decrypt",   "arg": 4,  "check": "pointer"},
    "bcryptencrypt":      {"tag": "Crypto_API_Encrypt",   "arg": 4,  "check": "pointer"},
    "cryptimportkey":     {"tag": "Crypto_API_Key",       "arg": 2,  "check": "pointer"},
    "cryptgenkey":        {"tag": "Crypto_API_Key",       "arg": -1, "check": "return"},
    "bcryptgeneratesymmetrickey": {"tag": "Crypto_API_Key", "arg": 2,  "check": "pointer"},
    "cryptacquirecontext":  {"tag": "Crypto_API_Key",     "arg": -1, "check": "return"},
    "cryptacquirecontexta": {"tag": "Crypto_API_Key",     "arg": -1, "check": "return"},
    # Registry
    "regqueryvalueex":    {"tag": "Registry_Read",        "arg": 4,  "check": "pointer"},
    "regqueryvalueexa":   {"tag": "Registry_Read",        "arg": 4,  "check": "pointer"},
    "regsetvalueex":      {"tag": "Registry_Write",       "arg": 4,  "check": "pointer"},
    "regsetvalueexa":     {"tag": "Registry_Write",       "arg": 4,  "check": "pointer"},
    "regopenkey":         {"tag": "Registry_Read",        "arg": 1,  "check": "pointer"},
    "regopenkeyexa":      {"tag": "Registry_Read",        "arg": 1,  "check": "pointer"},
    # Module/Library
    "getmodulehandlea":   {"tag": "Module_Resolve",       "arg": 0,  "check": "pointer"},
    "getmodulehandlew":   {"tag": "Module_Resolve",       "arg": 0,  "check": "pointer"},
    "getmodulehandleexa": {"tag": "Module_Resolve",       "arg": 0,  "check": "pointer"},
    "getmodulehandleexw": {"tag": "Module_Resolve",       "arg": 0,  "check": "pointer"},
    "loadlibrary":        {"tag": "Module_Resolve",       "arg": 0,  "check": "pointer"},
    "loadlibrarya":       {"tag": "Module_Resolve",       "arg": 0,  "check": "pointer"},
    "loadlibraryw":       {"tag": "Module_Resolve",       "arg": 0,  "check": "pointer"},
    "getprocaddress":     {"tag": "Module_Resolve",       "arg": 1,  "check": "pointer"},
}

# ---- 静态 S-Box 特征 ----
CRYPTO_SIGNATURES = {
    "AES_SBOX":  bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
    "AES_TE0":   bytes.fromhex("c66363a5f87c7c84ee777799f67b7b8d"),
    "DES_SBOX":  bytes.fromhex("0e040d010206080f000907030a0b050c"),
    "CRC32":     bytes.fromhex("0000000077073096ee0e612c990951ba"),
    "MD5_INIT":  bytes.fromhex("0123456789abcdeffedcba9876543210"),
    "SM4_SBOX":  bytes.fromhex("d690e9feccb13199adb2f885e8cedb8b"),
    "BLOWFISH_P": bytes.fromhex("243f6a8885a308d3131198a2e0370734"),
}

# ---- [V2-扩展] 动态分析常量库 (25 项) ----
CRYPTO_CONSTANTS = {
    # AES
    0x637c777b: "AES",          0xc66363a5: "AES",
    0x7c7c84f8: "AES",          0xf87c7c84: "AES",
    # TEA/XTEA
    0x9e3779b9: "TEA/XTEA",     0x61c88647: "TEA/XTEA",
    0xc6ef3720: "TEA/XTEA",
    # ChaCha20/Salsa20
    0x61707865: "ChaCha20",     0x3320646e: "ChaCha20",
    0x79622d32: "ChaCha20",     0x6b206574: "ChaCha20",
    # CRC32
    0xedb88320: "CRC32",        0x04c11db7: "CRC32",
    # Blowfish
    0x243f6a88: "Blowfish",     0x85a308d3: "Blowfish",
    # RC4 特征
    0x000000ff: "RC4",
    # SHA-256 init
    0x6a09e667: "SHA-256",      0xbb67ae85: "SHA-256",
    # MD5 constants
    0xd76aa478: "MD5",          0xe8c7b756: "MD5",
    # SM4
    0xa3b1bac6: "SM4",          0x56aa3350: "SM4",
    # DES
    0x00000001: None,           # 太通用, 不计入
    # Whirlpool / ARIA
    0x1823c6e8: "Whirlpool",
    # SipHash
    0x736f6d65: "SipHash",
}
# 移除 None 项
CRYPTO_CONSTANTS = {k: v for k, v in CRYPTO_CONSTANTS.items() if v is not None}

# ---- 标准场景类别 ----
SCENARIO_CLASSES = (
    "Payload_Decryption_Loading",
    "C2_Command_Execution",
    "Data_Exfiltration",
    "Ransomware_Encryption",
)

LLM_SYSTEM_PROMPT = (
    "You are a malware reverse-engineering analyst. "
    "You are given multi-stage analysis evidence (static YARA, opcode fingerprint, "
    "SSA dataflow, and dynamic symbolic execution) from a malware binary. "
    "Your task is to determine: 1) the crypto algorithm, 2) the adversarial behavior scenario, "
    "3) a confidence score 0-100. "
    "Output strict JSON only (no markdown). "
    "Scenario must be exactly one of: "
    "Payload_Decryption_Loading, C2_Command_Execution, "
    "Data_Exfiltration, Ransomware_Encryption. "
    "For algo, use standard names: AES, DES, RC4, ChaCha20, Salsa20, TEA, XTEA, "
    "Blowfish, SM4, RC5, RC6, XOR, Custom, API_Crypto, Unknown."
)


# ==============================================================================
# 2. Blueprint 解析器 — 提取 Step2 V3 的完整上下文
# ==============================================================================

class BlueprintParser:
    """将 Step2 V3 的 blueprint JSONL 解析为结构化任务列表"""

    @staticmethod
    def parse(path):
        """返回 {sample_name: [task, ...]} 的映射"""
        task_map = defaultdict(list)
        if not os.path.exists(path):
            return task_map

        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    bp = json.loads(line)
                except Exception:
                    continue

                sample = bp.get("sample")
                if not sample:
                    continue

                # 提取 Step2 V3 的完整字段
                task = {
                    "path_id":        bp.get("path_id", ""),
                    "sample":         sample,
                    "sample_hash":    bp.get("sample_hash"),
                    "target_func":    bp.get("target_func", "0x0"),
                    "target_func_name": bp.get("target_func_name", ""),
                    "path_addrs":     bp.get("path_addrs", []),
                    "chain_type":     bp.get("chain_type", "Unknown"),
                    "chain_scenario": bp.get("chain_scenario", "Unknown"),
                    "target_reason":  bp.get("target_reason", ""),
                    # Step2 语义分析结果
                    "semantic": bp.get("semantic", {}),
                    # Step2 数据流证据
                    "evidence": bp.get("evidence", {}),
                    # Step1 算法识别上下文 (经 Step2 透传)
                    "step1_algo_context": bp.get("step1_algo_context", {}),
                }

                task_map[sample].append(task)

        return task_map

    @staticmethod
    def extract_algo_votes(task):
        """从 blueprint 中提取多层算法投票"""
        votes = []

        # Layer-A: Step1 YARA/SBox 静态识别
        algo_ctx = task.get("step1_algo_context", {})
        yara_tags = algo_ctx.get("step1_yara_tags", [])
        for tag in yara_tags:
            votes.append(("step1_yara", tag, 85))

        algo_hints = algo_ctx.get("step1_algo_hints", [])
        for hint in algo_hints:
            algo_name = hint.get("algo", "Unknown") if isinstance(hint, dict) else str(hint)
            score = hint.get("score", 60) if isinstance(hint, dict) else 60
            if algo_name != "Unknown":
                votes.append(("step1_hint", algo_name, score))

        if algo_ctx.get("step1_sbox_confirmed"):
            votes.append(("step1_sbox", "SBox_Crypto", 80))

        # Layer-B: Step2 Opcode Fingerprint
        evidence = task.get("evidence", {})
        opcode_matches = evidence.get("opcode_fingerprint_matches", [])
        for match in opcode_matches[:2]:
            votes.append(("step2_opcode", match.get("algo_pattern", "Unknown"),
                         match.get("score", 50)))

        # Step2 语义分析
        semantic = task.get("semantic", {})
        s2_algo = semantic.get("algo", "Unknown")
        s2_conf = semantic.get("confidence", 0)
        if s2_algo and s2_algo != "Unknown":
            votes.append(("step2_semantic", s2_algo, s2_conf))

        # Step2 opcode_algo_match (直接匹配结果)
        opcode_algo = semantic.get("opcode_algo_match")
        if opcode_algo:
            votes.append(("step2_opcode_direct", opcode_algo, 65))

        return votes

    @staticmethod
    def extract_guided_context(task):
        """提取引导符号执行的上下文信息"""
        evidence = task.get("evidence", {})

        # Step2 已识别的 source/sink API
        sources = evidence.get("input_from_source", [])
        sinks = evidence.get("output_to_sink", [])

        # Step2 密钥定位
        key_material = evidence.get("key_material", [])

        # Step2 taint summary
        taint_summary = evidence.get("taint_summary", {})

        # 数据流验证状态
        chain_verified = task.get("semantic", {}).get("chain_verified", False)

        # 从 traces 中提取具体地址
        backward_addrs = []
        for line in evidence.get("backward_trace", []):
            m = re.search(r'0x[0-9a-fA-F]+@(0x[0-9a-fA-F]+)', str(line))
            if m:
                backward_addrs.append(m.group(1))

        forward_addrs = []
        for line in evidence.get("forward_trace", []):
            m = re.search(r'0x[0-9a-fA-F]+@(0x[0-9a-fA-F]+)', str(line))
            if m:
                forward_addrs.append(m.group(1))

        return {
            "sources": sources,
            "sinks": sinks,
            "key_material": key_material,
            "taint_summary": taint_summary,
            "chain_verified": chain_verified,
            "backward_addrs": backward_addrs[:20],
            "forward_addrs": forward_addrs[:20],
            "opcode_histogram": evidence.get("opcode_histogram"),
        }


# ==============================================================================
# 3. 算法识别 — 三层交叉验证投票器
# ==============================================================================

class AlgorithmVoter:
    """三层交叉验证: Step1静态 + Step2指纹 + Step3动态 → 最终算法判定"""

    # 算法名标准化映射
    ALGO_NORMALIZE = {
        "aes_sbox": "AES", "aes_te0": "AES", "aes (table)": "AES",
        "aes_manual": "AES", "aes": "AES",
        "tea/xtea": "TEA/XTEA", "tea delta": "TEA/XTEA", "tea": "TEA/XTEA",
        "xtea": "TEA/XTEA",
        "rc4-like": "RC4", "rc4": "RC4", "rc4 mask": "RC4",
        "chacha20": "ChaCha20", "chacha20/salsa20": "ChaCha20",
        "chacha20 sigma": "ChaCha20", "salsa20": "Salsa20",
        "blowfish": "Blowfish", "blowfish pi": "Blowfish",
        "sm4": "SM4", "sm4_sbox": "SM4",
        "des": "DES", "des_sbox": "DES", "3des": "DES",
        "crc32": "CRC32", "crc32 poly": "CRC32",
        "sha-256": "SHA-256", "sha256": "SHA-256",
        "md5": "MD5", "md5_init": "MD5",
        "custom_xor": "Custom_XOR", "custom_xor_cipher": "Custom_XOR",
        "xor": "Custom_XOR",
        "feistel_cipher": "Feistel_Cipher", "feistel": "Feistel_Cipher",
        "api_crypto": "API_Crypto",
        "sbox_crypto": "SBox_Crypto",
        "whirlpool": "Whirlpool", "siphash": "SipHash",
    }

    @staticmethod
    def normalize_algo(name):
        if not name:
            return "Unknown"
        return AlgorithmVoter.ALGO_NORMALIZE.get(name.lower().strip(), name)

    @staticmethod
    def vote(static_votes, dynamic_votes):
        """
        static_votes: [(source, algo_name, score), ...] — 来自 Step1+Step2
        dynamic_votes: [(source, algo_name, score), ...] — 来自 Step3 angr

        返回: (final_algo, confidence, vote_detail)
        """
        all_votes = static_votes + dynamic_votes

        if not all_votes:
            return "Unknown", 0, {}

        # 归一化算法名并按权重聚合
        algo_scores = defaultdict(lambda: {"total_score": 0, "count": 0, "sources": []})
        for source, algo, score in all_votes:
            norm = AlgorithmVoter.normalize_algo(algo)
            if norm == "Unknown":
                continue
            algo_scores[norm]["total_score"] += score
            algo_scores[norm]["count"] += 1
            algo_scores[norm]["sources"].append(source)

        if not algo_scores:
            return "Unknown", 0, {}

        # 选择加权得分最高的
        ranked = sorted(algo_scores.items(),
                       key=lambda x: (x[1]["count"], x[1]["total_score"]),
                       reverse=True)
        winner, detail = ranked[0]

        # 计算综合置信度
        confidence = min(95, detail["total_score"] // max(1, detail["count"]))

        # 多层验证加分
        source_types = set(s.split("_")[0] for s in detail["sources"])
        if len(source_types) >= 3:
            confidence = min(98, confidence + 12)  # 三层都验证
        elif len(source_types) >= 2:
            confidence = min(95, confidence + 8)   # 两层验证

        vote_detail = {
            "winner": winner,
            "votes": detail["count"],
            "layers": sorted(source_types),
            "runners_up": [(a, d["total_score"]) for a, d in ranked[1:3]],
        }

        return winner, confidence, vote_detail


# ==============================================================================
# 4. 行为分类器 — 数据流验证攻击链
# ==============================================================================

class BehaviorClassifier:
    """基于数据流验证的三段式攻击链行为判定"""

    @staticmethod
    def classify(source_type, sinks, chain_verified, algo, evidence, chain_scenario, s2_conf=0):
        """
        返回: (behavior, confidence, attack_chain, reasoning)
        """
        # 1. 优先使用 Step2 已验证的 chain_scenario
        if chain_scenario and chain_scenario.lower() != "unknown":
            norm = BehaviorClassifier._normalize_scenario(chain_scenario)
            if norm:
                # [V5-Fix1] 根据 Step2 置信度和验证状态调整
                if chain_verified:
                    base_conf = max(82, min(95, s2_conf + 15))
                else:
                    base_conf = max(60, min(85, s2_conf))
                chain = BehaviorClassifier._build_attack_chain(
                    source_type, algo, sinks, evidence
                )
                return norm, base_conf, chain, "step2_scenario"

        # 2. 规则引擎
        sink_str = " ".join(sinks).lower()
        src = source_type.lower()

        scenario = None
        base_conf = 0
        reasoning = "rule_based"

        # Source→Crypto→Sink 三段式匹配
        has_net = src in ("network",) or any(
            x in sink_str for x in ("c2_recv", "payload_download",
                                     "internetopen", "winhttpopen", "connect")
        )
        has_exec = any(x in sink_str for x in (
            "command_execution", "payload_execution"
        ))
        has_payload = any(x in sink_str for x in (
            "payload_mem_alloc", "payload_injection", "payload_execution"
        ))
        has_exfil = any(x in sink_str for x in (
            "data_exfiltration",
        ))
        has_file_w = any(x in sink_str for x in ("file_write",))
        has_file_r = any(x in sink_str for x in ("file_read",))
        has_crypto_enc = any(x in sink_str for x in ("crypto_api_encrypt",))
        has_crypto_dec = any(x in sink_str for x in ("crypto_api_decrypt",))
        has_crypto_key = any(x in sink_str for x in (
            "crypto_api_key", "cryptimport", "cryptgen", "bcryptgenerate",
        ))
        has_module = any(x in sink_str for x in (
            "module_resolve", "getmodulehandle", "loadlibrary", "getprocaddress",
        ))

        # 规则匹配 (按优先级排序)
        if has_payload and (has_net or has_crypto_dec):
            scenario = "Payload_Decryption_Loading"
            base_conf = 78
        elif has_exec and has_net:
            scenario = "C2_Command_Execution"
            base_conf = 76
        elif has_exfil and (has_file_r or has_crypto_enc or has_net):
            scenario = "Data_Exfiltration"
            base_conf = 74
        elif has_crypto_enc and has_file_w:
            scenario = "Ransomware_Encryption"
            base_conf = 72
        elif has_payload and has_module:
            scenario = "Payload_Decryption_Loading"
            base_conf = 70
        elif has_crypto_enc or (has_file_w and has_file_r):
            scenario = "Ransomware_Encryption"
            base_conf = 65
        elif has_exec:
            scenario = "C2_Command_Execution"
            base_conf = 60
        elif has_payload:
            scenario = "Payload_Decryption_Loading"
            base_conf = 60
        elif has_exfil or (has_net and algo and algo != "Unknown"):
            scenario = "Data_Exfiltration"
            base_conf = 58
        elif has_module and algo and algo != "Unknown":
            # 模块解析 + 加密算法 → 很可能是 payload 解密
            scenario = "Payload_Decryption_Loading"
            base_conf = 55
        elif has_net:
            scenario = "C2_Command_Execution"
            base_conf = 50
        elif has_file_w and algo and algo != "Unknown":
            scenario = "Ransomware_Encryption"
            base_conf = 50
        elif has_file_r and algo and algo != "Unknown":
            scenario = "Payload_Decryption_Loading"
            base_conf = 48
        elif has_crypto_key:
            scenario = "Payload_Decryption_Loading"
            base_conf = 48
        elif src == "module" and algo and algo != "Unknown":
            scenario = "Payload_Decryption_Loading"
            base_conf = 48
            reasoning = "source_module+crypto"
        elif src == "network":
            scenario = "C2_Command_Execution"
            base_conf = 48
            reasoning = "source_network"
        elif src == "file":
            scenario = "Payload_Decryption_Loading"
            base_conf = 45
            reasoning = "source_file"
        else:
            scenario = "Data_Exfiltration"
            base_conf = 40
            reasoning = "fallback"

        # 3. chain_verified 调整
        if chain_verified:
            base_conf = min(95, base_conf + 15)
            reasoning += "+chain_verified"
        elif evidence and (
            evidence.get("backward_trace") or evidence.get("forward_trace")
        ):
            # 有 trace 但未验证: 轻微降分
            base_conf = max(35, base_conf - 5)

        # 4. 构建攻击链
        chain = BehaviorClassifier._build_attack_chain(
            source_type, algo, sinks, evidence
        )

        return scenario, base_conf, chain, reasoning

    @staticmethod
    def _normalize_scenario(raw):
        txt = str(raw or "").strip()
        if txt in SCENARIO_CLASSES:
            return txt
        s = txt.lower()
        if any(x in s for x in ("payload", "loader", "decrypt", "loading", "inject")):
            return "Payload_Decryption_Loading"
        if any(x in s for x in ("c2", "command", "exec")):
            return "C2_Command_Execution"
        if any(x in s for x in ("exfil", "steal", "transmit", "send")):
            return "Data_Exfiltration"
        if any(x in s for x in ("ransom", "encrypt", "locker")):
            return "Ransomware_Encryption"
        return None

    @staticmethod
    def _build_attack_chain(source_type, algo, sinks, evidence):
        """构建 Source → Crypto → Sink 三段式攻击链"""
        chain = []

        # Source 阶段
        sources = []
        if evidence:
            sources = evidence.get("input_from_source", [])
        if source_type and source_type != "Unknown":
            chain.append({
                "stage": "Source",
                "type": source_type,
                "apis": sources[:5],
            })

        # Crypto 阶段
        if algo and algo != "Unknown":
            key_info = []
            if evidence:
                for km in evidence.get("key_material", [])[:3]:
                    key_info.append({
                        "api": km.get("api"),
                        "site": km.get("site"),
                        "desc": km.get("desc"),
                    })
            chain.append({
                "stage": "Crypto",
                "algo": algo,
                "key_material": key_info,
            })

        # Sink 阶段
        if sinks:
            chain.append({
                "stage": "Sink",
                "apis": sinks[:8],
            })

        return chain


# ==============================================================================
# 5. 分析引擎 (Worker)
# ==============================================================================

class WorkerEngine:
    def __init__(self, key_path, sample_name, log_file_handle=None):
        self.bn, self.MLIL, self.SymType, self.angr, self.claripy, self.OpenAI = lazy_import()
        self.client = None
        self.sample_name = sample_name
        # [V4-Fix2] 单进程模式: 直接写日志文件, 不经 Queue
        self._log_f = log_file_handle

        if os.path.exists(key_path):
            try:
                with open(key_path, 'r') as f:
                    key = f.read().strip()
                if key:
                    self.client = self.OpenAI(
                        api_key=key, base_url="https://api.deepseek.com"
                    )
            except Exception:
                self.client = None

    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{self.sample_name[:8]}] {msg}"
        if self._log_f:
            try:
                self._log_f.write(line + "\n")
                self._log_f.flush()
            except Exception:
                pass

    def diag(self, msg):
        """单进程模式下 diag 等同于 log"""
        self.log(msg)

    # ------------------------------------------------------------------
    # MLIL 结构分析 (本地静态 — Layer-C 的补充)
    # ------------------------------------------------------------------

    def _expr_contains_const(self, expr, target):
        if not hasattr(expr, 'operation'):
            return False
        if expr.operation == self.MLIL.MLIL_CONST and expr.constant == target:
            return True
        if expr.operation == self.MLIL.MLIL_CONST_PTR and expr.constant == target:
            return True
        if hasattr(expr, 'operands'):
            return any(
                self._expr_contains_const(op, target)
                for op in expr.operands if hasattr(op, 'operation')
            )
        return False

    def _func_references_constant(self, func, target_const):
        if not func or not func.mlil:
            return False
        try:
            for block in func.mlil:
                for instr in block:
                    if self._expr_contains_const(instr, target_const):
                        return True
        except Exception:
            pass
        return False

    def _count_ops_recursive(self, expr, metrics):
        if not hasattr(expr, 'operation'):
            return
        op = expr.operation
        if op == self.MLIL.MLIL_XOR:
            metrics["xor"] += 1
        elif op in (self.MLIL.MLIL_LSL, self.MLIL.MLIL_LSR,
                    self.MLIL.MLIL_ROL, self.MLIL.MLIL_ROR):
            metrics["shift"] += 1
        elif op == self.MLIL.MLIL_ADD:
            metrics["add"] += 1
        elif op == self.MLIL.MLIL_SUB:
            metrics["sub"] += 1
        elif op == self.MLIL.MLIL_AND:
            metrics["and_op"] += 1
        if hasattr(expr, 'operands'):
            for operand in expr.operands:
                self._count_ops_recursive(operand, metrics)

    def _analyze_mlil_structure(self, func):
        metrics = {"xor": 0, "shift": 0, "add": 0, "sub": 0,
                   "and_op": 0, "loops": 0, "total_instr": 0}
        if not func or not func.mlil:
            return metrics
        try:
            for block in func.mlil:
                for edge in block.outgoing_edges:
                    if edge.target.start < block.start:
                        metrics["loops"] += 1
                for instr in block:
                    metrics["total_instr"] += 1
                    self._count_ops_recursive(instr, metrics)
        except Exception:
            pass
        return metrics

    # ------------------------------------------------------------------
    # [V5] MLIL 静态 Sink 检测 — 不依赖 angr, 直接扫描调用树
    # ------------------------------------------------------------------

    def _get_mlil_call_target(self, instr, bv):
        """从 MLIL CALL 指令提取调用目标地址"""
        try:
            if hasattr(instr, 'dest'):
                dest = instr.dest
                if hasattr(dest, 'constant'):
                    return dest.constant
                if hasattr(dest, 'operation'):
                    if dest.operation == self.MLIL.MLIL_CONST_PTR:
                        return dest.constant
                    if dest.operation == self.MLIL.MLIL_CONST:
                        return dest.constant
                    # 间接调用: [mem] 形式 — 尝试解析
                    if dest.operation == self.MLIL.MLIL_LOAD:
                        load_src = dest.src
                        if hasattr(load_src, 'constant'):
                            # 可能是 IAT entry: call [0x41234]
                            ptr_addr = load_src.constant
                            # 读取 IAT 指向的地址
                            try:
                                ptr_data = bv.read(ptr_addr, bv.address_size)
                                if len(ptr_data) == bv.address_size:
                                    import struct
                                    if bv.address_size == 4:
                                        return struct.unpack('<I', ptr_data)[0]
                                    else:
                                        return struct.unpack('<Q', ptr_data)[0]
                            except Exception:
                                pass
                            return ptr_addr  # fallback: 返回 IAT 地址本身
        except Exception:
            pass
        return None

    def _detect_mlil_api_calls(self, bv, func_obj, api_map, max_depth=3):
        """[V5] 静态扫描函数调用树, 找出所有被调用的 monitored API"""
        found_sinks = []
        visited = set()

        def _match_name(name):
            if not name:
                return None
            clean = name.lower().replace("_imp_", "").replace("__imp_", "")
            clean = re.sub(r'^j_', '', clean)
            clean = re.sub(r'@\d+$', '', clean)
            for api_name, api_info in API_BEHAVIOR_MAP.items():
                if api_name in clean:
                    return f"{api_info['tag']}::{api_name}"
            return None

        def scan_func(func, depth):
            if depth > max_depth or not func or func.start in visited:
                return
            visited.add(func.start)
            try:
                # 方法1: BinaryNinja callee 列表 (最可靠)
                for callee in func.callees:
                    match = _match_name(callee.name)
                    if match:
                        if match not in found_sinks:
                            found_sinks.append(match)
                    elif depth < max_depth:
                        scan_func(callee, depth + 1)

                # 方法2: MLIL CALL 指令扫描
                if func.mlil:
                    for block in func.mlil:
                        for instr in block:
                            op = getattr(instr, 'operation', None)
                            if op not in (self.MLIL.MLIL_CALL, self.MLIL.MLIL_CALL_UNTYPED,
                                          self.MLIL.MLIL_TAILCALL):
                                continue
                            target = self._get_mlil_call_target(instr, bv)
                            if target is None:
                                continue
                            # 检查 api_map
                            hit = api_map.get(target)
                            if hit:
                                sink = f"{hit['tag']}::{hit['name']}"
                                if sink not in found_sinks:
                                    found_sinks.append(sink)
                                continue
                            # 检查符号名
                            sym = bv.get_symbol_at(target)
                            if sym:
                                match = _match_name(sym.name)
                                if match and match not in found_sinks:
                                    found_sinks.append(match)
                            # 检查函数名
                            tfunc = bv.get_function_at(target)
                            if tfunc:
                                match = _match_name(tfunc.name)
                                if match and match not in found_sinks:
                                    found_sinks.append(match)
            except Exception:
                pass

        try:
            scan_func(func_obj, 0)
        except Exception:
            pass
        return found_sinks

    def _collect_step2_sinks(self, task):
        """[V5] 从 Step2 evidence 中提取已识别的 sink 和 source API 标签"""
        sinks = []
        evidence = task.get('evidence', {})

        def _match_api(name):
            clean = str(name).lower().strip()
            clean = re.sub(r'^j_|_imp_|__imp_', '', clean)
            for api_name, api_info in API_BEHAVIOR_MAP.items():
                if api_name in clean:
                    return f"{api_info['tag']}::{api_name}"
            return None

        # Step2 的 output_to_sink
        for sink_api in evidence.get('output_to_sink', []):
            match = _match_api(sink_api)
            if match and match not in sinks:
                sinks.append(match)

        # Step2 的 input_from_source (也可能是有意义的 API)
        for src_api in evidence.get('input_from_source', []):
            match = _match_api(src_api)
            if match and match not in sinks:
                sinks.append(match)

        # [V5] 从 forward_trace 中提取 API 引用
        for trace_line in evidence.get('forward_trace', []):
            line_str = str(trace_line).lower()
            for api_name, api_info in API_BEHAVIOR_MAP.items():
                if api_name in line_str:
                    tag = f"{api_info['tag']}::{api_name}"
                    if tag not in sinks:
                        sinks.append(tag)

        # [V5] 从 key_material 中提取 crypto API
        for km in evidence.get('key_material', []):
            api = km.get('api', '')
            if api:
                match = _match_api(api)
                if match and match not in sinks:
                    sinks.append(match)

        return sinks

    # ------------------------------------------------------------------
    # [V2-需求2] 调用链重建
    # ------------------------------------------------------------------

    def _get_call_chain(self, bv, func_addr, depth=0):
        """从目标函数向上追溯调用链 (沿 xref 回溯)"""
        if depth >= MAX_CALL_CHAIN_DEPTH:
            return []

        func = bv.get_function_at(func_addr)
        if not func:
            return []

        chain = [{
            "addr": hex(func_addr),
            "name": func.name or hex(func_addr),
            "depth": depth,
        }]

        refs = list(bv.get_code_refs(func_addr))
        if not refs:
            return chain

        # 选择 xref 最少的 caller (更具体的业务逻辑)
        callers = []
        for ref in refs[:10]:
            caller = getattr(ref, "function", None)
            if caller is None:
                continue
            try:
                caller_xrefs = len(list(bv.get_code_refs(caller.start)))
            except Exception:
                caller_xrefs = 999
            callers.append((caller_xrefs, caller.start, ref.address))

        if not callers:
            return chain

        callers.sort()
        best_caller_addr = callers[0][1]
        parent_chain = self._get_call_chain(bv, best_caller_addr, depth + 1)
        return parent_chain + chain

    # ------------------------------------------------------------------
    # 核心流程 (重写)
    # ------------------------------------------------------------------

    def run_analysis(self, bin_path, tasks):
        """[V4-Fix] 逐 task 增量分析 + 增量写入 temp file"""
        results = {}
        extracted = []

        self.log(f"--- Start Analysis: {bin_path} ({len(tasks)} tasks) ---")
        try:
            bv = self.bn.load(bin_path)
        except Exception:
            return None, None
        if not bv:
            return None, None

        api_map = self._build_global_api_map(bv)
        crypto_tables = self._scan_and_link_crypto_tables(bv)
        raw_static_keys = self._scan_static_keys(bv)
        self.log(f"✅ Loaded. APIs: {len(api_map)}, Tables: {len(crypto_tables)}, "
                 f"Static Keys: {len(raw_static_keys)}")

        try:
            proj = self.angr.Project(
                bin_path, main_opts={'base_addr': bv.start}, auto_load_libs=False
            )
        except Exception as e:
            self.log(f"angr Project Error: {e}")
            bv.file.close()
            return None, None

        sample_name = os.path.basename(bin_path)
        temp_file = os.path.join(TEMP_DIR, f"{sample_name}.json")
        filtered_count = 0

        for i, task in enumerate(tasks):
            task_id = task.get('path_id', '?')[:16]
            self.diag(f"TASK {i+1}/{len(tasks)}: {task_id} starting")
            try:
                result = self._analyze_single_target(
                    bv, proj, api_map, crypto_tables, task
                )
                if result:
                    results[task['path_id']] = result["report"]
                    extracted.extend(result.get("keys", []))
                    self.log(f"  [{task_id}] ✅ => {result['report'].get('algorithm','?')} "
                             f"| {result['report'].get('behavior','?')} "
                             f"(keys={len(result.get('keys',[]))})")
                    self.diag(f"TASK {i+1}/{len(tasks)}: ✅ result produced")
                else:
                    filtered_count += 1
                    self.log(f"  [{task_id}] ⊘ Filtered (no significant result)")
                    self.diag(f"TASK {i+1}/{len(tasks)}: ⊘ filtered (None)")
            except Exception as e:
                self.log(f"  [{task_id}] ❌ Task Error: {e}")
                self.diag(f"TASK {i+1}/{len(tasks)}: ❌ Exception: {type(e).__name__}: {e}")

            # [V4-Fix] 每个 task 完成后立即写入 temp file (无论是否有结果)
            # 这样即使后续 task 导致进程被杀, 已完成的结果不会丢失
            try:
                self.diag(f"TASK {i+1}: writing temp -> {temp_file}")
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        "res": results,
                        "ext": extracted,
                        "progress": f"{i+1}/{len(tasks)}",
                        "filtered": filtered_count,
                    }, f, default=str)
                self.diag(f"TASK {i+1}: temp written OK (res={len(results)}, ext={len(extracted)})")
            except Exception as e:
                self.diag(f"TASK {i+1}: temp write FAILED: {e}")

        # 样本级汇总
        self.log(f"--- Summary: {len(results)}/{len(tasks)} tasks produced results, "
                 f"{filtered_count} filtered, {len(extracted)} keys extracted ---")

        # Fallback: 静态密钥
        if not extracted and raw_static_keys:
            self.log(f"⚠️ Saving {len(raw_static_keys)} static keys as fallback.")
            for sk in raw_static_keys[:10]:
                extracted.append({
                    "sample": os.path.basename(bin_path),
                    "key_hex": sk["hex"],
                    "location": sk["loc"],
                    "algo": "Static",
                    "behavior": "Potential_Key",
                    "entropy": sk.get("entropy", 0),
                })
            # 增量写入 fallback keys
            if extracted:
                try:
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        json.dump({
                            "res": results,
                            "ext": extracted,
                            "progress": "complete",
                        }, f, default=str)
                except Exception:
                    pass

        bv.file.close()
        del proj
        return results, extracted

    def _analyze_single_target(self, bv, proj, api_map, crypto_tables, task):
        """分析单个目标函数 — 完整三层流水线"""
        func_addr = int(task['target_func'], 16)
        func_obj = bv.get_function_at(func_addr)
        if not func_obj:
            self.diag(f"SKIP: func_obj is None at {hex(func_addr)}")
            return None

        path_id = task.get("path_id", "")
        guided = BlueprintParser.extract_guided_context(task)

        self.log(f"[{path_id[:12]}] Analyzing {hex(func_addr)} "
                 f"({task.get('target_func_name', '?')})")
        self.diag(f"STEP-1: Analyzing {hex(func_addr)} ({task.get('target_func_name','?')})")

        # ---- Layer-A+B: 从 Step1+Step2 收集静态投票 ----
        static_votes = BlueprintParser.extract_algo_votes(task)
        self.diag(f"STEP-2: static_votes={len(static_votes)}")

        # ---- Layer-C 补充: 本地 MLIL 结构分析 ----
        try:
            metrics = self._analyze_mlil_structure(func_obj)
            self.diag(f"STEP-3: MLIL metrics ok: loops={metrics.get('loops',0)}, xor={metrics.get('xor',0)}")
        except Exception as e:
            self.diag(f"STEP-3: MLIL CRASHED: {e}")
            metrics = {"loops": 0, "xor": 0, "add": 0, "total_instr": 0}

        # TEA 检测: 循环 + XOR + delta 常量
        if (metrics["loops"] >= 1 and metrics["xor"] >= 4
                and self._func_references_constant(func_obj, 0x9E3779B9)):
            static_votes.append(("step3_mlil", "TEA/XTEA", 82))

        # RC4 检测: 多循环 + 低 XOR + 高 ADD (KSA + PRGA)
        if metrics["loops"] >= 2 and metrics["xor"] < 5 and metrics["add"] > 10:
            static_votes.append(("step3_mlil", "RC4", 65))

        # AES 表检测
        aes_table = any(
            hex(func_addr) in t.get('referencing_funcs', [])
            for t in crypto_tables if "AES" in t.get('algo', '')
        )
        if aes_table:
            static_votes.append(("step3_table", "AES", 88))

        # [V5-Fix3] 增强算法模式检测

        # XOR 在循环中 → 至少是 Custom_XOR
        if metrics["loops"] >= 1 and metrics["xor"] >= 1 and metrics["total_instr"] > 5:
            xor_ratio = metrics["xor"] / max(1, metrics["total_instr"])
            if xor_ratio > 0.05:
                static_votes.append(("step3_mlil", "Custom_XOR", 55))

        # 高 XOR 比例 → 强 XOR 信号
        if metrics["total_instr"] > 0 and metrics["xor"] > 10:
            xor_ratio = metrics["xor"] / metrics["total_instr"]
            if xor_ratio > 0.15:
                static_votes.append(("step3_mlil", "Custom_XOR", 70))

        # Feistel / 分组密码: 循环 + XOR + SHIFT + 中等体积
        if (metrics["loops"] >= 1 and metrics["xor"] >= 4
                and metrics["shift"] >= 2 and metrics["total_instr"] > 20):
            static_votes.append(("step3_mlil", "Feistel_Cipher", 55))

        # ChaCha20/Salsa20 特征: 高 ADD + 高 XOR + 高 SHIFT/ROL
        if (metrics["add"] >= 10 and metrics["xor"] >= 10
                and metrics["shift"] >= 10 and metrics["loops"] >= 1):
            static_votes.append(("step3_mlil", "ChaCha20", 60))
            # 更精确: 检测 sigma 常量
            if self._func_references_constant(func_obj, 0x61707865):
                static_votes.append(("step3_const", "ChaCha20", 90))

        # Blowfish 特征: PI 常量
        if self._func_references_constant(func_obj, 0x243F6A88):
            static_votes.append(("step3_const", "Blowfish", 85))

        # SHA-256 常量
        if self._func_references_constant(func_obj, 0x6A09E667):
            static_votes.append(("step3_const", "SHA-256", 85))

        # MD5 常量
        if self._func_references_constant(func_obj, 0xD76AA478):
            static_votes.append(("step3_const", "MD5", 85))

        # SM4 常量
        if self._func_references_constant(func_obj, 0xA3B1BAC6):
            static_votes.append(("step3_const", "SM4", 85))

        # CRC32 多项式
        if self._func_references_constant(func_obj, 0xEDB88320):
            static_votes.append(("step3_const", "CRC32", 85))

        # TEA 另一个 delta
        if self._func_references_constant(func_obj, 0x61C88647):
            static_votes.append(("step3_const", "TEA/XTEA", 82))

        # [V5] 综合 S-Box 表检测 — 扫描所有已知 S-Box
        for t in crypto_tables:
            algo = t.get('algo', 'Unknown')
            if algo != 'Unknown' and hex(func_addr) in t.get('referencing_funcs', []):
                static_votes.append(("step3_table", algo, 85))

        # ---- Layer-C: angr 动态分析 ----
        dynamic_votes = []
        try:
            dfg = self._exec_taint_analysis(proj, func_addr, api_map, task, guided)
        except Exception as e:
            self.log(f"    angr exception: {type(e).__name__}: {e}")
            dfg = {
                "taint_source": "Unknown", "sinks": [], "key_candidates": [],
                "trace_len": 0, "return_tainted": False,
                "detected_algo": "Unknown", "detected_constants": [],
            }

        if dfg['detected_algo'] != "Unknown":
            dynamic_votes.append(("step3_angr", dfg['detected_algo'], 80))
            self.log(f"  -> ⚡ Dynamic Algo: {dfg['detected_algo']}")

        # ---- [V5] MLIL 静态 Sink 检测 — 不依赖 angr ----
        mlil_sinks = self._detect_mlil_api_calls(bv, func_obj, api_map)
        if mlil_sinks:
            self.log(f"  -> 🔍 MLIL Sinks ({len(mlil_sinks)}): {mlil_sinks[:5]}")

        # ---- [V5] Step2 证据 Sink — 直接利用已识别的 source/sink ----
        step2_sinks = self._collect_step2_sinks(task)
        if step2_sinks:
            self.log(f"  -> 📋 Step2 Sinks ({len(step2_sinks)}): {step2_sinks[:5]}")

        # [V5] 总是记录 sink 数量
        if not mlil_sinks and not step2_sinks:
            self.diag(f"  Sinks: none found (mlil=0, s2=0)")

        # ---- [V5] 三源 Sink 合并: angr动态 + MLIL静态 + Step2证据 ----
        merged_sinks = list(dfg['sinks'])  # angr 发现的 (通常为空)
        for s in mlil_sinks + step2_sinks:
            if s not in merged_sinks:
                merged_sinks.append(s)

        # ---- 三层投票 → 最终算法判定 ----
        final_algo, algo_conf, vote_detail = AlgorithmVoter.vote(
            static_votes, dynamic_votes
        )
        self.log(f"  -> 🎯 Algo Vote: {final_algo} (conf={algo_conf}, "
                 f"layers={vote_detail.get('layers', [])})")

        # ---- [V5] 行为分类 — 使用合并 sinks ----
        source_type = self._classify_source(
            dfg['taint_source'], merged_sinks, guided['sources']
        )

        # [V5-Fix1] chain_scenario 优先级: task.chain_scenario > semantic.scenario
        chain_scenario = task.get('chain_scenario', 'Unknown')
        if not chain_scenario or chain_scenario.lower() == 'unknown':
            chain_scenario = task.get('semantic', {}).get('scenario', 'Unknown')

        # [V5-Fix1] chain_verified 也从 semantic 读取
        chain_verified = guided['chain_verified']
        if not chain_verified:
            chain_verified = task.get('semantic', {}).get('chain_verified', False)

        # [V5-Fix1] 将 Step2 semantic.confidence 传入, 用于置信度校准
        s2_conf = task.get('semantic', {}).get('confidence', 0)

        behavior, behav_conf, attack_chain, reasoning = BehaviorClassifier.classify(
            source_type,
            merged_sinks,
            chain_verified,
            final_algo,
            task.get('evidence', {}),
            chain_scenario,
            s2_conf,  # [V5] 传入 Step2 置信度
        )

        # ---- LLM 增强 (当规则置信度不足时) ----
        if behav_conf < 70 and final_algo != "Unknown":
            ai_res = self._llm_enhanced_classify(
                task, dfg, final_algo, source_type, algo_conf
            )
            if ai_res:
                ai_conf = ai_res.get("confidence", 0)
                if ai_conf > behav_conf:
                    behavior = ai_res.get("scenario", behavior)
                    behav_conf = ai_conf
                    reasoning += "+llm_override"
                if ai_res.get("algo", "Unknown") != "Unknown" and final_algo == "Unknown":
                    final_algo = ai_res["algo"]
                self.log(f"  -> 🤖 LLM: {behavior} (conf={behav_conf})")

        self.log(f"  -> ✅ Final: {final_algo} | {behavior} "
                 f"(algo_conf={algo_conf}, behav_conf={behav_conf}, "
                 f"sinks=[angr:{len(dfg['sinks'])},mlil:{len(mlil_sinks)},s2:{len(step2_sinks)}], "
                 f"src={source_type}, reason={reasoning})")

        # ---- [V2-需求2] 调用链重建 ----
        self.diag(f"STEP-9: _get_call_chain()")
        call_chain = self._get_call_chain(bv, func_addr)

        # ---- 过滤判定 ----
        self.diag(f"STEP-10: filter check")
        # [V4-Fix] 大幅放宽: Step2 已筛选目标函数, Step3 不应再大面积丢弃
        # 只在以下 *极端* 情况丢弃:
        #   - angr 什么都没跑出来 (trace=0)
        #   - 没有检测到 sink
        #   - 算法投票完全失败 (Unknown 且 conf=0)
        #   - Step2 也没给任何上下文
        #   - 没有任何 key material
        is_truly_empty = (
            dfg['trace_len'] == 0
            and not dfg['sinks']
            and final_algo == "Unknown"
            and algo_conf == 0
            and not dfg['key_candidates']
            and not static_votes
        )
        if is_truly_empty:
            self.log(f"  -> ⊘ Dropped: truly empty (no trace, no votes, no keys)")
            self.diag(f"STEP-11: DROPPED (truly_empty)")
            return None

        self.diag(f"STEP-11: PASSED filter, assembling report")

        sample_name = os.path.basename(task.get("sample", ""))
        report = {
            "sample": sample_name,
            "path_id": path_id,
            "function": task['target_func'],
            "function_name": task.get("target_func_name", ""),
            "algorithm": final_algo,
            "algo_confidence": algo_conf,
            "algo_vote_detail": vote_detail,
            "behavior": behavior,
            "behavior_confidence": behav_conf,
            "behavior_reasoning": reasoning,
            "chain_verified": chain_verified,  # V5: 使用校正后的值
            "attack_chain": attack_chain,
            "call_chain": call_chain[:MAX_CALL_CHAIN_DEPTH],
            "data_flow": {
                "taint_source": dfg['taint_source'],
                "sinks": merged_sinks,  # V5: 三源合并 sinks
                "trace_len": dfg['trace_len'],
                "return_tainted": dfg['return_tainted'],
                "detected_algo": dfg['detected_algo'],
                "detected_constants": dfg.get('detected_constants', []),
                "key_candidates_count": len(dfg['key_candidates']),
            },
            # 透传 Step2 上下文供后续审计
            "step2_semantic": task.get("semantic", {}),
            "step2_taint_summary": task.get("evidence", {}).get("taint_summary", {}),
        }

        keys = []
        for k in dfg['key_candidates']:
            keys.append({
                "sample": sample_name,
                "key_hex": k['hex'],
                "location": k['loc'],
                "entropy": k.get('entropy', 0),
                "algo": final_algo,
                "behavior": behavior,
                "function": task['target_func'],
            })

        self.diag(f"STEP-12: returning report algo={final_algo} behav={behavior} keys={len(keys)}")
        return {"report": report, "keys": keys}

    # ------------------------------------------------------------------
    # [V2-需求2] 引导式符号执行
    # ------------------------------------------------------------------

    def _exec_taint_analysis(self, proj, addr, api_map, task, guided):
        """[V3] 引导式符号执行 — 修复 find_addrs 未使用、单状态检查、循环卡死"""
        report = {
            "taint_source": "Unknown",
            "sinks": [],
            "key_candidates": [],
            "trace_len": 0,
            "return_tainted": False,
            "detected_algo": "Unknown",
            "detected_constants": [],
        }

        start = time.time()
        steps = 0

        try:
            self.diag(f"  angr: call_state({hex(addr)})")
            state = proj.factory.call_state(addr)
            state.options.add(self.angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            state.options.add(self.angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            # [V3] LAZY_SOLVES: 延迟约束求解, 大幅提升性能
            state.options.add(self.angr.options.LAZY_SOLVES)

            # [V5-Fix2] Hook 所有外部调用为 ReturnUnconstrained
            # 防止 angr 遇到外部调用立即 deadend (steps=4 的根因)
            try:
                for sym in proj.loader.main_object.symbols:
                    if sym.is_import and sym.name:
                        if not proj.is_hooked(sym.rebased_addr):
                            proj.hook(sym.rebased_addr,
                                      self.angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](),
                                      replace=True)
            except Exception:
                pass

            self.diag(f"  angr: state created, injecting taint")

            bit_width = 64 if 'AMD64' in proj.arch.name else 32
            taint_vars = [
                self.claripy.BVS(f"taint_arg_{i}", bit_width) for i in range(4)
            ]
            self._inject_taint(proj, state, taint_vars)

            # 从 Step2 evidence 获取 taint source
            sources = guided.get("sources", [])
            if sources and sources[0] != "FuncArgs":
                report["taint_source"] = sources[0]
            else:
                report["taint_source"] = (
                    task.get('evidence', {})
                    .get('input_from_source', ['FuncArgs'])[0]
                )

            # 密钥提取 hook
            self._setup_key_extraction(state, report, guided)

            # 动态常量检测 hook
            def crypto_const_hook(s):
                if s.inspect.mem_read_address.concrete:
                    try:
                        val = s.memory.load(
                            s.inspect.mem_read_address, 4,
                            endness=proj.arch.memory_endness
                        )
                        if val.concrete:
                            v = s.solver.eval(val)
                            algo_name = CRYPTO_CONSTANTS.get(v)
                            if algo_name:
                                if report["detected_algo"] == "Unknown":
                                    report["detected_algo"] = algo_name
                                entry = f"{algo_name}@{hex(v)}"
                                if entry not in report["detected_constants"]:
                                    report["detected_constants"].append(entry)
                    except Exception:
                        pass

            state.inspect.b('mem_read', when=self.angr.BP_AFTER,
                          action=crypto_const_hook)

            # ---- [V3-Fix1] 收集引导地址: Step2 的 sink 地址 + API 地址 ----
            find_addrs = set()
            for sink_addr_str in guided.get("forward_addrs", [])[:10]:
                try:
                    find_addrs.add(int(sink_addr_str, 16))
                except Exception:
                    pass

            # 同时把 api_map 中的地址加入引导集
            guided_api_addrs = set(api_map.keys())

            simgr = proj.factory.simulation_manager(state)
            self.diag(f"  angr: simgr created, setting up techniques")

            # ---- [V3-Fix4] LoopSeer + DFS 混合策略 ----
            # LoopSeer: 限制循环展开次数, 防止在 crypto 循环中无限迭代
            try:
                simgr.use_technique(
                    self.angr.exploration_techniques.LoopSeer(
                        bound=LOOP_BOUND, limit_concrete_loops=True
                    )
                )
            except Exception:
                pass  # LoopSeer 不可用时 fallback 到纯 DFS
            simgr.use_technique(self.angr.exploration_techniques.DFS())

            # [V3-Fix3] 地址访问频率计数 — 检测并裁剪无限循环状态
            addr_visit_count = defaultdict(int)

            self.diag(f"  angr: entering simulation loop, active={len(simgr.active)}")

            start = time.time()
            steps = 0

            while simgr.active:
                if time.time() - start > ANGR_TIMEOUT:
                    self.log(f"    ⏰ Angr timeout at step {steps}")
                    break
                if steps >= ANGR_MAX_STEPS:
                    break

                # ---- [V3-Fix1] 引导探索: 检查是否有状态到达了 find_addrs ----
                if find_addrs:
                    reached = [
                        s for s in simgr.active
                        if s.addr in find_addrs
                    ]
                    for rs in reached:
                        self._check_all_sinks_on_state(rs, api_map, report)
                        # 不移除状态, 继续探索它的后续路径

                try:
                    simgr.step()
                except Exception:
                    if simgr.active:
                        simgr.active.pop(0)
                    continue

                if not simgr.active:
                    break

                steps += 1

                # ---- [V3-Fix2] 检查 *所有* 活跃状态的 API 命中 ----
                for s in list(simgr.active):
                    report["trace_len"] += 1

                    # 地址访问频率统计
                    addr_visit_count[s.addr] += 1

                    self._check_all_sinks_on_state(s, api_map, report)

                # ---- [V3-Fix3] 智能状态裁剪 ----
                if len(simgr.active) > ANGR_PRUNE_TRIGGER:
                    simgr.active = self._prune_states(
                        simgr.active, api_map, guided_api_addrs,
                        find_addrs, addr_visit_count
                    )

                # [V3-Fix3] 移除卡在同一地址的状态
                simgr.active = [
                    s for s in simgr.active
                    if addr_visit_count[s.addr] <= ADDR_VISIT_LIMIT
                ]

            # 检查返回值污点: 遍历所有 deadended 状态 (不限 2 个)
            self.diag(f"  angr: loop ended, steps={steps}, checking deadended states")
            for dead in simgr.deadended[:10]:
                if self._check_is_tainted(dead, -1):
                    report["return_tainted"] = True
                    break

            # [V3] 也检查 spinning 出来的状态 (LoopSeer 产生)
            for spinning in getattr(simgr, 'spinning', [])[:5]:
                self._check_all_sinks_on_state(spinning, api_map, report)

        except Exception as e:
            self.log(f"    Angr Error: {e}")
            self.diag(f"  angr: EXCEPTION: {type(e).__name__}: {e}")

        # [V4-Fix] 诊断日志: angr 执行摘要
        elapsed = time.time() - start
        self.log(f"    angr: steps={steps}, trace={report['trace_len']}, "
                 f"sinks={len(report['sinks'])}, keys={len(report['key_candidates'])}, "
                 f"algo={report['detected_algo']}, {elapsed:.1f}s")
        self.diag(f"  angr: DONE steps={steps} trace={report['trace_len']} sinks={len(report['sinks'])} {elapsed:.1f}s")

        return report

    def _check_all_sinks_on_state(self, s, api_map, report):
        """[V3] 检查单个状态是否命中了 sink API — 提取为独立方法避免重复代码"""
        targets_to_check = [s.addr]

        # 也检查 jump_target
        jump_target = s.history.jump_target
        if jump_target is not None:
            try:
                concrete = s.solver.eval(jump_target)
                targets_to_check.append(concrete)
            except Exception:
                pass

        for target_addr in targets_to_check:
            hit = api_map.get(target_addr)
            if not hit:
                continue
            if self._check_is_tainted(s, hit['arg']):
                sink = f"{hit['tag']}::{hit['name']}"
                if sink not in report["sinks"]:
                    report["sinks"].append(sink)
                    self.log(f"    -> [Taint] Sink: {sink}")

    def _prune_states(self, active, api_map, guided_api_addrs,
                      find_addrs, addr_visit_count):
        """[V3] 评分裁剪: 保留高价值状态, 丢弃低价值状态

        优先保留:
        - 即将命中 API 地址的状态 (距 sink 近)
        - 在 find_addrs 引导集中的状态
        - 访问频率低的状态 (探索新路径)
        - 含有符号变量的状态 (可能传播污点)
        """
        scored = []
        for s in active:
            score = 0

            # 即将命中 monitored API
            if s.addr in guided_api_addrs:
                score += 50

            # 在 Step2 引导地址集中
            if s.addr in find_addrs:
                score += 40

            # 访问频率低 = 探索新路径
            visits = addr_visit_count.get(s.addr, 0)
            if visits <= 1:
                score += 20
            elif visits > ADDR_VISIT_LIMIT:
                score -= 30  # 惩罚循环卡住的状态

            # 寄存器含符号值 (污点传播中)
            try:
                reg = s.regs.eax if 'X86' in s.project.arch.name else s.regs.rax
                if reg.symbolic:
                    score += 15
            except Exception:
                pass

            scored.append((score, s))

        # 按得分排序, 保留 top ANGR_MAX_STATES
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:ANGR_MAX_STATES]]

    def _setup_key_extraction(self, state, report, guided):
        """[V2] 增强密钥提取 — 利用 Step2 key_material 聚焦"""
        state.globals['key_buffer'] = {}

        # [V2] 从 Step2 key_material 获取密钥 API 调用地址
        key_sites = set()
        for km in guided.get("key_material", []):
            site = km.get("site")
            if site:
                try:
                    key_sites.add(int(site, 16))
                except Exception:
                    pass
        state.globals['key_sites'] = key_sites

        def on_mem_write(s):
            try:
                addr_expr = s.inspect.mem_write_address
                val_expr = s.inspect.mem_write_expr
                if not addr_expr.concrete or not val_expr.concrete:
                    return
                addr = s.solver.eval(addr_expr)
                val_bytes = s.solver.eval(val_expr, cast_to=bytes)
                buf = s.globals['key_buffer']

                # 合并相邻写入
                merged = False
                for base in list(buf.keys()):
                    offset = addr - base
                    if 0 <= offset < 64:
                        curr_len = len(buf[base])
                        req_len = offset + len(val_bytes)
                        if req_len > curr_len:
                            buf[base].extend(b'\x00' * (req_len - curr_len))
                        buf[base][offset:offset + len(val_bytes)] = val_bytes
                        merged = True
                        break
                if not merged:
                    buf[addr] = bytearray(val_bytes)

                # 检查是否达到密钥长度
                for base, data in list(buf.items()):
                    if len(data) >= 16:
                        ent = _entropy(bytes(data[:32]))
                        if ent > 3.6 and not _is_mostly_ascii(bytes(data[:32])):
                            h = bytes(data[:32]).hex()
                            if len(report['key_candidates']) < MAX_KEY_CANDIDATES:
                                if not any(k['hex'] == h for k in report['key_candidates']):
                                    # [V2] 标记是否在 key_site 附近提取
                                    near_key_api = any(
                                        abs(base - ks) < 0x1000
                                        for ks in s.globals.get('key_sites', set())
                                    )
                                    report['key_candidates'].append({
                                        "hex": h,
                                        "loc": hex(base),
                                        "entropy": round(ent, 2),
                                        "near_key_api": near_key_api,
                                    })
            except Exception:
                pass

        state.inspect.b('mem_write', when=self.angr.BP_BEFORE, action=on_mem_write)

    def _inject_taint(self, proj, state, taint_vars):
        if 'AMD64' in proj.arch.name:
            for r, v in zip(['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'], taint_vars):
                setattr(state.regs, r, v)
        elif 'X86' in proj.arch.name:
            for i, v in enumerate(taint_vars):
                state.memory.store(
                    state.regs.esp + 4 * (i + 1), v,
                    endness=proj.arch.memory_endness
                )

    def _check_is_tainted(self, state, arg_idx):
        try:
            val = None
            if arg_idx == -1:
                val = (state.regs.eax if 'X86' in state.project.arch.name
                       else state.regs.rax)
            elif 'AMD64' in state.project.arch.name:
                regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
                if arg_idx < len(regs):
                    val = getattr(state.regs, regs[arg_idx])
            elif 'X86' in state.project.arch.name:
                val = state.memory.load(
                    state.regs.esp + 4 * (arg_idx + 1), 4,
                    endness=state.project.arch.memory_endness
                )

            if val is not None and val.symbolic:
                for v in val.variables:
                    if "taint_" in v:
                        return True

            # 检查指针解引用
            if val is not None and val.concrete:
                try:
                    mem = state.memory.load(val, 8)
                    if mem.symbolic:
                        for v in mem.variables:
                            if "taint_" in v:
                                return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # 静态扫描
    # ------------------------------------------------------------------

    def _scan_and_link_crypto_tables(self, bv):
        matches = []
        for section in bv.sections.values():
            if section.name not in [".rdata", ".data"]:
                continue
            try:
                size = min(section.end - section.start, 1024 * 1024)
                data = bv.read(section.start, size)
                for name, sig in CRYPTO_SIGNATURES.items():
                    if sig in data:
                        offset = data.find(sig)
                        addr = section.start + offset
                        refs = list(bv.get_code_refs(addr))
                        matches.append({
                            "algo": name,
                            "addr": hex(addr),
                            "referencing_funcs": [
                                hex(r.function.start) for r in refs if r.function
                            ],
                        })
            except Exception:
                pass
        return matches

    def _scan_static_keys(self, bv):
        keys = []
        for section in bv.sections.values():
            if section.name not in [".data", ".rdata"]:
                continue
            try:
                size = min(section.end - section.start, 512000)
                data = bv.read(section.start, size)
                for i in range(0, len(data) - 16, 16):
                    chunk = data[i:i + 16]
                    ent = _entropy(chunk)
                    if ent > 3.6 and not _is_mostly_ascii(chunk):
                        if len(list(bv.get_code_refs(section.start + i))) > 0:
                            keys.append({
                                "hex": chunk.hex(),
                                "loc": hex(section.start + i),
                                "entropy": round(ent, 2),
                            })
            except Exception:
                pass
        return keys

    def _build_global_api_map(self, bv):
        api_map = {}
        for sym in bv.get_symbols():
            if "Import" in str(sym.type):
                clean = sym.name.lower()
                for k, v in API_BEHAVIOR_MAP.items():
                    if k in clean:
                        api_map[sym.address] = {
                            "name": k, "arg": v["arg"],
                            "check": v["check"], "tag": v["tag"],
                        }
        return api_map

    # ------------------------------------------------------------------
    # [V2-增强] Source 分类 — 综合 Step2 evidence
    # ------------------------------------------------------------------

    def _classify_source(self, source_str, sinks, step2_sources):
        """综合 Step2 已识别的 source 和动态 sink 判断数据来源类型"""
        all_tokens = (
            str(source_str) + " "
            + " ".join(sinks) + " "
            + " ".join(str(s) for s in step2_sources)
        ).lower()

        if any(x in all_tokens for x in (
            "recv", "socket", "http", "download", "internet", "winhttp",
            "c2_recv", "payload_download", "connect", "wsastartup",
            "internetopen", "winhttpopen", "urldownload",
        )):
            return "Network"
        if any(x in all_tokens for x in (
            "readfile", "fread", "file_read", "fopen", "createfile",
        )):
            return "File"
        if any(x in all_tokens for x in ("registry", "regquery", "regopenkey")):
            return "Registry"
        if any(x in all_tokens for x in (
            "getmodulehandle", "loadlibrary", "getprocaddress", "module_resolve",
        )):
            return "Module"
        if any(x in all_tokens for x in (
            "virtualalloc", "heapalloc", "payload_mem_alloc",
        )):
            return "Memory"
        if any(x in all_tokens for x in (
            "cryptimport", "cryptgen", "bcryptgenerate", "crypto_api_key",
        )):
            return "CryptoKey"
        return "Unknown"

    # ------------------------------------------------------------------
    # [V2-需求3] LLM 增强分析 — 完整上下文
    # ------------------------------------------------------------------

    def _llm_enhanced_classify(self, task, dfg, algo, source_type, algo_conf):
        """带完整 Step1/Step2/Step3 上下文的 LLM 行为研判"""
        if not self.client:
            return None

        # 构造丰富的 prompt
        algo_ctx = task.get("step1_algo_context", {})
        evidence = task.get("evidence", {})
        semantic = task.get("semantic", {})

        step1_info = ""
        yara_tags = algo_ctx.get("step1_yara_tags", [])
        if yara_tags:
            step1_info = f"Step1 YARA Tags: {yara_tags}"

        step2_info = (
            f"Step2 Algo: {semantic.get('algo', 'Unknown')} "
            f"(conf={semantic.get('confidence', 0)}, "
            f"chain_verified={semantic.get('chain_verified', False)})"
        )

        opcode_matches = evidence.get("opcode_fingerprint_matches", [])
        opcode_info = ""
        if opcode_matches:
            opcode_info = f"Opcode Fingerprint: {opcode_matches[0].get('algo_pattern', '?')}"

        key_info = ""
        km = evidence.get("key_material", [])
        if km:
            key_info = f"Key APIs: {[k.get('api') for k in km[:3]]}"

        prompt = f"""Analyze malware function and classify adversarial behavior.

[Multi-Stage Evidence]
{step1_info}
{step2_info}
{opcode_info}
{key_info}

[Step3 Dynamic Analysis]
Algorithm Identified: {algo} (confidence: {algo_conf})
Source Type: {source_type}
Taint Sinks: {dfg['sinks']}
Dynamic Constants: {dfg.get('detected_constants', [])}
Trace Length: {dfg['trace_len']} blocks
Return Tainted: {dfg['return_tainted']}
Key Candidates Found: {len(dfg['key_candidates'])}

[Context]
Function: {task.get('target_func')} ({task.get('target_func_name', '?')})
Chain Type: {task.get('chain_type')}
Step2 Sources: {evidence.get('input_from_source', [])}
Step2 Sinks: {evidence.get('output_to_sink', [])}

[Task]
1) Confirm or refine the crypto algorithm identification.
2) Determine the adversarial behavior scenario.
   Must be one of: Payload_Decryption_Loading, C2_Command_Execution,
   Data_Exfiltration, Ransomware_Encryption.
3) Provide confidence 0-100.
Return JSON: {{"algo":"...","scenario":"<one_of_4>","confidence":int}}"""

        try:
            resp = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": LLM_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                timeout=45,
            )
            parsed = json.loads(resp.choices[0].message.content)
            return parsed
        except Exception as e:
            self.log(f"    LLM Error: {e}")
            return None


# ==============================================================================
# 6. 工具函数
# ==============================================================================

def _entropy(data):
    if not data:
        return 0.0
    e = 0.0
    length = len(data)
    for x in range(256):
        p = float(data.count(x)) / length
        if p > 0:
            e += -p * math.log(p, 2)
    return e


def _is_mostly_ascii(data):
    if not data:
        return True
    return (sum(1 for b in data if 32 <= b <= 126) / len(data)) > 0.4


# ==============================================================================
# 7. Final Report 生成器
# ==============================================================================

class FinalReportGenerator:
    """汇总所有样本分析结果, 生成 step3_final_report.json"""

    @staticmethod
    def generate(all_results, all_keys, output_path):
        """
        all_results: {path_id: report_dict, ...}
        all_keys: [key_record, ...]
        """
        # 按样本聚合
        sample_map = defaultdict(lambda: {
            "functions": [],
            "algorithms": set(),
            "behaviors": set(),
            "key_count": 0,
            "chain_verified_count": 0,
            "total_targets": 0,
        })

        for path_id, report in all_results.items():
            sample = report.get("sample", "unknown")
            entry = sample_map[sample]
            entry["total_targets"] += 1

            entry["functions"].append({
                "path_id": path_id,
                "function": report.get("function"),
                "function_name": report.get("function_name"),
                "algorithm": report.get("algorithm"),
                "algo_confidence": report.get("algo_confidence"),
                "behavior": report.get("behavior"),
                "behavior_confidence": report.get("behavior_confidence"),
                "chain_verified": report.get("chain_verified", False),
                "attack_chain": report.get("attack_chain", []),
                "call_chain": report.get("call_chain", []),
                "data_flow_summary": {
                    "sinks": report.get("data_flow", {}).get("sinks", []),
                    "trace_len": report.get("data_flow", {}).get("trace_len", 0),
                    "detected_algo": report.get("data_flow", {}).get("detected_algo"),
                },
            })

            algo = report.get("algorithm", "Unknown")
            if algo and algo != "Unknown":
                entry["algorithms"].add(algo)
            behav = report.get("behavior", "Unknown")
            if behav and behav != "Unknown":
                entry["behaviors"].add(behav)
            if report.get("chain_verified"):
                entry["chain_verified_count"] += 1

        # 密钥按样本聚合
        keys_by_sample = defaultdict(list)
        for k in all_keys:
            keys_by_sample[k.get("sample", "unknown")].append(k)

        # 构建最终报告
        samples = []
        algo_counter = defaultdict(int)
        behav_counter = defaultdict(int)

        for sample_name, entry in sorted(sample_map.items()):
            entry["algorithms"] = sorted(entry["algorithms"])
            entry["behaviors"] = sorted(entry["behaviors"])
            entry["key_count"] = len(keys_by_sample.get(sample_name, []))

            for a in entry["algorithms"]:
                algo_counter[a] += 1
            for b in entry["behaviors"]:
                behav_counter[b] += 1

            samples.append({
                "sample": sample_name,
                "summary": {
                    "algorithms": entry["algorithms"],
                    "behaviors": entry["behaviors"],
                    "total_targets": entry["total_targets"],
                    "chain_verified": entry["chain_verified_count"],
                    "keys_extracted": entry["key_count"],
                },
                "functions": entry["functions"],
                "keys": keys_by_sample.get(sample_name, []),
            })

        report = {
            "metadata": {
                "version": "Step3_V4",
                "generated_at": datetime.datetime.now().isoformat(),
                "total_samples": len(samples),
                "total_functions_analyzed": len(all_results),
                "total_keys_extracted": len(all_keys),
            },
            "statistics": {
                "algorithm_distribution": dict(
                    sorted(algo_counter.items(), key=lambda x: -x[1])
                ),
                "behavior_distribution": dict(
                    sorted(behav_counter.items(), key=lambda x: -x[1])
                ),
            },
            "samples": samples,
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        return report


# ==============================================================================
# 8. 主程序入口 — [V4-Fix2] 单进程顺序执行 (避免 angr C 库 fork 崩溃)
# ==============================================================================


def main():
    print(f"🚀 Step 3 V4: Enhanced Analysis Platform (Single-Process)")
    print(f"   - Input:  {INPUT_BLUEPRINT}")
    print(f"   - Report: {OUTPUT_FINAL_REPORT}")
    print(f"   - Keys:   {OUTPUT_KEYS_L}")
    print(f"   - Log:    {GLOBAL_LOG_FILE}")

    # 清空输出
    with open(OUTPUT_KEYS_L, 'w', encoding='utf-8'):
        pass
    with open(OUTPUT_BEHAVIOR_L, 'w', encoding='utf-8'):
        pass
    # 清空临时目录
    if os.path.exists(TEMP_DIR):
        for f in os.listdir(TEMP_DIR):
            try:
                os.remove(os.path.join(TEMP_DIR, f))
            except Exception:
                pass

    if not os.path.exists(INPUT_BLUEPRINT):
        print(f"❌ Blueprint not found: {INPUT_BLUEPRINT}")
        return

    task_map = BlueprintParser.parse(INPUT_BLUEPRINT)
    total_tasks = sum(len(v) for v in task_map.values())
    print(f"   - Samples: {len(task_map)}, Tasks: {total_tasks}")

    if not task_map:
        print("⚠️ No tasks to process.")
        return

    pbar = tqdm(total=len(task_map), unit="sample")
    log_f = open(GLOBAL_LOG_FILE, 'a', encoding='utf-8')

    all_results = {}
    all_keys = []

    # [V4-Fix2] 单进程: 只创建一次 WorkerEngine, 复用 angr/binaryninja 实例
    engine = None

    try:
        for sample, t_list in task_map.items():
            pbar.set_description(f"Analyzing {sample[:12]}")
            sample_start = time.time()

            try:
                # 每个样本新建 engine (需要不同的 sample_name 用于日志)
                engine = WorkerEngine(KEY_FILE, sample, log_file_handle=log_f)
                bin_path = os.path.join(TARGET_DIR, sample)
                results, extracted = engine.run_analysis(bin_path, t_list)

                # 汇总结果
                if results:
                    all_results.update(results)
                    with open(OUTPUT_BEHAVIOR_L, 'a', encoding='utf-8') as bf:
                        for path_id, report in results.items():
                            bf.write(json.dumps(report, default=str) + "\n")

                if extracted:
                    all_keys.extend(extracted)
                    with open(OUTPUT_KEYS_L, 'a', encoding='utf-8') as kf:
                        for k in extracted:
                            kf.write(json.dumps(k, default=str) + "\n")

                elapsed = time.time() - sample_start
                res_count = len(results) if results else 0
                ext_count = len(extracted) if extracted else 0
                log_f.write(f"[Main] {sample[:12]}: results={res_count}, "
                            f"keys={ext_count}, {elapsed:.1f}s\n")
                log_f.flush()

            except Exception as e:
                log_f.write(f"!!! [Main] {sample[:12]}: Exception: {type(e).__name__}: {e}\n")
                log_f.flush()
                log_f.write(traceback.format_exc() + "\n")
                log_f.flush()

            pbar.update(1)
            pbar.set_postfix(results=len(all_results), keys=len(all_keys))

            # [V4-Fix2] 单进程内存管理: 每个样本后清理
            gc.collect()

    finally:
        log_f.close()

    # 生成最终报告
    print(f"\n📊 Generating final report...")
    report = FinalReportGenerator.generate(all_results, all_keys, OUTPUT_FINAL_REPORT)

    stats = report.get("statistics", {})
    meta = report.get("metadata", {})

    print(f"\n✅ Analysis Complete.")
    print(f"   Samples:   {meta.get('total_samples', 0)}")
    print(f"   Functions: {meta.get('total_functions_analyzed', 0)}")
    print(f"   Keys:      {meta.get('total_keys_extracted', 0)}")
    print(f"   Algo Dist: {stats.get('algorithm_distribution', {})}")
    print(f"   Behav Dist: {stats.get('behavior_distribution', {})}")
    print(f"   Report:    {OUTPUT_FINAL_REPORT}")


if __name__ == "__main__":
    STACK_SIZE = 128 * 1024 * 1024  # 128 MB
    threading.stack_size(STACK_SIZE)
    t = threading.Thread(target=main)
    t.start()
    t.join()