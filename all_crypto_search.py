#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Step 4 — 恶意样本加密行为综合分析与可视化平台
==============================================================================
消费 Step1/Step2/Step3 全链路输出, 对每个样本:
  1) 展示数据流分析平台 (Source→Crypto→Sink 拓扑图)
  2) 生成分析结果图片 (算法识别、行为判定、污点追踪)
  3) 识别加密类对抗行为 (载荷解密、C2命令、数据窃取、勒索加密)
  4) 定位攻击载荷污点源、密码参数存储、C2接收执行、敏感数据窃取点
==============================================================================
"""

import os
import re
import sys
import json
import math
import logging
import hashlib
import datetime
import threading
from collections import defaultdict, Counter, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(it, **kw):
        return it

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import matplotlib.gridspec as gridspec
    from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, ArrowStyle
    from matplotlib.lines import Line2D
    import matplotlib.patheffects as pe
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False
    logging.warning("matplotlib not available — visualization disabled")

try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    HAS_NX = False

# ==============================================================================
# 配置
# ==============================================================================

BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR       = os.path.join(BASE_DIR, "output")
STEP1_CANDIDATES = os.path.join(OUTPUT_DIR, "step1_crypto_candidates.jsonl")
STEP2_BLUEPRINT  = os.path.join(OUTPUT_DIR, "step2_angr_blueprint.jsonl")
STEP2_REPORT     = os.path.join(OUTPUT_DIR, "step2_behavior_report.jsonl")
STEP3_REPORT     = os.path.join(OUTPUT_DIR, "step3_final_report.json")
STEP3_KEYS       = os.path.join(OUTPUT_DIR, "step3_extracted_keys.jsonl")

# Step4 输出
GRAPH_DIR        = os.path.join(OUTPUT_DIR, "step4_graphs")
OUTPUT_REPORT    = os.path.join(OUTPUT_DIR, "step4_final_report.json")
OUTPUT_JSONL     = os.path.join(OUTPUT_DIR, "step4_per_function.jsonl")

KEY_FILE         = os.path.join(BASE_DIR, "api_key.txt")
MAX_WORKERS      = 4
MAX_TRACE_LINES  = 40
MAX_GRAPH_NODES  = 30

# LLM 相关
LLM_TIMEOUT      = 60

# 线程锁
file_lock  = threading.Lock()
graph_lock = threading.Lock()

os.makedirs(GRAPH_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

# ==============================================================================
# 1. 算法签名常量库 (与前三步共享)
# ==============================================================================

SIG_DB = {
    0x9E3779B9: ("TEA/XTEA", 10),    0x61C88647: ("TEA/XTEA", 10),
    0x9E3779B1: ("XXHash", 5),         0x61707865: ("ChaCha/Salsa", 10),
    0x3320646E: ("ChaCha/Salsa", 8),   0x79622D32: ("ChaCha/Salsa", 8),
    0x6B206574: ("ChaCha/Salsa", 8),
    0x6A09E667: ("SHA256", 8),         0xBB67AE85: ("SHA256", 6),
    0x3C6EF372: ("SHA256", 5),         0x510E527F: ("SHA256", 5),
    0x67452301: ("MD5/SHA1", 6),       0xEFCDAB89: ("MD5/SHA1", 6),
    0x98BADCFE: ("MD5/SHA1", 5),       0x10325476: ("MD5/SHA1", 5),
    0xD76AA478: ("MD5", 8),            0xE8C7B756: ("MD5", 6),
    0x5A827999: ("SHA1", 6),           0x6ED9EBA1: ("SHA1", 6),
    0x8F1BBCDC: ("SHA1", 5),           0xCA62C1D6: ("SHA1", 5),
    0xB7E15163: ("RC5/RC6", 8),        0x9E3779B9: ("TEA/XTEA", 10),
    0xA3B1BAC6: ("SM4", 10),           0x56AA3350: ("SM4", 8),
    0xB27022DC: ("SM4", 8),
    0x01000000: ("CRC_Poly", 3),
    0x6C078965: ("MT19937", 6),
    0xB0000000 | 0x01: ("Blowfish", 4),
    0x243F6A88: ("Blowfish", 7),       0x85A308D3: ("Blowfish", 6),
    0xCBBB9D5D: ("SHA512", 7),         0x629A292A: ("SHA512", 5),
    0x9159015A: ("SHA512", 5),
    0x63707865: ("Salsa20", 8),
    0x0FC19DC6: ("AES_RCON", 6),       0x8C000000: ("AES_RCON", 4),
    0xC6EF3720: ("TEA_SUM_Final", 9),
}

NOISE_CONSTS = {
    0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0xFF,
    0x100, 0x200, 0x400, 0x800, 0x1000, 0x10000, 0x100000,
    0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
}

# ==============================================================================
# 2. 行为场景定义与颜色主题
# ==============================================================================

SCENARIO_META = {
    "Payload_Decryption_Loading": {
        "label":    "攻击载荷解密释放",
        "label_en": "Payload Decryption & Loading",
        "icon":     "💉",
        "color":    "#E53935",   # 红
        "light":    "#FFCDD2",
        "desc":     "接收加密载荷 → 解密 → 注入/执行",
        "source_type": "Network",
        "typical_sources": ["recv", "InternetReadFile", "WinHttpReadData", "URLDownloadToFile"],
        "typical_sinks":   ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection"],
    },
    "C2_Command_Execution": {
        "label":    "C2命令解密执行",
        "label_en": "C2 Command Decryption & Execution",
        "icon":     "🎯",
        "color":    "#FF6F00",   # 橙
        "light":    "#FFE0B2",
        "desc":     "接收加密C2指令 → 解密 → 执行",
        "source_type": "Network",
        "typical_sources": ["recv", "InternetReadFile", "HttpQueryInfo"],
        "typical_sinks":   ["CreateProcess", "WinExec", "ShellExecute", "system", "cmd.exe"],
    },
    "Data_Exfiltration": {
        "label":    "敏感数据加密传输",
        "label_en": "Sensitive Data Encryption & Exfiltration",
        "icon":     "📤",
        "color":    "#1565C0",   # 蓝
        "light":    "#BBDEFB",
        "desc":     "读取敏感数据 → 加密 → 外传",
        "source_type": "File/Registry",
        "typical_sources": ["ReadFile", "RegQueryValueEx", "CryptUnprotectData"],
        "typical_sinks":   ["send", "WSASend", "InternetWriteFile", "HttpSendRequest"],
    },
    "Ransomware_Encryption": {
        "label":    "勒索加密",
        "label_en": "Ransomware Encryption",
        "icon":     "🔐",
        "color":    "#6A1B9A",   # 紫
        "light":    "#E1BEE7",
        "desc":     "遍历文件 → 加密 → 写回",
        "source_type": "File",
        "typical_sources": ["ReadFile", "FindFirstFile", "FindNextFile"],
        "typical_sinks":   ["WriteFile", "MoveFile", "DeleteFile"],
    },
    "Unknown_Crypto_Operation": {
        "label":    "未分类加密操作",
        "label_en": "Unclassified Crypto Operation",
        "icon":     "❓",
        "color":    "#757575",
        "light":    "#E0E0E0",
        "desc":     "存在加密/哈希操作但行为链不完整",
        "source_type": "Unknown",
        "typical_sources": [],
        "typical_sinks":   [],
    },
}

# 算法族颜色
ALGO_FAMILY_COLORS = {
    "Symmetric":   "#1E88E5",
    "Stream":      "#43A047",
    "Hash":        "#FB8C00",
    "Asymmetric":  "#8E24AA",
    "Packer":      "#E53935",
    "Obfuscation": "#6D4C41",
    "Unknown":     "#9E9E9E",
}

# ==============================================================================
# 3. 工具函数
# ==============================================================================

def load_api_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE).read().strip()
    return os.environ.get("DEEPSEEK_API_KEY", "")


def safe_name(s):
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', str(s))[:60]


def normalize_family(name):
    if not name:
        return "Unknown"
    s = str(name).lower()
    if any(k in s for k in ("aes", "des", "3des", "blowfish", "sm4", "camellia", "aria",
                            "tea", "xtea", "rc5", "rc6", "twofish", "serpent")):
        return "Symmetric"
    if any(k in s for k in ("rc4", "chacha", "salsa", "rabbit", "spritz", "sosemanuk")):
        return "Stream"
    if any(k in s for k in ("md5", "sha", "ripemd", "crc", "whirlpool", "siphash", "blake")):
        return "Hash"
    if any(k in s for k in ("rsa", "dsa", "ecdsa", "curve25519", "ed25519", "dh")):
        return "Asymmetric"
    if any(k in s for k in ("upx", "vmprotect", "themida", "packer")):
        return "Packer"
    if any(k in s for k in ("xor_loop", "obfusc", "custom_xor", "base64")):
        return "Obfuscation"
    return "Unknown"


def aggregate_signature_hits(artifacts):
    """从常量列表中聚合算法签名命中"""
    algo_map = defaultdict(lambda: {"hit_count": 0, "total_score": 0, "values": [],
                                     "has_unique": False})
    for a in (artifacts or []):
        for tag in a.get("tags", []):
            parts = tag.split(":")
            if len(parts) >= 3:
                algo = parts[0]
                entry = algo_map[algo]
                entry["hit_count"] += 1
                entry["total_score"] += a.get("score", 0)
                entry["values"].append(a.get("hex", ""))
                w = int(parts[2]) if parts[2].isdigit() else 0
                if w >= 8:
                    entry["has_unique"] = True

    results = []
    for algo, info in algo_map.items():
        results.append({"algo": algo, **info})
    results.sort(key=lambda x: x["total_score"], reverse=True)
    return results


class AlgoSignatureMatcher:
    @staticmethod
    def match(val32):
        hits = []
        for sig_val, (algo, weight) in SIG_DB.items():
            if val32 == sig_val:
                hits.append((algo, sig_val, weight))
        return hits


# ==============================================================================
# 4. 多步骤数据加载器 — 消费 Step1/Step2/Step3 全部输出
# ==============================================================================

class MultiStepDataLoader:
    """
    加载并聚合 Step1→Step2→Step3 的全部输出,
    按样本名组织为统一数据结构.
    """

    def __init__(self):
        self.samples = OrderedDict()   # sample_name -> SampleData
        self._load_step1()
        self._load_step2_blueprint()
        self._load_step2_report()
        self._load_step3_report()
        self._load_step3_keys()
        self._cross_link()

    # -- Step1: 候选函数 --
    def _load_step1(self):
        if not os.path.exists(STEP1_CANDIDATES):
            logging.warning(f"Step1 output not found: {STEP1_CANDIDATES}")
            return
        with open(STEP1_CANDIDATES, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # GRAPH_META 类型的行
                if rec.get("_type") == "GRAPH_META":
                    sample = rec.get("sample", "")
                    sd = self._get_sample(sample)
                    sd["graph_meta"] = rec
                    # 提取全局攻击链
                    sd["global_chains"] = rec.get("global_chains", [])
                    sd["all_edges"]     = rec.get("all_edges", [])
                    sd["sbox_tables"]   = rec.get("sbox_tables", [])
                    continue

                sample = rec.get("sample", rec.get("sample_name", "Unknown"))
                sd = self._get_sample(sample)
                func_id = rec.get("id", "")
                sd["step1_funcs"][func_id] = {
                    "addr":           rec.get("addr"),
                    "func_name":      rec.get("func_name"),
                    "trigger_rules":  rec.get("trigger_rules", []),
                    "yara_algo_tags": rec.get("yara_algo_tags", []),
                    "static_algo":    rec.get("static_algo", {}),
                    "behavior":       rec.get("behavior", {}),
                    "topology":       rec.get("topology", {}),
                    "features":       rec.get("features", {}),
                    "analysis_flags": rec.get("analysis_flags", {}),
                }

    # -- Step2: Blueprint (含污点证据) --
    def _load_step2_blueprint(self):
        if not os.path.exists(STEP2_BLUEPRINT):
            logging.warning(f"Step2 blueprint not found: {STEP2_BLUEPRINT}")
            return
        with open(STEP2_BLUEPRINT, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sample = rec.get("sample", "Unknown")
                sd = self._get_sample(sample)
                path_id = rec.get("path_id", "")
                sd["step2_blueprints"][path_id] = {
                    "target_func":      rec.get("target_func"),
                    "target_func_name": rec.get("target_func_name"),
                    "chain_type":       rec.get("chain_type"),
                    "chain_scenario":   rec.get("chain_scenario"),
                    "semantic":         rec.get("semantic", {}),
                    "evidence":         rec.get("evidence", {}),
                    "step1_algo_context": rec.get("step1_algo_context", {}),
                    "path_addrs":       rec.get("path_addrs", []),
                }

    # -- Step2: Behavior Report --
    def _load_step2_report(self):
        if not os.path.exists(STEP2_REPORT):
            return
        with open(STEP2_REPORT, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sample = rec.get("sample", "Unknown")
                sd = self._get_sample(sample)
                func_addr = rec.get("target_func", "")
                sd["step2_reports"][func_addr] = rec

    # -- Step3: Final Report --
    def _load_step3_report(self):
        if not os.path.exists(STEP3_REPORT):
            logging.warning(f"Step3 report not found: {STEP3_REPORT}")
            return
        with open(STEP3_REPORT, 'r', encoding='utf-8') as f:
            report = json.load(f)
        for sample_entry in report.get("samples", []):
            sample = sample_entry.get("sample", "Unknown")
            sd = self._get_sample(sample)
            sd["step3_summary"] = sample_entry.get("summary", {})
            for func in sample_entry.get("functions", []):
                path_id = func.get("path_id", "")
                sd["step3_funcs"][path_id] = func
            sd["step3_keys"] = sample_entry.get("keys", [])

    # -- Step3: Extracted Keys --
    def _load_step3_keys(self):
        if not os.path.exists(STEP3_KEYS):
            return
        with open(STEP3_KEYS, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sample = rec.get("sample", "Unknown")
                sd = self._get_sample(sample)
                sd["extracted_keys"].append(rec)

    # -- 交叉关联 --
    def _cross_link(self):
        """将 Step2 blueprint 的证据与 Step3 函数结果交叉关联"""
        for sample, sd in self.samples.items():
            # 为每个 Step3 函数关联 Step2 的污点证据
            for path_id, s3_func in sd["step3_funcs"].items():
                if path_id in sd["step2_blueprints"]:
                    bp = sd["step2_blueprints"][path_id]
                    s3_func["_step2_evidence"] = bp.get("evidence", {})
                    s3_func["_step2_semantic"] = bp.get("semantic", {})
                    s3_func["_step2_chain_scenario"] = bp.get("chain_scenario")

            # 建立函数地址→path_id 映射
            sd["addr_to_pathid"] = {}
            for path_id, bp in sd["step2_blueprints"].items():
                addr = bp.get("target_func", "")
                sd["addr_to_pathid"][addr] = path_id

    def _get_sample(self, name):
        if name not in self.samples:
            self.samples[name] = {
                "step1_funcs":      {},
                "step2_blueprints": {},
                "step2_reports":    {},
                "step3_funcs":      {},
                "step3_summary":    {},
                "step3_keys":       [],
                "extracted_keys":   [],
                "graph_meta":       {},
                "global_chains":    [],
                "all_edges":        [],
                "sbox_tables":      [],
                "addr_to_pathid":   {},
            }
        return self.samples[name]


# ==============================================================================
# 5. 对抗行为分析器 — 融合三步证据进行最终行为判定
# ==============================================================================

class AdversarialBehaviorAnalyzer:
    """
    对每个分析目标函数, 融合 Step1/Step2/Step3 证据,
    输出: 行为场景、攻击链、污点定位
    """

    @staticmethod
    def analyze_function(s3_func, step2_evidence, step2_semantic,
                         step1_func_info, extracted_keys):
        """
        返回结构化的行为分析结果
        """
        result = {
            "behavior_scenario": "Unknown_Crypto_Operation",
            "behavior_confidence": 0,
            "algorithm": "Unknown",
            "algo_family": "Unknown",
            "algo_confidence": 0,
            "attack_chain": [],
            "taint_analysis": {
                "taint_sources":    [],
                "crypto_params":    [],
                "c2_command_path":  [],
                "exfil_points":     [],
                "key_material":     [],
            },
            "evidence_summary": [],
            "chain_verified": False,
            "data_flow_verified": False,
        }

        # -- 算法信息 --
        algo = s3_func.get("algorithm", "Unknown")
        algo_conf = s3_func.get("algo_confidence", 0)
        result["algorithm"] = algo
        result["algo_family"] = normalize_family(algo)
        result["algo_confidence"] = algo_conf

        # -- 行为场景判定: 多源融合 --
        s3_behavior = s3_func.get("behavior", "Unknown")
        s3_conf     = s3_func.get("behavior_confidence", 0)
        s2_scenario = s3_func.get("_step2_chain_scenario") or ""
        s2_conf     = (step2_semantic or {}).get("confidence", 0) or 0
        s3_verified = s3_func.get("chain_verified", False)

        # 优先级: Step3 chain_verified > Step2 scenario > Step3 rule
        if s3_behavior and s3_behavior != "Unknown" and s3_conf >= 60:
            result["behavior_scenario"] = s3_behavior
            result["behavior_confidence"] = s3_conf
        elif s2_scenario and s2_scenario.lower() not in ("unknown", "unknown_crypto_operation"):
            result["behavior_scenario"] = s2_scenario
            result["behavior_confidence"] = max(s2_conf, 55)
        elif s3_behavior and s3_behavior != "Unknown":
            result["behavior_scenario"] = s3_behavior
            result["behavior_confidence"] = s3_conf

        result["chain_verified"] = s3_verified

        # -- 攻击链 --
        attack_chain = s3_func.get("attack_chain", [])
        if attack_chain:
            result["attack_chain"] = attack_chain
        else:
            # 从 Step2 证据构建
            result["attack_chain"] = AdversarialBehaviorAnalyzer._build_chain_from_evidence(
                step2_evidence, algo, result["behavior_scenario"]
            )

        # -- 污点分析定位 --
        taint = result["taint_analysis"]
        evidence = step2_evidence or {}

        # 1) 污点源定位
        sources = evidence.get("input_from_source", [])
        backward_trace = evidence.get("backward_trace", [])
        for src_api in sources:
            taint["taint_sources"].append({
                "api": src_api,
                "type": AdversarialBehaviorAnalyzer._classify_source_api(src_api),
                "trace_depth": len(backward_trace),
                "verified": bool(backward_trace),
            })

        # 2) 密码参数存储位置
        key_material = evidence.get("key_material", [])
        for km in key_material:
            taint["crypto_params"].append({
                "api":        km.get("api", ""),
                "call_site":  km.get("site", ""),
                "key_length": km.get("desc", ""),
                "type":       "API Key Import",
            })
        # 补充 Step3 提取的密钥
        for key in (extracted_keys or []):
            taint["key_material"].append({
                "key_hex":   key.get("key_hex", ""),
                "location":  key.get("location", ""),
                "entropy":   key.get("entropy", 0),
                "algo":      key.get("algo", ""),
            })

        # 3) C2命令接收执行过程
        if result["behavior_scenario"] in ("C2_Command_Execution", "Payload_Decryption_Loading"):
            fw_trace = evidence.get("forward_trace", [])
            bw_trace = evidence.get("backward_trace", [])
            sinks = evidence.get("output_to_sink", [])

            c2_path = []
            if sources:
                c2_path.append({"stage": "recv",    "apis": sources[:3],
                                "desc": "C2指令/载荷接收点"})
            if algo and algo != "Unknown":
                c2_path.append({"stage": "decrypt", "algo": algo,
                                "key_info": [km.get("api") for km in key_material[:2]],
                                "desc": "解密处理"})
            if sinks:
                c2_path.append({"stage": "execute", "apis": sinks[:3],
                                "desc": "命令执行/载荷注入"})
            taint["c2_command_path"] = c2_path

        # 4) 敏感数据窃取点
        if result["behavior_scenario"] == "Data_Exfiltration":
            sinks = evidence.get("output_to_sink", [])
            for sink_api in sinks:
                taint["exfil_points"].append({
                    "api": sink_api,
                    "type": AdversarialBehaviorAnalyzer._classify_sink_api(sink_api),
                    "verified": bool(evidence.get("forward_trace")),
                })

        # -- 数据流验证状态 --
        has_bw = bool(evidence.get("backward_trace"))
        has_fw = bool(evidence.get("forward_trace"))
        result["data_flow_verified"] = has_bw or has_fw

        # -- 证据摘要 --
        evid_list = []
        if s3_func.get("algo_vote_detail"):
            evid_list.append(f"三层投票: {json.dumps(s3_func['algo_vote_detail'], ensure_ascii=False)[:120]}")
        if s3_verified:
            evid_list.append("✓ 数据流链路验证通过 (chain_verified)")
        if has_bw:
            evid_list.append(f"← 后向追踪深度: {len(backward_trace)} 层")
        if has_fw:
            evid_list.append(f"→ 前向追踪到 Sink: {evidence.get('output_to_sink', [])[:3]}")
        if key_material:
            evid_list.append(f"🔑 密钥素材: {len(key_material)} 处")
        if extracted_keys:
            evid_list.append(f"🔑 动态提取密钥: {len(extracted_keys)} 个")

        # Step1 YARA/S-Box 证据
        if step1_func_info:
            yara_tags = step1_func_info.get("yara_algo_tags", [])
            if yara_tags:
                evid_list.append(f"YARA算法标签: {yara_tags}")
            sbox = step1_func_info.get("static_algo", {}).get("sbox_confirmed")
            if sbox:
                evid_list.append("S-Box表确认")

        result["evidence_summary"] = evid_list
        return result

    @staticmethod
    def _build_chain_from_evidence(evidence, algo, scenario):
        chain = []
        if not evidence:
            return chain

        sources = evidence.get("input_from_source", [])
        sinks   = evidence.get("output_to_sink", [])
        keys    = evidence.get("key_material", [])

        if sources:
            src_type = "Network" if any(
                k in s.lower() for s in sources
                for k in ("recv", "internet", "http", "socket", "url", "winhttp")
            ) else "File/Registry"
            chain.append({"stage": "Source", "type": src_type, "apis": sources[:5]})

        if algo and algo != "Unknown":
            chain.append({
                "stage": "Crypto", "algo": algo,
                "key_material": [{"api": km.get("api"), "site": km.get("site"),
                                  "desc": km.get("desc")} for km in keys[:3]],
            })

        if sinks:
            chain.append({"stage": "Sink", "apis": sinks[:8]})

        return chain

    @staticmethod
    def _classify_source_api(api):
        s = api.lower()
        if any(k in s for k in ("recv", "internet", "http", "socket", "winhttp", "url")):
            return "Network"
        if any(k in s for k in ("readfile", "fread", "ntopenfile")):
            return "File"
        if any(k in s for k in ("reg", "registry")):
            return "Registry"
        return "Other"

    @staticmethod
    def _classify_sink_api(api):
        s = api.lower()
        if any(k in s for k in ("send", "internet", "http", "wsa")):
            return "Network_Exfil"
        if any(k in s for k in ("createprocess", "winexec", "shellexec", "system")):
            return "Command_Exec"
        if any(k in s for k in ("virtualalloc", "writeprocess", "ntmapview", "createremote")):
            return "Payload_Inject"
        if any(k in s for k in ("writefile", "fwrite")):
            return "File_Write"
        return "Other"


# ==============================================================================
# 6. 可视化引擎 — 每样本生成数据流平台图 + 行为分析图
# ==============================================================================

class SampleVisualizer:
    """为每个样本生成三类图表:
    (A) 数据流分析平台总览图  — Source→Crypto→Sink 拓扑
    (B) 对抗行为分析图       — 按行为场景展示攻击链
    (C) 算法识别与密钥定位图  — 算法投票、密钥存储位置
    """

    def __init__(self):
        if HAS_PLOT:
            plt.rcParams.update({
                'font.size': 9,
                'axes.titlesize': 11,
                'axes.labelsize': 9,
                'figure.dpi': 150,
                'savefig.bbox': 'tight',
                'savefig.pad_inches': 0.2,
            })
            # 尝试设置中文字体
            for font_name in ['SimHei', 'Microsoft YaHei', 'WenQuanYi Micro Hei',
                              'Noto Sans CJK SC', 'PingFang SC', 'Arial Unicode MS',
                              'DejaVu Sans']:
                try:
                    plt.rcParams['font.sans-serif'] = [font_name] + plt.rcParams.get('font.sans-serif', [])
                    break
                except Exception:
                    continue
            plt.rcParams['axes.unicode_minus'] = False

    # ==========================================================================
    # (A) 数据流分析平台总览图
    # ==========================================================================
    def draw_dataflow_platform(self, sample_name, analysis_results, sample_data, out_dir):
        """
        生成该样本的数据流分析平台全景图:
        - 上半部: 函数拓扑图 (Source/Crypto/Sink 节点, 数据流边)
        - 下半部: 各函数的污点追踪摘要
        """
        if not HAS_PLOT:
            return None

        # 收集所有已分析函数
        funcs = []
        for path_id, ar in analysis_results.items():
            s3f = sample_data["step3_funcs"].get(path_id, {})
            funcs.append({
                "path_id":  path_id,
                "name":     s3f.get("function_name") or s3f.get("function") or path_id,
                "addr":     s3f.get("function") or "0x0",
                "scenario": ar["behavior_scenario"],
                "algo":     ar["algorithm"],
                "conf":     ar["behavior_confidence"],
                "chain":    ar["attack_chain"],
                "verified": ar["chain_verified"],
                "taint":    ar["taint_analysis"],
            })

        if not funcs:
            return None

        n_funcs = len(funcs)
        fig_h = max(10, 4 + n_funcs * 2.8)
        fig = plt.figure(figsize=(16, fig_h))

        gs = gridspec.GridSpec(2, 1, height_ratios=[1.0, max(0.8, n_funcs * 0.6)],
                               hspace=0.35)

        # ---- 上半部: 数据流拓扑图 ----
        ax_top = fig.add_subplot(gs[0])
        self._draw_topology_panel(ax_top, sample_name, funcs, sample_data)

        # ---- 下半部: 污点追踪详情 ----
        ax_bot = fig.add_subplot(gs[1])
        self._draw_taint_detail_panel(ax_bot, funcs)

        safe = safe_name(sample_name)
        out_path = os.path.join(out_dir, f"{safe}_dataflow_platform.png")

        with graph_lock:
            plt.savefig(out_path, format='png', dpi=150, facecolor='white')
            plt.close(fig)

        return out_path

    def _draw_topology_panel(self, ax, sample_name, funcs, sample_data):
        """数据流拓扑: 按 Source→Crypto→Sink 三列布局"""
        ax.set_xlim(-0.5, 10.5)
        ax.set_ylim(-0.5, max(6, len(funcs) * 1.8 + 2))
        ax.set_aspect('auto')
        ax.axis('off')

        # 标题
        ax.text(5.0, ax.get_ylim()[1] - 0.3, f"Data Flow Analysis Platform — {sample_name}",
                ha='center', va='top', fontsize=13, fontweight='bold',
                color='#1A237E')

        # 三列标签
        col_x = {
            "Source": 1.5,
            "Crypto": 5.0,
            "Sink":   8.5,
        }
        col_colors = {
            "Source": "#4CAF50",
            "Crypto": "#FF9800",
            "Sink":   "#F44336",
        }

        y_header = ax.get_ylim()[1] - 1.0
        for col_name, cx in col_x.items():
            ax.add_patch(FancyBboxPatch(
                (cx - 0.8, y_header - 0.25), 1.6, 0.5,
                boxstyle="round,pad=0.1",
                facecolor=col_colors[col_name], edgecolor='white',
                alpha=0.85
            ))
            ax.text(cx, y_header, col_name, ha='center', va='center',
                    fontsize=10, fontweight='bold', color='white')

        # 绘制数据流连线和节点
        y_base = y_header - 1.2
        drawn_nodes = {}
        arrow_style = ArrowStyle('->', head_length=6, head_width=4)

        for i, func in enumerate(funcs):
            y = y_base - i * 1.5
            scenario = func["scenario"]
            meta = SCENARIO_META.get(scenario, SCENARIO_META["Unknown_Crypto_Operation"])
            chain = func["chain"]

            # 绘制链路中各阶段节点
            src_apis = []
            crypto_algo = func["algo"]
            sink_apis = []
            for stage in chain:
                if stage.get("stage") == "Source":
                    src_apis = stage.get("apis", [])
                elif stage.get("stage") == "Crypto":
                    crypto_algo = stage.get("algo", func["algo"])
                elif stage.get("stage") == "Sink":
                    sink_apis = stage.get("apis", [])

            # Source 节点
            src_label = "\n".join(src_apis[:2]) if src_apis else "—"
            self._draw_node(ax, col_x["Source"], y, src_label, "#E8F5E9", "#388E3C", 1.3, 0.45)

            # Crypto 节点
            crypto_label = f"{crypto_algo}\n{func['name'][:18]}"
            border_c = meta["color"]
            self._draw_node(ax, col_x["Crypto"], y, crypto_label, meta["light"], border_c, 1.5, 0.45)
            # 置信度标注
            conf_color = "#4CAF50" if func["conf"] >= 70 else ("#FF9800" if func["conf"] >= 50 else "#F44336")
            vmark = " ✓" if func["verified"] else ""
            ax.text(col_x["Crypto"] + 1.6, y + 0.15,
                    f"{func['conf']}%{vmark}", fontsize=7, color=conf_color, fontweight='bold')

            # Sink 节点
            sink_label = "\n".join(sink_apis[:2]) if sink_apis else "—"
            self._draw_node(ax, col_x["Sink"], y, sink_label, "#FFEBEE", "#C62828", 1.3, 0.45)

            # 箭头: Source → Crypto
            ax.annotate("", xy=(col_x["Crypto"] - 1.5, y),
                        xytext=(col_x["Source"] + 1.3, y),
                        arrowprops=dict(arrowstyle='->', color=meta["color"],
                                        lw=1.5, connectionstyle="arc3,rad=0.0"))

            # 箭头: Crypto → Sink
            ax.annotate("", xy=(col_x["Sink"] - 1.3, y),
                        xytext=(col_x["Crypto"] + 1.5, y),
                        arrowprops=dict(arrowstyle='->', color=meta["color"],
                                        lw=1.5, connectionstyle="arc3,rad=0.0"))

            # 行为标签
            ax.text(col_x["Crypto"], y - 0.35,
                    f"{meta['icon']} {meta['label_en']}", ha='center', va='top',
                    fontsize=7, color=meta["color"], fontstyle='italic')

    def _draw_node(self, ax, x, y, label, facecolor, edgecolor, w, h):
        """绘制圆角矩形节点"""
        ax.add_patch(FancyBboxPatch(
            (x - w/2, y - h/2), w, h,
            boxstyle="round,pad=0.08",
            facecolor=facecolor, edgecolor=edgecolor,
            linewidth=1.2, alpha=0.9
        ))
        ax.text(x, y, label, ha='center', va='center',
                fontsize=7, color='#212121', linespacing=1.3)

    def _draw_taint_detail_panel(self, ax, funcs):
        """污点追踪详情面板 — 表格形式"""
        ax.axis('off')
        ax.set_xlim(0, 10)
        ax.set_ylim(0, max(3, len(funcs) * 1.2 + 1.5))

        ax.text(5.0, ax.get_ylim()[1] - 0.2,
                "Taint Analysis Details — Source/Key/Sink Localization",
                ha='center', va='top', fontsize=11, fontweight='bold', color='#1A237E')

        # 表头
        headers = ["Function", "Scenario", "Taint Sources", "Crypto Params", "Sink Points", "Verified"]
        col_xs  = [0.5, 2.0, 3.5, 5.5, 7.5, 9.3]
        y_start = ax.get_ylim()[1] - 0.8

        for hx, h in zip(col_xs, headers):
            ax.text(hx, y_start, h, fontsize=7, fontweight='bold', color='#37474F',
                    ha='left', va='center')

        ax.axhline(y=y_start - 0.15, xmin=0.02, xmax=0.98, color='#90A4AE', lw=0.8)

        # 每行一个函数
        y = y_start - 0.5
        for func in funcs:
            taint = func["taint"]
            meta = SCENARIO_META.get(func["scenario"], SCENARIO_META["Unknown_Crypto_Operation"])

            # Function name
            ax.text(col_xs[0], y, func["name"][:16], fontsize=6.5, color='#212121',
                    ha='left', va='center', family='monospace')

            # Scenario
            ax.text(col_xs[1], y, f"{meta['icon']} {func['scenario'][:22]}", fontsize=6.5,
                    color=meta["color"], ha='left', va='center')

            # Taint sources
            srcs = taint.get("taint_sources", [])
            src_txt = ", ".join([s["api"][:15] for s in srcs[:2]]) if srcs else "—"
            ax.text(col_xs[2], y, src_txt, fontsize=6, color='#388E3C',
                    ha='left', va='center')

            # Crypto params
            params = taint.get("crypto_params", [])
            keys   = taint.get("key_material", [])
            param_txt = ""
            if params:
                param_txt = params[0].get("api", "")[:15]
            elif keys:
                param_txt = f"Key@{keys[0].get('location', '?')[:12]}"
            else:
                param_txt = "—"
            ax.text(col_xs[3], y, param_txt, fontsize=6, color='#E65100',
                    ha='left', va='center')

            # Sink points
            exfil = taint.get("exfil_points", [])
            c2    = taint.get("c2_command_path", [])
            if exfil:
                sink_txt = ", ".join([e["api"][:12] for e in exfil[:2]])
            elif c2 and len(c2) >= 3:
                sink_txt = ", ".join(c2[-1].get("apis", [])[:2])
            else:
                # 从 attack_chain 中提取
                sink_apis = []
                for stage in func.get("chain", []):
                    if stage.get("stage") == "Sink":
                        sink_apis = stage.get("apis", [])
                sink_txt = ", ".join([s[:12] for s in sink_apis[:2]]) if sink_apis else "—"
            ax.text(col_xs[4], y, sink_txt, fontsize=6, color='#C62828',
                    ha='left', va='center')

            # Verified
            v_mark = "✓ Verified" if func["verified"] else "○ Partial"
            v_color = "#2E7D32" if func["verified"] else "#9E9E9E"
            ax.text(col_xs[5], y, v_mark, fontsize=6.5, fontweight='bold',
                    color=v_color, ha='left', va='center')

            y -= 0.8

    # ==========================================================================
    # (B) 对抗行为分析图
    # ==========================================================================
    def draw_behavior_analysis(self, sample_name, analysis_results, sample_data, out_dir):
        """
        对每个已识别的行为场景生成攻击链详图:
        - 攻击链三段式详图 (含API、地址、密钥信息)
        - 行为置信度仪表盘
        """
        if not HAS_PLOT:
            return None

        # 按行为场景分组
        scenario_groups = defaultdict(list)
        for path_id, ar in analysis_results.items():
            scenario = ar["behavior_scenario"]
            scenario_groups[scenario].append((path_id, ar))

        if not scenario_groups:
            return None

        n_scenarios = len(scenario_groups)
        fig_h = max(6, n_scenarios * 4.5)
        fig, axes = plt.subplots(n_scenarios, 1, figsize=(14, fig_h))
        if n_scenarios == 1:
            axes = [axes]

        fig.suptitle(f"Adversarial Behavior Analysis — {sample_name}",
                     fontsize=14, fontweight='bold', color='#1A237E', y=0.98)

        for idx, (scenario, items) in enumerate(scenario_groups.items()):
            ax = axes[idx]
            meta = SCENARIO_META.get(scenario, SCENARIO_META["Unknown_Crypto_Operation"])
            self._draw_scenario_panel(ax, scenario, meta, items, sample_data)

        plt.tight_layout(rect=[0, 0, 1, 0.96])
        safe = safe_name(sample_name)
        out_path = os.path.join(out_dir, f"{safe}_behavior_analysis.png")

        with graph_lock:
            plt.savefig(out_path, format='png', dpi=150, facecolor='white')
            plt.close(fig)

        return out_path

    def _draw_scenario_panel(self, ax, scenario, meta, items, sample_data):
        """单个行为场景面板"""
        ax.set_xlim(0, 14)
        ax.set_ylim(0, max(3.5, len(items) * 1.5 + 2))
        ax.axis('off')

        y_top = ax.get_ylim()[1]

        # 场景标题栏
        ax.add_patch(FancyBboxPatch(
            (0.2, y_top - 0.8), 13.6, 0.7,
            boxstyle="round,pad=0.1",
            facecolor=meta["color"], edgecolor='white', alpha=0.9
        ))
        ax.text(7.0, y_top - 0.45,
                f"{meta['icon']}  {meta['label_en']}  —  {meta['desc']}",
                ha='center', va='center', fontsize=10, fontweight='bold', color='white')

        # 每个函数的攻击链
        y = y_top - 1.5
        for path_id, ar in items:
            chain = ar["attack_chain"]
            taint = ar["taint_analysis"]

            # 函数标识
            s3f = sample_data["step3_funcs"].get(path_id, {})
            func_name = s3f.get("function_name") or s3f.get("function") or path_id
            ax.text(0.3, y + 0.3, f"▸ {func_name}  [{ar['algorithm']}]",
                    fontsize=8, fontweight='bold', color='#37474F')

            conf = ar["behavior_confidence"]
            conf_c = "#4CAF50" if conf >= 70 else ("#FF9800" if conf >= 50 else "#F44336")
            verified_str = "  ✓chain_verified" if ar["chain_verified"] else ""
            ax.text(0.3, y + 0.05,
                    f"Confidence: {conf}%{verified_str}  |  Data Flow: {'✓' if ar['data_flow_verified'] else '✗'}",
                    fontsize=7, color=conf_c)

            # 攻击链三段式横排
            stage_x = [2.5, 6.0, 10.5]
            stage_w = 2.8
            stage_h = 0.55

            for si, stage in enumerate(chain[:3]):
                sx = stage_x[si] if si < len(stage_x) else stage_x[-1]
                stage_name = stage.get("stage", "?")

                if stage_name == "Source":
                    fc, ec = "#E8F5E9", "#2E7D32"
                    apis = stage.get("apis", [])
                    content = f"[{stage.get('type', '?')}]\n" + ", ".join(apis[:2])
                elif stage_name == "Crypto":
                    fc, ec = meta["light"], meta["color"]
                    km = stage.get("key_material", [])
                    km_str = f"\nKey: {km[0].get('api', '?')[:15]}" if km else ""
                    content = f"{stage.get('algo', '?')}{km_str}"
                elif stage_name == "Sink":
                    fc, ec = "#FFEBEE", "#C62828"
                    apis = stage.get("apis", [])
                    content = ", ".join(apis[:3])
                else:
                    fc, ec = "#F5F5F5", "#9E9E9E"
                    content = str(stage)[:30]

                self._draw_node(ax, sx, y - 0.35, content, fc, ec, stage_w, stage_h)

                # 箭头
                if si < len(chain) - 1 and si < 2:
                    ax.annotate("", xy=(stage_x[si+1] - stage_w/2, y - 0.35),
                                xytext=(sx + stage_w/2, y - 0.35),
                                arrowprops=dict(arrowstyle='->', color=meta["color"],
                                                lw=1.8))

            y -= 1.4

    # ==========================================================================
    # (C) 算法与密钥定位图
    # ==========================================================================
    def draw_algo_key_summary(self, sample_name, analysis_results, sample_data, out_dir):
        """
        算法识别统计 + 密钥存储位置定位图
        """
        if not HAS_PLOT:
            return None

        fig = plt.figure(figsize=(14, 7))
        gs = gridspec.GridSpec(1, 2, width_ratios=[1, 1.2], wspace=0.3)

        # 左: 算法分布
        ax_left = fig.add_subplot(gs[0])
        self._draw_algo_distribution(ax_left, analysis_results)

        # 右: 密钥定位
        ax_right = fig.add_subplot(gs[1])
        self._draw_key_locations(ax_right, analysis_results, sample_data)

        fig.suptitle(f"Algorithm Identification & Key Localization — {sample_name}",
                     fontsize=13, fontweight='bold', color='#1A237E', y=0.98)

        plt.tight_layout(rect=[0, 0, 1, 0.95])
        safe = safe_name(sample_name)
        out_path = os.path.join(out_dir, f"{safe}_algo_key_summary.png")

        with graph_lock:
            plt.savefig(out_path, format='png', dpi=150, facecolor='white')
            plt.close(fig)

        return out_path

    def _draw_algo_distribution(self, ax, analysis_results):
        """算法分布饼图 + 置信度"""
        algo_counts = Counter()
        family_counts = Counter()
        for path_id, ar in analysis_results.items():
            algo  = ar.get("algorithm", "Unknown")
            family = ar.get("algo_family", "Unknown")
            algo_counts[algo] += 1
            family_counts[family] += 1

        if not algo_counts:
            ax.text(0.5, 0.5, "No algorithms detected", ha='center', va='center',
                    fontsize=12, color='#9E9E9E', transform=ax.transAxes)
            ax.set_title("Algorithm Distribution")
            return

        labels = list(family_counts.keys())
        sizes  = list(family_counts.values())
        colors = [ALGO_FAMILY_COLORS.get(f, "#9E9E9E") for f in labels]

        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=colors,
            autopct='%1.0f%%', startangle=90, pctdistance=0.8,
            textprops={'fontsize': 8}
        )
        for at in autotexts:
            at.set_fontsize(7)
            at.set_color('white')
            at.set_fontweight('bold')

        ax.set_title("Algorithm Family Distribution", fontsize=10, fontweight='bold')

        # 右下角列出具体算法
        algo_text = "\n".join([f"  {a}: {c}" for a, c in algo_counts.most_common(8)])
        ax.text(0.0, -0.12, f"Detected Algorithms:\n{algo_text}",
                transform=ax.transAxes, fontsize=7, color='#424242',
                verticalalignment='top', family='monospace')

    def _draw_key_locations(self, ax, analysis_results, sample_data):
        """密钥素材存储位置列表"""
        ax.axis('off')
        ax.set_title("Crypto Key Material Locations", fontsize=10, fontweight='bold')

        all_keys = []
        all_params = []
        for path_id, ar in analysis_results.items():
            taint = ar.get("taint_analysis", {})
            for km in taint.get("key_material", []):
                all_keys.append(km)
            for cp in taint.get("crypto_params", []):
                all_params.append(cp)

        y = 0.92
        line_h = 0.06

        # API Key Imports
        ax.text(0.02, y, "▎ Key Import APIs", fontsize=9, fontweight='bold',
                color='#E65100', transform=ax.transAxes)
        y -= line_h

        if all_params:
            for cp in all_params[:8]:
                ax.text(0.05, y,
                        f"• {cp.get('api', '?')}  @ {cp.get('call_site', '?')}  ({cp.get('key_length', '')})",
                        fontsize=7, color='#424242', transform=ax.transAxes, family='monospace')
                y -= line_h
        else:
            ax.text(0.05, y, "(No API key imports detected)", fontsize=7,
                    color='#9E9E9E', transform=ax.transAxes)
            y -= line_h

        y -= line_h * 0.5

        # Extracted Keys
        ax.text(0.02, y, "▎ Dynamically Extracted Keys (Step3)", fontsize=9, fontweight='bold',
                color='#1565C0', transform=ax.transAxes)
        y -= line_h

        if all_keys:
            for k in all_keys[:8]:
                entropy = k.get("entropy", 0)
                e_color = "#4CAF50" if entropy >= 6 else ("#FF9800" if entropy >= 4 else "#9E9E9E")
                key_hex = k.get("key_hex", "?")
                if len(key_hex) > 32:
                    key_hex = key_hex[:32] + "..."
                ax.text(0.05, y,
                        f"• {key_hex}  @ {k.get('location', '?')}  "
                        f"[H={entropy:.1f}]  algo={k.get('algo', '?')}",
                        fontsize=7, color='#424242', transform=ax.transAxes, family='monospace')

                # 熵值小标记
                ax.plot(0.03, y + 0.005, 'o', markersize=4, color=e_color,
                        transform=ax.transAxes)
                y -= line_h
        else:
            ax.text(0.05, y, "(No keys extracted during symbolic execution)", fontsize=7,
                    color='#9E9E9E', transform=ax.transAxes)

        # Step3 keys from sample_data
        extra_keys = sample_data.get("extracted_keys", [])
        if extra_keys and not all_keys:
            y -= line_h
            ax.text(0.02, y, "▎ Step3 Key Records", fontsize=9, fontweight='bold',
                    color='#6A1B9A', transform=ax.transAxes)
            y -= line_h
            for k in extra_keys[:6]:
                ax.text(0.05, y,
                        f"• {k.get('key_hex', '?')[:32]}  "
                        f"func={k.get('function', '?')}  "
                        f"behavior={k.get('behavior', '?')}",
                        fontsize=7, color='#424242', transform=ax.transAxes, family='monospace')
                y -= line_h


# ==============================================================================
# 7. LLM 客户端 (DeepSeek)
# ==============================================================================

class RobustLLMClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.client = None
        if api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=api_key,
                    base_url="https://api.deepseek.com/v1"
                )
            except ImportError:
                logging.warning("openai package not available for LLM calls")

    def call_with_retry(self, prompt, retries=2):
        if not self.client:
            return self._fallback()
        for attempt in range(retries + 1):
            try:
                resp = self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": "You are a malware crypto analyst. Return valid JSON only."},
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                    timeout=LLM_TIMEOUT,
                )
                return json.loads(resp.choices[0].message.content)
            except Exception as e:
                logging.warning(f"LLM attempt {attempt+1} failed: {e}")
        return self._fallback()

    @staticmethod
    def _fallback():
        return {
            "algorithm_family": "Unknown",
            "algorithm_guess": "Unknown",
            "confidence": 0,
            "evidence": ["LLM unavailable"]
        }


# ==============================================================================
# 8. QuickClassifier (保留原有快速路径)
# ==============================================================================

class QuickClassifier:
    @staticmethod
    def classify(stats, sig_summary):
        density = stats.get("density", {})
        top_ops = stats.get("top_ops", {})

        if top_ops.get("aesenc", 0) > 0 or top_ops.get("aesdec", 0) > 0:
            guess = "AES-NI"
            if top_ops.get("pclmulqdq", 0) > 0:
                guess = "AES-GCM (Hardware)"
            return {
                "algorithm_family": "Symmetric",
                "algorithm_guess": guess,
                "confidence": 99,
                "evidence": ["AESENC/AESDEC present"]
            }

        if not sig_summary:
            return None

        best = sig_summary[0]
        algo_name = best["algo"]

        if algo_name == "SHA1" and not best.get("has_unique", False):
            return None

        if "ChaCha" in algo_name or "Salsa" in algo_name:
            if density.get('shift', 0) == 0:
                return None

        if best["hit_count"] >= 2 or best["total_score"] >= 10:
            arx_score = density.get("arithmetic", 0) + density.get("shift", 0) + density.get("bitwise", 0)
            if arx_score >= 0.3:
                return {
                    "algorithm_family": normalize_family(algo_name),
                    "algorithm_guess": algo_name,
                    "confidence": 90,
                    "evidence": [
                        f"Sig: {best['algo']} (Hits={best['hit_count']})",
                        f"Match ARX={arx_score:.2f}"
                    ]
                }
        return None


# ==============================================================================
# 9. TraceProcessor (从原 Step4 保留, 用于处理 Step3 执行追踪)
# ==============================================================================

class TraceProcessor:
    @staticmethod
    def get_op(t):
        return (t.get('op') or t.get('mnem') or t.get('mnemonic') or 'unk').lower()

    @staticmethod
    def profile(traces):
        op_counts = Counter([TraceProcessor.get_op(t) for t in traces])
        total = len(traces)
        cats = {'bitwise': 0, 'arithmetic': 0, 'shift': 0, 'crypto_hw': 0}
        for op, cnt in op_counts.items():
            if op in ['xor', 'pxor', 'and', 'or', 'not', 'vxorps']:
                cats['bitwise'] += cnt
            elif op in ['add', 'sub', 'inc', 'dec', 'imul', 'adc', 'sbb']:
                cats['arithmetic'] += cnt
            elif op in ['rol', 'ror', 'shl', 'shr', 'sar', 'rorx', 'rolx', 'sal']:
                cats['shift'] += cnt
            elif op in ['aesenc', 'aesdec', 'pclmulqdq']:
                cats['crypto_hw'] += cnt

        density = {k: round(v / total, 2) for k, v in cats.items()} if total else {k: 0.0 for k in cats}
        return {"total": total, "top_ops": dict(op_counts.most_common(10)), "density": density}

    @staticmethod
    def extract_artifacts(traces):
        candidates = defaultdict(lambda: {'score': 0.0, 'count': 0, 'ops': set(), 'tags': set()})
        for t in traces:
            instr = t.get('instr') or t.get('instruction') or ''
            op = TraceProcessor.get_op(t)
            hex_vals = re.findall(r'0x[0-9a-fA-F]+', instr)
            for v_str in hex_vals:
                try:
                    raw_val = int(v_str, 16)
                    val32 = raw_val & 0xFFFFFFFF
                    hits = AlgoSignatureMatcher.match(val32)
                    if hits:
                        entry = candidates[val32]
                        entry['score'] += 80.0
                        for algo, v32, w in hits:
                            entry['tags'].add(f"{algo}:{hex(v32)}:{w}")
                    else:
                        if val32 < 0x20 or val32 in NOISE_CONSTS:
                            continue
                        entry = candidates[val32]
                        is_ptr = (op in ['mov', 'lea'] and (val32 & 0xFFF) == 0)
                        if is_ptr:
                            entry['score'] += 0.1
                        elif op in ['xor', 'pxor', 'aesenc']:
                            entry['score'] += 3.0
                        elif op in ['add', 'sub', 'rol']:
                            entry['score'] += 2.0
                        else:
                            entry['score'] += 0.5
                    entry['count'] += 1
                    entry['ops'].add(op)
                except (ValueError, OverflowError):
                    pass

        results = []
        for v, info in candidates.items():
            results.append({
                "hex": hex(v), "score": round(info['score'], 1),
                "count": info['count'], "ops": list(info['ops'])[:5],
                "tags": sorted(list(info['tags']))
            })
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:10]


# ==============================================================================
# 10. Step4 主引擎
# ==============================================================================

class Step4Engine:
    """
    Step4 综合分析引擎:
    1. 加载 Step1/Step2/Step3 全部输出
    2. 对每个样本的每个目标函数进行融合分析
    3. 生成三类可视化图表
    4. 输出最终报告 JSON
    """

    def __init__(self):
        logging.info("=" * 70)
        logging.info("Step 4 — Adversarial Crypto Behavior Analysis Platform")
        logging.info("=" * 70)

        # 加载数据
        logging.info("[1/4] Loading multi-step analysis data...")
        self.data = MultiStepDataLoader()
        logging.info(f"  Loaded {len(self.data.samples)} samples")

        # LLM
        key = load_api_key()
        self.llm = RobustLLMClient(key) if key else None

        # 可视化器
        self.viz = SampleVisualizer()

        # 结果存储
        self.all_results = OrderedDict()  # sample -> {path_id -> analysis_result}
        self.per_func_records = []

    def run(self):
        logging.info("[2/4] Analyzing adversarial behaviors per sample...")

        total_funcs = 0
        total_behaviors = Counter()

        for sample_name, sd in tqdm(self.data.samples.items(), desc="Samples", unit="sample"):
            sample_results = self._analyze_sample(sample_name, sd)
            self.all_results[sample_name] = sample_results

            for path_id, ar in sample_results.items():
                total_funcs += 1
                total_behaviors[ar["behavior_scenario"]] += 1

        logging.info(f"  Analyzed {total_funcs} functions across {len(self.all_results)} samples")
        logging.info(f"  Behavior distribution: {dict(total_behaviors)}")

        # 可视化
        logging.info("[3/4] Generating visualizations...")
        self._generate_all_visualizations()

        # 报告
        logging.info("[4/4] Generating final report...")
        self._generate_report()

        logging.info("=" * 70)
        logging.info(f"✅ Step 4 Complete. Report: {OUTPUT_REPORT}")
        logging.info(f"   Graphs: {GRAPH_DIR}")
        logging.info("=" * 70)

    def _analyze_sample(self, sample_name, sd):
        """分析单个样本中所有目标函数"""
        sample_results = OrderedDict()

        # 优先使用 Step3 的分析结果
        for path_id, s3_func in sd["step3_funcs"].items():
            # 获取关联的 Step2 证据
            step2_evidence = s3_func.get("_step2_evidence", {})
            step2_semantic = s3_func.get("_step2_semantic", {})

            # 尝试匹配 Step1 函数信息
            func_addr = s3_func.get("function", "")
            step1_info = None
            for fid, s1f in sd["step1_funcs"].items():
                if s1f.get("addr") == func_addr:
                    step1_info = s1f
                    break

            # 相关密钥
            func_keys = [k for k in sd.get("extracted_keys", [])
                         if k.get("function") == func_addr]

            # 融合分析
            ar = AdversarialBehaviorAnalyzer.analyze_function(
                s3_func, step2_evidence, step2_semantic,
                step1_info, func_keys
            )

            sample_results[path_id] = ar

            # 记录逐函数输出
            self.per_func_records.append({
                "sample":  sample_name,
                "path_id": path_id,
                "func":    s3_func.get("function_name") or s3_func.get("function"),
                "addr":    s3_func.get("function"),
                **ar,
            })

        # 如果没有 Step3 数据, 回退到 Step2 报告
        if not sample_results and sd["step2_reports"]:
            for func_addr, s2r in sd["step2_reports"].items():
                path_id = sd["addr_to_pathid"].get(func_addr, f"s2_{func_addr}")
                bp = sd["step2_blueprints"].get(path_id, {})
                evidence = bp.get("evidence", {})

                # 构造模拟 s3_func
                s3_func = {
                    "function": func_addr,
                    "function_name": s2r.get("func", ""),
                    "algorithm": s2r.get("algo", "Unknown"),
                    "algo_confidence": s2r.get("confidence", 0),
                    "behavior": s2r.get("scenario", "Unknown"),
                    "behavior_confidence": s2r.get("confidence", 0),
                    "chain_verified": s2r.get("chain_verified", False),
                    "attack_chain": [],
                    "_step2_evidence": evidence,
                    "_step2_semantic": bp.get("semantic", {}),
                    "_step2_chain_scenario": s2r.get("chain_scenario"),
                }

                step1_info = None
                for fid, s1f in sd["step1_funcs"].items():
                    if s1f.get("addr") == func_addr:
                        step1_info = s1f
                        break

                ar = AdversarialBehaviorAnalyzer.analyze_function(
                    s3_func, evidence, bp.get("semantic", {}),
                    step1_info, []
                )
                sample_results[path_id] = ar

        return sample_results

    def _generate_all_visualizations(self):
        """为每个样本生成三类图表"""
        if not HAS_PLOT:
            logging.warning("matplotlib not available, skipping visualization")
            return

        for sample_name, sample_results in tqdm(self.all_results.items(),
                                                 desc="Visualizing", unit="sample"):
            sd = self.data.samples[sample_name]

            try:
                # (A) 数据流分析平台图
                p1 = self.viz.draw_dataflow_platform(
                    sample_name, sample_results, sd, GRAPH_DIR)
                if p1:
                    logging.info(f"  📊 {sample_name}: dataflow_platform -> {os.path.basename(p1)}")

                # (B) 对抗行为分析图
                p2 = self.viz.draw_behavior_analysis(
                    sample_name, sample_results, sd, GRAPH_DIR)
                if p2:
                    logging.info(f"  📊 {sample_name}: behavior_analysis -> {os.path.basename(p2)}")

                # (C) 算法与密钥定位图
                p3 = self.viz.draw_algo_key_summary(
                    sample_name, sample_results, sd, GRAPH_DIR)
                if p3:
                    logging.info(f"  📊 {sample_name}: algo_key_summary -> {os.path.basename(p3)}")

            except Exception as e:
                logging.error(f"Visualization error for {sample_name}: {e}")

    def _generate_report(self):
        """生成最终 JSON 报告"""
        # 全局统计
        algo_counter = Counter()
        behavior_counter = Counter()
        family_counter = Counter()
        verified_count = 0
        total_keys = 0
        total_funcs = 0

        sample_reports = []

        for sample_name, sample_results in self.all_results.items():
            sd = self.data.samples[sample_name]

            sample_algos = set()
            sample_behaviors = set()
            sample_func_list = []

            for path_id, ar in sample_results.items():
                total_funcs += 1

                algo = ar["algorithm"]
                fam  = ar["algo_family"]
                behav = ar["behavior_scenario"]

                if algo and algo != "Unknown":
                    algo_counter[algo] += 1
                    sample_algos.add(algo)
                family_counter[fam] += 1

                if behav and behav != "Unknown_Crypto_Operation":
                    behavior_counter[behav] += 1
                    sample_behaviors.add(behav)

                if ar["chain_verified"]:
                    verified_count += 1

                s3f = sd["step3_funcs"].get(path_id, {})

                sample_func_list.append({
                    "path_id":             path_id,
                    "function":            s3f.get("function") or ar.get("addr"),
                    "function_name":       s3f.get("function_name") or "",
                    "algorithm":           algo,
                    "algo_family":         fam,
                    "algo_confidence":     ar["algo_confidence"],
                    "behavior_scenario":   behav,
                    "behavior_confidence": ar["behavior_confidence"],
                    "chain_verified":      ar["chain_verified"],
                    "data_flow_verified":  ar["data_flow_verified"],
                    "attack_chain":        ar["attack_chain"],
                    "taint_analysis":      ar["taint_analysis"],
                    "evidence_summary":    ar["evidence_summary"],
                })

            n_keys = len(sd.get("extracted_keys", []))
            total_keys += n_keys

            # 每样本图片路径
            safe = safe_name(sample_name)
            graphs = {
                "dataflow_platform": os.path.join(GRAPH_DIR, f"{safe}_dataflow_platform.png"),
                "behavior_analysis": os.path.join(GRAPH_DIR, f"{safe}_behavior_analysis.png"),
                "algo_key_summary":  os.path.join(GRAPH_DIR, f"{safe}_algo_key_summary.png"),
            }
            # 过滤实际存在的
            graphs = {k: v for k, v in graphs.items() if os.path.exists(v)}

            sample_reports.append({
                "sample": sample_name,
                "summary": {
                    "algorithms":     sorted(sample_algos),
                    "behaviors":      sorted(sample_behaviors),
                    "total_functions": len(sample_results),
                    "chain_verified":  sum(1 for ar in sample_results.values() if ar["chain_verified"]),
                    "keys_extracted":  n_keys,
                },
                "graphs":    graphs,
                "functions": sample_func_list,
                "keys":      sd.get("extracted_keys", []),
            })

        report = {
            "metadata": {
                "version":      "Step4_V2_AdversarialBehaviorPlatform",
                "generated_at":  datetime.datetime.now().isoformat(),
                "total_samples": len(self.all_results),
                "total_functions_analyzed": total_funcs,
                "total_keys_extracted":     total_keys,
                "chain_verified_count":     verified_count,
            },
            "statistics": {
                "algorithm_distribution": dict(
                    sorted(algo_counter.items(), key=lambda x: -x[1])
                ),
                "algorithm_family_distribution": dict(
                    sorted(family_counter.items(), key=lambda x: -x[1])
                ),
                "behavior_distribution": dict(
                    sorted(behavior_counter.items(), key=lambda x: -x[1])
                ),
                "behavior_details": {
                    scenario: {
                        "label":    meta["label"],
                        "label_en": meta["label_en"],
                        "count":    behavior_counter.get(scenario, 0),
                        "desc":     meta["desc"],
                    }
                    for scenario, meta in SCENARIO_META.items()
                    if behavior_counter.get(scenario, 0) > 0
                },
            },
            "samples": sample_reports,
        }

        # 写入
        tmp = OUTPUT_REPORT + ".tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, OUTPUT_REPORT)

        # 逐函数 JSONL
        with open(OUTPUT_JSONL, 'w', encoding='utf-8') as f:
            for rec in self.per_func_records:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")

        # 打印摘要
        print(f"\n{'='*70}")
        print(f"  Step 4 — Adversarial Crypto Behavior Analysis Report")
        print(f"{'='*70}")
        print(f"  Samples Analyzed:     {len(self.all_results)}")
        print(f"  Functions Analyzed:   {total_funcs}")
        print(f"  Chain Verified:       {verified_count}")
        print(f"  Keys Extracted:       {total_keys}")
        print(f"")
        print(f"  Algorithm Distribution:")
        for algo, cnt in algo_counter.most_common(10):
            print(f"    {algo:.<30s} {cnt}")
        print(f"")
        print(f"  Adversarial Behavior Distribution:")
        for behav, cnt in behavior_counter.most_common():
            meta = SCENARIO_META.get(behav, {})
            icon = meta.get("icon", "?")
            label = meta.get("label_en", behav)
            print(f"    {icon} {label:.<40s} {cnt}")
        print(f"")
        print(f"  Graphs:  {GRAPH_DIR}")
        print(f"  Report:  {OUTPUT_REPORT}")
        print(f"  Details: {OUTPUT_JSONL}")
        print(f"{'='*70}")


# ==============================================================================
# 11. 入口
# ==============================================================================

if __name__ == "__main__":
    try:
        engine = Step4Engine()
        engine.run()
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user.")
    except Exception as e:
        logging.exception(f"Fatal error in Step 4: {e}")
        sys.exit(1)