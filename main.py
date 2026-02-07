import yara
import binaryninja
from binaryninja.enums import MediumLevelILOperation, SymbolType
import logging
import json
import os
import glob
import hashlib
import time
import re
from collections import Counter, defaultdict, deque
from tqdm import tqdm
from openai import OpenAI

# ================= 工业级配置 =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIRECTORY = r"D:\Experimental data\ori100\malicious"
RULES_DIRECTORY = os.path.join(BASE_DIR, "rules")
KEY_FILE = os.path.join(BASE_DIR, "keys", "deepseek_key.txt")

OUTPUT_DIR = os.path.join(BASE_DIR, "output")
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

OUTPUT_JSON = os.path.join(OUTPUT_DIR, "step1_crypto_candidates.json")
LOG_FILE = os.path.join(OUTPUT_DIR, "scan_history.log")

# 限流配置
MAX_TOTAL_NODES = 2000
MAX_EXPANSION_DEPTH = 2

# LLM 配置
ENABLE_LLM_REFINEMENT = True
LLM_TRIGGER_MIN_CONF = 40
LLM_TRIGGER_MAX_CONF = 85

# === 算法签名库 ===
SIG_DB = {
    0x9E3779B9: ("TEA/XTEA", 5, "BLOCK"), 0x61C88647: ("TEA/XTEA", 5, "BLOCK"),
    0xB7E15163: ("RC5", 5, "BLOCK"), 0x243F6A88: ("Blowfish", 5, "BLOCK"),
    0xA3B1BAC6: ("SM4", 5, "BLOCK"), 0x56AA3350: ("SM4", 5, "BLOCK"),
    0x61707865: ("ChaCha/Salsa", 5, "STREAM"), 0x3320646E: ("ChaCha/Salsa", 5, "STREAM"),
    0x79622D32: ("ChaCha/Salsa", 5, "STREAM"), 0x6B206574: ("ChaCha/Salsa", 5, "STREAM"),
    0x5A827999: ("SHA1", 8, "HASH"), 0x6ED9EBA1: ("SHA1", 8, "HASH"),
    0x8F1BBCDC: ("SHA1", 8, "HASH"), 0xCA62C1D6: ("SHA1", 8, "HASH"),
    0xA953FD4E: ("RIPEMD160", 8, "HASH"), 0x50A28BE6: ("RIPEMD160", 8, "HASH"),
    0x67452301: ("MD5/SHA1", 1, "HASH"), 0xEFCDAB89: ("MD5/SHA1", 1, "HASH"),
    0xC3D2E1F0: ("SHA1", 5, "HASH"), 0x428A2F98: ("SHA256", 5, "HASH"),
    0xEDB88320: ("CRC32", 5, "HASH"), 0x5BD1E995: ("MurmurHash", 5, "HASH")
}

# === API 角色 ===
API_ROLES_EXACT = {
    "recv": ("net", "src"), "wsarecv": ("net", "src"), "recvfrom": ("net", "src"), "wsarecvfrom": ("net", "src"),
    "send": ("net", "sink"), "wsasend": ("net", "sink"), "sendto": ("net", "sink"), "wsasendto": ("net", "sink"),
    "connect": ("net", "io"), "bind": ("net", "io"), "listen": ("net", "io"), "accept": ("net", "io"),
    "internetreadfile": ("net", "src"), "internetreadfileex": ("net", "src"),
    "internetopen": ("net", "ctx"), "internetopenurl": ("net", "ctx"), "internetconnect": ("net", "ctx"),
    "httpsendrequest": ("net", "sink"), "httpsendrequestex": ("net", "sink"),
    "httpqueryinfo": ("net", "src"), "internetquerydataavailable": ("net", "src"),
    "winhttpreaddata": ("net", "src"), "winhttpsendrequest": ("net", "sink"),
    "winhttpreceiveresponse": ("net", "src"), "winhttpopen": ("net", "ctx"), "winhttpconnect": ("net", "ctx"),
    "urldownloadtofile": ("net", "src"),
    "readfile": ("file", "src"), "fread": ("file", "src"), "readfileex": ("file", "src"),
    "writefile": ("file", "sink"), "fwrite": ("file", "sink"), "writefileex": ("file", "sink"),
    "createfile": ("file", "ctx"), "fopen": ("file", "ctx"),
    "createprocess": ("exec", "sink"), "createprocessinternal": ("exec", "sink"),
    "shellexecute": ("exec", "sink"), "shellexecuteex": ("exec", "sink"), "winexec": ("exec", "sink"),
    "createremotethread": ("exec", "sink"), "virtualalloc": ("mem", "alloc"), "virtualallocex": ("mem", "alloc"),
    "writeprocessmemory": ("exec", "sink"), "loadlibrary": ("exec", "load"), "loadlibraryex": ("exec", "load"),
    # Crypto Core
    "cryptdecrypt": ("crypto", "api"), "bcryptdecrypt": ("crypto", "api"),
    "cryptencrypt": ("crypto", "api"), "bcryptencrypt": ("crypto", "api"),
    "aes_encrypt": ("crypto", "api"), "evp_encrypt": ("crypto", "api"),
    # Crypto Context (Low Priority)
    "cryptacquirecontext": ("crypto", "ctx"), "cryptcreatehash": ("crypto", "ctx"),
    "cryptderivekey": ("crypto", "ctx"), "bcryptopenalgorithmprovider": ("crypto", "ctx")
}

DYNAMIC_RES_APIS = {"getprocaddress", "loadlibrary", "ldrgetprocedureaddress", "ldrloaddll", "freelibrary"}
RULE_BLACKLIST = ["Microsoft", "Visual", "RichHeader", "Manifest", "Linker", "Compiler", "Library", "Runtime"]
MATH_LIB_FILTER = ["exp", "log", "pow", "sqrt", "sin", "cos", "operator new"]
CALL_RESOLVE_CACHE = {}

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
logger = logging.getLogger("CryptoStep1")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logging.getLogger("binaryninja").setLevel(logging.ERROR)


# === LLM Refiner ===
class LLMRefiner:
    def __init__(self, key_path):
        self.client = None
        if not ENABLE_LLM_REFINEMENT: return
        if os.path.exists(key_path):
            try:
                with open(key_path, 'r') as f:
                    key = f.read().strip()
                self.client = OpenAI(api_key=key, base_url="https://api.deepseek.com")
            except:
                pass

    def refine(self, func_name, code_snippet, static_conf):
        if not self.client: return None
        prompt = f"""
        Role: Malware Analyst. Task: Identify function capability.
        Function: {func_name}
        Static Score: {static_conf}/100
        Code:
        ```
        {code_snippet[:1000]}
        ```
        Classify as: Encryption, Hashing, Compression, Encoding, Other.
        Return JSON: {{ "category": "...", "confidence": int, "algorithm": "..." }}
        """
        try:
            resp = self.client.chat.completions.create(
                model="deepseek-chat", messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"}
            )
            return json.loads(resp.choices[0].message.content)
        except:
            return None


# === Helpers ===
def calculate_sha256(filepath):
    try:
        s = hashlib.sha256()
        with open(filepath, "rb") as f:
            for b in iter(lambda: f.read(4096), b""): s.update(b)
        return s.hexdigest()
    except:
        return f"err_{time.time()}"


def load_processed_files():
    processed = set()
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if "| [DONE] " in line: processed.add(line.split("|")[2].strip())
        except:
            pass
    return processed


def load_yara_rules():
    files = glob.glob(os.path.join(RULES_DIRECTORY, '*.yar')) + glob.glob(os.path.join(RULES_DIRECTORY, '*.rules'))
    if not files: return None
    try:
        return yara.compile(filepaths={f"r{i}": f for i, f in enumerate(files)})
    except Exception as e:
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


def _norm_base_api(n):
    n = (n or "").lower()
    for p in ("__imp_", "imp_", "j_"):
        if n.startswith(p): n = n[len(p):]
    if "@" in n: n = n.split("@")[0]
    if len(n) > 1 and n.endswith(('a', 'w')): return n[:-1]
    return n


def _is_import_name(n):
    n = (n or "").lower()
    return any(x in n for x in ["__imp_", "imp_", "iat", "j_", "!", ".dll"])


def file_offset_to_vaddr(bv, off: int):
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
    except:
        pass
    return None


def _resolve_name_to_addr(bv, name):
    n = name or ""
    try:
        fs = bv.get_functions_by_name(n)
        if fs: return fs[0].start
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


# === Detection & Analysis ===
class StaticAlgoDetector:
    @staticmethod
    def detect(imm_consts, op_profile, total_ops, struct_feats):
        hints = defaultdict(float)
        for val, count in imm_consts.items():
            if val in SIG_DB:
                name, weight, _ = SIG_DB[val]
                hints[name] += weight * count

        style = "UNKNOWN";
        confidence = 0
        if total_ops > 10:
            xor_r = op_profile.get("xor", 0) / total_ops
            shift_r = op_profile.get("shift", 0) / total_ops
            aes_ops = op_profile.get("crypto_hw", 0)
            if aes_ops > 0:
                style = "AES-NI"; confidence = 99
            elif xor_r > 0.15 and shift_r > 0.05:
                style = "ARX"; confidence = 75
            elif xor_r > 0.25:
                style = "XOR-Intensive"; confidence = 60

        if struct_feats.get("loops", 0) > 0: confidence += 10
        if struct_feats.get("table_lookups", 0) > 2: style += "+SBOX"; confidence += 10

        top_hints = sorted([{"algo": k, "score": v} for k, v in hints.items()], key=lambda x: x['score'], reverse=True)[
            :3]
        return {"algo_hints": top_hints, "crypto_style": style, "crypto_confidence_fast": confidence}


def _collect_ops_mlil(expr, op_counter, limit=2048):
    if expr is None or op_counter.get("total", 0) >= limit: return
    try:
        op_counter["total"] += 1
        name = expr.operation.name
        if "XOR" in name:
            op_counter["xor"] += 1
        elif "SHL" in name or "SHR" in name:
            op_counter["shift"] += 1
        elif "ROL" in name or "ROR" in name:
            op_counter["rotate"] += 1

        ops = getattr(expr, "operands", []) or []
        for o in ops:
            if hasattr(o, "operation"):
                _collect_ops_mlil(o, op_counter, limit)
            elif isinstance(o, list):
                for it in o:
                    if hasattr(it, "operation"): _collect_ops_mlil(it, op_counter, limit)
    except:
        pass


def resolve_call_target(bv, func, instr):
    try:
        dest = instr.dest
        if dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
            addr = dest.constant
            f = bv.get_function_at(addr)
            # Thunk/Import check
            if f:
                try:  # Check for thunk
                    if getattr(f, "is_thunk", False):
                        tf = getattr(f, "thunked_function", None)
                        if tf: return tf.name, hex(tf.start), "import" if _is_import_name(tf.name) else "internal", True
                except:
                    pass
                # Check symbol
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

        # Fallback text match
        m = re.search(r'call\(\s*([a-zA-Z0-9_@\.\!\-]+)\s*\)', str(instr))
        if m:
            name = m.group(1)
            base = _norm_base_api(name)
            if base in API_ROLES_EXACT: return name, None, "import", True
            return name, None, "indirect", True

        return None, None, None, True
    except:
        return None, None, None, True


def analyze_function(bv, func):
    stats = {"op_profile": Counter(), "api_calls": [], "imm_consts": Counter(),
             "complexity": {"blocks": len(func.basic_blocks)}}
    topo = {"call_edges": []}
    behavior = {"io_events": [], "templates": set()}
    struct = {"loops": 0, "table_lookups": 0}

    # Callers
    for ref in bv.get_code_refs(func.start):
        if ref.function:
            topo["call_edges"].append({"src": hex(ref.function.start), "dst": hex(func.start), "dst_name": func.name,
                                       "site": hex(ref.address), "dst_kind": "internal"})

    try:
        if func.mlil:
            for block in func.mlil:
                # Loop Check
                for edge in block.outgoing_edges:
                    if edge.target.start < block.start: struct["loops"] += 1

                for instr in block:
                    _collect_ops_mlil(instr, stats["op_profile"])

                    # Consts
                    if instr.operation == MediumLevelILOperation.MLIL_CONST:
                        v = int(instr.constant) & 0xFFFFFFFF
                        if v in SIG_DB: stats["imm_consts"][v] += 1

                    # Calls
                    if instr.operation.name in ("MLIL_CALL", "MLIL_TAILCALL", "MLIL_CALL_UNTYPED"):
                        t_name, t_addr, t_kind, is_indir = resolve_call_target(bv, func, instr)
                        site = hex(instr.address)
                        if t_name:
                            # Canonicalize
                            if t_kind == "internal" and t_addr and t_addr.startswith("0x"):
                                t_name, t_addr, _ = _canonicalize_internal_target(bv, t_addr, t_name)

                            topo["call_edges"].append(
                                {"src": hex(func.start), "dst": t_addr, "dst_name": t_name, "site": site,
                                 "dst_kind": t_kind})
                            stats["api_calls"].append({"name": t_name, "kind": t_kind})

                            base = _norm_base_api(t_name)
                            if base in API_ROLES_EXACT:
                                cat, kind = API_ROLES_EXACT[base]
                                behavior["io_events"].append({"cat": cat, "kind": kind, "api": t_name, "site": site})
    except:
        pass

    op_total = max(1, stats["op_profile"].get("total", 1))
    algo = StaticAlgoDetector.detect(stats["imm_consts"], stats["op_profile"], op_total, struct)

    # Dedup Edges
    ded = {}
    for e in topo["call_edges"]:
        if e.get("dst"): ded[edge_key(e)] = e
    topo["call_edges"] = list(ded.values())

    return stats, topo, behavior, algo


def _propagate_taint_attributes(results, all_edges_dict, sources, sinks):
    # Build Graph
    adj = defaultdict(list);
    rev_adj = defaultdict(list)
    addr_map = {v["addr"]: k for k, v in results.items()}
    for e in all_edges_dict.values():
        src, dst = e.get("src"), e.get("dst")
        if src and dst and src in addr_map and dst in addr_map:
            adj[src].append(dst);
            rev_adj[dst].append(src)

    # BFS Reachability
    def bfs(start_nodes, direction="fwd"):
        reached = set(start_nodes);
        q = deque(start_nodes)
        while q:
            curr = q.popleft()
            neighbors = adj[curr] if direction == "fwd" else rev_adj[curr]
            for n in neighbors:
                if n not in reached: reached.add(n); q.append(n)
        return reached

    reach_src = bfs(sources,
                    "bwd")  # Reachable FROM source (Wait, logic: Source -> Node. So traverse forward from Source? No, 'source_reachable' usually means 'can this node connect back to a source'. Actually, flow is Source -> Node. So we trace Forward from Source.)
    # Correction:
    # 'source_reachable': Node is reachable FROM Source. BFS FWD from Source.
    # 'sink_reachable': Node can reach Sink. BFS BWD from Sink (Sink is descendant).

    reach_src = bfs(sources, "fwd")
    reach_sink = bfs(sinks, "bwd")

    # [Fix 2] Enhanced Crypto Detection
    cryptos = set()
    for v in results.values():
        io = v.get("behavior", {}).get("io_events", [])
        algo = v.get("static_algo", {})

        # Criteria 1: IO - Explicit Crypto API
        has_crypto_api = any(x.get("cat") == "crypto" and x.get("kind") == "api" for x in io)

        # Criteria 2: Strong Static Heuristic
        strong_static = algo.get("crypto_confidence_fast", 0) >= 60 or len(algo.get("algo_hints", [])) > 0

        # Criteria 3: YARA / Rule Hit (New)
        has_yara = len(v.get("trigger_rules", [])) > 0 or len(v.get("yara_hits", [])) > 0

        # Criteria 4: LLM Verdict (New)
        is_llm_crypto = "encrypt" in str(v.get("llm_verdict", {})).lower() or "hash" in str(
            v.get("llm_verdict", {})).lower()

        if has_crypto_api or strong_static or has_yara or is_llm_crypto:
            cryptos.add(v["addr"])

    reach_crypto = bfs(cryptos, "bwd")  # Can reach crypto (Crypto is descendant) OR Crypto is ancestor?
    # Usually we want: Source -> ... -> Crypto -> ... -> Sink.
    # So Crypto should be reachable from Source, and Sink reachable from Crypto.

    return reach_src, reach_sink, cryptos


def analyze_sample_chain(results, all_edges_dict, max_chains=50):
    addr2name = {v["addr"]: v.get("func_name", v["addr"]) for v in results.values()}
    sources = {v["addr"] for v in results.values() if
               any(x.get("kind") == "src" for x in v.get("behavior", {}).get("io_events", []))}
    sinks = {v["addr"] for v in results.values() if
             any(x.get("kind") == "sink" for x in v.get("behavior", {}).get("io_events", []))}

    reach_src, reach_sink, cryptos = _propagate_taint_attributes(results, all_edges_dict, sources, sinks)

    # Fill Flags
    for v in results.values():
        v["analysis_flags"] = {
            "source_reachable": v["addr"] in reach_src,
            "sink_reachable": v["addr"] in reach_sink,
            "is_crypto": v["addr"] in cryptos
        }

    chains = [];
    seen = set()
    adj = defaultdict(list)
    for e in all_edges_dict.values():
        if e.get("src") and e.get("dst"): adj[e["src"]].append(e["dst"])

    # [Fix 3] Linear Chain Discovery (BFS)
    # Path: Source -> ... -> Crypto -> ... -> Sink
    for src in sources:
        if src not in reach_sink: continue  # Optimization

        # Queue: (current_node, path_list, has_encountered_crypto)
        q = deque([(src, [src], src in cryptos)])

        while q and len(chains) < max_chains:
            curr, path, has_crypto = q.popleft()
            if len(path) > 6: continue  # Depth limit

            if curr in cryptos: has_crypto = True

            if curr in sinks and has_crypto:
                # Valid Chain Found
                t = tuple(path)
                if t not in seen:
                    seen.add(t)
                    # Find first crypto node for metadata
                    c_node = next((x for x in path if x in cryptos), None)
                    chains.append({
                        "type": "Linear Attack Chain",
                        "src_func": addr2name.get(src),
                        "crypto_func": addr2name.get(c_node),
                        "sink_func": addr2name.get(curr),
                        "path_addrs": path,
                        "path_names": [addr2name.get(p) for p in path]
                    })

            for child in adj[curr]:
                if child in reach_sink or child in cryptos or child in sinks:  # Pruning
                    q.append((child, path + [child], has_crypto))

    # Orchestrator Pattern (Backup)
    for addr, v in results.items():
        if v["addr"] in reach_src and v["addr"] in reach_sink:
            # Check if it calls a crypto function
            called_cryptos = [child for child in adj[v["addr"]] if child in cryptos]
            if called_cryptos:
                target = called_cryptos[0]
                chains.append({
                    "type": "Orchestrator (Direct)",
                    "src_func": addr2name.get(v["addr"]),
                    "crypto_func": addr2name.get(target),
                    "sink_func": addr2name.get(v["addr"]),
                    "path_addrs": [v["addr"], target]
                })

    return chains


def process_sample(binary_path, rules, llm_refiner):
    filename = os.path.basename(binary_path)
    file_hash = calculate_sha256(binary_path)
    results = {};
    all_edges_dict = {}
    bv = None

    try:
        bv = binaryninja.load(binary_path)
        if not bv: return None, "LOAD_ERR"
        bv.update_analysis_and_wait()

        matches = rules.match(binary_path)

        # 1. Packer/EP
        packer_rules = [m.rule for m in matches if "pack" in m.rule.lower()]
        if packer_rules and bv.entry_function:
            ep = bv.entry_function
            key = f"{file_hash[:12]}_{hex(ep.start)}"
            feat, topo, beh, algo = analyze_function(bv, ep)
            for e in topo['call_edges']:
                if e.get("dst"): all_edges_dict[edge_key(e)] = e
            results[key] = {
                "id": key, "sample": filename, "sample_hash": file_hash, "addr": hex(ep.start),
                "func_name": f"EP_{ep.name}", "trigger_rules": packer_rules, "yara_hits": [],
                "packed": True, "features": feat, "topology": topo, "behavior": beh, "static_algo": algo
            }

        # 2. YARA Candidates
        for match in matches:
            if is_noise(match.rule): continue
            for offset, ident in iter_yara_offsets(match):
                vaddr = file_offset_to_vaddr(bv, offset)
                if not vaddr: continue
                # find_references logic inline or helper
                # ... (Assuming helper similar to V54 logic)
                try:
                    for ref in bv.get_code_refs(vaddr):
                        func = ref.function
                        if func:
                            key = f"{file_hash[:12]}_{hex(func.start)}"
                            if key not in results:
                                feat, topo, beh, algo = analyze_function(bv, func)
                                for e in topo['call_edges']:
                                    if e.get("dst"): all_edges_dict[edge_key(e)] = e
                                results[key] = {
                                    "id": key, "sample": filename, "sample_hash": file_hash, "addr": hex(func.start),
                                    "func_name": func.name, "trigger_rules": [match.rule], "yara_hits": [],
                                    "features": feat, "topology": topo, "behavior": beh, "static_algo": algo,
                                    "instruction_logic": "\n".join([str(i) for b in func.mlil for i in b][:300])
                                }
                            results[key]["yara_hits"].append({"rule": match.rule, "offset": hex(offset)})
                except:
                    pass

        # 3. IO Seeds
        for seed_func in [f for f in bv.functions if f.symbol.type == SymbolType.ImportedFunctionSymbol]:
            # Seed logic...
            pass  # (Simplified for brevity, use V54 logic)

        # 4. Expansion & LLM Refinement
        # Queue init...
        candidate_addrs = set(v["addr"] for v in results.values())
        queue = deque([(int(a, 16), 0) for a in candidate_addrs])
        visited = set(candidate_addrs)

        while queue:
            if len(results) >= MAX_TOTAL_NODES: break
            curr, depth = queue.popleft()
            if depth >= MAX_EXPANSION_DEPTH: continue

            # [Fix 1] Downward Expansion (Callees)
            f = bv.get_function_at(curr)
            if f:
                # Upward (Callers) - standard
                for ref in bv.get_code_refs(f.start):
                    if ref.function and ref.function.start not in visited:
                        # Add caller logic...
                        pass

                        # Downward (Callees)
                if f.mlil:
                    budget = 0
                    for block in f.mlil:
                        for instr in block:
                            budget += 1
                            if budget > 300: break
                            if instr.operation.name in ("MLIL_CALL", "MLIL_TAILCALL"):
                                _, t_addr, kind, _ = resolve_call_target(bv, f, instr)
                                if kind == "internal" and t_addr:
                                    try:
                                        ta = int(t_addr, 16)
                                        if ta not in visited:
                                            visited.add(ta)
                                            tf = bv.get_function_at(ta)
                                            if tf:
                                                # Analyze Callee
                                                feat, topo, beh, algo = analyze_function(bv, tf)
                                                for e in topo['call_edges']:
                                                    if e.get("dst"): all_edges_dict[edge_key(e)] = e
                                                key = f"{file_hash[:12]}_{hex(ta)}"
                                                results[key] = {
                                                    "id": key, "sample": filename, "sample_hash": file_hash,
                                                    "addr": hex(ta),
                                                    "func_name": tf.name, "behavior": beh, "static_algo": algo,
                                                    "features": feat, "topology": topo, "is_context": True
                                                }
                                                queue.append((ta, depth + 1))
                                    except:
                                        pass

        # LLM Loop
        if llm_refiner:
            candidates = []
            for v in results.values():
                c = v.get("static_algo", {}).get("crypto_confidence_fast", 0)
                if LLM_TRIGGER_MIN_CONF <= c <= LLM_TRIGGER_MAX_CONF:
                    candidates.append(v)

            # Prioritize top 5
            candidates.sort(key=lambda x: x.get("static_algo", {}).get("crypto_confidence_fast", 0), reverse=True)
            for v in candidates[:5]:
                code = v.get("instruction_logic") or ""  # Fetch if empty
                if not code and v.get("addr"):
                    try:
                        f = bv.get_function_at(int(v["addr"], 16))
                        if f: code = "\n".join([str(i) for b in f.mlil for i in b][:300])
                    except:
                        pass

                if code:
                    res = llm_refiner.refine(v.get("func_name", ""), code,
                                             v.get("static_algo", {}).get("crypto_confidence_fast", 0))
                    if res:
                        v["llm_verdict"] = res
                        if "encrypt" in res.get("category", "").lower():
                            v["static_algo"]["crypto_confidence_fast"] = 95  # Boost

        # Chain Analysis
        chains = analyze_sample_chain(results, all_edges_dict)

        # [Fix 4] Meta Output
        final_res = {}
        for k, v in results.items():
            # Filter logic
            if v.get("packed") or v.get("trigger_rules") or v.get("yara_hits"):
                final_res[k] = v
            elif v.get("static_algo", {}).get("crypto_confidence_fast", 0) >= 40:
                final_res[k] = v
            elif v.get("behavior", {}).get("io_events"):
                final_res[k] = v

        if final_res:
            final_res[f"{file_hash[:12]}__GRAPH_META"] = {
                "type": "graph_meta", "sample": filename, "sample_hash": file_hash,
                "all_edges": list(all_edges_dict.values()), "global_chains": chains
            }

        return final_res, f"HIT {len(final_res)}"

    except Exception as e:
        return None, f"ERR: {e}"
    finally:
        if bv: bv.file.close()


def main():
    if not os.path.exists(TARGET_DIRECTORY): return
    rules = load_yara_rules()
    llm = LLMRefiner(KEY_FILE)

    files = glob.glob(os.path.join(TARGET_DIRECTORY, "*"))
    files = [f for f in files if os.path.isfile(f) and not f.endswith('.json')]

    print(f"🚀 Step 1 V56 Start | {len(files)} files")

    full_results = {}
    with tqdm(total=len(files)) as pbar:
        for path in files:
            pbar.set_description(os.path.basename(path)[:10])
            res, status = process_sample(path, rules, llm)
            if res:
                full_results.update(res)
                # Save incremental...
                try:
                    with open(OUTPUT_JSON, 'w') as f:
                        json.dump(full_results, f, indent=2)
                except:
                    pass
            pbar.update(1)


if __name__ == "__main__":
    main()