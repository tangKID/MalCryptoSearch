这是一个基于您提供的四个核心 Python 脚本生成的详细中文 `README.md` 文档。该文档涵盖了项目介绍、架构流程、核心功能、安装依赖及使用说明。

---

# 基于 LLM 引导的恶意样本加密行为自动化追踪系统

**Malware Crypto-Behavior Analysis Platform**

## 📖 项目简介

本项目是一个自动化的恶意代码逆向分析平台，旨在解决**加密算法识别**、**密钥提取**以及**对抗行为（如勒索加密、C2通信）研判**的难题。

系统采用流水线架构，融合了**静态特征匹配**、**BinaryNinja 中间语言分析**、**LLM（大语言模型）语义推理**以及**Angr 符号执行**技术。它能够在无源码的情况下，自动追踪“数据源 (Source) -> 加密操作 (Crypto) -> 敏感行为 (Sink)”的完整攻击链，并精准提取解密密钥。

## 🚀 核心特性

* **多层算法交叉验证**：结合 YARA 静态特征 (Layer-A)、SSA 数据流指纹 (Layer-B) 和 动态运行时常量检测 (Layer-C) 进行三层投票，提高识别准确率。
* **LLM 语义引导**：利用 DeepSeek/OpenAI 模型分析汇编代码语义，生成“引导蓝图”，指导符号执行引擎避开死代码，解决路径爆炸问题。
* **精准密钥提取**：通过动态内存监控 (Hook) 和香农熵 (Shannon Entropy) 分析，在运行时自动捕获高熵值的 AES/RC4 等密钥。
* **攻击链闭环验证**：不仅识别加密函数，还能验证数据流是否真正从网络/文件流向了加密函数并最终被执行或发送，确认恶意意图。
* **可视化报告**：自动生成数据流拓扑图和详细的 JSON/Markdown 分析报告。

## 🛠️ 系统架构与工作流

项目分为四个按顺序执行的步骤（Step 1 - Step 4）：

### Step 1: 静态特征发现 (Crypto Discovery)

* **脚本**: `crypto_discovery.py`
* **功能**: 快速筛选候选函数。
* **技术**:
* 加载 YARA 规则库匹配加密常量。
* 全量扫描 S-Box / T-Table 特征。
* 利用 AES-NI 指令检测。
* 生成初始的候选函数列表 (`step1_crypto_candidates.json`)。



### Step 2: 混合语义分析 (Hybrid Analysis)

* **脚本**: `hybrid_analysis.py`
* **功能**: 数据流追踪与蓝图构建。
* **技术**:
* 基于 BinaryNinja MLIL (中级中间语言) 的 SSA (静态单赋值) 分析。
* **LLM 增强**: 将反汇编代码发送给 LLM，推断函数意图（如“这是 RC4 密钥调度”）。
* 生成**符号执行引导蓝图**，标记 Source/Sink 和关键路径节点。



### Step 3: 引导式符号执行 (Symbolic Execution)

* **脚本**: `symbolic_execution.py`
* **功能**: 动态验证与密钥提取。
* **技术**:
* **Angr 框架**: 加载 Step 2 的蓝图进行受控路径探索。
* **LoopSeer**: 自动限制循环展开次数，防止死循环。
* **Lazy Solves**: 延迟约束求解以提升性能。
* **密钥捕获**: Hook 内存写入操作，计算数据熵值，提取潜在密钥。



### Step 4: 综合研判与可视化 (Final Synthesis)

* **脚本**: `all_crypto_search.py`
* **功能**: 结果汇总与图表生成。
* **技术**:
* 消费前三步的所有数据。
* 绘制 Source-Crypto-Sink 数据流拓扑图。
* 生成最终的威胁情报报告 (`step4_final_report.json`)。



## ⚙️ 环境依赖

本项目依赖 **Python 3.8+** 以及以下核心库。注意：本项目需要 **BinaryNinja 商业版** (Headless API) 支持。

1. **基础依赖**:
```bash
pip install angr claripy yara-python openai tqdm networkx matplotlib pandas

```


2. **BinaryNinja**:
请确保已安装 BinaryNinja 并配置好 `binaryninja` Python 库路径。
3. **API Key**:
在 `keys/` 目录下创建文件 `deepseek_key.txt`，填入你的 LLM API Key。

## 📂 目录结构

```text
.
├── crypto_discovery.py      # Step 1: 静态特征扫描
├── hybrid_analysis.py       # Step 2: 语义分析与蓝图生成
├── symbolic_execution.py    # Step 3: Angr 符号执行与密钥提取
├── all_crypto_search.py     # Step 4: 报告生成与可视化
├── keys/
│   └── deepseek_key.txt     # LLM API 密钥
├── output/                  # 所有分析结果输出目录
├── rules/                   # (可选) YARA 规则目录
└── input_samples/           # 待分析的恶意样本存放处

```

## 🏃‍♂️ 使用指南

请按照以下顺序运行脚本：

**1. 运行静态发现**
扫描目标目录下的二进制文件，寻找加密特征。

```bash
python crypto_discovery.py

```

**2. 运行混合分析**
利用 LLM 分析候选函数的语义，生成 Step 3 所需的蓝图。

```bash
python hybrid_analysis.py

```

**3. 运行符号执行**
启动 Angr 引擎进行动态验证和密钥提取（此步骤耗时较长，支持多进程）。

```bash
python symbolic_execution.py

```

**4. 生成最终报告**
汇总所有数据，生成可视化图表和最终 JSON 报告。

```bash
python all_crypto_search.py

```

## 📊 输出结果示例

最终报告 `output/step4_final_report.json` 将包含如下结构：

```json
{
  "sample_hash": "0000de7e...",
  "verdict": "Malicious (Ransomware)",
  "confidence": 95,
  "extracted_secrets": [
    {
      "type": "Key",
      "algorithm": "AES-256",
      "hex_data": "1f2b3c4d...",
      "location": "0x402100"
    }
  ],
  "attack_chains": [
    {
      "scenario": "Payload_Decryption_Loading",
      "root_function": "0x4015ae",
      "verified": true,
      "steps": ["ReadFile", "AES_Decrypt", "VirtualAlloc"]
    }
  ]
}

```

## ⚠️ 注意事项

1. **资源消耗**: Step 3 (Angr) 极其消耗内存和 CPU，建议在 16GB+ 内存的机器上运行。
2. **LLM 成本**: Step 2 会频繁调用 LLM API，请注意 Token 消耗。
3. **安全性**: 请在隔离的沙箱或虚拟机环境中运行恶意样本分析，尽管本工具主要进行静态和模拟执行，但处理恶意软件始终存在风险。

---
