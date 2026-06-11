# eSIM IoT Attack Reproduction & SM9-QKD Fusion Authentication

> Companion code for: **"Attack Reproduction and SM9-QKD Fusion Authentication for eSIM IoT: A Closed-Loop Verification Framework"**

This repository contains all experimental code for reproducing the results in the paper. The framework implements a closed-loop "attack reproducible → defense verifiable" methodology across three IoT scenarios (connected vehicles, smart meters, industrial sensors).

## Experimental Platform

| Item | Specification |
|------|---------------|
| CPU | Intel Core i7-10510U @ 1.80GHz (4 cores / 8 threads) |
| RAM | 16 GB DDR4 |
| OS | Windows 10 Professional (64-bit) |
| Python | 3.13 |
| Core Dependencies | NumPy 2.x, PyCryptodome, Matplotlib |

## Repository Structure

```
.
├── 01_javacard_detection.py          # Java Card bytecode verification detector (T1)
├── 02_dpa_side_channel.py            # CPA side-channel attack & masking defense (T2)
├── 03_sm9_authentication.py          # SM9 identity-based crypto & performance (D1)
├── 04_qkd_simulation.py              # BB84+decoy-state QKD key-rate simulation (D3)
├── 05_attack_defense_simulation.py   # Adversarial simulation framework (A1-A4 vs D1-D4)
├── requirements.txt                   # Python dependencies
├── Dockerfile                         # Docker containerized deployment
├── data/                              # Output directory (JSON results)
└── README.md                          # This file
```

## Module Descriptions

### 01_javacard_detection.py — Java Card Bytecode Verification Detector (T1)

Implements a bytecode verification detector that parses CAP file bytecode, identifies type confusion vulnerability patterns, and calculates checkcast coverage rate.

- **Pattern 1 (CRITICAL):** `getfield` → `putfield` without `checkcast`
- **Pattern 2 (HIGH):** `getfield` → `aaload` (object reference used as array)
- **Pattern 3 (HIGH):** `anewarray` → `putfield` (array assigned to object field)

Output: `data/javacard_detection_results.json`

### 02_dpa_side_channel.py — CPA Side-Channel Attack (T2)

Implements Correlation Power Analysis (CPA) attack on MILENAGE AES-128, including:

- Full 16-byte key recovery (500 traces, ρ=0.95)
- **Table 3:** Trace count sensitivity (N=50→2000)
- **Table 4:** Leakage coefficient α sensitivity (α=0.1→2.0)
- **Table 5:** Masking defense evaluation (σ=0.5→10.0)

Power model: `T = α·HW(SBox(p⊕k)) + N(0,σ²)`

Output: `data/dpa_side_channel_results.json`

### 03_sm9_authentication.py — SM9 Identity-Based Cryptography (D1)

Implements SM9 (GM/T 0044-2016) identity-based cryptography for eSIM remote provisioning:

- Key generation, sign, verify, encrypt, decrypt
- Three-phase authentication framework: Registration → Download → Confirmation
- **Table 6:** Performance benchmark (1,000 iterations, avg 5.0ms/op)

Output: `data/sm9_authentication_results.json`

### 04_qkd_simulation.py — BB84+Decoy-State QKD (D3)

Implements QKD key-rate simulation based on GLLP formula:

- Fiber channel model (α=0.2 dB/km, Y₀=1.7×10⁻⁶, η_d=14.5%)
- **Table 7:** Key rate vs. distance (10→200 km)
- 30km: 21,531 kbps, QBER=1.50% (consistent with China Mobile experiment)

Output: `data/qkd_simulation_results.json`

### 05_attack_defense_simulation.py — Adversarial Simulation Framework

Implements the full attack-defense closed-loop simulation:

- **Table 9:** Ablation experiment (7 configs × 4 attacks)
- **Table 10:** Attack-defense module framework
- **Table 11:** Three IoT scenario adversarial results
- **Table 8:** Authentication delay comparison (5G-AKA / EAP-AKA' / PQC-AKA / SM9+QKD)
- Remote write attack rate: 0.8% → 0.003% (267× improvement)

Output: `data/attack_defense_simulation_results.json`

## Quick Start

### Option 1: Local Python

```bash
pip install -r requirements.txt

# Run individual modules
python 01_javacard_detection.py
python 02_dpa_side_channel.py
python 03_sm9_authentication.py
python 04_qkd_simulation.py
python 05_attack_defense_simulation.py
```

### Option 2: Docker (Recommended for Reproducibility)

```bash
# Build image
docker build -t esim-security .

# Run all experiments
docker run --rm -v $(pwd)/data:/app/data esim-security

# Run individual module
docker run --rm -v $(pwd)/data:/app/data esim-security python 02_dpa_side_channel.py
```

## Key Results Summary

| Metric | Value |
|--------|-------|
| DPA key recovery (N=500) | 16/16 bytes, ρ_max=0.95 |
| SM9 single operation latency | 5.0 ms |
| QKD key rate @ 30km | 21,531 kbps |
| QKD QBER @ 30km | 1.50% |
| SM9+QKD total auth delay | 6.0 ms |
| Remote write attack rate (no defense) | 0.8% |
| Remote write attack rate (SM9+QKD) | 0.003% |
| Improvement factor | 267× |

## Paper Reference

If you use this code, please cite:

> X. Zhao, J. Wang, Y. Pei, and G. Liu, "Attack Reproduction and SM9-QKD Fusion Authentication for eSIM IoT: A Closed-Loop Verification Framework," *IEEE Internet of Things Journal*, 2026.

## License

This code is provided for academic research and reproducibility verification purposes only. All experiments follow the "minimum necessary" principle and are conducted in controlled simulation environments without involving any live operator networks.
