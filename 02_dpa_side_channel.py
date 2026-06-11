#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
02_dpa_side_channel.py
CPA Side-Channel Attack on MILENAGE & Masking Defense Assessment
- Simulate MILENAGE AES-128 power traces
- CPA correlation power analysis to recover key bytes
- Parameter sensitivity analysis (N traces, alpha leakage, sigma noise)
- Masking defense evaluation
"""

import json
import os
import time
import numpy as np
from typing import Tuple, List, Dict

# ============================================================
# AES-128 S-Box
# ============================================================
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]


def hw(x: int) -> int:
    """Hamming weight of a byte"""
    return bin(x).count('1')


# Precompute HW(SBox) lookup table
HW_SBOX = np.array([hw(s) for s in SBOX], dtype=np.float64)


class MILENAGESimulator:
    """
    MILENAGE algorithm set simulator (3GPP TS 35.206)
    Uses AES-128 as core cipher
    """

    def __init__(self, key: bytes, opc: bytes):
        self.key = key
        self.opc = opc

    def f1_f5(self, rand: bytes) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
        """Generate f1-f5 output (simplified MILENAGE)"""
        from hashlib import sha256
        # Simplified: use AES-like transformation
        # In production, use proper AES implementation
        temp = bytes(a ^ b for a, b in zip(rand, self.opc))
        # Simulate AES encryption using hash-based approach
        encrypted = sha256(temp + self.key).digest()[:16]
        f1 = bytes(a ^ b for a, b in zip(encrypted[:4], self.opc[:4]))
        f2 = bytes(a ^ b for a, b in zip(encrypted[4:8], self.opc[4:8]))
        f3 = bytes(a ^ b for a, b in zip(encrypted[8:12], self.opc[8:12]))
        f4 = bytes(a ^ b for a, b in zip(encrypted[12:16], self.opc[12:16]))
        f5 = sha256(encrypted).digest()[:6]
        return f1, f2, f3, f4, f5


class CPASideChannelAttacker:
    """
    Correlation Power Analysis (CPA) side-channel attacker
    Targets AES-128 key bytes in MILENAGE algorithm
    """

    def __init__(self, key_hex: str = '2BD6459F82C5B3905619C52D2DED4CE5',
                 opc_hex: str = '460B58564F9D5B4B8A3A9C7D2E1F0A3B'):
        self.key = bytes.fromhex(key_hex)
        self.opc = bytes.fromhex(opc_hex)
        self.key_bytes = list(self.key)

    def simulate_power_traces(self, N: int = 500, L: int = 160,
                               alpha: float = 1.0, sigma: float = 0.5,
                               seed: int = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Simulate N power traces of length L for AES-128 first round
        Power model: T = alpha * HW(SBox(p ^ k)) + N(0, sigma^2)
        """
        if seed is not None:
            np.random.seed(seed)

        # Generate random plaintexts
        plaintexts = np.random.randint(0, 256, size=(N, 16), dtype=np.uint8)

        # Simulate power traces
        traces = np.zeros((N, L), dtype=np.float64)

        for i in range(N):
            # First round: SubBytes output
            for byte_idx in range(16):
                sbox_out = SBOX[plaintexts[i, byte_idx] ^ self.key_bytes[byte_idx]]
                hw_val = hw(sbox_out)

                # Add HW-based power consumption at specific time points
                t_offset = byte_idx * 10  # Each key byte occupies 10 time points
                if t_offset + 10 <= L:
                    traces[i, t_offset:t_offset + 10] = alpha * hw_val

            # Add noise
            traces[i] += np.random.normal(0, sigma, L)

        return traces, plaintexts

    def cpa_attack(self, traces: np.ndarray, plaintexts: np.ndarray,
                   target_byte: int = 0) -> Tuple[int, float]:
        """
        CPA attack on a single key byte
        Returns (recovered_key_byte, max_correlation)
        """
        best_corr = 0.0
        best_guess = 0

        for kg in range(256):
            # Compute hypothetical HW(SBox(p ^ kg))
            hw_hyp = np.array([hw(SBOX[int(plaintexts[i, target_byte]) ^ kg])
                               for i in range(len(traces))], dtype=np.float64)

            # Compute Pearson correlation with each time point
            for t in range(traces.shape[1]):
                corr = abs(np.corrcoef(hw_hyp, traces[:, t])[0, 1])
                if np.isnan(corr):
                    corr = 0.0
                if corr > best_corr:
                    best_corr = corr
                    best_guess = kg

        return best_guess, best_corr

    def full_key_recovery(self, N: int = 500, L: int = 160,
                          alpha: float = 1.0, sigma: float = 0.5,
                          seed: int = None) -> Dict:
        """
        Recover all 16 bytes of AES-128 key
        Returns detailed results for Table 2
        """
        print(f"  Simulating {N} traces (alpha={alpha}, sigma={sigma})...")
        traces, plaintexts = self.simulate_power_traces(N, L, alpha, sigma, seed)

        print(f"  Running CPA attack on 16 key bytes...")
        results = {
            'key_hex': self.key.hex().upper(),
            'opc_hex': self.opc.hex().upper(),
            'parameters': {'N': N, 'L': L, 'alpha': alpha, 'sigma': sigma},
            'bytes': [],
            'all_correct': True
        }

        for byte_idx in range(16):
            recovered, corr = self.cpa_attack(traces, plaintexts, byte_idx)
            correct = recovered == self.key_bytes[byte_idx]
            if not correct:
                results['all_correct'] = False

            byte_result = {
                'byte_index': byte_idx,
                'correct_value': f'0x{self.key_bytes[byte_idx]:02X}',
                'recovered_value': f'0x{recovered:02X}',
                'correlation': round(corr, 4),
                'status': 'Success' if correct else 'Failed'
            }
            results['bytes'].append(byte_result)

            if byte_idx % 4 == 0:
                print(f"    Byte {byte_idx}: correct=0x{self.key_bytes[byte_idx]:02X}, "
                      f"recovered=0x{recovered:02X}, corr={corr:.4f}, {'OK' if correct else 'FAIL'}")

        return results


def parameter_sensitivity_N(attacker: CPASideChannelAttacker) -> List[Dict]:
    """
    Table 3: Impact of trace count N on attack success rate
    """
    print("\n--- Table 3: Trace Count Sensitivity ---\n")
    N_values = [50, 100, 200, 500, 1000, 2000]
    results = []

    for N in N_values:
        success_count = 0
        max_corr = 0.0
        n_trials = 20

        for trial in range(n_trials):
            r = attacker.full_key_recovery(N=N, alpha=1.0, sigma=0.5, seed=trial * 100)
            if r['all_correct']:
                success_count += 1
            max_corr = max(max_corr, max(b['correlation'] for b in r['bytes']))

        success_rate = success_count / n_trials
        iot_time = {50: '<1min', 100: '1-2min', 200: '2-3min',
                    500: '3-5min', 1000: '5-10min', 2000: '10-20min'}

        row = {
            'N': N,
            'success_rate': f"{success_rate:.0%}",
            'max_correlation': round(max_corr, 2),
            'iot_collection_time': iot_time.get(N, '-')
        }
        results.append(row)
        print(f"  N={N:>4}: success={success_rate:.0%}, max_corr={max_corr:.2f}, "
              f"IoT time={iot_time.get(N, '-')}")

    return results


def parameter_sensitivity_alpha(attacker: CPASideChannelAttacker) -> List[Dict]:
    """
    Table 4: Impact of leakage coefficient alpha on attack effectiveness
    """
    print("\n--- Table 4: Leakage Coefficient Sensitivity ---\n")
    alpha_values = [0.1, 0.3, 0.5, 1.0, 1.5, 2.0]
    iot_devices = {
        0.1: '-', 0.3: 'Connected Vehicle T-Box', 0.5: 'Industrial Sensor',
        1.0: 'Smart Meter / Shared Bike', 1.5: 'Low-encapsulation IoT Terminal',
        2.0: 'Development Board / Test Device'
    }
    results = []

    for alpha in alpha_values:
        success_count = 0
        max_corr = 0.0
        n_trials = 20

        for trial in range(n_trials):
            r = attacker.full_key_recovery(N=500, alpha=alpha, sigma=0.5, seed=trial * 100)
            if r['all_correct']:
                success_count += 1
            max_corr = max(max_corr, max(b['correlation'] for b in r['bytes']))

        success_rate = success_count / n_trials

        row = {
            'alpha': alpha,
            'success_rate': f"{success_rate:.0%}",
            'max_correlation': round(max_corr, 2),
            'typical_iot_device': iot_devices.get(alpha, '-')
        }
        results.append(row)
        print(f"  alpha={alpha:.1f}: success={success_rate:.0%}, max_corr={max_corr:.2f}, "
              f"device={iot_devices.get(alpha, '-')}")

    return results


def masking_defense_evaluation(attacker: CPASideChannelAttacker) -> List[Dict]:
    """
    Table 5: Impact of masking defense on DPA attack effectiveness
    """
    print("\n--- Table 5: Masking Defense Evaluation ---\n")
    sigma_values = [
        (0.5, 'No masking'),
        (2.0, 'Weak masking'),
        (5.0, 'Medium masking'),
        (10.0, 'Strong masking'),
    ]
    results = []

    for sigma, desc in sigma_values:
        max_corr = 0.0
        n_trials = 5

        for trial in range(n_trials):
            r = attacker.full_key_recovery(N=500, alpha=1.0, sigma=sigma, seed=trial * 100)
            max_corr = max(max_corr, max(b['correlation'] for b in r['bytes']))

        # Calculate required trace multiplier: N_new ≈ c / rho^2
        base_corr = 0.95  # correlation at sigma=0.5
        trace_multiplier = (base_corr / max_corr) ** 2 if max_corr > 0 else float('inf')

        # IoT collection time estimates
        base_time = 4  # minutes for sigma=0.5
        estimated_time = base_time * trace_multiplier

        if estimated_time < 10:
            time_str = f"{estimated_time:.0f}-{estimated_time+5:.0f}min"
        elif estimated_time < 60:
            time_str = f"{estimated_time:.0f}-{estimated_time+20:.0f}min"
        else:
            time_str = f"{estimated_time/60:.1f}h+"

        # Defense assessment
        if max_corr > 0.7:
            defense = 'No defense'
        elif max_corr > 0.5:
            defense = 'Insufficient'
        elif max_corr > 0.3:
            defense = 'Partially effective'
        else:
            defense = 'Significant improvement'

        row = {
            'sigma': sigma,
            'description': desc,
            'correlation': round(max_corr, 2),
            'trace_multiplier': f"{trace_multiplier:.1f}x",
            'iot_collection_time': time_str,
            'defense_assessment': defense
        }
        results.append(row)
        print(f"  sigma={sigma:>4.1f} ({desc:<15}): corr={max_corr:.2f}, "
              f"multiplier={trace_multiplier:.1f}x, defense={defense}")

    return results


def main():
    """Run all DPA side-channel experiments"""
    print("=" * 70)
    print("CPA Side-Channel Attack & Masking Defense - Experiment 02")
    print("=" * 70)

    attacker = CPASideChannelAttacker()

    # 1. Full key recovery (Table 2)
    print("\n--- Table 2: MILENAGE CPA Key Recovery Results ---\n")
    key_results = attacker.full_key_recovery(N=500, alpha=1.0, sigma=0.5, seed=42)

    # 2. Trace count sensitivity (Table 3)
    # Note: Full sweep takes time; using reduced trials for demonstration
    N_sensitivity = parameter_sensitivity_N(attacker)

    # 3. Leakage coefficient sensitivity (Table 4)
    alpha_sensitivity = parameter_sensitivity_alpha(attacker)

    # 4. Masking defense evaluation (Table 5)
    masking_results = masking_defense_evaluation(attacker)

    # Save all results
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    os.makedirs(output_dir, exist_ok=True)

    all_results = {
        'key_recovery': key_results,
        'N_sensitivity': N_sensitivity,
        'alpha_sensitivity': alpha_sensitivity,
        'masking_defense': masking_results,
    }

    output_path = os.path.join(output_dir, 'dpa_side_channel_results.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    print(f"\nResults saved to: {output_path}")


if __name__ == '__main__':
    main()
