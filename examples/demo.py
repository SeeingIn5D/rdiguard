#!/usr/bin/env python3
"""
RDIGuard Demo - Demonstrates attack detection capabilities
"""

import numpy as np
import sys
import os

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rdiguard import RegularityAnalyzer, Config


def generate_human_pattern(n=50):
    """Simulate human login timing - irregular intervals"""
    intervals = np.random.exponential(scale=3600, size=n)  # ~1 hour avg
    intervals += np.random.normal(0, 600, size=n)  # noise
    return np.abs(intervals)


def generate_attack_pattern(n=50):
    """Simulate bot attack timing - machine-precise intervals"""
    intervals = np.ones(n) * 0.3  # 300ms between attempts
    intervals += np.random.normal(0, 0.02, size=n)  # tiny variance
    return np.abs(intervals)


def main():
    print("=" * 60)
    print("RDIGuard Demo - Entropy-Based Attack Detection")
    print("=" * 60)
    print()
    
    config = Config()
    analyzer = RegularityAnalyzer(config)
    
    # Test human pattern
    print("--- Test 1: NORMAL Human Login Pattern ---")
    human = generate_human_pattern()
    h_metrics = analyzer.compute_metrics(human)
    print(f"Regularity Score: {h_metrics['regularity_score']:.3f}")
    print(f"Threat Level: {h_metrics['threat_level']}")
    print(f"CV: {h_metrics['cv']:.3f}, Entropy: {h_metrics['entropy']:.3f}")
    print()
    
    # Test attack pattern  
    print("--- Test 2: ATTACK Pattern (Brute Force) ---")
    attack = generate_attack_pattern()
    a_metrics = analyzer.compute_metrics(attack)
    print(f"Regularity Score: {a_metrics['regularity_score']:.3f}")
    print(f"Threat Level: {a_metrics['threat_level']}")
    print(f"CV: {a_metrics['cv']:.3f}, Entropy: {a_metrics['entropy']:.3f}")
    print()
    
    # Summary
    print("=" * 60)
    print("DETECTION SUMMARY")
    print("=" * 60)
    print(f"Human Score: {h_metrics['regularity_score']:.3f} (should be < 0.4)")
    print(f"Attack Score: {a_metrics['regularity_score']:.3f} (should be > 0.5)")
    
    ratio = a_metrics['regularity_score'] / max(h_metrics['regularity_score'], 0.001)
    print(f"Discrimination Ratio: {ratio:.1f}x")
    
    if a_metrics['regularity_score'] > h_metrics['regularity_score']:
        print("✓ Detection working: Clear separation between attack and normal")
    else:
        print("✗ Detection needs tuning")


if __name__ == '__main__':
    main()
