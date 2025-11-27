#!/usr/bin/env python3
"""
Test suite for RDIGuard v5.0
"""

import unittest
import numpy as np
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Updated imports for v5.0
try:
    from RDIGuard_ssh import RegularityAnalyzer, Config, LogParser
except ImportError:
    print("Error: Make sure RDIGuard_ssh.py is in the same directory")
    sys.exit(1)

class TestRegularityAnalyzer(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.analyzer = RegularityAnalyzer(self.config)
    
    def test_human_pattern(self):
        """Test detection of normal human login pattern"""
        # Human: irregular intervals
        intervals = np.random.exponential(3600, 50)  # Avg 1 hour
        intervals = np.clip(intervals, 60, 86400)
        
        metrics = self.analyzer.compute_metrics(intervals)
        
        self.assertLess(metrics['regularity_score'], 0.4)
        self.assertEqual(metrics['threat_level'], 'NORMAL')
        print(f"✓ Human pattern: score={metrics['regularity_score']:.3f}")
    
    def test_bot_attack_pattern(self):
        """Test detection of automated attack"""
        # Bot: very regular intervals
        intervals = np.ones(100) * 1.0  # Every second
        intervals += np.random.normal(0, 0.01, 100)  # Tiny noise
        intervals = np.abs(intervals)  # Keep positive
        
        metrics = self.analyzer.compute_metrics(intervals)
        
        self.assertGreater(metrics['regularity_score'], 0.5)
        self.assertIn(metrics['threat_level'], ['MEDIUM', 'HIGH', 'CRITICAL'])
        print(f"✓ Bot pattern: score={metrics['regularity_score']:.3f}")
    
    def test_insufficient_data(self):
        """Test handling of insufficient data"""
        intervals = [1, 2, 3]
        
        metrics = self.analyzer.compute_metrics(intervals)
        
        self.assertEqual(metrics['threat_level'], 'INSUFFICIENT_DATA')
        print("✓ Insufficient data handling works")
    
    def test_mixed_pattern(self):
        """Test mixed human/bot pattern"""
        human = np.random.exponential(3600, 30)
        bot = np.ones(30) * 1.0
        mixed = np.concatenate([human, bot])
        
        metrics = self.analyzer.compute_metrics(mixed)
        
        # Should be somewhere in between
        self.assertGreater(metrics['regularity_score'], 0.2)
        self.assertLess(metrics['regularity_score'], 0.8)
        print(f"✓ Mixed pattern: score={metrics['regularity_score']:.3f}")

class TestLogParser(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.parser = LogParser(self.config)
    
    def test_timestamp_parsing(self):
        """Test various timestamp formats"""
        # Test format 1: "Nov 22 08:05"
        ts = self.parser.parse_timestamp("Nov 22", "08:05", 2024)
        self.assertIsNotNone(ts)
        
        # Test format 2: "2024-11-22 08:05:00"  
        ts = self.parser.parse_timestamp("2024-11-22 08:05:00")
        self.assertIsNotNone(ts)
        print("✓ Timestamp parsing works")

class TestAttackPatterns(unittest.TestCase):
    """Test specific attack pattern detection"""
    
    def test_ssh_bruteforce(self):
        """Test SSH brute force detection"""
        config = Config()
        analyzer = RegularityAnalyzer(config)
        
        # Brute force: constant rate
        intervals = np.ones(100) * 0.1  # Every 0.1 seconds
        metrics = analyzer.compute_metrics(intervals)
        
        self.assertGreater(metrics['regularity_score'], 0.6)
        print(f"✓ Brute force detected: score={metrics['regularity_score']:.3f}")
    
    def test_slow_scan(self):
        """Test slow port scan detection"""
        config = Config()
        analyzer = RegularityAnalyzer(config)
        
        # Slow scan: regular but spaced out
        intervals = np.ones(50) * 60  # Once per minute
        intervals += np.random.normal(0, 1, 50)
        
        metrics = analyzer.compute_metrics(intervals)
        
        # Should still detect regularity
        self.assertGreater(metrics['regularity_score'], 0.4)
        print(f"✓ Slow scan detected: score={metrics['regularity_score']:.3f}")

def run_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("RDIGuard v5.0 Test Suite")
    print("="*60 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add tests
    suite.addTests(loader.loadTestsFromTestCase(TestRegularityAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestLogParser))
    suite.addTests(loader.loadTestsFromTestCase(TestAttackPatterns))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "="*60)
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED")
    else:
        print(f"❌ {len(result.failures)} tests failed")
    print("="*60)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)