#!/usr/bin/env python3
"""
RDIGuard SSH Monitor v5.0 Final - Production Ready
Entropy-based SSH attack detection for real-world deployment
Author: Joe Miller / Anthropic Capital Research

v5.0 Final Features:
- Real timestamp parsing
- Multiple log sources
- Configuration file support
- Proper error handling
- IP extraction and tracking
- JSON and syslog output
- Optional sudo mode
- Webhook alerts
- Fixed entropy binning
"""

import subprocess
import numpy as np
from datetime import datetime, timedelta
import sys
import os
import re
import argparse
import json
import time
import signal
import yaml
import logging
from collections import defaultdict, deque
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RDIGuard')

class Config:
    """Configuration management"""
    
    DEFAULT_CONFIG = {
        'thresholds': {
            'critical': 0.75,
            'high': 0.60,
            'medium': 0.45,
            'low': 0.30
        },
        'monitoring': {
            'interval': 60,
            'lookback_hours': 4,
            'min_events': 10,
            'max_interval_seconds': 86400
        },
        'output': {
            'log_file': 'rdiguard.json',
            'enable_syslog': False,
            'verbose': False,
            'webhook_url': None
        },
        'sources': {
            'use_last': True,
            'use_system_log': False,
            'use_auth_log': False
        }
    }
    
    def __init__(self, config_file=None):
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Deep merge configs
                    self._deep_merge(self.config, user_config)
                logger.info(f"Loaded config from {config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")
    
    def _deep_merge(self, base, update):
        """Recursively merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def get(self, key_path, default=None):
        """Get config value by dot notation path"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value

class LogParser:
    """Parse authentication logs from various sources"""
    
    def __init__(self, config):
        self.config = config
        
    def parse_timestamp(self, date_str, time_str=None, year=None):
        """Parse various timestamp formats"""
        if year is None:
            year = datetime.now().year
            
        try:
            # Format: "Nov 22 08:05" or "Nov 22 2024 08:05"
            if time_str:
                dt_str = f"{year} {date_str} {time_str}"
                formats = [
                    "%Y %b %d %H:%M",
                    "%Y %m %d %H:%M",
                    "%Y %b %d %H:%M:%S"
                ]
            else:
                dt_str = date_str
                formats = [
                    "%Y-%m-%d %H:%M:%S",
                    "%b %d %H:%M:%S",
                    "%Y %b %d %H:%M"
                ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(dt_str, fmt)
                    return dt.timestamp()
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"Failed to parse timestamp: {date_str} {time_str}: {e}")
            
        return None
    
    def parse_last_command(self):
        """Parse output from 'last' command"""
        events = []
        
        try:
            # Get more history
            cmd = "last -100 2>/dev/null"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.warning("Failed to run 'last' command")
                return events
            
            year = datetime.now().year
            
            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                    
                # Skip system events
                if any(skip in line.lower() for skip in ['wtmp', 'reboot', 'shutdown', 'begins']):
                    continue
                
                # Parse different formats of last output
                # Format 1: "username  pts/0    192.168.1.1    Thu Nov 21 10:30   still logged in"
                # Format 2: "username  console                   Thu Nov 21 10:30 - 11:45  (01:15)"
                
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                username = parts[0]
                tty = parts[1]
                
                # Find date/time in the line
                # Look for day of week pattern
                days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
                
                for i, part in enumerate(parts):
                    if part in days and i + 3 < len(parts):
                        # Found day, next should be month day time
                        month = parts[i + 1]
                        day = parts[i + 2]
                        time_str = parts[i + 3]
                        
                        if ':' in time_str:  # Valid time
                            ts = self.parse_timestamp(f"{month} {day}", time_str, year)
                            
                            if ts:
                                # Extract IP if present
                                ip = None
                                if i > 2 and '.' in parts[2]:
                                    ip = parts[2]
                                
                                events.append({
                                    'timestamp': ts,
                                    'user': username,
                                    'tty': tty,
                                    'ip': ip or 'local',
                                    'type': 'login',
                                    'source': 'last'
                                })
                                break
                
        except Exception as e:
            logger.error(f"Error parsing last command: {e}")
            
        return events
    
    def parse_auth_log(self):
        """Parse /var/log/auth.log (Linux) or /var/log/secure (RedHat)"""
        events = []
        
        log_files = ['/var/log/auth.log', '/var/log/secure']
        
        for log_file in log_files:
            if not os.path.exists(log_file):
                continue
                
            try:
                # Try to read last N lines (may require sudo)
                cmd = f"sudo tail -n 1000 {log_file} 2>/dev/null"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.debug(f"Could not read {log_file} (needs sudo)")
                    continue
                
                for line in result.stdout.split('\n'):
                    # Look for SSH authentication attempts
                    if 'sshd' not in line:
                        continue
                    
                    # Extract timestamp (format: Nov 22 08:05:01)
                    ts_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
                    if ts_match:
                        ts = self.parse_timestamp(ts_match.group(1))
                        
                        # Determine if success or failure
                        if 'Accepted' in line:
                            event_type = 'ssh_success'
                        elif 'Failed' in line or 'Invalid' in line:
                            event_type = 'ssh_failed'
                        else:
                            continue
                        
                        # Extract IP
                        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        ip = ip_match.group(1) if ip_match else 'unknown'
                        
                        # Extract username
                        user_match = re.search(r'for\s+(\w+)', line)
                        user = user_match.group(1) if user_match else 'unknown'
                        
                        if ts:
                            events.append({
                                'timestamp': ts,
                                'user': user,
                                'ip': ip,
                                'type': event_type,
                                'source': 'auth.log'
                            })
                            
            except Exception as e:
                logger.debug(f"Error reading {log_file}: {e}")
                
        return events

class RegularityAnalyzer:
    """Analyze interval patterns for regularity (attack detection)"""
    
    def __init__(self, config):
        self.config = config
        
    def compute_metrics(self, intervals):
        """
        Compute regularity metrics for attack detection
        Returns dict with various statistical measures
        """
        if len(intervals) < self.config.get('monitoring.min_events', 10):
            return {
                'regularity_score': 0.5,
                'threat_level': 'INSUFFICIENT_DATA',
                'cv': 0,
                'entropy': 0,
                'autocorr': 0,
                'n_intervals': len(intervals)
            }
        
        intervals = np.array(intervals)
        intervals = intervals[(intervals > 0) & (intervals < self.config.get('monitoring.max_interval_seconds', 86400))]
        
        if len(intervals) < 5:
            return {
                'regularity_score': 0.5,
                'threat_level': 'INSUFFICIENT_DATA',
                'cv': 0,
                'entropy': 0,
                'autocorr': 0,
                'n_intervals': len(intervals)
            }
        
        # Statistical metrics
        mean_int = np.mean(intervals)
        std_int = np.std(intervals)
        cv = std_int / (mean_int + 1e-10)
        
        # Shannon entropy with fixed binning
        n_bins = max(10, min(20, len(intervals)//2))  # Prevent under-binning
        hist, _ = np.histogram(intervals, bins=n_bins)
        hist = hist[hist > 0]
        if len(hist) > 0:
            probs = hist / hist.sum()
            entropy = -np.sum(probs * np.log2(probs + 1e-10))
        else:
            entropy = 0
        
        # Autocorrelation
        if len(intervals) > 10:
            corr = np.corrcoef(intervals[:-1], intervals[1:])[0, 1]
            autocorr = abs(corr) if not np.isnan(corr) else 0
        else:
            autocorr = 0
        
        # Unique value ratio
        unique_ratio = len(np.unique(np.round(intervals, 1))) / len(intervals)
        
        # Compute regularity score
        regularity_score = (
            (1.0 - np.tanh(cv * 2)) * 0.35 +        # Low CV = regular
            (1.0 - min(entropy / 4, 1)) * 0.35 +    # Low entropy = regular
            min(autocorr * 2, 1) * 0.20 +           # High autocorr = regular
            (1.0 - unique_ratio) * 0.10             # Few unique = regular
        )
        
        regularity_score = np.clip(regularity_score, 0, 1)
        
        # Determine threat level
        thresholds = self.config.get('thresholds', {})
        
        if regularity_score > thresholds.get('critical', 0.75):
            threat_level = 'CRITICAL'
        elif regularity_score > thresholds.get('high', 0.60):
            threat_level = 'HIGH'
        elif regularity_score > thresholds.get('medium', 0.45):
            threat_level = 'MEDIUM'
        elif regularity_score > thresholds.get('low', 0.30):
            threat_level = 'LOW'
        else:
            threat_level = 'NORMAL'
        
        return {
            'regularity_score': regularity_score,
            'threat_level': threat_level,
            'cv': cv,
            'entropy': entropy,
            'autocorr': autocorr,
            'unique_ratio': unique_ratio,
            'mean_interval': mean_int,
            'std_interval': std_int,
            'n_intervals': len(intervals)
        }

class RDIGuard:
    """Main RDIGuard application"""
    
    def __init__(self, config_file=None):
        self.config = Config(config_file)
        self.parser = LogParser(self.config)
        self.analyzer = RegularityAnalyzer(self.config)
        self.threat_history = deque(maxlen=100)
        
        # Setup output
        self.log_file = self.config.get('output.log_file', 'rdiguard.json')
        
    def get_events(self):
        """Aggregate events from all configured sources"""
        events = []
        
        if self.config.get('sources.use_last', True):
            events.extend(self.parser.parse_last_command())
            
        if self.config.get('sources.use_auth_log', False):
            events.extend(self.parser.parse_auth_log())
        
        # Remove duplicates and sort
        seen = set()
        unique_events = []
        
        for event in events:
            key = (event['timestamp'], event['user'], event.get('ip', ''))
            if key not in seen:
                seen.add(key)
                unique_events.append(event)
        
        return sorted(unique_events, key=lambda x: x['timestamp'])
    
    def analyze(self):
        """Run analysis on current logs"""
        events = self.get_events()
        
        if not events:
            logger.warning("No events found to analyze")
            return None
        
        logger.info(f"Analyzing {len(events)} events")
        
        # Calculate intervals
        timestamps = [e['timestamp'] for e in events]
        intervals = np.diff(sorted(timestamps))
        
        # Get metrics
        metrics = self.analyzer.compute_metrics(intervals)
        
        # Add event details
        metrics['total_events'] = len(events)
        metrics['time_span'] = (max(timestamps) - min(timestamps)) / 3600 if len(timestamps) > 1 else 0
        
        # IP analysis
        ip_counts = defaultdict(int)
        for event in events:
            if 'ip' in event and event['ip'] != 'local':
                ip_counts[event['ip']] += 1
        
        metrics['top_ips'] = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # User analysis
        user_counts = defaultdict(int)
        for event in events:
            user_counts[event.get('user', 'unknown')] += 1
        
        metrics['top_users'] = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return metrics
    
    def log_results(self, metrics):
        """Log analysis results"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics
        }
        
        try:
            with open(self.log_file, 'a') as f:
                json.dump(entry, f)
                f.write('\n')
        except Exception as e:
            logger.error(f"Failed to write log: {e}")
    
    def send_alert(self, webhook_url, metrics):
        """Send alert to webhook (Slack/Discord/Teams compatible)"""
        if not webhook_url or metrics.get('threat_level') not in ['CRITICAL', 'HIGH']:
            return
        
        try:
            import requests
            
            # Format message
            threat = metrics['threat_level']
            score = metrics['regularity_score']
            top_ip = 'unknown'
            
            if metrics.get('top_ips'):
                top_ip = f"{metrics['top_ips'][0][0]} ({metrics['top_ips'][0][1]} attempts)"
            
            payload = {
                'text': f"🚨 RDIGuard Security Alert\n"
                       f"Threat Level: {threat}\n"
                       f"Regularity Score: {score:.3f}\n"
                       f"Top IP: {top_ip}\n"
                       f"Events: {metrics.get('total_events', 0)}"
            }
            
            response = requests.post(webhook_url, json=payload, timeout=5)
            if response.status_code == 200:
                logger.info("Alert sent to webhook")
        except Exception as e:
            logger.warning(f"Failed to send webhook alert: {e}")
    
    def print_results(self, metrics):
        """Display results to console"""
        if not metrics:
            print("No results to display")
            return
        
        print("\n" + "="*60)
        print("RDIGUARD ANALYSIS RESULTS")
        print("="*60)
        
        threat = metrics.get('threat_level', 'UNKNOWN')
        score = metrics.get('regularity_score', 0)
        
        # Threat indicator
        indicators = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': '👁',
            'NORMAL': '✓',
            'INSUFFICIENT_DATA': '❓'
        }
        
        print(f"{indicators.get(threat, '?')} Threat Level: {threat}")
        print(f"Regularity Score: {score:.3f} (0=human, 1=bot)")
        
        if threat != 'INSUFFICIENT_DATA':
            print(f"\nStatistics:")
            print(f"  Events Analyzed: {metrics.get('total_events', 0)}")
            print(f"  Time Span: {metrics.get('time_span', 0):.1f} hours")
            print(f"  Mean Interval: {metrics.get('mean_interval', 0):.1f} seconds")
            print(f"  Entropy: {metrics.get('entropy', 0):.3f}")
            print(f"  CV: {metrics.get('cv', 0):.3f}")
            
            if metrics.get('top_ips'):
                print(f"\nTop IPs:")
                for ip, count in metrics['top_ips'][:3]:
                    print(f"  {ip}: {count} attempts")
            
            if metrics.get('top_users'):
                print(f"\nTop Users:")
                for user, count in metrics['top_users'][:3]:
                    print(f"  {user}: {count} logins")
        
        if threat in ['CRITICAL', 'HIGH']:
            print("\n" + "!"*60)
            print("SECURITY ALERT - POTENTIAL ATTACK DETECTED")
            print("Recommended Actions:")
            print("  1. Review authentication logs immediately")
            print("  2. Check for unauthorized access")
            print("  3. Consider blocking suspicious IPs")
            print("!"*60)
    
    def monitor(self, interval=60):
        """Continuous monitoring mode"""
        logger.info(f"Starting monitoring mode (interval: {interval}s)")
        print(f"Monitoring every {interval} seconds. Press Ctrl+C to stop.\n")
        
        def signal_handler(sig, frame):
            print("\nStopping monitor...")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        while True:
            try:
                metrics = self.analyze()
                
                if metrics:
                    self.print_results(metrics)
                    
                    # Log threats
                    if metrics.get('threat_level') not in ['NORMAL', 'LOW', 'INSUFFICIENT_DATA']:
                        self.log_results(metrics)
                    
                    # Send webhook alert if configured
                    webhook_url = self.config.get('output.webhook_url')
                    if webhook_url:
                        self.send_alert(webhook_url, metrics)
                
                print(f"\nNext check in {interval} seconds...")
                time.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(
        description='RDIGuard SSH Monitor v5.0 - Production Ready'
    )
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--monitor', action='store_true', help='Continuous monitoring mode')
    parser.add_argument('--interval', type=int, default=60, help='Monitor interval (seconds)')
    parser.add_argument('--output', help='Output log file path')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--sudo', action='store_true', 
                       help='Enable auth.log parsing (requires sudo privileges)')
    parser.add_argument('--webhook', help='Webhook URL for alerts')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("="*60)
    print("RDIGuard SSH Monitor v5.0 Final")
    print("Production-Ready Attack Detection")
    print("="*60)
    
    # Initialize
    guard = RDIGuard(config_file=args.config)
    
    # Enable sudo features if requested
    if args.sudo:
        guard.config.config['sources']['use_auth_log'] = True
        print("⚠️  Note: Auth.log parsing enabled (may require sudo password)")
        print()
    
    # Set output file if specified
    if args.output:
        guard.log_file = args.output
    
    # Set webhook if specified
    if args.webhook:
        guard.config.config['output']['webhook_url'] = args.webhook
    
    # Run
    if args.monitor:
        guard.monitor(interval=args.interval)
    else:
        metrics = guard.analyze()
        if metrics:
            guard.print_results(metrics)
            
            # Send webhook for one-off analysis if threat detected
            if args.webhook and metrics.get('threat_level') in ['CRITICAL', 'HIGH']:
                guard.send_alert(args.webhook, metrics)
        else:
            print("No data to analyze")

if __name__ == '__main__':
    main()