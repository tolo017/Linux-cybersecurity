"""
WEB ATTACK DETECTOR - Log Analysis & Threat Intelligence
Author: Tolo Otieno
Description: Advanced log analysis tool for detecting web attacks and suspicious patterns.
"""

import re
import json
from datetime import datetime
from collections import Counter, defaultdict

class WebAttackDetector:
    def __init__(self):
        # Attack patterns - real-world signatures
        self.attack_patterns = {
            'sql_injection': [
                r'union.*select', r'select.*from', r'insert.*into', 
                r'drop.*table', r'1=1', r'or.*1=1', r'exec.*xp_',
                r';.*--', r'waitfor.*delay'
            ],
            'xss_attacks': [
                r'<script>', r'javascript:', r'onmouseover=', 
                r'alert\(', r'document\.cookie', r'<iframe'
            ],
            'path_traversal': [
                r'\.\./', r'\.\.\\', r'etc/passwd', r'win.ini',
                r'proc/self', r'\.\.%2f', r'%2e%2e%2f'
            ],
            'command_injection': [
                r';.*ls', r';.*cat', r';.*whoami', r';.*id',
                r'\|\|.*ls', r'&&.*cat', r'`.*`', r'\$\(.*\)'
            ],
            'brute_force': [
                r'POST.*login', r'POST.*auth', r'wp-login',
                r'failed.*password', r'invalid.*credentials'
            ]
        }
        
        self.detected_attacks = defaultdict(list)
        self.suspicious_ips = Counter()
    
    def analyze_log_line(self, line):
        """Analyze single log line for attack patterns"""
        line_lower = line.lower()
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    # Extract IP address if present
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    ip = ip_match.group(1) if ip_match else 'Unknown'
                    
                    attack_info = {
                        'line': line.strip(),
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'ip_address': ip,
                        'pattern': pattern
                    }
                    
                    self.detected_attacks[attack_type].append(attack_info)
                    self.suspicious_ips[ip] += 1
                    break
    
    def analyze_log_file(self, file_path):
        """Analyze entire log file"""
        print(f"📊 Analyzing log file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    self.analyze_log_line(line)
                    
                    # Progress indicator
                    if line_num % 100 == 0:
                        print(f"Processed {line_num} lines...")
        
        except FileNotFoundError:
            print(f"❌ Error: File {file_path} not found")
            return False
        
        return True
    
    def generate_attack_report(self):
        """Generate comprehensive attack report"""
        print("\n" + "="*70)
        print("🛡️  WEB ATTACK DETECTION REPORT")
        print("="*70)
        
        total_attacks = sum(len(attacks) for attacks in self.detected_attacks.values())
        print(f"\n🚨 TOTAL ATTACKS DETECTED: {total_attacks}")
        
        for attack_type, attacks in self.detected_attacks.items():
            if attacks:
                print(f"\n🔥 {attack_type.upper().replace('_', ' ')}: {len(attacks)} attempts")
                for i, attack in enumerate(attacks[:3], 1):  # Show first 3 of each type
                    print(f"   {i}. IP: {attack['ip_address']}")
                    print(f"      Pattern: {attack['pattern']}")
                    print(f"      Sample: {attack['line'][:100]}...")
        
        # Top suspicious IPs
        if self.suspicious_ips:
            print(f"\n📡 TOP SUSPICIOUS IP ADDRESSES:")
            for ip, count in self.suspicious_ips.most_common(5):
                print(f"   🔴 {ip}: {count} attacks")
        
        # Security recommendations
        print(f"\n💡 SECURITY RECOMMENDATIONS:")
        if self.detected_attacks['sql_injection']:
            print("   • Implement SQL injection protection (parameterized queries)")
        if self.detected_attacks['xss_attacks']:
            print("   • Enable XSS filters and input sanitization")
        if self.detected_attacks['brute_force']:
            print("   • Implement rate limiting and account lockout policies")
        
        return {
            'total_attacks': total_attacks,
            'attack_breakdown': {k: len(v) for k, v in self.detected_attacks.items()},
            'suspicious_ips': dict(self.suspicious_ips.most_common(10))
        }

def create_sample_log():
    """Create sample log file for demonstration"""
    sample_logs = [
        '192.168.1.100 - - [10/Dec/2023:10:30:45] "GET /admin.php?query=union select password FROM users" 200 345',
        '10.0.0.50 - - [10/Dec/2023:10:31:22] "POST /login.php HTTP/1.1" 302 -',
        '192.168.1.100 - - [10/Dec/2023:10:32:01] "GET /../../../etc/passwd HTTP/1.1" 404 234',
        '127.0.0.1 - - [10/Dec/2023:10:33:15] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.100 - - [10/Dec/2023:10:34:30] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 567',
        '203.0.113.5 - - [10/Dec/2023:10:35:00] "POST /wp-login.php HTTP/1.1" 200 234',
        '192.168.1.100 - - [10/Dec/2023:10:36:45] "GET /download?file=../../etc/shadow HTTP/1.1" 404 123'
    ]
    
    with open('sample_web_logs.log', 'w') as f:
        for log in sample_logs:
            f.write(log + '\n')
    
    print("✅ Created sample_web_logs.log for testing")

def main():
    # Create sample data for demonstration
    create_sample_log()
    
    # Initialize detector
    detector = WebAttackDetector()
    
    # Analyze log file
    print("🚀 Starting Web Attack Detection...")
    success = detector.analyze_log_file('sample_web_logs.log')
    
    if success:
        # Generate report
        report = detector.generate_attack_report()
        
        # Save detailed report to JSON
        with open('attack_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n💾 Detailed report saved to: attack_report.json")

if __name__ == "__main__":
    main()
