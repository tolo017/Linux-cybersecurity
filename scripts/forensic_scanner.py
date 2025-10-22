"""
FORENSIC SCANNER - Cybersecurity File System Investigator
Author: Tolo Otieno
Description: Advanced file system scanner for incident response and threat hunting.
"""

import os
import sys
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

class ForensicScanner:
    def __init__(self):
        self.suspicious_patterns = [
            'backdoor', 'shell', 'malware', 'exploit', 'passwd', 'shadow',
            '\.tmp$', '\.swp$', '\.hidden', '^\.'
        ]
        self.results = {
            'hidden_files': [],
            'recent_files': [],
            'large_files': [],
            'suspicious_names': [],
            'executable_files': []
        }
    
    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of file - crucial for malware analysis"""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def find_hidden_files(self, start_path="."):
        """Find hidden files and directories"""
        print("🔍 Hunting hidden files...")
        hidden_count = 0
        
        for path in Path(start_path).rglob('*'):
            try:
                if path.name.startswith('.') and path.name not in ['.', '..']:
                    file_info = {
                        'path': str(path),
                        'size': path.stat().st_size,
                        'modified': datetime.fromtimestamp(path.stat().st_mtime),
                        'hash': self.calculate_file_hash(path) if path.is_file() else 'Directory'
                    }
                    self.results['hidden_files'].append(file_info)
                    hidden_count += 1
            except Exception as e:
                continue
        
        return hidden_count
    
    def find_recent_files(self, start_path=".", hours=24):
        """Find files modified in last X hours"""
        print("🕐 Scanning for recently modified files...")
        recent_count = 0
        time_threshold = datetime.now() - timedelta(hours=hours)
        
        for path in Path(start_path).rglob('*'):
            try:
                if path.is_file():
                    mtime = datetime.fromtimestamp(path.stat().st_mtime)
                    if mtime > time_threshold:
                        file_info = {
                            'path': str(path),
                            'size': path.stat().st_size,
                            'modified': mtime,
                            'hash': self.calculate_file_hash(path)
                        }
                        self.results['recent_files'].append(file_info)
                        recent_count += 1
            except Exception:
                continue
        
        return recent_count
    
    def find_large_files(self, start_path=".", size_mb=10):
        """Find files larger than specified MB"""
        print("📏 Hunting large files...")
        large_count = 0
        size_threshold = size_mb * 1024 * 1024
        
        for path in Path(start_path).rglob('*'):
            try:
                if path.is_file() and path.stat().st_size > size_threshold:
                    file_info = {
                        'path': str(path),
                        'size_mb': round(path.stat().st_size / (1024 * 1024), 2),
                        'modified': datetime.fromtimestamp(path.stat().st_mtime),
                        'hash': self.calculate_file_hash(path)
                    }
                    self.results['large_files'].append(file_info)
                    large_count += 1
            except Exception:
                continue
        
        return large_count
    
    def generate_report(self):
        """Generate professional forensic report"""
        print("\n" + "="*60)
        print("🕵️‍♂️ FORENSIC SCAN REPORT")
        print("="*60)
        
        print(f"\n📁 HIDDEN FILES FOUND: {len(self.results['hidden_files'])}")
        for file in self.results['hidden_files'][:5]:  # Show first 5
            print(f"   🔸 {file['path']} | Size: {file['size']} bytes")
        
        print(f"\n🕐 RECENT FILES (Last 24h): {len(self.results['recent_files'])}")
        for file in self.results['recent_files'][:5]:
            print(f"   🔸 {file['path']} | Modified: {file['modified']}")
        
        print(f"\n📏 LARGE FILES (>10MB): {len(self.results['large_files'])}")
        for file in self.results['large_files'][:5]:
            print(f"   🔸 {file['path']} | Size: {file['size_mb']} MB")
        
        print(f"\n🔐 FILES HASHED: {sum(1 for category in self.results.values() for file in category if 'hash' in file and 'Error' not in file['hash'])}")
        
        return self.results

def main():
    scanner = ForensicScanner()
    
    print("🚀 INITIATING FORENSIC SCAN...")
    print("Scanning current directory for security threats...")
    
    # Run all scans
    hidden_count = scanner.find_hidden_files()
    recent_count = scanner.find_recent_files()
    large_count = scanner.find_large_files()
    
    # Generate report
    report = scanner.generate_report()
    
    print(f"\n✅ SCAN COMPLETE!")
    print(f"📊 Summary: {hidden_count} hidden files, {recent_count} recent files, {large_count} large files")
    print("\n💡 Tip: Investigate suspicious files further for potential security threats")

if __name__ == "__main__":
    main()
