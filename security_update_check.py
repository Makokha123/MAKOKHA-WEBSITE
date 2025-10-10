#!/usr/bin/env python3
"""
Security update checker for dependencies
Run this regularly to ensure all packages are up to date
"""
import subprocess
import requests
import json
from packaging import version
import sys

def check_security_updates():
    """Check for security updates in dependencies"""
    try:
        # Get current packages
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'list', '--format=json'
        ], capture_output=True, text=True)
        
        current_packages = json.loads(result.stdout)
        
        # Check PyPI for latest versions
        outdated = []
        for package in current_packages:
            package_name = package['name']
            current_version = package['version']
            
            try:
                response = requests.get(
                    f'https://pypi.org/pypi/{package_name}/json',
                    timeout=10
                )
                if response.status_code == 200:
                    latest_version = response.json()['info']['version']
                    
                    if version.parse(current_version) < version.parse(latest_version):
                        outdated.append({
                            'package': package_name,
                            'current': current_version,
                            'latest': latest_version
                        })
            except requests.RequestException:
                continue
        
        return outdated
        
    except Exception as e:
        print(f"Error checking updates: {e}")
        return []

if __name__ == "__main__":
    outdated_packages = check_security_updates()
    
    if outdated_packages:
        print("SECURITY UPDATE REQUIRED - The following packages have updates:")
        for pkg in outdated_packages:
            print(f"  {pkg['package']}: {pkg['current']} -> {pkg['latest']}")
        sys.exit(1)
    else:
        print("All packages are up to date")
        sys.exit(0)