import json
import ipaddress
import urllib.request
import time
from typing import Dict, Optional
from pathlib import Path
import os

class IPGeolocation:
    def __init__(self, cache_dir: str = "ip_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_expiration = 30 * 24 * 60 * 60
        self.memory_cache = {}
        self.max_memory_cache = 1000
    
    def _is_private_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def _get_from_cache(self, ip: str) -> Optional[Dict]:
        if ip in self.memory_cache:
            return self.memory_cache[ip]
        
        cache_file = self.cache_dir / f"{ip}.json"
        if cache_file.exists():
            if time.time() - cache_file.stat().st_mtime < self.cache_expiration:
                try:
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                        if len(self.memory_cache) < self.max_memory_cache:
                            self.memory_cache[ip] = data
                        return data
                except (json.JSONDecodeError, IOError):
                    cache_file.unlink(missing_ok=True)
        
        return None
    
    def _save_to_cache(self, ip: str, data: Dict) -> None:
        if len(self.memory_cache) < self.max_memory_cache:
            self.memory_cache[ip] = data
        
        cache_file = self.cache_dir / f"{ip}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except IOError:
            pass
    
    def get_ip_data(self, ip: str) -> Dict:
        if ip == "127.0.0.1" or ip == "localhost" or self._is_private_ip(ip):
            return {
                "ip": ip,
                "country": "Local Network",
                "country_code": "LO",
                "city": "Local",
                "region": "Local",
                "latitude": 0,
                "longitude": 0,
                "isp": "Local Network",
                "is_private": True
            }
        
        cached_data = self._get_from_cache(ip)
        if cached_data:
            return cached_data
        
        try:
            url = f"https://ipapi.co/{ip}/json/"
            headers = {
                "User-Agent": "IPGeolocation/1.0 (Educational purposes only)"
            }
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                
                geo_data = {
                    "ip": ip,
                    "country": data.get("country_name", "Unknown"),
                    "country_code": data.get("country_code", "XX"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "latitude": data.get("latitude", 0),
                    "longitude": data.get("longitude", 0),
                    "isp": data.get("org", "Unknown"),
                    "is_private": False
                }
                
                self._save_to_cache(ip, geo_data)
                
                return geo_data
                
        except Exception as e:
            return {
                "ip": ip,
                "country": "Unknown",
                "country_code": "XX",
                "city": "Unknown",
                "region": "Unknown",
                "latitude": 0,
                "longitude": 0,
                "isp": "Unknown",
                "is_private": False,
                "error": str(e)
            }
    
    def batch_lookup(self, ips: list) -> Dict[str, Dict]:
        result = {}
        for ip in ips:
            result[ip] = self.get_ip_data(ip)
            time.sleep(0.1)
        
        return result