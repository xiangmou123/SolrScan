#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2019-12409 漏洞检测模块
Apache Solr JMX服务 RCE漏洞
"""

import socket
import logging
import time
from urllib.parse import urlparse

# 日志配置
logger = logging.getLogger(__name__)

def check(scanner, jmx_port=18983):
    """
    检测CVE-2019-12409 JMX服务RCE漏洞
    
    Args:
        scanner: SolrScanner实例
        jmx_port: JMX服务端口，默认为18983
        
    Returns:
        (bool, str): (是否存在漏洞, 详细信息)
    """
    try:
        # 参数校验
        if not scanner or not hasattr(scanner, 'target_url'):
            return False, "无效的扫描器实例"
        
        try:
            jmx_port = int(jmx_port)
        except (ValueError, TypeError):
            return False, f"无效的JMX端口: {jmx_port}，必须为整数"
        
        # 获取Solr信息，检查版本
        info = scanner.get_solr_info()
        version = scanner.version if hasattr(scanner, 'version') and scanner.version else "未知"
        
        # 解析目标URL，获取主机名
        parsed_url = urlparse(scanner.target_url)
        host = parsed_url.hostname
        
        if not host:
            return False, f"无法解析主机名: {scanner.target_url}"
        
        logger.info(f"检测CVE-2019-12409漏洞，目标: {host}，JMX端口: {jmx_port}")
        
        # 检查版本是否在受影响范围内
        version_vulnerable = False
        if version != "未知":
            if version.startswith("8.1.1") or version.startswith("8.2.0"):
                version_vulnerable = True
                logger.info(f"Solr版本 {version} 在CVE-2019-12409漏洞影响范围内")
            else:
                logger.info(f"Solr版本 {version} 不在CVE-2019-12409漏洞影响范围内")
        
        # 尝试连接JMX端口
        try:
            # 创建socket连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(scanner.timeout if hasattr(scanner, 'timeout') else 10)
            result = sock.connect_ex((host, jmx_port))
            sock.close()
            
            if result == 0:
                # 端口开放，尝试发送JMX握手包
                is_jmx = check_jmx_protocol(host, jmx_port, timeout=scanner.timeout if hasattr(scanner, 'timeout') else 10)
                if is_jmx:
                    if version_vulnerable:
                        return True, f"存在CVE-2019-12409漏洞，JMX服务端口{jmx_port}开放且可连接，Solr版本{version}在漏洞影响范围内"
                    else:
                        return True, f"JMX服务端口{jmx_port}开放且可连接，但Solr版本{version}可能不受影响，建议进一步验证"
                else:
                    return False, f"端口{jmx_port}开放但不是JMX服务"
            else:
                return False, f"JMX服务端口{jmx_port}未开放"
        except Exception as e:
            logger.error(f"连接JMX端口{jmx_port}异常: {str(e)}")
            return False, f"连接JMX端口{jmx_port}异常: {str(e)}"
    except Exception as e:
        logger.error(f"检测CVE-2019-12409异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def check_jmx_protocol(host, port, timeout=10):
    """
    检查指定端口是否为JMX协议
    
    Args:
        host: 目标主机
        port: 目标端口
        timeout: 超时时间
        
    Returns:
        bool: 是否为JMX协议
    """
    try:
        # JMX握手包
        jmx_handshake = bytes([
            0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b
        ])
        
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # 发送JMX握手包
        sock.sendall(jmx_handshake)
        
        # 接收响应
        response = sock.recv(1024)
        sock.close()
        
        # 检查响应是否符合JMX协议
        if response and len(response) > 0:
            # JMX协议响应通常以JRMI开头
            if response.startswith(b'JRMI') or b'java.rmi' in response:
                return True
        
        return False
    except Exception as e:
        logger.error(f"检查JMX协议异常: {str(e)}")
        return False

def exploit(scanner, jmx_port=18983, command=None):
    """
    利用CVE-2019-12409漏洞执行命令
    
    Args:
        scanner: SolrScanner实例
        jmx_port: JMX服务端口，默认为18983
        command: 要执行的命令
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    # 参数校验
    if not scanner or not hasattr(scanner, 'target_url'):
        return False, "无效的扫描器实例"
    
    try:
        jmx_port = int(jmx_port)
    except (ValueError, TypeError):
        return False, f"无效的JMX端口: {jmx_port}，必须为整数"
    
    if not command:
        return False, "请提供要执行的命令"
    
    # 检查漏洞是否存在
    is_vulnerable, details = check(scanner, jmx_port)
    if not is_vulnerable:
        return False, f"目标不存在CVE-2019-12409漏洞: {details}"
    
    # 提示用户需要使用专业工具进行实际利用
    exploit_guide = """
CVE-2019-12409漏洞利用需要构建完整的JMX利用链，当前仅支持检测功能。
请按照以下步骤使用专业工具进行实际利用:

1. 使用JMXploit或MLet工具:
   - https://github.com/mogwailabs/mjet
   - https://github.com/qtc-de/beanshooter

2. 连接到JMX服务:
   $ java -jar jmxploit.jar -t {host} -p {port} -c "{command}"

3. 或使用yso-mlet.jar创建恶意MBean:
   $ java -jar yso-mlet.jar -t {host} -p {port} -c "{command}"

检测到JMX服务开放在 {host}:{port}，可以尝试利用。
""".format(
        host=urlparse(scanner.target_url).hostname,
        port=jmx_port,
        command=command
    )
    
    return True, exploit_guide
