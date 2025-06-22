#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SolrScan 核心工具模块
提供通用工具函数
"""

import os
import sys
import json
import logging
import base64
import random
import string
import time
import re
from urllib.parse import urlparse, urljoin

# 日志配置
logger = logging.getLogger(__name__)

def normalize_url(url):
    """规范化URL
    
    Args:
        url: 输入URL
        
    Returns:
        str: 规范化后的URL
    """
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def generate_random_string(length=8):
    """生成随机字符串
    
    Args:
        length: 字符串长度
        
    Returns:
        str: 随机字符串
    """
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def encode_command(command):
    """Base64编码命令
    
    Args:
        command: 要编码的命令
        
    Returns:
        str: 编码后的命令
    """
    return base64.b64encode(command.encode()).decode()

def decode_command(encoded):
    """Base64解码命令
    
    Args:
        encoded: 编码的命令
        
    Returns:
        str: 解码后的命令
    """
    return base64.b64decode(encoded.encode()).decode()

def extract_file_content(response_text):
    """从响应中提取文件内容
    
    Args:
        response_text: 响应文本
        
    Returns:
        str: 提取的文件内容
    """
    # 尝试解析JSON
    try:
        data = json.loads(response_text)
        # 检查常见的JSON结构
        if "streams" in data:
            streams = data["streams"]
            if streams and len(streams) > 0:
                return streams[0].get("stream", "")
        elif "exception" in data:
            # 尝试从异常中提取文件内容
            exception = data["exception"]
            file_content = re.search(r'file content:(.*)', exception, re.DOTALL)
            if file_content:
                return file_content.group(1).strip()
            else:
                return exception
        return response_text
    except:
        # 不是JSON格式，尝试其他提取方法
        # 检查是否包含常见的文件内容标记
        if "root:" in response_text and ":/bin/" in response_text:
            # 可能是/etc/passwd文件
            lines = response_text.split('\n')
            passwd_lines = [line for line in lines if ':/' in line]
            if passwd_lines:
                return '\n'.join(passwd_lines)
        return response_text

def parse_version(version_str):
    """解析版本号
    
    Args:
        version_str: 版本字符串
        
    Returns:
        tuple: (主版本号, 次版本号, 补丁版本号)
    """
    parts = version_str.split('.')
    major = int(parts[0]) if parts and parts[0].isdigit() else 0
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return (major, minor, patch)

def version_compare(version_str, target_version):
    """比较版本号
    
    Args:
        version_str: 当前版本字符串
        target_version: 目标版本字符串
        
    Returns:
        int: -1(小于), 0(等于), 1(大于)
    """
    v1 = parse_version(version_str)
    v2 = parse_version(target_version)
    
    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0

def is_version_affected(version_str, affected_range):
    """检查版本是否在受影响范围内
    
    Args:
        version_str: 当前版本字符串
        affected_range: 受影响版本范围描述
        
    Returns:
        bool: 是否受影响
    """
    # 解析版本范围描述
    if '<' in affected_range:
        # 小于某个版本
        target = affected_range.replace('<', '').strip()
        return version_compare(version_str, target) < 0
    elif '>' in affected_range:
        # 大于某个版本
        target = affected_range.replace('>', '').strip()
        return version_compare(version_str, target) > 0
    elif '-' in affected_range:
        # 版本范围
        parts = affected_range.split('-')
        min_version = parts[0].strip()
        max_version = parts[1].strip()
        return (version_compare(version_str, min_version) >= 0 and 
                version_compare(version_str, max_version) <= 0)
    else:
        # 精确版本匹配
        return version_str.strip() == affected_range.strip()
