#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SolrScan 测试脚本
用于测试漏洞检测和利用功能
"""

import sys
import argparse
import logging
from modules.core import SolrScanner

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="SolrScan 测试工具")
    parser.add_argument("-t", "--target", required=True, help="目标URL")
    parser.add_argument("-v", "--vuln", help="指定漏洞ID")
    parser.add_argument("-c", "--core", help="指定核心名称")
    parser.add_argument("-cmd", "--command", help="要执行的命令")
    parser.add_argument("-f", "--file", help="要读取的文件路径")
    parser.add_argument("-d", "--dnslog", help="DNSLOG域名")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间")
    parser.add_argument("--proxy", help="代理设置")
    parser.add_argument("--list", action="store_true", help="列出所有支持的漏洞")
    args = parser.parse_args()
    
    # 列出所有支持的漏洞
    if args.list:
        from main import VULN_DETAILS
        print("支持的漏洞列表:")
        for vuln_id, details in VULN_DETAILS.items():
            print(f"  - {vuln_id}: {details['name']} ({details['type']})")
        return
    
    # 创建扫描器
    scanner = SolrScanner(args.target, timeout=args.timeout, proxy=args.proxy)
    
    # 获取Solr信息
    info = scanner.get_solr_info()
    if info:
        print(f"Solr版本: {scanner.version}")
        cores = scanner.get_cores()
        print(f"核心列表: {', '.join(cores) if cores else '未发现核心'}")
    else:
        print("无法获取Solr信息")
    
    # 检测或利用漏洞
    if args.vuln:
        if args.command:
            # 执行命令
            print(f"利用漏洞 {args.vuln} 执行命令: {args.command}")
            success, result = scanner.exploit_vulnerability(
                args.vuln, 
                core=args.core,
                command=args.command
            )
            print(f"执行结果: {'成功' if success else '失败'}")
            print(result)
        elif args.file:
            # 读取文件
            print(f"利用漏洞 {args.vuln} 读取文件: {args.file}")
            success, result = scanner.exploit_vulnerability(
                args.vuln, 
                core=args.core,
                file_path=args.file
            )
            print(f"读取结果: {'成功' if success else '失败'}")
            print(result)
        elif args.dnslog:
            # DNSLOG测试
            print(f"利用漏洞 {args.vuln} 发送DNSLOG请求: {args.dnslog}")
            success, result = scanner.exploit_vulnerability(
                args.vuln, 
                core=args.core,
                dnslog_domain=args.dnslog
            )
            print(f"DNSLOG请求结果: {'成功' if success else '失败'}")
            print(result)
        else:
            # 检测漏洞
            print(f"检测漏洞: {args.vuln}")
            is_vulnerable, details = scanner.check_vulnerability(
                args.vuln, 
                core=args.core
            )
            print(f"检测结果: {'存在漏洞' if is_vulnerable else '未发现漏洞'}")
            print(details)
    else:
        # 检测所有漏洞
        from main import VULN_DETAILS
        print("检测所有漏洞:")
        for vuln_id in VULN_DETAILS.keys():
            print(f"检测漏洞: {vuln_id}")
            is_vulnerable, details = scanner.check_vulnerability(
                vuln_id, 
                core=args.core
            )
            print(f"  - {vuln_id}: {'存在漏洞' if is_vulnerable else '未发现漏洞'}")
            if is_vulnerable:
                print(f"    详情: {details}")

if __name__ == "__main__":
    main()
