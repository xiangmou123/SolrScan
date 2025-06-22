import os
import sys
import json
import logging
import requests
import importlib
import inspect
import time
import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# 日志配置
logger = logging.getLogger(__name__)

class SolrScanner:
    """Solr漏洞扫描器类"""
    
    def __init__(self, target_url, timeout=10, proxy=None, retry=2):
        """初始化扫描器
        
        Args:
            target_url: 目标URL
            timeout: 请求超时时间
            proxy: 代理设置
            retry: 请求重试次数
        """
        self.target_url = target_url.rstrip("/")
        self.target = target_url.rstrip("/")  # 添加target属性，兼容旧代码
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.version = None
        self.cores = []
        self.retry = retry
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        })
        self.session.verify = False
        
        # 添加线程锁，防止并发问题
        self.lock = threading.Lock()
    
    def request(self, method, path, **kwargs):
        """发送HTTP请求，支持重试机制
        
        Args:
            method: 请求方法
            path: 请求路径
            **kwargs: 请求参数
            
        Returns:
            requests.Response: 响应对象
        """
        url = urljoin(self.target_url, path.lstrip("/"))
        
        # 设置默认参数
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("proxies", self.proxies)
        
        # 添加重试机制
        for attempt in range(self.retry + 1):
            try:
                return self.session.request(method, url, **kwargs)
            except requests.exceptions.Timeout:
                if attempt < self.retry:
                    logger.warning(f"请求超时，正在进行第 {attempt+1} 次重试: {url}")
                    time.sleep(1)  # 重试前等待1秒
                else:
                    logger.error(f"请求超时，已达到最大重试次数: {url}")
                    return None
            except requests.exceptions.ConnectionError:
                if attempt < self.retry:
                    logger.warning(f"连接错误，正在进行第 {attempt+1} 次重试: {url}")
                    time.sleep(1)  # 重试前等待1秒
                else:
                    logger.error(f"连接错误，已达到最大重试次数: {url}")
                    return None
            except Exception as e:
                logger.error(f"请求异常: {str(e)}")
                return None
    
    def get_solr_info(self):
        """获取Solr信息
        
        Returns:
            dict: Solr信息
        """
        try:
            # 尝试获取系统信息
            resp = self.request("GET", "/solr/admin/info/system?wt=json")
            if resp and resp.status_code == 200:
                data = resp.json()
                self.version = data.get("lucene", {}).get("solr-spec-version", "未知")
                return data
            
            # 尝试使用认证绕过方式获取系统信息
            resp = self.request("GET", "/solr/admin/info/system:/admin/info/key?wt=json")
            if resp and resp.status_code == 200:
                data = resp.json()
                self.version = data.get("lucene", {}).get("solr-spec-version", "未知")
                return data
            
            return None
        except Exception as e:
            logger.error(f"获取Solr信息异常: {str(e)}")
            return None
    
    def get_cores(self):
        """获取Solr核心列表
        
        Returns:
            list: 核心列表
        """
        # 使用线程锁保护共享资源
        with self.lock:
            if self.cores:
                return self.cores
            
            try:
                # 尝试获取核心列表
                resp = self.request("GET", "/solr/admin/cores?wt=json&indexInfo=false")
                if resp and resp.status_code == 200:
                    data = resp.json()
                    self.cores = list(data.get("status", {}).keys())
                    return self.cores
                
                # 尝试使用认证绕过方式获取核心列表
                resp = self.request("GET", "/solr/admin/cores:/admin/info/key?wt=json&indexInfo=false")
                if resp and resp.status_code == 200:
                    data = resp.json()
                    self.cores = list(data.get("status", {}).keys())
                    return self.cores
                
                return []
            except Exception as e:
                logger.error(f"获取核心列表异常: {str(e)}")
                return []
    
    def check_vulnerability(self, vuln_id, **kwargs):
        """检测漏洞
        
        Args:
            vuln_id: 漏洞ID
            **kwargs: 其他参数
            
        Returns:
            (bool, str): (是否存在漏洞, 详细信息)
        """
        try:
            # 动态导入漏洞模块
            module_name = vuln_id.lower().replace("-", "_")
            try:
                module = importlib.import_module(f"modules.vulns.{module_name}")
            except ImportError:
                # 尝试使用标准化的CVE ID格式
                if "cve" in module_name:
                    parts = module_name.split("_")
                    if len(parts) >= 3:
                        year = parts[1]
                        number = parts[2]
                        module_name = f"cve_{year}_{number}"
                        try:
                            module = importlib.import_module(f"modules.vulns.{module_name}")
                        except ImportError:
                            return False, f"未找到漏洞模块: {vuln_id}"
                else:
                    return False, f"未找到漏洞模块: {vuln_id}"
            
            # 检查模块是否有check函数
            if hasattr(module, "check"):
                # 获取函数签名
                sig = inspect.signature(module.check)
                
                # 准备参数
                call_args = {"scanner": self}
                
                # 添加其他参数
                for param_name in sig.parameters:
                    if param_name != "scanner" and param_name in kwargs:
                        call_args[param_name] = kwargs[param_name]
                
                # 调用check函数
                return module.check(**call_args)
            else:
                return False, f"漏洞模块 {vuln_id} 没有check函数"
        except Exception as e:
            logger.error(f"检测漏洞 {vuln_id} 异常: {str(e)}")
            return False, f"检测异常: {str(e)}"
    
    def exploit_vulnerability(self, vuln_id, **kwargs):
        """利用漏洞
        
        Args:
            vuln_id: 漏洞ID
            **kwargs: 其他参数
            
        Returns:
            (bool, str): (是否成功, 结果信息)
        """
        try:
            # 动态导入漏洞模块
            module_name = vuln_id.lower().replace("-", "_")
            try:
                module = importlib.import_module(f"modules.vulns.{module_name}")
            except ImportError:
                # 尝试使用标准化的CVE ID格式
                if "cve" in module_name:
                    parts = module_name.split("_")
                    if len(parts) >= 3:
                        year = parts[1]
                        number = parts[2]
                        module_name = f"cve_{year}_{number}"
                        try:
                            module = importlib.import_module(f"modules.vulns.{module_name}")
                        except ImportError:
                            return False, f"未找到漏洞模块: {vuln_id}"
                else:
                    return False, f"未找到漏洞模块: {vuln_id}"
            
            # 检查模块是否有exploit函数
            if hasattr(module, "exploit"):
                # 获取函数签名
                sig = inspect.signature(getattr(module, "exploit"))
                
                # 准备参数
                call_args = {"scanner": self}
                
                # 添加其他参数
                for param_name in sig.parameters:
                    if param_name != "scanner" and param_name in kwargs:
                        call_args[param_name] = kwargs[param_name]
                
                # 调用exploit函数
                return module.exploit(**call_args)
            else:
                return False, f"漏洞模块 {vuln_id} 没有exploit函数"
        except Exception as e:
            logger.error(f"利用漏洞 {vuln_id} 异常: {str(e)}")
            return False, f"利用异常: {str(e)}"
    
    def get_required_params(self, vuln_id, operation="check"):
        """获取漏洞检测或利用所需的参数
        
        Args:
            vuln_id: 漏洞ID
            operation: 操作类型，"check"或"exploit"
            
        Returns:
            list: 参数列表
        """
        try:
            # 动态导入漏洞模块
            module_name = vuln_id.lower().replace("-", "_")
            try:
                module = importlib.import_module(f"modules.vulns.{module_name}")
            except ImportError:
                # 尝试使用标准化的CVE ID格式
                if "cve" in module_name:
                    parts = module_name.split("_")
                    if len(parts) >= 3:
                        year = parts[1]
                        number = parts[2]
                        module_name = f"cve_{year}_{number}"
                        try:
                            module = importlib.import_module(f"modules.vulns.{module_name}")
                        except ImportError:
                            return []
                else:
                    return []
            
            # 检查模块是否有指定的函数
            if hasattr(module, operation):
                # 获取函数签名
                sig = inspect.signature(getattr(module, operation))
                
                # 获取参数列表，排除scanner参数
                params = [param for param in sig.parameters if param != "scanner"]
                return params
            else:
                return []
        except Exception as e:
            logger.error(f"获取漏洞 {vuln_id} 参数异常: {str(e)}")
            return []

class BatchScanner:
    """批量扫描器类，优化多线程性能"""
    
    def __init__(self, targets, selected_vulns, timeout=10, proxy=None, max_threads=10, retry=2):
        """初始化批量扫描器
        
        Args:
            targets: 目标URL列表
            selected_vulns: 选择的漏洞ID列表
            timeout: 请求超时时间
            proxy: 代理设置
            max_threads: 最大线程数
            retry: 请求重试次数
        """
        self.targets = targets
        self.selected_vulns = selected_vulns
        self.timeout = timeout
        self.proxy = proxy
        self.max_threads = max_threads
        self.retry = retry
        self.results = {}
        self.stop_event = threading.Event() # 使用Event对象来控制停止
        
        # 进度回调函数
        self.on_progress = None
        self.on_result = None
        self.on_finished = None
    
    def scan(self):
        """执行批量扫描"""
        total = len(self.targets)
        completed = 0
        
        # 创建线程池
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # 提交所有任务
            future_to_target = {
                executor.submit(self._scan_target, target): target 
                for target in self.targets
            }
            
            # 处理完成的任务
            for future in as_completed(future_to_target):
                if self.stop_event.is_set(): # 检查停止事件
                    # 取消所有未完成的任务
                    for f in future_to_target:
                        if not f.done():
                            f.cancel()
                    break
                
                target = future_to_target[future]
                try:
                    result = future.result()
                    self.results[target] = result
                    
                    # 回调通知结果
                    if self.on_result:
                        self.on_result({target: result})
                except Exception as e:
                    logger.error(f"扫描目标 {target} 异常: {str(e)}")
                    self.results[target] = {
                        "target": target,
                        "error": str(e),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                
                # 更新进度
                completed += 1
                if self.on_progress:
                    self.on_progress(completed, total)
        
        # 扫描完成回调
        if self.on_finished and not self.stop_event.is_set(): # 检查停止事件
            self.on_finished(self.results)
    
    def _scan_target(self, target):
        """扫描单个目标
        
        Args:
            target: 目标URL
            
        Returns:
            dict: 扫描结果
        """
        if self.stop_event.is_set(): # 在任务开始前检查停止事件
            return {
                "target": target,
                "status": "stopped",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }

        # 创建扫描器实例
        scanner = SolrScanner(
            target, 
            timeout=self.timeout, 
            proxy=self.proxy,
            retry=self.retry
        )
        
        # 初始化结果
        result = {
            "target": target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 获取基本信息
        info = scanner.get_solr_info()
        if info:
            result["info"] = {
                "version": scanner.version,
                "cores": scanner.get_cores()
            }
        else:
            result["info"] = {
                "version": "未知",
                "cores": []
            }
        
        # 检测选定的漏洞
        result["vulnerabilities"] = {}
        
        for vuln_id in self.selected_vulns:
            if self.stop_event.is_set(): # 在每个漏洞检测前检查停止事件
                break
                
            # 检测漏洞
            try:
                is_vulnerable, details = scanner.check_vulnerability(vuln_id)
                result["vulnerabilities"][vuln_id] = {
                    "vulnerable": is_vulnerable,
                    "details": details
                }
            except Exception as e:
                logger.error(f"检测漏洞 {vuln_id} 异常: {str(e)}")
                result["vulnerabilities"][vuln_id] = {
                    "vulnerable": False,
                    "details": f"检测异常: {str(e)}"
                }
        
        return result
    
    def stop(self):
        """停止扫描"""
        self.stop_event.set() # 设置停止事件

