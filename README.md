# SolrScan GUI 模块化重构与POC补全

## 项目概述

本项目对Apache Solr漏洞扫描工具进行了全面的模块化重构和POC补全，在保持原有GUI界面和功能不变的前提下，优化了代码架构，使其更易于维护和扩展。

## 主要改进

1. **模块化架构**：
   - 将所有漏洞POC从主程序中提取为独立模块
   - 创建核心扫描器模块，实现动态加载漏洞模块
   - 统一漏洞检测和利用接口，标准化参数传递

2. **POC补全**：
   - 补充实现了所有缺失的POC，包括：
     - CVE-2019-12409 (Apache Solr JMX服务 RCE)
     - CVE-2020-13957 (Apache Solr RCE 未授权上传漏洞)
     - CNVD-2023-27598 (Apache Solr 代码执行漏洞)
   - 修复了CVE-2021-27905 (原代码中误写为CVE-2021-28905)的实现
   - 完善了CVE-2023-50290的实现

3. **参数传递机制优化**：
   - 确保GUI中用户输入的参数能正确传递到漏洞检测和利用函数
   - 统一了所有POC模块的参数签名，使其与GUI参数采集机制兼容
   - 实现了动态参数传递，支持core、dnslog_domain、command、file_path等参数

4. **测试与验证**：
   - 添加了独立的测试脚本，支持命令行测试所有漏洞
   - 验证了所有POC模块与主程序的集成效果

## 目录结构

```
solrscan_gui/
├── modules/                # 模块目录
│   ├── __init__.py         # 模块包初始化
│   ├── core.py             # 核心扫描器模块
│   ├── utils.py            # 通用工具函数
│   └── vulns/              # 漏洞模块目录
│       ├── __init__.py     # 漏洞模块包初始化
│       ├── cve_2017_12629.py  # CVE-2017-12629 漏洞模块
│       ├── cve_2019_0193.py   # CVE-2019-0193 漏洞模块
│       ├── cve_2019_17558.py  # CVE-2019-17558 漏洞模块
│       ├── cve_2019_12409.py  # CVE-2019-12409 漏洞模块 (新增)
│       ├── cve_2020_13957.py  # CVE-2020-13957 漏洞模块 (新增)
│       ├── cve_2021_27905.py  # CVE-2021-27905 漏洞模块 (修复)
│       ├── cve_2023_50290.py  # CVE-2023-50290 漏洞模块 (完善)
│       ├── cnvd_2023_27598.py # CNVD-2023-27598 漏洞模块 (新增)
│       ├── cve_2024_45216.py  # CVE-2024-45216 漏洞模块
│       └── solr_stream_file_read.py  # RemoteStreaming文件读取漏洞模块
├── main.py                 # 主程序（GUI界面）
├── run.py                  # 启动脚本
└── test.py                 # 测试脚本
```

## 使用说明

1. **GUI界面**：
   ```
   python run.py
   ```

2. **命令行测试**：
   ```
   # 列出所有支持的漏洞
   python test.py --list
   
   # 检测指定漏洞
   python test.py -t http://target-solr:8983/ -v CVE-2019-17558
   
   # 利用漏洞执行命令
   python test.py -t http://target-solr:8983/ -v CVE-2019-17558 -cmd "id"
   
   # 利用漏洞读取文件
   python test.py -t http://target-solr:8983/ -v SOLR-STREAM-FILE-READ -f "/etc/passwd"
   ```

## 扩展指南

### 添加新漏洞

1. 在`modules/vulns/`目录下创建新的漏洞模块文件，如`cve_yyyy_nnnnn.py`
2. 实现标准的`check()`和`exploit()`函数
3. 在`main.py`的`VULN_DETAILS`字典中添加漏洞信息

### 修改现有漏洞

直接编辑对应的漏洞模块文件，无需修改主程序代码。

## 注意事项

- 所有漏洞模块都遵循统一的参数签名，确保与GUI参数采集机制兼容
- 核心扫描器支持动态加载漏洞模块，无需手动导入
- 测试脚本支持命令行参数，方便单独测试各个漏洞
