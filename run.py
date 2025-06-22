#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SolrScan 启动脚本
"""

import sys

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow
from main import MainWindow
class MyWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # 设置窗口图标（支持 PNG、ICO 等格式）
        self.setWindowIcon(QIcon('icon.jpg'))  # 替换成你的图标路径
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    # 设置全局图标（可选，任务栏图标）
    app.setWindowIcon(QIcon('icon.jpg'))
    window.show()
    sys.exit(app.exec_())




