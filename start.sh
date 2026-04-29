#!/bin/bash
# 招标信息监控系统启动脚本
cd "$(dirname "$0")"
source venv/bin/activate
python3 main.py