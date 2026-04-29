#!/bin/bash
# 招标监控系统 - 直连启动脚本（绕过系统代理）
cd "$(dirname "$0")"

# 清理旧进程
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
sleep 1

# 绕过代理（让 curl/requests 直连 localhost）
export NO_PROXY="localhost,127.0.0.1"
export no_proxy="localhost,127.0.0.1"

# 启动后端
source venv/bin/activate
python3 main.py &
BACKEND_PID=$!
echo "后端已启动 (PID: $BACKEND_PID)"

# 等待后端就绪
sleep 2
curl -s "http://localhost:8000/api/health" > /dev/null && echo "后端健康检查 OK" || echo "后端启动异常"

echo ""
echo "请使用以下方式之一打开 index.html："
echo "1. 直接双击 index.html 文件"
echo "2. 或终端输入: open -a 'Google Chrome' file://$(pwd)/index.html"
echo ""
echo "如需停止服务: kill $BACKEND_PID"