#!/bin/bash
# 招标监控系统 - 强制直连启动（使用 Safari）
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 1. 停止旧进程
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
sleep 1

# 2. 启动后端
unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY
export NO_PROXY="localhost,127.0.0.1"
export no_proxy="localhost,127.0.0.1"

source venv/bin/activate
python3 main.py &
BACKEND_PID=$!

sleep 3

# 3. 验证后端健康
HEALTH=$(curl -s --noproxy '*' http://localhost:8000/api/health 2>/dev/null)
TOTAL=$(echo "$HEALTH" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['bids']['total'])" 2>/dev/null || echo "无法连接")
echo "后端健康状态: bids total=$TOTAL"

# 4. 用 Safari 打开 index.html（Safari 不走系统代理）
open -a Safari "file://$SCRIPT_DIR/index.html"

echo ""
echo "后端 PID: $BACKEND_PID"
echo "停止: kill $BACKEND_PID"
echo ""
echo "已在 Safari 中打开 index.html"
echo "如果显示条数少于预期，在 Safari 的 Develop → JavaScript Console 里执行:"
echo "fetch('http://localhost:8000/api/bids?page=1&page_size=20').then(r=>r.json()).then(d=>{console.log('total:', d.total, 'items:', d.items.length); document.querySelectorAll('#main-content table tbody tr').forEach(r=>console.log(r.querySelector('td:first-child').textContent.trim()))})"