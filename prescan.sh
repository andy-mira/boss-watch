#!/usr/bin/env bash
# boss-watch 推送前自检：禁词短语扫描 + 密钥模式扫描
# 用法: 在仓库根运行 bash prescan.sh ；退出码非0 = 有敏感内容，禁止 push
set -u
cd "$(dirname "$0")"

BLOCKLIST=".nova-blocklist.txt"
FAIL=0
MDFILES=$(git ls-files '*.md')
[ -z "$MDFILES" ] && { echo "prescan OK (no md files tracked)"; exit 0; }

# 1) 词库短语扫描（跳过 # 注释行；短语整体匹配，不按空格拆）
if [ -f "$BLOCKLIST" ]; then
  grep -v '^#' "$BLOCKLIST" | sed 's/^[^:]*://' | tr '/' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$' | while IFS= read -r w; do
    [ "${#w}" -lt 2 ] && continue
    if grep -iqF -e "$w" $MDFILES >/dev/null 2>&1; then
      echo "BLOCKED word: $w"
      grep -inF -e "$w" $MDFILES | head -2
      echo "$w" >> /tmp/bosswatch_hit.txt
    fi
  done
  if [ -f /tmp/bosswatch_hit.txt ]; then FAIL=1; rm -f /tmp/bosswatch_hit.txt; fi
fi

# 2) 密钥/凭证模式
if xargs grep -nE 'sk-[A-Za-z0-9_-]{10,}|gh[oprs]_[A-Za-z0-9]{20,}|BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY|xox[bpars]-|AKIA[0-9A-Z]{16}|eyJhbGciOi' <<< "$MDFILES" >/dev/null 2>&1; then
  echo "BLOCKED: credential pattern found"
  xargs grep -nE 'sk-[A-Za-z0-9_-]{10,}|gh[oprs]_[A-Za-z0-9]{20,}|BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY' <<< "$MDFILES" | head -3
  FAIL=1
fi

if [ "$FAIL" -eq 1 ]; then
  echo "prescan FAILED — do not push"
  exit 1
fi
echo "prescan OK"
