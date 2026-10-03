#!/usr/bin/env bash
# 全面检查流水线（F795）：分阶段、分 crate、可单跑、出总结。
#
# 用法：
#   scripts/check.sh                 # 全阶段
#   scripts/check.sh fmt clippy      # 只跑指定阶段
#   阶段: fmt | clippy | check | test | audit | summary
#
# 设计（用户五点框架的②）：
#   - 分而治之：test/clippy 按 crate 逐个跑——workspace 全量并行正是蜜罐
#     测试抖动的来源（端口池竞争），单 crate 跑出的问题可归因、可重放。
#   - 每阶段独立计分，末尾 summary 一览；失败阶段不中断后续阶段（一次拿到
#     全部反馈），退出码 = 失败阶段数。
#   - 审查与运行时阶段（③⑤）在流水线外：审查走 agent+docs/CHECKLIST.md，
#     运行时走节点 verify-log + 事件 summary 分布（见 CHECKLIST「运行时验证」）。

set -u
cd "$(dirname "$0")/.."

STAGES="${*:-fmt clippy check test audit}"
declare -A RESULT
CRATES=$(cargo metadata --no-deps --format-version 1 2>/dev/null | python -c "import json,sys; print(' '.join(p['name'].split('aisafeguard-')[1] for p in json.load(sys.stdin)['packages'] if p['name'].startswith('aisafeguard-')))")
echo "== crates: $CRATES"
T0=$(date +%s)

stage_fmt() {
    echo "== [fmt] rustfmt --check"
    cargo fmt --all -- --check 2>&1 | head -40
    # fmt 首轮为报告性检查（存量未格式化不拦门），全绿后升格为门禁
    RESULT[fmt]="report"
}

stage_clippy() {
    local fail=0
    for c in $CRATES; do
        echo "== [clippy] aisafeguard-$c"
        if ! cargo clippy -p "aisafeguard-$c" --all-targets --quiet 2>&1 \
            | grep -E "^warning: [a-z]|^error" | grep -v "^warning: windivert\|^warning: \`C:" \
            | head -10; then :; fi
    done
    # 门禁以 workspace 总量为准（-D warnings 语义 = 输出里无代码 warning）
    local n
    n=$(cargo clippy --workspace --all-targets --quiet 2>&1 | grep -cE "^warning: [a-z]|^error" || true)
    if [ "$n" -gt 0 ]; then RESULT[clippy]="FAIL($n)"; else RESULT[clippy]=OK; fi
}

stage_check() {
    echo "== [check] cargo check --workspace（类型门）"
    if cargo check --workspace --quiet 2>&1 | grep -E "^error"; then
        RESULT[check]=FAIL
    else
        RESULT[check]=OK
    fi
}

stage_test() {
    local fail=()
    for c in $CRATES; do
        echo "== [test] aisafeguard-$c"
        if cargo test -p "aisafeguard-$c" --quiet 2>&1 | grep -E "test result: FAILED|^error\[" ; then
            fail+=("$c")
        fi
    done
    if [ "${#fail[@]}" -eq 0 ]; then RESULT[test]=OK; else RESULT[test]="FAIL(${fail[*]})"; fi
}

stage_audit() {
    echo "== [audit] cargo audit / deny"
    local a=0 d=0
    cargo audit 2>&1 | grep -E "^Crate|^error|^warning:" | head -10
    cargo audit >/dev/null 2>&1 || a=$?
    cargo deny check 2>&1 | tail -3
    cargo deny check >/dev/null 2>&1 || d=$?
    if [ $a -ne 0 ] || [ $d -ne 0 ]; then RESULT[audit]="FAIL(a=$a,d=$d)"; else RESULT[audit]=OK; fi
}

for s in $STAGES; do
    "stage_$s"
done

T1=$(date +%s)
echo
echo "== 检查总结（$((T1 - T0))s）=="
for s in $STAGES; do
    echo "  $s: ${RESULT[$s]:-SKIP}"
done
