#!/usr/bin/env bash
#
# Протокол тестирования стенда X-Forwarded-For.
#
# Каждый кейс:
#   - печатает выполняемый curl;
#   - печатает поле x_forwarded_for_chain из ответа приложения;
#   - сравнивает фактическую цепочку XFF (без первого хопа - IP клиента/гейтвея)
#     с ожидаемой и помечает кейс PASS/FAIL.
#
# Запуск:  bash tests/run_tests.sh
# Требования: bash, curl. JSON парсится средствами shell, внешних зависимостей нет.
#
# Замечание: curl вызывается с --noproxy '*', чтобы обойти прокси из окружения
# (http_proxy / https_proxy), если он задан в системе.
#

set -u

HOST="${HOST:-localhost}"
N1="http://${HOST}:8081"
N2="http://${HOST}:8082"
N3="http://${HOST}:8083"

# Фиксированные IP nginx в сети proxynet (см. docker-compose.yml).
IP1="10.10.0.11"
IP2="10.10.0.12"
IP3="10.10.0.13"

PASS=0
FAIL=0

c_reset=$'\e[0m'; c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_cyn=$'\e[36m'

# Извлечь массив x_forwarded_for_chain из ответа JSON и привести к CSV.
# Полагаемся на формат, который пишет наш app.py (FastAPI/JSONResponse) - массив
# строк без вложенностей: "x_forwarded_for_chain":["a","b","c"].
extract_chain() {
    sed -n 's/.*"x_forwarded_for_chain":\[\([^]]*\)\].*/\1/p' \
        | tr -d '"' \
        | tr -d ' '
}

# Аргументы: <название> <ожидаемый_tail_XFF> <curl-args...>
#   ожидаемый_tail_XFF - часть цепочки ПОСЛЕ IP клиента (т.е. IP nginx-хопов).
#   IP клиента в стенде = 10.10.0.1 (docker gateway), но проверяем именно «хвост»,
#   так как реальный клиентский адрес может отличаться (например, при запуске изнутри сети).
run_case() {
    local name="$1"; shift
    local expected_tail="$1"; shift

    echo
    echo "${c_cyn}=== ${name} ===${c_reset}"
    echo "${c_ylw}\$ curl -s --noproxy '*' $*${c_reset}"

    local body
    body="$(curl -s --noproxy '*' "$@")" || { echo "${c_red}curl failed${c_reset}"; FAIL=$((FAIL+1)); return; }
    if [[ -z "$body" ]]; then
        echo "${c_red}empty response${c_reset}"
        FAIL=$((FAIL+1))
        return
    fi

    echo "$body"

    local chain tail
    chain="$(printf '%s' "$body" | extract_chain)"
    # tail = всё после первой запятой; если запятой нет - пусто.
    if [[ "$chain" == *,* ]]; then
        tail="${chain#*,}"
    else
        tail=""
    fi

    echo "x_forwarded_for_chain: [${chain}]"

    if [[ "$tail" == "$expected_tail" ]]; then
        echo "${c_grn}PASS${c_reset}  (proxy chain tail = \"${tail}\", expected \"${expected_tail}\")"
        PASS=$((PASS+1))
    else
        echo "${c_red}FAIL${c_reset}  (proxy chain tail = \"${tail}\", expected \"${expected_tail}\")"
        FAIL=$((FAIL+1))
    fi

    # Жёсткая проверка отсутствия подделанных значений из заголовка клиента.
    if printf '%s' "$chain" | grep -qE '(^|,)(1\.2\.3\.4|5\.6\.7\.8|6\.6\.6\.6|evil\.example\.com)(,|$)'; then
        echo "${c_red}!! SECURITY FAIL: forged value leaked into XFF chain${c_reset}"
        FAIL=$((FAIL+1))
    fi
}

echo "Stand entry points: ${N1} ${N2} ${N3}"
echo "Trusted nginx IPs : ${IP1} (nginx1)  ${IP2} (nginx2)  ${IP3} (nginx3)"

# -----------------------------------------------------------------------------
# 1. Прямые запросы - клиент попадает на каждый nginx и далее в app.
#    Цепочка XFF на стороне app = только адрес клиента (хвост пустой).
# -----------------------------------------------------------------------------
run_case "case-01: user -> nginx1 -> app" \
    "" \
    "${N1}/"

run_case "case-02: user -> nginx2 -> app" \
    "" \
    "${N2}/"

run_case "case-03: user -> nginx3 -> app" \
    "" \
    "${N3}/"

# -----------------------------------------------------------------------------
# 2. Цепочки из 2-х nginx.
# -----------------------------------------------------------------------------
run_case "case-04: user -> nginx1 -> nginx2 -> app" \
    "${IP1}" \
    "${N1}/via/2/"

run_case "case-05: user -> nginx2 -> nginx3 -> app" \
    "${IP2}" \
    "${N2}/via/3/"

run_case "case-06: user -> nginx3 -> nginx1 -> app" \
    "${IP3}" \
    "${N3}/via/1/"

# -----------------------------------------------------------------------------
# 3. Цепочки из 3-х nginx.
# -----------------------------------------------------------------------------
run_case "case-07: user -> nginx1 -> nginx2 -> nginx3 -> app" \
    "${IP1},${IP2}" \
    "${N1}/via/2/via/3/"

run_case "case-08: user -> nginx3 -> nginx2 -> nginx1 -> app" \
    "${IP3},${IP2}" \
    "${N3}/via/2/via/1/"

run_case "case-09: user -> nginx2 -> nginx1 -> nginx3 -> app" \
    "${IP2},${IP1}" \
    "${N2}/via/1/via/3/"

# -----------------------------------------------------------------------------
# 4. Атаки: пользователь сам подкладывает фейковый X-Forwarded-For.
#    Ожидаем: подделка не должна попасть в цепочку, видимую приложением.
# -----------------------------------------------------------------------------
run_case "case-10: forged XFF, single hop (nginx1)" \
    "" \
    -H "X-Forwarded-For: 1.2.3.4" \
    "${N1}/"

run_case "case-11: forged XFF (multi-value), single hop (nginx2)" \
    "" \
    -H "X-Forwarded-For: 1.2.3.4, 5.6.7.8" \
    "${N2}/"

run_case "case-12: forged XFF, chain 1->2->3" \
    "${IP1},${IP2}" \
    -H "X-Forwarded-For: 6.6.6.6" \
    "${N1}/via/2/via/3/"

run_case "case-13: forged XFF with hostname, chain 3->2->1" \
    "${IP3},${IP2}" \
    -H "X-Forwarded-For: evil.example.com" \
    "${N3}/via/2/via/1/"

# -----------------------------------------------------------------------------
# Итог.
# -----------------------------------------------------------------------------
echo
echo "==========================================="
echo "  PASS: ${PASS}    FAIL: ${FAIL}"
echo "==========================================="
[[ "$FAIL" -eq 0 ]]
