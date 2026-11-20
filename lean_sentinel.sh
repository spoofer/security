lean-sentinel.sh
#!/bin/sh
# Lean Sentinel - Schlanke, selbstheilende Canary-Dateiüberwachung (POSIX sh)
# Unterstützt Debian & Ubuntu ohne Python oder externe Frameworks.

set -u
umask 022

DEFAULT_COOLDOWN=60
SERVICE_NAME="lean-sentinel.service"
STOP_REQUESTED=0
INOTIFY_PID=""
SELF_PATH=$0

init_paths() {
    if [ -n "${SENTINEL_TEST_ROOT:-}" ]; then
        IS_TEST_MODE=1
        TEST_ROOT=${SENTINEL_TEST_ROOT%/}
    else
        IS_TEST_MODE=0
        TEST_ROOT=""
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    fi
    export PATH

    BIN_PATH="${TEST_ROOT}/usr/local/sbin/lean-sentinel"
    CONF_DIR="${TEST_ROOT}/etc/lean-sentinel"
    CONF_FILE="${CONF_DIR}/sentinel.conf"
    CANARIES_FILE="${CONF_DIR}/canaries.list"
    CREATED_FILE="${CONF_DIR}/created.list"
    LOG_FILE="${TEST_ROOT}/var/log/lean_sentinel.log"
    RUN_DIR="${TEST_ROOT}/run/lean-sentinel"
    UNIT_FILE="${TEST_ROOT}/etc/systemd/system/${SERVICE_NAME}"
}

require_root() {
    if [ "$IS_TEST_MODE" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
        printf 'Fehler: Muss als root ausgeführt werden (z. B. sudo %s).\n' "$SELF_PATH" >&2
        exit 1
    fi
}

run_systemctl() {
    local sys_bin
    if [ "$IS_TEST_MODE" -eq 1 ]; then
        sys_bin=$(command -v systemctl 2>/dev/null || true)
        case "$sys_bin" in
            "${TEST_ROOT}/"*)
                "$sys_bin" "$@"
                return $?
                ;;
            *)
                return 0
                ;;
        esac
    fi
    systemctl "$@"
}

ensure_log_file() {
    local log_dir
    log_dir=${LOG_FILE%/*}
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" || return 1
    fi
    if [ ! -f "$LOG_FILE" ]; then
        : > "$LOG_FILE" || return 1
        chmod 0600 "$LOG_FILE" 2>/dev/null || true
    fi
}

log_line() {
    local ts
    ensure_log_file || return 1
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf '%s %s\n' "$ts" "$1" >> "$LOG_FILE"
}

add_unique_line() {
    local file line dir
    file=$1
    line=$2
    dir=${file%/*}
    [ -d "$dir" ] || mkdir -p "$dir"
    [ -f "$file" ] || : > "$file"
    if ! grep -Fqx -- "$line" "$file" 2>/dev/null; then
        printf '%s\n' "$line" >> "$file"
    fi
}

load_config() {
    local k v
    ALERT_EMAIL=""
    COOLDOWN_SECONDS="$DEFAULT_COOLDOWN"
    [ -f "$CONF_FILE" ] || return 0

    while IFS='=' read -r k v || [ -n "$k" ]; do
        case "$k" in
            ''|'#'*) continue ;;
            ALERT_EMAIL)
                ALERT_EMAIL=$(printf '%s' "$v" | tr -d '\r\n')
                ;;
            COOLDOWN_SECONDS)
                v=$(printf '%s' "$v" | tr -d '\r\n')
                case "$v" in
                    ''|*[!0-9]*) ;;
                    *) COOLDOWN_SECONDS=$v ;;
                esac
                ;;
        esac
    done < "$CONF_FILE"
}

save_config() {
    local tmp
    mkdir -p "$CONF_DIR" || return 1
    chmod 0700 "$CONF_DIR" 2>/dev/null || true
    tmp=$(mktemp "${CONF_DIR}/.conf.XXXXXX") || return 1
    {
        printf '# Lean Sentinel Konfiguration\n'
        printf 'ALERT_EMAIL=%s\n' "$ALERT_EMAIL"
        printf 'COOLDOWN_SECONDS=%s\n' "$COOLDOWN_SECONDS"
    } > "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 0600 "$tmp" 2>/dev/null || true
    mv -fT -- "$tmp" "$CONF_FILE" || { rm -f -- "$tmp"; return 1; }
}

validate_email() {
    local addr
    addr=$1
    if [ -z "$addr" ] || [ "$addr" = "-" ]; then
        return 0
    fi
    case "$addr" in
        *[[:space:]]*|*\"*|*\'*|*\\*) return 1 ;;
        ?*@?*.?*) return 0 ;;
        *) return 1 ;;
    esac
}

canary_payload() {
    cat <<'EOF'
# Production Environment Secrets - DO NOT DISTRIBUTE
DB_HOST=127.0.0.1
DB_USER=prod_service
DB_PASSWORD=trap_token_do_not_use_9f8a7b6c
API_SECRET_KEY=sk_live_lean_sentinel_canary_trap
EOF
}

canary_content_matches() {
    local path
    path=$1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    canary_payload | cmp -s - "$path" 2>/dev/null
}

write_canary_safe() {
    local canary parent_dir tmp
    canary=$1
    case "$canary" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$canary" in
        */) return 1 ;;
    esac

    parent_dir=${canary%/*}
    [ -n "$parent_dir" ] || parent_dir="/"

    if [ -L "$parent_dir" ] || [ ! -d "$parent_dir" ]; then
        log_line "[LEAN-ERROR] Elternverzeichnis ungültig oder Symlink: ${parent_dir}"
        return 1
    fi

    # Entferne eventuelle Symlinks oder Altdateien vor dem atomaren Platzieren
    rm -f -- "$canary" 2>/dev/null || true
    tmp=$(mktemp "${parent_dir}/.sentinel_tmp.XXXXXX") || return 1
    if ! canary_payload > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if ! chmod 0444 "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    if [ "$IS_TEST_MODE" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        chown root:root "$tmp" 2>/dev/null || true
    fi
    if ! mv -fT -- "$tmp" "$canary"; then
        rm -f -- "$tmp"
        return 1
    fi
    add_unique_line "$CREATED_FILE" "$canary"
    return 0
}

is_created_canary() {
    local cand
    cand=$1
    [ -f "$CREATED_FILE" ] && grep -Fqx -- "$cand" "$CREATED_FILE" 2>/dev/null
}

pick_canary_path() {
    local dir name cand clean_dir
    dir=$1
    [ -d "$dir" ] && [ ! -L "$dir" ] || return 1
    clean_dir=${dir%/}
    [ -n "$clean_dir" ] || clean_dir=""

    for name in .env_secret .credentials_secret.env .db_secret.env; do
        cand="${clean_dir}/${name}"
        if [ ! -e "$cand" ] && [ ! -L "$cand" ]; then
            printf '%s\n' "$cand"
            return 0
        fi
        if is_created_canary "$cand"; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    return 1
}

discover_core_targets() {
    local d cand
    for d in \
        "${TEST_ROOT}/root" \
        "${TEST_ROOT}/var/www/html" \
        "${TEST_ROOT}/var/www" \
        "${TEST_ROOT}/srv/www" \
        "${TEST_ROOT}/opt"
    do
        if [ -d "$d" ] && [ ! -L "$d" ]; then
            cand=$(pick_canary_path "$d" || true)
            [ -n "$cand" ] && printf '%s\n' "$cand"
        fi
    done

    if [ -d "${TEST_ROOT}/home" ] && [ ! -L "${TEST_ROOT}/home" ]; then
        for d in "${TEST_ROOT}/home"/*; do
            [ -d "$d" ] && [ ! -L "$d" ] || continue
            cand=$(pick_canary_path "$d" || true)
            [ -n "$cand" ] && printf '%s\n' "$cand"
        done
    fi
}

discover_web_subdirs() {
    local www_root d base cand
    www_root="${TEST_ROOT}/var/www"
    [ -d "$www_root" ] && [ ! -L "$www_root" ] || return 0
    for d in "$www_root"/*; do
        [ -d "$d" ] && [ ! -L "$d" ] || continue
        base=${d##*/}
        case "$base" in
            html|*.bak|*backup*|__pycache__|moodledata*|.*) continue ;;
        esac
        cand=$(pick_canary_path "$d" || true)
        [ -n "$cand" ] && printf '%s\n' "$cand"
    done
}

detect_mailer() {
    local bin
    bin=$(command -v sendmail 2>/dev/null || true)
    if [ -n "$bin" ] && [ -x "$bin" ]; then
        printf 'sendmail:%s\n' "$bin"
        return 0
    fi
    if [ "$IS_TEST_MODE" -eq 0 ]; then
        for bin in /usr/sbin/sendmail /usr/lib/sendmail; do
            if [ -x "$bin" ]; then
                printf 'sendmail:%s\n' "$bin"
                return 0
            fi
        done
    fi
    for bin in mail mailx; do
        bin=$(command -v "$bin" 2>/dev/null || true)
        if [ -n "$bin" ] && [ -x "$bin" ]; then
            printf 'mail:%s\n' "$bin"
            return 0
        fi
    done
    printf 'none\n'
}

ensure_dependencies() {
    if [ ! -f "${TEST_ROOT}/etc/debian_version" ] && [ ! -f /etc/debian_version ]; then
        printf 'Hinweis: Kein Debian/Ubuntu erkannt – versuche Installation dennoch.\n'
    fi

    if command -v inotifywait >/dev/null 2>&1; then
        return 0
    fi

    if [ "$IS_TEST_MODE" -eq 1 ]; then
        printf 'Fehler: inotifywait fehlt im Test-PATH.\n' >&2
        return 1
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        printf 'Fehler: apt-get nicht gefunden. Bitte inotify-tools manuell installieren.\n' >&2
        return 1
    fi

    printf 'Installiere fehlendes Paket: inotify-tools ...\n'
    if ! apt-get update -qq; then
        printf 'Fehler: apt-get update fehlgeschlagen.\n' >&2
        return 1
    fi
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends inotify-tools; then
        printf 'Fehler: Installation von inotify-tools fehlgeschlagen.\n' >&2
        return 1
    fi
    if ! command -v inotifywait >/dev/null 2>&1; then
        printf 'Fehler: inotifywait nach Installation weiterhin nicht verfügbar.\n' >&2
        return 1
    fi
    return 0
}

get_open_fd_pids() {
    local target fd pid comm result
    target=$1
    result=""
    for fd in $(find /proc/[0-9]*/fd -lname "$target" 2>/dev/null || true); do
        pid=${fd#/proc/}
        pid=${pid%%/*}
        comm=$(tr -d '\n' < "/proc/${pid}/comm" 2>/dev/null || true)
        result="${result}PID=${pid}(${comm}) "
    done
    if [ -n "$result" ]; then
        printf '%s' "$result"
    else
        printf 'keine offenen File-Handles mehr aktiv'
    fi
}

send_alert_email() {
    local canary ev_mask msg mailer mailer_type mailer_bin
    local sum cd_file now last_ts host ts sessions open_pids subject mail_rc
    canary=$1
    ev_mask=$2
    msg=$3

    load_config
    if [ -z "$ALERT_EMAIL" ]; then
        return 0
    fi

    mkdir -p "$RUN_DIR" 2>/dev/null || true
    set -- $(printf '%s' "$canary" | cksum)
    sum=$1
    cd_file="${RUN_DIR}/cd_${sum}"
    now=$(date '+%s')

    if [ -f "$cd_file" ]; then
        read -r last_ts < "$cd_file" 2>/dev/null || last_ts=""
        case "$last_ts" in
            ''|*[!0-9]*) ;;
            *)
                if [ $((now - last_ts)) -lt "$COOLDOWN_SECONDS" ]; then
                    log_line "[LEAN-INFO] E-Mail-Benachrichtigung übersprungen (E-Mail-Cooldown aktiv, ${COOLDOWN_SECONDS}s) für: ${canary}"
                    return 0
                fi
                ;;
        esac
    fi

    mailer=$(detect_mailer)
    if [ "$mailer" = "none" ]; then
        log_line "[LEAN-INFO] Kein Mail-Versand möglich (Mail nicht verfügbar) – Alarm lokal protokolliert."
        return 0
    fi

    mailer_type=${mailer%%:*}
    mailer_bin=${mailer#*:}
    host=$(uname -n 2>/dev/null || hostname 2>/dev/null || printf 'unbekannt')
    ts=$(date '+%Y-%m-%d %H:%M:%S %z')
    sessions=$(who 2>/dev/null | tr '\n' ';' || true)
    [ -n "$sessions" ] || sessions="keine"
    open_pids=$(get_open_fd_pids "$canary")
    subject="[LEAN-SENTINEL] Alarm auf ${host}: ${canary}"

    mail_rc=1
    if [ "$mailer_type" = "sendmail" ]; then
        {
            printf 'From: Lean Sentinel <root@%s>\n' "$host"
            printf 'To: %s\n' "$ALERT_EMAIL"
            printf 'Subject: %s\n' "$subject"
            printf 'Content-Type: text/plain; charset=UTF-8\n\n'
            printf 'Lean Sentinel Sicherheitsalarm\n'
            printf '==============================\n'
            printf 'Host:         %s\n' "$host"
            printf 'Zeitpunkt:    %s\n' "$ts"
            printf 'Canary-Datei: %s\n' "$canary"
            printf 'Event-Maske:  %s\n' "$ev_mask"
            printf 'Ereignis:     %s\n' "$msg"
            printf 'Offene FDs:   %s\n' "$open_pids"
            printf 'Logins (who): %s\n' "$sessions"
            printf 'Logdatei:     %s\n' "$LOG_FILE"
        } | "$mailer_bin" -t -oi 2>/dev/null
        mail_rc=$?
    else
        {
            printf 'Lean Sentinel Sicherheitsalarm\n'
            printf '==============================\n'
            printf 'Host:         %s\n' "$host"
            printf 'Zeitpunkt:    %s\n' "$ts"
            printf 'Canary-Datei: %s\n' "$canary"
            printf 'Event-Maske:  %s\n' "$ev_mask"
            printf 'Ereignis:     %s\n' "$msg"
            printf 'Offene FDs:   %s\n' "$open_pids"
            printf 'Logins (who): %s\n' "$sessions"
            printf 'Logdatei:     %s\n' "$LOG_FILE"
        } | "$mailer_bin" -s "$subject" "$ALERT_EMAIL" 2>/dev/null
        mail_rc=$?
    fi

    if [ "$mail_rc" -eq 0 ]; then
        printf '%s\n' "$now" > "$cd_file"
        log_line "[LEAN-INFO] Alarm-E-Mail an ${ALERT_EMAIL} versendet (${canary})."
    else
        log_line "[LEAN-INFO] Kein Mail-Versand möglich (Mail-Versand fehlgeschlagen) – Alarm lokal protokolliert."
    fi
}

trigger_alert() {
    local canary ev_mask msg
    canary=$1
    ev_mask=$2
    msg=$3
    log_line "[LEAN-ALERT] Zugriff auf Canary erkannt: ${canary} - ${msg} [Events: ${ev_mask}]"
    printf '[ALARM] %s: %s (%s)\n' "$canary" "$msg" "$ev_mask"
    send_alert_email "$canary" "$ev_mask" "$msg"
}

read_configured_canaries() {
    local line
    [ -f "$CANARIES_FILE" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | tr -d '\r')
        case "$line" in
            ''|'#'*) continue ;;
            *) printf '%s\n' "$line" ;;
        esac
    done < "$CANARIES_FILE"
}

prepare_watch_list() {
    local mode watch_file tmp_list line count
    mode=$1
    watch_file=$2
    tmp_list="${watch_file}.tmp"
    : > "$tmp_list"
    count=0

    while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | tr -d '\r')
        case "$line" in
            ''|'#'*) continue ;;
        esac

        if [ -L "$line" ] || [ ! -f "$line" ]; then
            if write_canary_safe "$line"; then
                if [ "$mode" = "alert" ]; then
                    trigger_alert "$line" "RESTORED_MISSING" "Canary-Datei wurde gelöscht/verschoben und wiederhergestellt"
                fi
            else
                continue
            fi
        elif ! canary_content_matches "$line"; then
            if write_canary_safe "$line"; then
                if [ "$mode" = "alert" ]; then
                    trigger_alert "$line" "RESTORED_MODIFIED" "Canary-Datei wurde verändert und wiederhergestellt"
                fi
            else
                continue
            fi
        else
            chmod 0444 "$line" 2>/dev/null || true
            if [ "$IS_TEST_MODE" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
                chown root:root "$line" 2>/dev/null || true
            fi
        fi

        if [ -f "$line" ] && [ ! -L "$line" ]; then
            printf '%s\n' "$line" >> "$tmp_list"
            count=$((count + 1))
        fi
    done < "$CANARIES_FILE"

    mv -f "$tmp_list" "$watch_file"
    printf '%s\n' "$count"
}

sweep_other_canaries() {
    local skip_path line
    skip_path=$1
    [ -f "$CANARIES_FILE" ] || return 0

    while IFS= read -r line || [ -n "$line" ]; do
        line=$(printf '%s' "$line" | tr -d '\r')
        case "$line" in
            ''|'#'*) continue ;;
        esac
        [ "$line" = "$skip_path" ] && continue

        if [ -L "$line" ] || [ ! -f "$line" ]; then
            if write_canary_safe "$line"; then
                trigger_alert "$line" "SWEEP_MISSING" "Canary-Datei wurde gelöscht/verschoben und wiederhergestellt"
            fi
        elif ! canary_content_matches "$line"; then
            if write_canary_safe "$line"; then
                trigger_alert "$line" "SWEEP_MODIFIED" "Canary-Datei wurde verändert und wiederhergestellt"
            fi
        fi
    done < "$CANARIES_FILE"
}

cleanup_daemon() {
    if [ -n "${INOTIFY_PID:-}" ]; then
        kill "$INOTIFY_PID" 2>/dev/null || true
        wait "$INOTIFY_PID" 2>/dev/null || true
        INOTIFY_PID=""
    fi
}

on_term_signal() {
    STOP_REQUESTED=1
    cleanup_daemon
    exit 0
}

run_daemon() {
    local watch_file event_file watch_count rc ev_line ev_mask ev_path msg

    require_root
    if ! command -v inotifywait >/dev/null 2>&1; then
        printf 'Fehler: inotifywait nicht gefunden. Bitte zuerst installieren.\n' >&2
        exit 1
    fi
    if [ ! -s "$CANARIES_FILE" ]; then
        printf 'Fehler: Keine Canary-Dateien in %s konfiguriert.\n' "$CANARIES_FILE" >&2
        exit 1
    fi

    mkdir -p "$RUN_DIR" || exit 1
    chmod 0700 "$RUN_DIR" 2>/dev/null || true
    ensure_log_file || exit 1

    watch_file="${RUN_DIR}/watch.list"
    event_file="${RUN_DIR}/event.out"

    trap on_term_signal INT TERM
    trap cleanup_daemon EXIT

    watch_count=$(prepare_watch_list "silent" "$watch_file")
    printf 'Lean Sentinel aktiv. Überwache %s Canary-Datei(en).\n' "$watch_count"
    log_line "[LEAN-INFO] Lean Sentinel gestartet. Überwache ${watch_count} Canary-Datei(en)."

    while [ "$STOP_REQUESTED" -eq 0 ]; do
        watch_count=$(prepare_watch_list "alert" "$watch_file")
        if [ "$watch_count" -eq 0 ]; then
            sleep 5
            continue
        fi

        : > "$event_file"
        # Einmaliger synchroner Watch: bei Löschung/Wiederherstellung wird der neue Inode
        # im nächsten Durchlauf automatisch neu überwacht, ohne Selbst-Alarme auszulösen.
        inotifywait -q --format '%e|%w%f' \
            -e open -e access -e modify -e attrib -e move_self -e delete_self \
            --fromfile "$watch_file" > "$event_file" 2>/dev/null &
        INOTIFY_PID=$!
        wait "$INOTIFY_PID"
        rc=$?
        INOTIFY_PID=""

        [ "$STOP_REQUESTED" -ne 0 ] && break

        ev_line=""
        if [ -f "$event_file" ]; then
            IFS= read -r ev_line < "$event_file" 2>/dev/null || ev_line=""
        fi

        ev_path=""
        if [ "$rc" -eq 0 ] && [ -n "$ev_line" ]; then
            ev_mask=${ev_line%%|*}
            ev_path=${ev_line#*|}

            if [ -L "$ev_path" ] || [ ! -f "$ev_path" ]; then
                write_canary_safe "$ev_path" || true
                msg="Canary-Datei wurde gelöscht/verschoben und wiederhergestellt"
            elif ! canary_content_matches "$ev_path"; then
                write_canary_safe "$ev_path" || true
                msg="Canary-Datei wurde verändert und wiederhergestellt"
            else
                case ",${ev_mask}," in
                    *,DELETE_SELF,*|*,MOVE_SELF,*)
                        write_canary_safe "$ev_path" || true
                        msg="Canary-Datei wurde gelöscht/verschoben und wiederhergestellt"
                        ;;
                    *,MODIFY,*)
                        write_canary_safe "$ev_path" || true
                        msg="Canary-Datei wurde verändert und wiederhergestellt"
                        ;;
                    *,ATTRIB,*)
                        chmod 0444 "$ev_path" 2>/dev/null || true
                        if [ "$IS_TEST_MODE" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
                            chown root:root "$ev_path" 2>/dev/null || true
                        fi
                        msg="Attribute der Canary-Datei wurden geändert/geprüft"
                        ;;
                    *)
                        msg="Canary-Datei wurde gelesen (Falle betreten)"
                        ;;
                esac
            fi

            trigger_alert "$ev_path" "$ev_mask" "$msg"
        fi

        sweep_other_canaries "$ev_path"
        if [ "$rc" -ne 0 ]; then
            sleep 1
        fi
    done
}

prompt_email() {
    local current mailer input ans
    load_config
    current=$ALERT_EMAIL
    mailer=$(detect_mailer)

    printf '\n--- E-Mail-Benachrichtigung konfigurieren ---\n'
    if [ "$mailer" = "none" ]; then
        printf 'Hinweis: Aktuell kein lokales Mail-System (sendmail/mail) verfügbar.\n'
        printf 'Alarme werden in diesem Fall lokal in %s protokolliert.\n' "$LOG_FILE"
    else
        printf 'Erkanntes Mail-System: %s\n' "${mailer#*:}"
    fi

    if [ -n "$current" ]; then
        printf 'Aktueller Empfänger: %s\n' "$current"
    else
        printf 'Aktueller Empfänger: (keiner – nur lokales Log)\n'
    fi

    while true; do
        printf 'E-Mail-Empfänger eingeben (leer = unverändert, "-" = deaktivieren): '
        IFS= read -r input || return 1
        if [ -z "$input" ]; then
            break
        elif [ "$input" = "-" ]; then
            ALERT_EMAIL=""
            break
        elif validate_email "$input"; then
            ALERT_EMAIL=$input
            break
        else
            printf 'Ungültige E-Mail-Adresse. Bitte erneut versuchen.\n'
        fi
    done

    save_config || {
        printf 'Fehler: Konfiguration konnte nicht in %s gespeichert werden.\n' "$CONF_FILE" >&2
        return 1
    }

    if [ -n "$ALERT_EMAIL" ]; then
        printf 'E-Mail-Empfänger gespeichert: %s\n' "$ALERT_EMAIL"
        if [ "$mailer" != "none" ] && [ -t 0 ]; then
            printf 'Test-Mail an %s jetzt senden? [j/N]: ' "$ALERT_EMAIL"
            IFS= read -r ans || ans=""
            case "$ans" in
                j|J|y|Y|ja|JA)
                    rm -f "${RUN_DIR}/cd_"* 2>/dev/null || true
                    send_alert_email "TEST-KONFIGURATION" "MANUAL_TEST" "Test-Benachrichtigung nach E-Mail-Konfiguration"
                    printf 'Test-Mail ausgelöst (Details in %s).\n' "$LOG_FILE"
                    ;;
            esac
        fi
    else
        printf 'E-Mail-Benachrichtigung deaktiviert (nur lokales Log).\n'
    fi
}

set_email_cli() {
    local addr
    addr=$1
    require_root
    load_config
    if ! validate_email "$addr"; then
        printf 'Fehler: Ungültige E-Mail-Adresse: %s\n' "$addr" >&2
        exit 1
    fi
    if [ "$addr" = "-" ]; then
        ALERT_EMAIL=""
    else
        ALERT_EMAIL=$addr
    fi
    save_config || exit 1
    if [ -n "$ALERT_EMAIL" ]; then
        printf 'Alert-E-Mail gesetzt auf: %s\n' "$ALERT_EMAIL"
    else
        printf 'Alert-E-Mail deaktiviert (nur lokales Log).\n'
    fi
}

write_systemd_unit() {
    local unit_dir tmp
    unit_dir=${UNIT_FILE%/*}
    mkdir -p "$unit_dir" || return 1
    tmp=$(mktemp "${unit_dir}/.unit.XXXXXX") || return 1
    cat <<EOF > "$tmp"
[Unit]
Description=Lean Sentinel
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --daemon
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$tmp" 2>/dev/null || true
    mv -fT -- "$tmp" "$UNIT_FILE" || { rm -f -- "$tmp"; return 1; }
}

install_self_binary() {
    local bin_dir tmp
    bin_dir=${BIN_PATH%/*}
    mkdir -p "$bin_dir" || return 1
    if [ -e "$BIN_PATH" ] && [ "$SELF_PATH" -ef "$BIN_PATH" ] 2>/dev/null; then
        chmod 0755 "$BIN_PATH"
        return 0
    fi
    tmp=$(mktemp "${bin_dir}/.sentinel_bin.XXXXXX") || return 1
    cp -- "$SELF_PATH" "$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 0755 "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -fT -- "$tmp" "$BIN_PATH" || { rm -f -- "$tmp"; return 1; }
}

do_install() {
    local core_list web_list selected_list choice extra cand count
    require_root

    printf '\n=== Lean Sentinel Installation ===\n'
    ensure_dependencies || return 1

    core_list=$(discover_core_targets)
    web_list=$(discover_web_subdirs)

    printf '\nDynamisch erkannte Standard-Ziele auf diesem System:\n'
    if [ -n "$core_list" ]; then
        printf '%s\n' "$core_list" | while IFS= read -r cand; do
            printf '  - %s\n' "$cand"
        done
    else
        printf '  (keine Standardverzeichnisse gefunden)\n'
    fi

    if [ -n "$web_list" ]; then
        printf '\nZusätzliche Web-Unterverzeichnisse in /var/www/* verfügbar:\n'
        printf '%s\n' "$web_list" | while IFS= read -r cand; do
            printf '  + %s\n' "$cand"
        done
    fi

    selected_list=$core_list
    if [ -t 0 ]; then
        printf '\nAuswahl:\n'
        printf '  [Enter] / j = Standard-Ziele übernehmen\n'
        if [ -n "$web_list" ]; then
            printf '  w           = Standard-Ziele + alle /var/www/* Web-Unterverzeichnisse\n'
        fi
        printf '  a           = Eigene Verzeichnisse oder Dateipfade ergänzen\n'
        printf 'Ihre Wahl [j]: '
        IFS= read -r choice || choice="j"

        case "$choice" in
            w|W)
                if [ -n "$web_list" ]; then
                    if [ -n "$selected_list" ]; then
                        selected_list=$(printf '%s\n%s\n' "$selected_list" "$web_list")
                    else
                        selected_list=$web_list
                    fi
                fi
                ;;
            a|A)
                printf 'Zusätzliche Verzeichnisse oder Dateipfade (leer = fertig):\n'
                while true; do
                    printf 'Pfad: '
                    IFS= read -r extra || break
                    [ -n "$extra" ] || break
                    if [ -d "$extra" ] && [ ! -L "$extra" ]; then
                        cand=$(pick_canary_path "$extra" || true)
                        if [ -n "$cand" ]; then
                            selected_list=$(printf '%s\n%s\n' "$selected_list" "$cand")
                            printf '  -> Hinzugefügt: %s\n' "$cand"
                        else
                            printf '  -> Übersprungen (alle Standardnamen bereits belegt).\n'
                        fi
                    elif [ "${extra#/}" != "$extra" ]; then
                        if [ -e "$extra" ] && ! is_created_canary "$extra"; then
                            printf '  -> Warnung: Datei existiert bereits und wird zum Schutz nicht überschrieben.\n'
                        else
                            selected_list=$(printf '%s\n%s\n' "$selected_list" "$extra")
                            printf '  -> Hinzugefügt: %s\n' "$extra"
                        fi
                    else
                        printf '  -> Bitte absoluten Pfad angeben.\n'
                    fi
                done
                ;;
        esac
    fi

    mkdir -p "$CONF_DIR" || return 1
    chmod 0700 "$CONF_DIR" 2>/dev/null || true
    : > "$CANARIES_FILE"

    count=0
    if [ -n "$selected_list" ]; then
        printf '%s\n' "$selected_list" | while IFS= read -r cand; do
            [ -n "$cand" ] || continue
            if ! grep -Fqx -- "$cand" "$CANARIES_FILE" 2>/dev/null; then
                if write_canary_safe "$cand"; then
                    printf '%s\n' "$cand" >> "$CANARIES_FILE"
                fi
            fi
        done
    fi

    if [ ! -s "$CANARIES_FILE" ]; then
        printf 'Fehler: Keine gültigen Canary-Dateien eingerichtet.\n' >&2
        return 1
    fi

    while IFS= read -r cand; do
        [ -n "$cand" ] && count=$((count + 1))
    done < "$CANARIES_FILE"

    if [ -t 0 ]; then
        prompt_email || return 1
    else
        load_config
        save_config || return 1
    fi

    ensure_log_file || return 1
    install_self_binary || return 1
    write_systemd_unit || return 1

    run_systemctl daemon-reload || true
    run_systemctl enable --now "$SERVICE_NAME" || true

    printf '\nInstallation abgeschlossen!\n'
    printf '  Binary:        %s\n' "$BIN_PATH"
    printf '  Konfiguration: %s\n' "$CONF_FILE"
    printf '  Canary-Liste:  %s (%s Datei(en))\n' "$CANARIES_FILE" "$count"
    printf '  Logdatei:      %s\n' "$LOG_FILE"
    printf '  Service:       %s\n' "$SERVICE_NAME"
    log_line "[LEAN-INFO] Lean Sentinel installiert (${count} Canary-Dateien)."
}

do_uninstall() {
    local interactive_flag cand removed ans
    interactive_flag=${1:-0}
    require_root

    printf '\n=== Lean Sentinel Deinstallation ===\n'

    run_systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    run_systemctl disable "$SERVICE_NAME" 2>/dev/null || true

    if [ -f "$UNIT_FILE" ]; then
        rm -f -- "$UNIT_FILE"
        printf 'Service-Unit entfernt: %s\n' "$UNIT_FILE"
    fi
    run_systemctl daemon-reload 2>/dev/null || true

    removed=0
    if [ -f "$CREATED_FILE" ]; then
        while IFS= read -r cand || [ -n "$cand" ]; do
            cand=$(printf '%s' "$cand" | tr -d '\r')
            [ -n "$cand" ] || continue
            if [ -e "$cand" ] || [ -L "$cand" ]; then
                rm -f -- "$cand"
                removed=$((removed + 1))
            fi
        done < "$CREATED_FILE"
    fi
    printf 'Von Lean Sentinel erstellte Canary-Dateien entfernt: %s\n' "$removed"

    rm -rf -- "$CONF_DIR" "$RUN_DIR"
    if [ -e "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; then
        rm -f -- "$BIN_PATH"
        printf 'Binary entfernt: %s\n' "$BIN_PATH"
    fi

    if [ -f "$LOG_FILE" ]; then
        if [ "$interactive_flag" -eq 1 ] && [ -t 0 ]; then
            printf 'Logdatei %s ebenfalls löschen? [j/N]: ' "$LOG_FILE"
            IFS= read -r ans || ans=""
            case "$ans" in
                j|J|y|Y|ja|JA)
                    rm -f -- "$LOG_FILE"
                    printf 'Logdatei entfernt.\n'
                    ;;
                *)
                    printf 'Logdatei behalten: %s\n' "$LOG_FILE"
                    ;;
            esac
        else
            printf 'Logdatei behalten: %s\n' "$LOG_FILE"
        fi
    fi

    printf 'Deinstallation abgeschlossen.\n'
}

show_status() {
    local state mailer cand count
    load_config
    mailer=$(detect_mailer)

    printf '\n=== Lean Sentinel Status ===\n'
    if [ -f "$UNIT_FILE" ]; then
        if [ "$IS_TEST_MODE" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
            state=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || printf 'inaktiv')
        else
            state="installiert (Test-Modus)"
        fi
        printf 'Installation:   Installiert (%s)\n' "$state"
    else
        printf 'Installation:   Nicht installiert\n'
    fi

    printf 'Binary:         %s\n' "$BIN_PATH"
    printf 'Alert-E-Mail:   %s\n' "${ALERT_EMAIL:-(keine – nur lokales Log)}"
    printf 'Mail-System:    %s\n' "$mailer"
    printf 'Logdatei:       %s\n' "$LOG_FILE"

    if [ -f "$CANARIES_FILE" ]; then
        printf '\nÜberwachte Canary-Dateien:\n'
        count=0
        while IFS= read -r cand || [ -n "$cand" ]; do
            cand=$(printf '%s' "$cand" | tr -d '\r')
            case "$cand" in
                ''|'#'*) continue ;;
            esac
            count=$((count + 1))
            if [ -f "$cand" ] && [ ! -L "$cand" ]; then
                printf '  [OK]     %s\n' "$cand"
            else
                printf '  [FEHLT]  %s\n' "$cand"
            fi
        done < "$CANARIES_FILE"
        [ "$count" -eq 0 ] && printf '  (keine)\n'
    fi

    if [ -f "$LOG_FILE" ]; then
        printf '\nLetzte Log-Einträge:\n'
        tail -n 10 "$LOG_FILE"
    fi
    printf '\n'
}

do_test_alert() {
    local first_canary
    require_root
    load_config
    first_canary=$(read_configured_canaries | head -n 1 || true)
    if [ -z "$first_canary" ]; then
        first_canary="${TEST_ROOT}/var/www/html/.env_secret"
    fi
    rm -f "${RUN_DIR}/cd_"* 2>/dev/null || true
    trigger_alert "$first_canary" "MANUAL_TEST" "Manueller Test-Alarm ausgelöst"
}

show_discover() {
    local core web
    core=$(discover_core_targets)
    web=$(discover_web_subdirs)
    printf 'Dynamisch erkannte Standard-Canary-Ziele:\n'
    if [ -n "$core" ]; then
        printf '%s\n' "$core" | sed 's/^/  /'
    else
        printf '  (keine)\n'
    fi
    if [ -n "$web" ]; then
        printf 'Optionale /var/www/* Web-Unterverzeichnisse:\n'
        printf '%s\n' "$web" | sed 's/^/  /'
    fi
}

show_help() {
    cat <<EOF
Verwendung: $SELF_PATH [OPTION]

Ohne Option wird das interaktive Menü gestartet (Erststart: Installation / Deinstallation / E-Mail).

Optionen:
  --install            Interaktive Installation starten
  --uninstall          Lean Sentinel und alle erzeugten Canaries entfernen
  --set-email <ADDR>   Empfänger-E-Mail setzen ("-" für nur lokales Log)
  --status             Status, überwachte Dateien und letzte Logs anzeigen
  --discover           Dynamisch passende Canary-Ziele anzeigen (nur lesend)
  --test-alert         Test-Alarm (Log + E-Mail) auslösen
  --daemon             Hintergrund-Überwachungsschleife starten (systemd)
  -h, --help           Diese Hilfe anzeigen
EOF
}

show_menu() {
    local installed_label choice
    require_root

    while true; do
        load_config
        if [ -f "$UNIT_FILE" ]; then
            installed_label="Installiert"
        else
            installed_label="Noch nicht installiert (Erststart)"
        fi

        printf '\n========================================\n'
        printf ' Lean Sentinel - Menü\n'
        printf '========================================\n'
        printf ' Status:     %s\n' "$installed_label"
        printf ' E-Mail:     %s\n' "${ALERT_EMAIL:-(nicht gesetzt – nur lokales Log)}"
        printf '----------------------------------------\n'
        printf ' 1) Installieren (oder neu einrichten)\n'
        printf ' 2) Deinstallieren\n'
        printf ' 3) E-Mail-Empfänger eingeben / ändern\n'
        printf ' 4) Status & letzte Log-Einträge anzeigen\n'
        printf ' 5) Test-Alarm auslösen\n'
        printf ' 0) Beenden\n'
        printf 'Auswahl: '
        IFS= read -r choice || break

        case "$choice" in
            1) do_install ;;
            2) do_uninstall 1 ;;
            3) prompt_email ;;
            4) show_status ;;
            5) do_test_alert ;;
            0|q|Q) break ;;
            *) printf 'Ungültige Auswahl.\n' ;;
        esac
    done
}

main() {
    init_paths

    case "${1:-}" in
        "")
            show_menu
            ;;
        --daemon)
            run_daemon
            ;;
        --install)
            do_install
            ;;
        --uninstall)
            do_uninstall 0
            ;;
        --set-email)
            if [ $# -lt 2 ]; then
                printf 'Fehler: --set-email erwartet eine Adresse (oder "-").\n' >&2
                exit 1
            fi
            set_email_cli "$2"
            ;;
        --status)
            show_status
            ;;
        --discover)
            show_discover
            ;;
        --test-alert)
            do_test_alert
            ;;
        -h|--help)
            show_help
            ;;
        *)
            printf 'Unbekannte Option: %s\n\n' "$1" >&2
            show_help >&2
            exit 1
            ;;
    esac
}

main "$@"
exit $?
