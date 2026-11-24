#!/usr/bin/env python3
"""JSON Lines (формат json_binding.h) -> MariaDB snort.snort_alerts.

  pip install pymysql
  MARIADB_PASSWORD=... ./snort3_loader.py --file alerts.jsonl            # разовая загрузка
  MARIADB_PASSWORD=... ./snort3_loader.py --file alerts.jsonl --follow   # tail -f

Идемпотентен: INSERT IGNORE + UNIQUE uq_alert, повторный запуск безопасен.
Битые/оборванные строки пишутся в <file>.rejects.
"""
import argparse, json, os, sys, time
import pymysql

COLS = ("alert_time src_ip dst_ip src_port dst_port protocol priority generator_id "
        "sig_id sig_revision classification action pkt_len ttl iface rule_msg flow_id raw_json").split()
STR = {"alert_time", "src_ip", "dst_ip", "classification", "action", "iface", "rule_msg"}
SQL = "INSERT IGNORE INTO snort_alerts (%s) VALUES (%s)" % (",".join(COLS), ",".join(["%s"] * len(COLS)))


def to_row(line):
    j = json.loads(line)
    ts = j["alert_time"]
    if not isinstance(ts, str) or len(ts) < 19:
        raise ValueError("bad alert_time")
    row = []
    for c in COLS:
        if c == "raw_json":
            row.append(line.strip())
        elif c in STR:
            v = j.get(c)
            row.append("" if v is None else str(v))
        else:
            v = j.get(c, 0)
            row.append(max(0, int(v)) if isinstance(v, (int, float)) else 0)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=3306)
    ap.add_argument("--user", default="snort")
    ap.add_argument("--db", default="snort")
    ap.add_argument("--batch", type=int, default=500)
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--from-end", action="store_true", help="с --follow: не читать уже записанное")
    a = ap.parse_args()

    db = pymysql.connect(host=a.host, port=a.port, user=a.user, database=a.db,
                         password=os.environ.get("MARIADB_PASSWORD", ""), autocommit=True,
                         charset="utf8mb4")
    rej = open(a.file + ".rejects", "a")
    buf, total, bad = [], 0, 0

    def flush():
        nonlocal buf, total
        if not buf:
            return
        try:
            with db.cursor() as cur:
                cur.executemany(SQL, buf)
        except pymysql.err.OperationalError:
            db.ping(reconnect=True)          # сессия оборвалась: переподключиться и повторить пачку
            with db.cursor() as cur:
                cur.executemany(SQL, buf)
        total += len(buf)
        buf = []

    with open(a.file, "r", encoding="utf-8", errors="replace") as f:
        if a.follow and a.from_end:
            f.seek(0, os.SEEK_END)
        pending = ""
        while True:
            chunk = f.readline()
            if not chunk:
                flush()
                if not a.follow:
                    break
                time.sleep(1)
                continue
            pending += chunk
            if not pending.endswith("\n"):   # строка ещё дописывается Snort'ом
                continue
            line, pending = pending.strip(), ""
            if not line:
                continue
            try:
                buf.append(to_row(line))
            except Exception:
                bad += 1
                rej.write(line + "\n")
                continue
            if len(buf) >= a.batch:
                flush()
    flush()
    print("sent=%d (дубликаты отсекает INSERT IGNORE) rejected=%d" % (total, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
