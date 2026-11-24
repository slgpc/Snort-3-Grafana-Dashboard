# Snort-3-Grafana-Dashboard

Please donate project:

Paypal SLGPC.sec@gmail.com

Crypto Wallet Ethereum:

0x6176e91b6511f2690461d34de746913e2728451f

Tron TRX: TTKccWwswwHKQHqUCUdn9XSaxWEGankcYq

USDT Trc20: TTKccWwswwHKQHqUCUdn9XSaxWEGankcYq

Bitcoin: 164ryq5PbcfCcvU73iwYwnUCYpiHchrMaz

# Snort 3 -> MariaDB -> Grafana

Workflow: Snort 3 (your plugin / JSONL in `json_binding.h` format) -> `snort3_loader.py` -> MariaDB `snort.snort_alerts` -> Grafana (MySQL data source).

## Installation
1. Run `mysql < schema.sql` and create the following users: `snort` (with `INSERT` privileges) for the loader, and `grafana_ro` (with `SELECT` privileges) for Grafana.
2. Loader setup: run `pip install pymysql`, then execute:
`MARIADB_PASSWORD=... python3 snort3_loader.py --user snort --file alerts.jsonl --follow`
(Omit `--follow` for a one-time import; the script is safe to run multiple times).
3. In Grafana (v10+): Go to Connections -> Data sources -> MySQL (MariaDB), set the host to `:3306`, database to `snort`, and user to `grafana_ro`.
4. Go to Dashboards -> Import -> `snort3_dashboard.json` and select the MariaDB data source in the dashboard variable.

## How Drill-Down Works
- Click on a **sig_id** in the "Alert Groups" section to open a menu that allows you to filter the entire dashboard by SID or view the signature description on snort.org.
- Click on an **IP / flow_id** in the tables to filter by IP (source or destination) or by flow.
- A details table containing the `raw_json` is provided at the bottom. To reset filters, enter `%` into the filter text boxes.

## Important Notes
- Timestamps in the database are in UTC (as defined in `json_binding.h`); Grafana expects this format.
- Text-box filters are injected directly into SQL queries; this is intended for trusted administrators and should not be exposed for public access.
- The dashboard has not been tested in your specific environment. The JSON was generated according to Grafana 10+ specifications; minor adjustments to the panels may be required after import. - If you are logging directly to MariaDB from a plugin, replace the HeavyDB HTTP connector with a MariaDB client (using INSERT statements for the same table).
