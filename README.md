# Paqet-X Quick Install

> IMPORTANT: Run as `root`. The installer configures `systemd`, `iptables`, and `cron`.

## Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/MohmRzw/Paqet-X/main/install.sh)
```

> NOTE: If you get `404`, `install.sh` is not yet pushed to the `main` branch.

## Script Preview

```text
+------------------------------------------------------+
| PAQET-X MANAGER                                      |
| 1) Install Dependencies                              |
| 2) Install / Update Core                             |
| 3) Configure Server (Kharej)                         |
| 4) Configure Client (Iran)                           |
| 5) Service Management                                |
| 6) Status                                            |
| 7) Uninstall                                         |
+------------------------------------------------------+
```

## Verify Installation

```bash
systemctl list-unit-files | grep paqet-x
```

Key paths:
- `/usr/local/bin/Paqet-X`
- `/etc/paqet-x/`
- `/etc/systemd/system/paqet-x-*.service`

## Troubleshooting

```bash
journalctl -u paqet-x-<service-name> -n 100 --no-pager
```

## Security

Review `install.sh` before running on production servers.
