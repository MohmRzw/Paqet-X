# Paqet-X Quick Guide

> [!IMPORTANT]
> Run as `root`.

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/MohmRzw/Paqet-X/main/install.sh)
```

## Menu Preview

```text
[1] Install Dependencies
[2] Install / Update Core
[3] Configure Server (Kharej)
[4] Configure Client (Iran)
[5] Service Management
[6] Status
[7] Uninstall
```

## Verify

```bash
systemctl list-unit-files | grep paqet-x
```

`/usr/local/bin/Paqet-X`  
`/etc/paqet-x/`  
`/etc/systemd/system/paqet-x-*.service`

## Logs

```bash
journalctl -u paqet-x-<service-name> -n 100 --no-pager
```

> [!NOTE]
> Review `install.sh` before using on production.
