'''
You can also create your own table if you not like this one
so, if you don't like it or it's complex for you then you can make your own by just understanding the self.arp_info
I also created one but it was basic and i'm not into these type decorative stuff so that's why my partner created it
'''

import atexit
import ipaddress

_live = None         # the rich Live display, created on the first call
_drawn_lines = 0     # lines printed last time (plain-text fallback)


def stop_table() -> None:
    """Optional: call after your scan loop ends so the final table stays on screen."""
    global _live
    if _live is not None:
        _live.stop()
        _live = None


def print_devices_table(devices_list: list) -> None:
    """Print scan results as a table (uses rich if installed, plain text otherwise)."""
    global _live
    # Sort numerically by IP (so .6 comes before .10)
    rows = sorted(devices_list, key=lambda d: ipaddress.ip_address(d["ip"]))

    try:
        from rich.live import Live
        from rich.table import Table
        from rich import box
    except ImportError:
        _print_plain(rows)
        return

    table = Table(
        title=f"Network Scan Results ({len(rows)} devices)",
        box=box.ROUNDED,
        header_style="bold cyan",
        title_style="bold",
        show_lines=False,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("IP Address", style="green", no_wrap=True)
    table.add_column("MAC Address", style="yellow", no_wrap=True)
    table.add_column("Vendor", overflow="fold")
    table.add_column("Seen", justify="center")

    for i, d in enumerate(rows, 1):
        vendor = d["vendor"] or "Unknown"
        if "Randomized" in vendor:
            vendor = f"[italic magenta]{vendor}[/]"
        elif vendor == "Unknown":
            vendor = f"[red]{vendor}[/]"
        table.add_row(str(i), d["ip"], d["mac"], vendor, str(d["count"]))

    # First call starts the live display, every later call redraws the same table
    if _live is None:
        _live = Live(table, refresh_per_second=8)
        _live.start()
        atexit.register(stop_table)
    else:
        _live.update(table)


def _print_plain(rows: list) -> None:
    global _drawn_lines
    headers = ["#", "IP Address", "MAC Address", "Vendor", "Seen"]
    data = [[str(i), d["ip"], d["mac"], d["vendor"] or "Unknown", str(d["count"])]
            for i, d in enumerate(rows, 1)]
    widths = [max(len(r[c]) for r in [headers] + data) for c in range(len(headers))]

    def line(l, m, r):
        return l + m.join("─" * (w + 2) for w in widths) + r

    def row(cells):
        return "│" + "│".join(f" {c.ljust(w)} " for c, w in zip(cells, widths)) + "│"

    lines = [line("┌", "┬", "┐"), row(headers), line("├", "┼", "┤")]
    lines += [row(r) for r in data]
    lines.append(line("└", "┴", "┘"))

    # Move the cursor up over the previous table and clear it, then redraw
    if _drawn_lines:
        print(f"\033[{_drawn_lines}A\033[J", end="")
    print("\n".join(lines))
    _drawn_lines = len(lines)




