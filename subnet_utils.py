import ipaddress
import io
import os
import re
import logging

import pandas as pd

logger = logging.getLogger(__name__)


def _env_int(name, default):
    try:
        value = int(os.environ.get(name, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


# Maximum number of IP addresses a single scan may include
MAX_SCAN_IPS = _env_int('MAX_SCAN_IPS', 65536)


def _too_many(count, limit):
    return ValueError(f"Too many IP addresses: {count} exceeds limit of {limit}")


def _add_error(errors, message):
    logger.warning("Subnet input error: %s", message)
    if isinstance(errors, list):
        errors.append(message)


def _network_hosts(network):
    """Usable hosts of a network; /31, /32, /127 and /128 return every address."""
    if network.num_addresses <= 2:
        return list(network)
    return list(network.hosts())


def _parse_range(token, errors):
    """Parse 'a-b' or IPv4 shorthand 'a.b.c.d-e'. Returns (start, end) or None."""
    start_s, end_s = [part.strip() for part in token.split('-', 1)]
    try:
        start = ipaddress.ip_address(start_s)
    except ValueError:
        _add_error(errors, f"{token}: invalid range start address")
        return None

    if start.version == 4 and re.fullmatch(r'\d{1,3}', end_s):
        end_s = '.'.join(start_s.split('.')[:3] + [end_s])
    try:
        end = ipaddress.ip_address(end_s)
    except ValueError:
        _add_error(errors, f"{token}: invalid range end address")
        return None

    if start.version != end.version:
        _add_error(errors, f"{token}: range mixes IPv4 and IPv6")
        return None
    if int(start) > int(end):
        _add_error(errors, f"{token}: range start is after end")
        return None
    return start, end


def parse_subnet_input(input_text, max_ips=None, errors=None):
    """
    Parse subnet input (CIDR, single addresses, ranges; IPv4 and IPv6) separated
    by newlines, commas or whitespace, and return a sorted, de-duplicated list
    of IP address strings.

    Args:
        input_text: The text to parse.
        max_ips: Maximum number of addresses (defaults to MAX_SCAN_IPS).
        errors: Optional list that collects messages for invalid tokens.

    Raises:
        ValueError: if the result would exceed max_ips.
    """
    limit = max_ips if max_ips is not None else MAX_SCAN_IPS
    if not input_text:
        return []

    addresses = set()

    def check(extra):
        # Fail before materializing a block that can never fit, then re-check
        # the de-duplicated total after adding it (memory stays O(2 * limit)).
        if extra > limit:
            raise _too_many(extra, limit)
        if len(addresses) > limit:
            raise _too_many(len(addresses), limit)

    text = re.sub(r'[ \t]*-[ \t]*', '-', str(input_text))  # allow 'a - b'
    for token in re.split(r'[\s,;]+', text):
        token = token.strip()
        if not token:
            continue

        if '/' in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                _add_error(errors, f"{token}: invalid network")
                continue
            count = network.num_addresses if network.num_addresses <= 2 else network.num_addresses - (
                2 if network.version == 4 else 1)
            check(count)
            addresses.update(_network_hosts(network))
            check(0)
            continue

        # IPv6 addresses contain ':' and never '-', so '-' always means a range
        if '-' in token:
            parsed = _parse_range(token, errors)
            if parsed is None:
                continue
            start, end = parsed
            count = int(end) - int(start) + 1
            check(count)
            cls = ipaddress.IPv4Address if start.version == 4 else ipaddress.IPv6Address
            addresses.update(cls(i) for i in range(int(start), int(end) + 1))
            check(0)
            continue

        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            if re.fullmatch(r'[0-9.]+', token) or ':' in token:
                _add_error(errors, f"{token}: invalid IP address")
            else:
                _add_error(errors, f"{token}: hostnames are not supported")
            continue
        addresses.add(addr)
        if len(addresses) > limit:
            raise _too_many(len(addresses), limit)

    if len(addresses) > limit:
        raise _too_many(len(addresses), limit)

    return [str(ip) for ip in sorted(addresses, key=lambda ip: (ip.version, int(ip)))]


def parse_csv_file(csv_content, max_ips=None, errors=None):
    """Parse CSV content containing IP addresses, ranges or subnets.

    Uses a column named ip/ip_address/subnet/... when present, else the first
    column. Same return value, limits and errors behavior as parse_subnet_input.
    """
    try:
        df = pd.read_csv(io.StringIO(csv_content), dtype=str)
    except Exception as e:
        _add_error(errors, f"Could not parse CSV: {e}")
        return []

    ip_column = None
    for col in df.columns:
        if str(col).strip().lower() in ['ip', 'ipaddress', 'ip_address', 'subnet', 'address', 'network']:
            ip_column = col
            break
    if ip_column is None and len(df.columns) > 0:
        ip_column = df.columns[0]
    if ip_column is None:
        return []

    values = [v for v in df[ip_column].dropna().astype(str).tolist() if v.strip()]
    # If the first column has no recognised header, the header itself may be an address
    header = str(ip_column).strip()
    if header.lower() not in ['ip', 'ipaddress', 'ip_address', 'subnet', 'address', 'network'] \
            and re.fullmatch(r'[0-9A-Fa-f:.\-/]+', header) and re.search(r'\d', header):
        values.insert(0, header)
    return parse_subnet_input('\n'.join(values), max_ips=max_ips, errors=errors)
