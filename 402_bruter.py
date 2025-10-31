#!/usr/bin/env python3
"""
check_basic_auth_urls_with_protection.py

Like check_basic_auth_urls.py but:
 - skips to the next URL if too many consecutive errors occur (--max-errors)
 - adds retry/backoff and delay options between requests
 - catches SSL and timeout errors and counts them as errors

Usage:
 python3 check_basic_auth_urls_with_protection.py --urls urls.txt --users users.txt --passwords passwords.txt --output output.txt --concurrency 5 --timeout 6 --max-errors 20 --retries 2 --delay 0.1
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.auth import HTTPBasicAuth
from itertools import product
import os
import time
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import SSLError, ConnectTimeout, ConnectionError, ReadTimeout, RequestException


def make_session(retries, backoff_factor, status_forcelist=None, verify=True, ca_bundle=None):
    """Create a requests.Session with retry and backoff settings."""
    s = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist or [500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    # Optionally set a custom CA bundle; None means system default
    s.verify = ca_bundle if ca_bundle else verify
    return s


def check_one(session, url, user, pwd, timeout, verify, delay):
    """Returns (user, pwd, status_code or None, info_string)"""
    try:
        if delay:
            time.sleep(delay)
        r = session.get(url, auth=HTTPBasicAuth(user, pwd), timeout=timeout)
        return (user, pwd, r.status_code, r.reason)
    except SSLError as e:
        return (user, pwd, None, f"SSLError: {e}")
    except (ConnectTimeout, ReadTimeout) as e:
        return (user, pwd, None, f"Timeout: {e}")
    except ConnectionError as e:
        return (user, pwd, None, f"ConnectionError: {e}")
    except RequestException as e:
        return (user, pwd, None, f"RequestException: {e}")


def load_list(path):
    """Loads a file into a list, ignoring comments and blank lines."""
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line)
    return items


def main():
    p = argparse.ArgumentParser(description="Validate HTTP Basic credentials against multiple URLs with error protection and retries.")
    p.add_argument("--urls", required=True, help="File containing list of URLs (one per line)")
    p.add_argument("--users", required=True, help="File containing list of usernames")
    p.add_argument("--passwords", required=True, help="File containing list of passwords")
    p.add_argument("--output", default="valid_creds.txt", help="File to save valid credentials (append mode)")
    p.add_argument("--concurrency", type=int, default=5, help="Number of concurrent threads")
    p.add_argument("--timeout", type=float, default=6.0, help="Request timeout (seconds)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification (Insecure)")
    p.add_argument("--stop-on-success", action="store_true", help="Stop after finding the first valid credential per URL")
    p.add_argument("--max-errors", type=int, default=20, help="Maximum consecutive errors before skipping to the next URL")
    p.add_argument("--retries", type=int, default=2, help="Automatic retries per request (urllib3 Retry)")
    p.add_argument("--backoff", type=float, default=0.5, help="Backoff factor for retries")
    p.add_argument("--delay", type=float, default=0.0, help="Delay (seconds) added before each request to spread traffic")
    p.add_argument("--ca-bundle", help="(Optional) Path to a custom CA bundle for TLS verification")
    args = p.parse_args()

    urls = load_list(args.urls)
    users = load_list(args.users)
    passwords = load_list(args.passwords)

    if not urls:
        print("No valid URLs found in the file.")
        return
    if not users:
        print("No valid users found in the file.")
        return
    if not passwords:
        print("No valid passwords found in the file.")
        return

    verify = not args.insecure
    # Prepare output file (append mode)
    if not os.path.exists(args.output):
        open(args.output, "w", encoding="utf-8").close()

    # Create shared session with retries/backoff
    session = make_session(retries=args.retries, backoff_factor=args.backoff, verify=verify, ca_bundle=args.ca_bundle)

    for url in urls:
        print(f"\n=== Checking URL: {url} ===")
        creds = list(product(users, passwords))
        found = []
        consecutive_errors = 0
        max_errors = args.max_errors

        with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
            futures = {ex.submit(check_one, session, url, u, pss, args.timeout, verify, args.delay): (u, pss) for (u, pss) in creds}
            try:
                for fut in as_completed(futures):
                    u, pss = futures[fut]
                    user, pwd, status, info = fut.result()
                    if status is None:
                        # Connection/SSL/timeout/retry exhausted error
                        consecutive_errors += 1
                        print(f"[ERROR] {user}:*** -> {info}  (consecutive_errors={consecutive_errors})")
                        if consecutive_errors >= max_errors:
                            print(f"[WARN] Reached max-errors ({max_errors}) for {url}, skipping to next URL.")
                            for other in list(futures.keys()):
                                if not other.done():
                                    other.cancel()
                            break
                    else:
                        # Valid HTTP response (including 401, 302, 200, etc.)
                        consecutive_errors = 0
                        if 200 <= status < 300:
                            print(f"[OK]    {user}:{pwd} -> {status} {info}")
                            found.append((user, pwd, status))
                            with open(args.output, "a", encoding="utf-8") as f:
                                f.write(f"{url} {user}:{pwd} HTTP {status}\n")
                            if args.stop_on_success:
                                for other in list(futures.keys()):
                                    if not other.done():
                                        other.cancel()
                                break
                        elif status == 401:
                            print(f"[FAIL]  {user}:*** -> {status} Unauthorized")
                        else:
                            print(f"[INFO]  {user}:*** -> {status} {info}")
            except KeyboardInterrupt:
                print("Interrupted by user. Cancelling pending tasks...")
                for other in list(futures.keys()):
                    if not other.done():
                        other.cancel()
                raise

        # Summary per URL
        if found:
            print("\nValid credentials found for this URL:")
            for u, p, s in found:
                print(f"  {u}:{p}  (HTTP {s})")
        else:
            print("\nNo valid credentials found for this URL (or skipped due to too many errors).")


if __name__ == "__main__":
    main()
