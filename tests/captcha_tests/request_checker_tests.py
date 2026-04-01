"""
Request checker / inspector test suite.

Tests all 6 detection modules of the request_inspector:
  Module 1 - Volume threshold (burst flooding)
  Module 2 - Frequency regularity (metronomic intervals, sleep-loop detection)
  Module 3 - Sequential pattern (repeated path subsequences, transition dominance)
  Module 4 - Fingerprint consistency (cross-IP fingerprint sharing, header anomalies)
  Module 5 - Funnel timing (inhuman page-to-action speed, session replay)
  Module 6 - Distributed botnet (mass onboarding, subnet concentration,
             sequential IPs, synchronized bursts, cross-IP timing similarity)

Run:
    cd tests
    python -m pytest captcha_tests/request_checker_tests.py -v

Requires Redis running on localhost:6379 (docker compose up redis).
"""

import sys
import os
import time
import pytest
import redis as redis_lib

# Add the request_inspector package to path so we can import it directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "request_inspector"))

import inspector  # noqa: E402

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_HOST = "localhost"
REDIS_PORT = 6379
BANNED_PREFIX = "ban:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _redis():
    return redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def clear_all_bans(*ips):
    """Delete ban keys for given IPs."""
    r = _redis()
    for ip in ips:
        r.delete(f"{BANNED_PREFIX}{ip}")
        r.delete(f"rate:{ip}")


def reset_inspector_state():
    """Wipe all in-memory state in the inspector module so tests are isolated."""
    inspector.ip_history.clear()
    inspector.fp_to_ips.clear()
    inspector.ip_header_stats.clear()
    inspector.ip_first_seen.clear()
    inspector.global_timeline.clear()
    inspector.ip_interval_sig.clear()


def is_banned(ip):
    r = _redis()
    return bool(r.exists(f"{BANNED_PREFIX}{ip}"))


def make_event(ip, ts, path="/", kind="page", ua="Mozilla/5.0 Chrome/120",
               al="en-US", ae="gzip, deflate, br", acc="text/html",
               ref="", hdr_order="abc123", cookie_present=True):
    """Build an event dict matching what the web service publishes."""
    return {
        "ip": ip,
        "ts": ts,
        "path": path,
        "method": "GET",
        "kind": kind,
        "ua": ua,
        "al": al,
        "ae": ae,
        "acc": acc,
        "ref": ref,
        "hdr_order": hdr_order,
        "cookie_present": cookie_present,
        "username": "anonymous",
    }


# ===========================================================================
#  MODULE 1 - Volume threshold
# ===========================================================================

class TestModule1VolumeThreshold:
    """Tests that exceeding MAX_REQ in WINDOW_SECONDS triggers a ban."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.0.1")

    def teardown_method(self):
        clear_all_bans("10.0.0.1")

    def test_burst_exceeding_threshold_triggers_ban(self):
        """Sending more than MAX_REQ requests in the window bans the IP."""
        ip = "10.0.0.1"
        now = int(time.time())

        for i in range(inspector.MAX_REQ + 5):
            result = inspector.check_volume(ip, now)
            if result:
                break

        assert is_banned(ip), \
            f"IP should be banned after {inspector.MAX_REQ}+ requests."

    def test_requests_under_threshold_not_banned(self):
        """Sending fewer than MAX_REQ requests should NOT ban."""
        ip = "10.0.0.1"
        now = int(time.time())

        for i in range(inspector.MAX_REQ - 5):
            inspector.check_volume(ip, now)

        assert not is_banned(ip), \
            "IP should NOT be banned when under threshold."

    def test_captcha_kind_requests_skip_volume_check(self):
        """Events with kind='captcha' should not count toward volume."""
        ip = "10.0.0.1"
        now = int(time.time())

        # Send many captcha-kind events through handle_event
        # Use irregular timestamps and unique paths to avoid triggering
        # Module 2 (frequency regularity) and Module 3 (sequential pattern)
        import random
        rng = random.Random(42)
        t = float(now)
        for i in range(inspector.MAX_REQ + 10):
            t += rng.uniform(1.0, 8.0)
            evt = make_event(ip, t, path=f"/captcha/item/{i}", kind="captcha",
                             ref="http://localhost:8080/captcha")
            inspector.handle_event(evt)

        assert not is_banned(ip), \
            "Captcha-kind requests should not trigger volume ban."


# ===========================================================================
#  MODULE 2  Frequency regularity
# ===========================================================================

class TestModule2FrequencyRegularity:
    """Tests detection of metronomic request intervals."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.1.1")

    def teardown_method(self):
        clear_all_bans("10.0.1.1")

    def test_perfectly_regular_intervals_trigger_ban(self):
        """Requests at exact 2-second intervals (CV ~= 0) should be flagged."""
        ip = "10.0.1.1"
        base_ts = time.time()

        # 8 requests, exactly 2 seconds apart
        for i in range(8):
            ts = base_ts + i * 2.0
            inspector.ip_history[ip].append({"ts": ts, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert result, "Perfectly regular intervals should trigger ban."
        assert is_banned(ip)

    def test_irregular_human_intervals_not_flagged(self):
        """Requests with high variance (human-like) should NOT be flagged."""
        ip = "10.0.1.1"
        base_ts = time.time()

        # Irregular intervals: 1.2s, 4.7s, 0.8s, 3.1s, 6.5s, 2.3s, 1.9s
        offsets = [0, 1.2, 5.9, 6.7, 9.8, 16.3, 18.6, 20.5]
        for offset in offsets:
            inspector.ip_history[ip].append({"ts": base_ts + offset, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert not result, "Human-like irregular intervals should NOT trigger ban."
        assert not is_banned(ip)

    def test_sleep_loop_base_multiple_detected(self):
        """Intervals that are integer multiples of a base (e.g. 1s, 2s, 3s, 1s)
        should be detected as a sleep-loop pattern."""
        ip = "10.0.1.1"
        base_ts = time.time()

        # Intervals: 1s, 2s, 1s, 3s, 2s, 1s, 2s — all multiples of 1s
        offsets = [0, 1, 3, 4, 7, 9, 10, 12]
        for offset in offsets:
            inspector.ip_history[ip].append({"ts": base_ts + offset, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert result, "Sleep-loop base-multiple pattern should trigger ban."

    def test_too_few_requests_not_checked(self):
        """Fewer than FREQ_MIN_REQUESTS should not be analysed."""
        ip = "10.0.1.1"
        base_ts = time.time()

        # Only 3 requests (below threshold of 6)
        for i in range(3):
            inspector.ip_history[ip].append({"ts": base_ts + i * 2.0, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert not result, "Too few requests should not trigger analysis."


# ===========================================================================
#  MODULE 3 — Sequential pattern detection
# ===========================================================================

class TestModule3SequentialPattern:
    """Tests detection of repeated path sequences and transition dominance."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.2.1")

    def teardown_method(self):
        clear_all_bans("10.0.2.1")

    def test_repeated_path_sequence_detected(self):
        """A repeating path pattern (A->B->C->A->B->C->A->B->C) should be flagged."""
        ip = "10.0.2.1"
        base_ts = time.time()
        pattern = ["/", "/article/1", "/article/2"]

        # Repeat the pattern 4 times = 12 entries
        for rep in range(4):
            for j, path in enumerate(pattern):
                ts = base_ts + rep * 3 + j
                inspector.ip_history[ip].append({"ts": ts, "path": path})

        result = inspector.check_sequential_pattern(ip)
        assert result, "Repeated path sequence should trigger ban."
        assert is_banned(ip)

    def test_transition_dominance_detected(self):
        """If one path always follows another (p >= 0.90), it should be flagged."""
        ip = "10.0.2.1"
        base_ts = time.time()

        # / always followed by /article/1 (10 times)
        # /article/1 always followed by / (10 times)
        # This creates a dominant transition: / -> /article/1 (p=1.0)
        for i in range(10):
            inspector.ip_history[ip].append(
                {"ts": base_ts + i * 2, "path": "/"})
            inspector.ip_history[ip].append(
                {"ts": base_ts + i * 2 + 1, "path": "/article/1"})

        result = inspector.check_sequential_pattern(ip)
        assert result, "Dominant transition should trigger ban."

    def test_diverse_navigation_not_flagged(self):
        """Random, non-repeating navigation should NOT be flagged."""
        ip = "10.0.2.1"
        base_ts = time.time()
        paths = ["/", "/article/1", "/article/3", "/captcha",
                 "/article/2", "/", "/article/5", "/article/1",
                 "/captcha", "/article/4"]

        for i, path in enumerate(paths):
            inspector.ip_history[ip].append({"ts": base_ts + i * 3, "path": path})

        result = inspector.check_sequential_pattern(ip)
        assert not result, "Diverse navigation should NOT trigger ban."

    def test_too_few_requests_not_checked(self):
        """Fewer than SEQ_MIN_REQUESTS should not be analysed."""
        ip = "10.0.2.1"
        base_ts = time.time()

        for i in range(3):
            inspector.ip_history[ip].append({"ts": base_ts + i, "path": "/"})

        result = inspector.check_sequential_pattern(ip)
        assert not result


# ===========================================================================
#  MODULE 4 — Fingerprint consistency
# ===========================================================================

class TestModule4FingerprintConsistency:
    """Tests cross-IP fingerprint sharing and per-IP header anomaly detection."""

    def setup_method(self):
        reset_inspector_state()
        self._test_ips = ["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4"]
        clear_all_bans(*self._test_ips)

    def teardown_method(self):
        clear_all_bans(*self._test_ips)

    def test_same_fingerprint_across_multiple_ips_triggers_ban(self):
        """3+ IPs with identical fingerprints should all be banned."""
        now = time.time()
        # All 3 IPs send requests with identical UA/AL/AE/hdr_order
        for ip in self._test_ips[:3]:
            evt = make_event(ip, now, ua="BotUA/1.0", al="en",
                             ae="gzip", hdr_order="same_hash")
            result = inspector.check_fingerprint(ip, evt)

        # At least the last one should have triggered the cross-IP ban
        for ip in self._test_ips[:3]:
            assert is_banned(ip), \
                f"IP {ip} should be banned (shared fingerprint)."

    def test_different_fingerprints_not_flagged(self):
        """IPs with different fingerprints should NOT be flagged."""
        now = time.time()
        for i, ip in enumerate(self._test_ips[:3]):
            evt = make_event(ip, now, ua=f"Browser/{i}",
                             al=f"lang-{i}", hdr_order=f"hash_{i}")
            inspector.check_fingerprint(ip, evt)

        for ip in self._test_ips[:3]:
            assert not is_banned(ip), \
                f"IP {ip} should NOT be banned (unique fingerprint)."

    def test_browser_missing_accept_language_flagged(self):
        """A UA claiming to be a browser but missing Accept-Language should be flagged."""
        ip = self._test_ips[0]
        now = time.time()

        # Send 4 requests with browser UA but no Accept-Language
        for i in range(4):
            evt = make_event(ip, now + i, ua="Mozilla/5.0 Chrome/120",
                             al="", ae="gzip, br", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert is_banned(ip), \
            "Browser UA with missing Accept-Language should be flagged."

    def test_browser_missing_accept_encoding_flagged(self):
        """A UA claiming to be a browser but missing Accept-Encoding should be flagged."""
        ip = self._test_ips[0]
        now = time.time()

        for i in range(4):
            evt = make_event(ip, now + i, ua="Mozilla/5.0 Firefox/115",
                             al="en-US", ae="", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert is_banned(ip), \
            "Browser UA with missing Accept-Encoding should be flagged."

    def test_non_browser_ua_missing_headers_not_flagged(self):
        """A non-browser UA (e.g. curl) missing Accept-Language is normal."""
        ip = self._test_ips[0]
        now = time.time()

        for i in range(4):
            evt = make_event(ip, now + i, ua="curl/7.88", al="",
                             ae="", acc="*/*", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert not is_banned(ip), \
            "Non-browser UA with missing headers should NOT be flagged."

    def test_internal_nav_without_referer_flagged(self):
        """Navigating to /article/* without a Referer header is suspicious."""
        ip = self._test_ips[0]
        now = time.time()

        for i in range(4):
            evt = make_event(ip, now + i, path=f"/article/{i}",
                             ref="", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert is_banned(ip), \
            "Internal navigation without Referer should be flagged."


# ===========================================================================
#  MODULE 5 — Funnel timing
# ===========================================================================

class TestModule5FunnelTiming:
    """Tests detection of inhuman funnel completion speed and session replay."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.5.1")

    def teardown_method(self):
        clear_all_bans("10.0.5.1")

    def test_inhuman_page_to_action_speed_detected(self):
        """Completing captcha_load -> captcha_action in < 0.8s across 2+ sessions
        should trigger a ban."""
        ip = "10.0.5.1"
        base_ts = time.time()

        # Session 1: load at t=0, action at t=0.3 (inhuman)
        inspector.ip_history[ip].append(
            {"ts": base_ts, "path": "/captcha"})
        inspector.ip_history[ip].append(
            {"ts": base_ts + 0.3, "path": "/captcha/verify"})
        inspector.ip_history[ip].append(
            {"ts": base_ts + 0.5, "path": "/"})

        # Gap to create new session
        # Session 2: load at t=60, action at t=60.2 (inhuman)
        inspector.ip_history[ip].append(
            {"ts": base_ts + 60, "path": "/captcha"})
        inspector.ip_history[ip].append(
            {"ts": base_ts + 60.2, "path": "/captcha/verify"})
        inspector.ip_history[ip].append(
            {"ts": base_ts + 60.5, "path": "/"})

        result = inspector.check_funnel_timing(ip)
        assert result, "Inhuman page-to-action speed should trigger ban."
        assert is_banned(ip)

    def test_normal_human_speed_not_flagged(self):
        """Human-speed sessions (several seconds between steps) should not trigger."""
        ip = "10.0.5.1"
        base_ts = time.time()

        # Session 1: load at t=0, action at t=5, page at t=8
        inspector.ip_history[ip].append({"ts": base_ts, "path": "/captcha"})
        inspector.ip_history[ip].append({"ts": base_ts + 5, "path": "/captcha/verify"})
        inspector.ip_history[ip].append({"ts": base_ts + 8, "path": "/"})

        # Session 2: slightly different timing
        inspector.ip_history[ip].append({"ts": base_ts + 60, "path": "/captcha"})
        inspector.ip_history[ip].append({"ts": base_ts + 67, "path": "/captcha/verify"})
        inspector.ip_history[ip].append({"ts": base_ts + 72, "path": "/"})

        # Session 3
        inspector.ip_history[ip].append({"ts": base_ts + 120, "path": "/captcha"})
        inspector.ip_history[ip].append({"ts": base_ts + 124, "path": "/captcha/verify"})
        inspector.ip_history[ip].append({"ts": base_ts + 130, "path": "/"})

        result = inspector.check_funnel_timing(ip)
        assert not result, "Human-speed funnel should NOT trigger ban."

    def test_identical_session_durations_detected(self):
        """Multiple sessions with near-zero variance in duration should be flagged."""
        ip = "10.0.5.1"
        base_ts = time.time()

        # 4 sessions, all exactly 10.0 seconds long
        for s in range(4):
            session_start = base_ts + s * 60
            inspector.ip_history[ip].append(
                {"ts": session_start, "path": "/captcha"})
            inspector.ip_history[ip].append(
                {"ts": session_start + 5.0, "path": "/captcha/verify"})
            inspector.ip_history[ip].append(
                {"ts": session_start + 10.0, "path": "/"})

        result = inspector.check_funnel_timing(ip)
        assert result, "Identical session durations should trigger ban."

    def test_identical_step_timing_across_sessions_detected(self):
        """Sessions with identical inter-step intervals = scripted replay."""
        ip = "10.0.5.1"
        base_ts = time.time()

        # 4 sessions with identical step intervals: 3s, 2s, 4s
        for s in range(4):
            session_start = base_ts + s * 60
            inspector.ip_history[ip].append(
                {"ts": session_start, "path": "/captcha"})
            inspector.ip_history[ip].append(
                {"ts": session_start + 3.0, "path": "/captcha/verify"})
            inspector.ip_history[ip].append(
                {"ts": session_start + 5.0, "path": "/captcha/verify"})
            inspector.ip_history[ip].append(
                {"ts": session_start + 9.0, "path": "/"})

        result = inspector.check_funnel_timing(ip)
        assert result, "Identical step timing across sessions should trigger ban."


# ===========================================================================
#  MODULE 6 — Distributed botnet detection
# ===========================================================================

class TestModule6DistributedBotnet:
    """Tests all 5 sub-checks of Module 6."""

    def setup_method(self):
        reset_inspector_state()
        # Clear bans for all IPs used in tests
        ips = [f"10.2.0.{i}" for i in range(1, 20)]
        ips += [f"10.3.0.{i}" for i in range(1, 10)]
        ips += [f"10.4.{j}.{i}" for j in range(1, 4) for i in range(1, 10)]
        clear_all_bans(*ips)

    def teardown_method(self):
        ips = [f"10.2.0.{i}" for i in range(1, 20)]
        ips += [f"10.3.0.{i}" for i in range(1, 10)]
        ips += [f"10.4.{j}.{i}" for j in range(1, 4) for i in range(1, 10)]
        clear_all_bans(*ips)

    def test_mass_onboarding_detected(self):
        """5+ never-before-seen IPs appearing within 10 seconds triggers ban."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 7)]  # 6 new IPs

        # Register all as first-seen within a tight window
        for ip in ips:
            inspector.ip_first_seen[ip] = now
            # Need at least some history for the IP to be processable
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_mass_onboarding(now)
        assert result is not None, "Mass onboarding should be detected."
        assert len(result) >= inspector.BOT_ONBOARD_THRESHOLD

    def test_gradual_onboarding_not_flagged(self):
        """IPs appearing gradually over time should NOT trigger mass onboarding."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 7)]

        # Each IP first seen 30 seconds apart — well outside the onboard window
        for i, ip in enumerate(ips):
            inspector.ip_first_seen[ip] = now - (i * 30)

        result = inspector._check_mass_onboarding(now)
        assert result is None, "Gradual onboarding should NOT trigger detection."

    def test_subnet_concentration_detected(self):
        """4+ active IPs from the same /24 subnet triggers ban."""
        now = time.time()
        ips = [f"10.3.0.{i}" for i in range(1, 6)]  # 5 IPs in 10.3.0.0/24

        for ip in ips:
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_subnet_concentration(now)
        assert result is not None, "Subnet concentration should be detected."
        subnet, flagged_ips = result
        assert subnet == "10.3.0"
        assert len(flagged_ips) >= inspector.BOT_SUBNET_THRESHOLD

    def test_different_subnets_not_flagged(self):
        """IPs from different /24 subnets should NOT trigger subnet concentration."""
        now = time.time()
        ips = ["10.1.1.1", "10.2.2.1", "10.3.3.1", "10.4.4.1", "10.5.5.1"]

        for ip in ips:
            inspector.ip_history[ip].append({"ts": now, "path": "/"})
            clear_all_bans(ip)

        result = inspector._check_subnet_concentration(now)
        assert result is None, "IPs from different subnets should NOT trigger."

        for ip in ips:
            clear_all_bans(ip)

    def test_sequential_ips_detected(self):
        """4+ numerically consecutive IPs triggers ban."""
        now = time.time()
        # .10, .11, .12, .13, .14 — consecutive
        ips = [f"10.2.0.{i}" for i in range(10, 15)]

        for ip in ips:
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_sequential_ips(now)
        assert result is not None, "Sequential IPs should be detected."
        assert len(result) >= inspector.BOT_SEQUENTIAL_THRESHOLD

    def test_non_sequential_ips_not_flagged(self):
        """IPs that are NOT numerically adjacent should NOT trigger."""
        now = time.time()
        ips = ["10.2.0.10", "10.2.0.50", "10.2.0.100", "10.2.0.200"]

        for ip in ips:
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_sequential_ips(now)
        assert result is None, "Non-sequential IPs should NOT trigger."

    def test_synchronized_bursts_detected(self):
        """4+ IPs sending requests within 500ms windows, 3+ times, triggers ban."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 6)]  # 5 IPs

        # Create 4 synchronized bursts, 5 seconds apart
        for burst_idx in range(4):
            burst_time = now - 20 + burst_idx * 5
            for ip in ips:
                inspector.global_timeline.append({
                    "ts": burst_time + 0.05,  # all within 500ms of each other
                    "ip": ip,
                    "path": "/",
                })

        # Sort timeline (it should be sorted, but be safe)
        inspector.global_timeline.sort(key=lambda x: x["ts"])

        result = inspector._check_synchronized_bursts(now)
        assert result is not None, "Synchronized bursts should be detected."
        assert len(result) >= inspector.BOT_BURST_MIN_IPS

    def test_non_synchronized_requests_not_flagged(self):
        """Requests spread out in time should NOT trigger burst detection."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 6)]

        # Each IP sends requests at different, non-overlapping times
        for i, ip in enumerate(ips):
            inspector.global_timeline.append({
                "ts": now - 60 + i * 10,  # 10 seconds apart
                "ip": ip,
                "path": "/",
            })

        result = inspector._check_synchronized_bursts(now)
        assert result is None, "Non-synchronized requests should NOT trigger."

    def test_cross_ip_identical_timing_detected(self):
        """3+ IPs with identical inter-request interval patterns triggers ban."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 5)]  # 4 IPs

        # All 4 IPs have identical interval patterns: 2s, 3s, 2s, 3s
        for ip in ips:
            base = now - 20
            inspector.ip_history[ip] = [
                {"ts": base, "path": "/"},
                {"ts": base + 2.0, "path": "/article/1"},
                {"ts": base + 5.0, "path": "/article/2"},
                {"ts": base + 7.0, "path": "/"},
                {"ts": base + 10.0, "path": "/article/1"},
            ]

        result = inspector._check_cross_ip_timing(now)
        assert result is not None, "Identical timing across IPs should be detected."
        assert len(result) >= inspector.BOT_TIMING_MIN_IPS

    def test_different_timing_across_ips_not_flagged(self):
        """IPs with different interval patterns should NOT trigger."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 5)]

        # Each IP has distinctly different intervals
        intervals_per_ip = [
            [0, 1.5, 4.0, 5.5, 9.0],    # intervals: 1.5, 2.5, 1.5, 3.5
            [0, 3.0, 4.0, 8.0, 10.0],    # intervals: 3.0, 1.0, 4.0, 2.0
            [0, 0.5, 5.0, 6.0, 12.0],    # intervals: 0.5, 4.5, 1.0, 6.0
            [0, 2.0, 2.5, 7.0, 7.5],     # intervals: 2.0, 0.5, 4.5, 0.5
        ]

        for ip, offsets in zip(ips, intervals_per_ip):
            base = now - 20
            inspector.ip_history[ip] = [
                {"ts": base + t, "path": f"/p{j}"}
                for j, t in enumerate(offsets)
            ]

        result = inspector._check_cross_ip_timing(now)
        assert result is None, "Different timing patterns should NOT trigger."

    def test_full_handle_event_botnet_ban(self):
        """End-to-end: feeding events through handle_event should trigger
        Module 6 ban for sequential IPs."""
        now = int(time.time())
        # 5 consecutive IPs each sending a few requests
        ips = [f"10.2.0.{i}" for i in range(10, 15)]

        for ip in ips:
            clear_all_bans(ip)

        for ip in ips:
            for j in range(3):
                evt = make_event(ip, now + j, path="/")
                inspector.handle_event(evt)

        # At least some of them should be banned by Module 6 sequential check
        banned_count = sum(1 for ip in ips if is_banned(ip))
        assert banned_count >= 4, \
            f"Expected >=4 IPs banned by sequential detection, got {banned_count}."

        for ip in ips:
            clear_all_bans(ip)


# ===========================================================================
#  INTEGRATION — Full pipeline
# ===========================================================================

class TestFullPipeline:
    """End-to-end tests that feed events through handle_event and verify
    the correct module triggers."""

    def setup_method(self):
        reset_inspector_state()
        self._test_ips = ["10.9.0.1", "10.9.0.2"]
        clear_all_bans(*self._test_ips)

    def teardown_method(self):
        clear_all_bans(*self._test_ips)

    def test_volume_ban_via_handle_event(self):
        """Flooding requests through handle_event triggers Module 1."""
        ip = "10.9.0.1"
        now = int(time.time())

        for i in range(inspector.MAX_REQ + 5):
            evt = make_event(ip, now)
            inspector.handle_event(evt)
            if is_banned(ip):
                break

        assert is_banned(ip), "Volume flood via handle_event should trigger ban."

    def test_frequency_ban_via_handle_event(self):
        """Metronomic requests through handle_event triggers Module 2."""
        ip = "10.9.0.1"
        base_ts = time.time()

        # Send 8 requests at exactly 1-second intervals
        # Use unique timestamps to avoid Module 1 (they're spread over 8 seconds)
        for i in range(8):
            ts = base_ts + i * 1.0
            evt = make_event(ip, ts)
            inspector.handle_event(evt)
            if is_banned(ip):
                break

        assert is_banned(ip), \
            "Metronomic requests via handle_event should trigger ban."

    def test_legitimate_traffic_not_banned(self):
        """Normal, varied requests should NOT trigger any module."""
        ip = "10.9.0.2"
        base_ts = time.time()

        # 5 requests with varied timing, paths, and enough variance
        entries = [
            (base_ts, "/"),
            (base_ts + 3.7, "/article/1"),
            (base_ts + 8.2, "/"),
            (base_ts + 15.1, "/article/2"),
            (base_ts + 22.9, "/article/3"),
        ]

        for ts, path in entries:
            evt = make_event(ip, ts, path=path, ref="http://localhost:8080/")
            inspector.handle_event(evt)

        assert not is_banned(ip), \
            "Legitimate varied traffic should NOT trigger any ban."
