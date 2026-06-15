"""Suita unitara pentru cele 6 module ale inspectorului de cereri."""

import sys
import os
import time
import pytest
import redis as redis_lib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "request_inspector"))

import inspector  # noqa: E402

REDIS_HOST = "localhost"
REDIS_PORT = 6379
BANNED_PREFIX = "ban:"

def _redis():
    return redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def clear_all_bans(*ips):
    """Sterge cheile de ban pentru IP-urile date."""
    r = _redis()
    for ip in ips:
        r.delete(f"{BANNED_PREFIX}{ip}")
        r.delete(f"rate:{ip}")

def reset_inspector_state():
    """Sterge toata starea in-memory a inspectorului pentru izolarea testelor."""
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
    """Construieste un dict de eveniment in formatul publicat de serviciul web."""
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

class TestModule1VolumeThreshold:
    """Verifica banul la depasirea MAX_REQ in WINDOW_SECONDS."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.0.1")

    def teardown_method(self):
        clear_all_bans("10.0.0.1")

    def test_burst_exceeding_threshold_triggers_ban(self):
        """Trimiterea a mai mult de MAX_REQ cereri in fereastra duce la ban."""
        ip = "10.0.0.1"
        now = int(time.time())

        for i in range(inspector.MAX_REQ + 5):
            result = inspector.check_volume(ip, now)
            if result:
                break

        assert is_banned(ip), \
            f"IP should be banned after {inspector.MAX_REQ}+ requests."

    def test_requests_under_threshold_not_banned(self):
        """Sub pragul MAX_REQ nu trebuie sa apara ban."""
        ip = "10.0.0.1"
        now = int(time.time())

        for i in range(inspector.MAX_REQ - 5):
            inspector.check_volume(ip, now)

        assert not is_banned(ip), \
            "IP should NOT be banned when under threshold."

    def test_captcha_kind_requests_skip_volume_check(self):
        """Evenimentele de tip captcha nu trebuie sa intre in volum."""
        ip = "10.0.0.1"
        now = int(time.time())

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

class TestModule2FrequencyRegularity:
    """Verifica detectia intervalelor metronomice de cereri."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.1.1")

    def teardown_method(self):
        clear_all_bans("10.0.1.1")

    def test_perfectly_regular_intervals_trigger_ban(self):
        """Cereri la intervale exacte de 2 secunde (CV zero) trebuie marcate."""
        ip = "10.0.1.1"
        base_ts = time.time()

        for i in range(8):
            ts = base_ts + i * 2.0
            inspector.ip_history[ip].append({"ts": ts, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert result, "Perfectly regular intervals should trigger ban."
        assert is_banned(ip)

    def test_irregular_human_intervals_not_flagged(self):
        """Cereri cu varianta mare (cvasi-umane) nu trebuie marcate."""
        ip = "10.0.1.1"
        base_ts = time.time()

        offsets = [0, 1.2, 5.9, 6.7, 9.8, 16.3, 18.6, 20.5]
        for offset in offsets:
            inspector.ip_history[ip].append({"ts": base_ts + offset, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert not result, "Human-like irregular intervals should NOT trigger ban."
        assert not is_banned(ip)

    def test_sleep_loop_base_multiple_detected(self):
        """Intervalele multipli intregi ai unei baze trebuie detectate."""
        ip = "10.0.1.1"
        base_ts = time.time()

        offsets = [0, 1, 3, 4, 7, 9, 10, 12]
        for offset in offsets:
            inspector.ip_history[ip].append({"ts": base_ts + offset, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert result, "Sleep-loop base-multiple pattern should trigger ban."

    def test_too_few_requests_not_checked(self):
        """Sub pragul minim de cereri nu se face analiza."""
        ip = "10.0.1.1"
        base_ts = time.time()

        for i in range(3):
            inspector.ip_history[ip].append({"ts": base_ts + i * 2.0, "path": "/"})

        result = inspector.check_frequency_regularity(ip)
        assert not result, "Too few requests should not trigger analysis."

class TestModule3SequentialPattern:
    """Verifica detectia secventelor repetate si a tranzitiilor dominante."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.2.1")

    def teardown_method(self):
        clear_all_bans("10.0.2.1")

    def test_repeated_path_sequence_detected(self):
        """O secventa de path-uri care se repeta trebuie marcata."""
        ip = "10.0.2.1"
        base_ts = time.time()
        pattern = ["/", "/article/1", "/article/2"]

        for rep in range(4):
            for j, path in enumerate(pattern):
                ts = base_ts + rep * 3 + j
                inspector.ip_history[ip].append({"ts": ts, "path": path})

        result = inspector.check_sequential_pattern(ip)
        assert result, "Repeated path sequence should trigger ban."
        assert is_banned(ip)

    def test_transition_dominance_detected(self):
        """Daca un path urmeaza mereu altul cu p mare, trebuie marcat."""
        ip = "10.0.2.1"
        base_ts = time.time()

        for i in range(10):
            inspector.ip_history[ip].append(
                {"ts": base_ts + i * 2, "path": "/"})
            inspector.ip_history[ip].append(
                {"ts": base_ts + i * 2 + 1, "path": "/article/1"})

        result = inspector.check_sequential_pattern(ip)
        assert result, "Dominant transition should trigger ban."

    def test_diverse_navigation_not_flagged(self):
        """Navigarea aleatorie nu trebuie marcata."""
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
        """Sub pragul minim de cereri nu se face analiza."""
        ip = "10.0.2.1"
        base_ts = time.time()

        for i in range(3):
            inspector.ip_history[ip].append({"ts": base_ts + i, "path": "/"})

        result = inspector.check_sequential_pattern(ip)
        assert not result

class TestModule4FingerprintConsistency:
    """Verifica partajarea de amprenta intre IP-uri si anomaliile de antete."""

    def setup_method(self):
        reset_inspector_state()
        self._test_ips = ["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4"]
        clear_all_bans(*self._test_ips)

    def teardown_method(self):
        clear_all_bans(*self._test_ips)

    def test_same_fingerprint_across_multiple_ips_triggers_ban(self):
        """3 sau mai multe IP-uri cu amprente identice trebuie banate."""
        now = time.time()
        for ip in self._test_ips[:3]:
            evt = make_event(ip, now, ua="BotUA/1.0", al="en",
                             ae="gzip", hdr_order="same_hash")
            result = inspector.check_fingerprint(ip, evt)

        for ip in self._test_ips[:3]:
            assert is_banned(ip), \
                f"IP {ip} should be banned (shared fingerprint)."

    def test_different_fingerprints_not_flagged(self):
        """IP-uri cu amprente diferite nu trebuie marcate."""
        now = time.time()
        for i, ip in enumerate(self._test_ips[:3]):
            evt = make_event(ip, now, ua=f"Browser/{i}",
                             al=f"lang-{i}", hdr_order=f"hash_{i}")
            inspector.check_fingerprint(ip, evt)

        for ip in self._test_ips[:3]:
            assert not is_banned(ip), \
                f"IP {ip} should NOT be banned (unique fingerprint)."

    def test_browser_missing_accept_language_flagged(self):
        """UA de browser fara Accept-Language trebuie marcat."""
        ip = self._test_ips[0]
        now = time.time()

        for i in range(4):
            evt = make_event(ip, now + i, ua="Mozilla/5.0 Chrome/120",
                             al="", ae="gzip, br", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert is_banned(ip), \
            "Browser UA with missing Accept-Language should be flagged."

    def test_browser_missing_accept_encoding_flagged(self):
        """UA de browser fara Accept-Encoding trebuie marcat."""
        ip = self._test_ips[0]
        now = time.time()

        for i in range(4):
            evt = make_event(ip, now + i, ua="Mozilla/5.0 Firefox/115",
                             al="en-US", ae="", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert is_banned(ip), \
            "Browser UA with missing Accept-Encoding should be flagged."

    def test_non_browser_ua_missing_headers_not_flagged(self):
        """Un UA non-browser (ex. curl) fara Accept-Language e normal."""
        ip = self._test_ips[0]
        now = time.time()

        for i in range(4):
            evt = make_event(ip, now + i, ua="curl/7.88", al="",
                             ae="", acc="*/*", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert not is_banned(ip), \
            "Non-browser UA with missing headers should NOT be flagged."

    def test_internal_nav_without_referer_flagged(self):
        """Navigarea catre /article fara Referer e suspecta."""
        ip = self._test_ips[0]
        now = time.time()

        for i in range(4):
            evt = make_event(ip, now + i, path=f"/article/{i}",
                             ref="", hdr_order=f"h{i}")
            inspector.check_fingerprint(ip, evt)

        assert is_banned(ip), \
            "Internal navigation without Referer should be flagged."

class TestModule5FunnelTiming:
    """Verifica detectia vitezei inumane a palniei si a replay-ului de sesiuni."""

    def setup_method(self):
        reset_inspector_state()
        clear_all_bans("10.0.5.1")

    def teardown_method(self):
        clear_all_bans("10.0.5.1")

    def test_inhuman_page_to_action_speed_detected(self):
        """Completarea captcha_load catre captcha_action in sub 0.8s trebuie marcata."""
        ip = "10.0.5.1"
        base_ts = time.time()

        inspector.ip_history[ip].append(
            {"ts": base_ts, "path": "/captcha"})
        inspector.ip_history[ip].append(
            {"ts": base_ts + 0.3, "path": "/captcha/verify"})
        inspector.ip_history[ip].append(
            {"ts": base_ts + 0.5, "path": "/"})

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
        """Sesiunile umane normale nu trebuie sa declanseze marcare."""
        ip = "10.0.5.1"
        base_ts = time.time()

        inspector.ip_history[ip].append({"ts": base_ts, "path": "/captcha"})
        inspector.ip_history[ip].append({"ts": base_ts + 5, "path": "/captcha/verify"})
        inspector.ip_history[ip].append({"ts": base_ts + 8, "path": "/"})

        inspector.ip_history[ip].append({"ts": base_ts + 60, "path": "/captcha"})
        inspector.ip_history[ip].append({"ts": base_ts + 67, "path": "/captcha/verify"})
        inspector.ip_history[ip].append({"ts": base_ts + 72, "path": "/"})

        inspector.ip_history[ip].append({"ts": base_ts + 120, "path": "/captcha"})
        inspector.ip_history[ip].append({"ts": base_ts + 124, "path": "/captcha/verify"})
        inspector.ip_history[ip].append({"ts": base_ts + 130, "path": "/"})

        result = inspector.check_funnel_timing(ip)
        assert not result, "Human-speed funnel should NOT trigger ban."

    def test_identical_session_durations_detected(self):
        """Durate identice de sesiune trebuie marcate."""
        ip = "10.0.5.1"
        base_ts = time.time()

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
        """Intervale identice intre pasi pe mai multe sesiuni indica scripted replay."""
        ip = "10.0.5.1"
        base_ts = time.time()

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

class TestModule6DistributedBotnet:
    """Verifica toate cele 5 sub-verificari ale modulului 6."""

    def setup_method(self):
        reset_inspector_state()
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
        """5 sau mai multe IP-uri noi in 10 secunde declanseaza ban."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 7)]

        for ip in ips:
            inspector.ip_first_seen[ip] = now
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_mass_onboarding(now)
        assert result is not None, "Mass onboarding should be detected."
        assert len(result) >= inspector.BOT_ONBOARD_THRESHOLD

    def test_gradual_onboarding_not_flagged(self):
        """IP-uri care apar treptat in timp nu trebuie marcate."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 7)]

        for i, ip in enumerate(ips):
            inspector.ip_first_seen[ip] = now - (i * 30)

        result = inspector._check_mass_onboarding(now)
        assert result is None, "Gradual onboarding should NOT trigger detection."

    def test_subnet_concentration_detected(self):
        """4 sau mai multe IP-uri din aceeasi /24 declanseaza ban."""
        now = time.time()
        ips = [f"10.3.0.{i}" for i in range(1, 6)]

        for ip in ips:
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_subnet_concentration(now)
        assert result is not None, "Subnet concentration should be detected."
        subnet, flagged_ips = result
        assert subnet == "10.3.0"
        assert len(flagged_ips) >= inspector.BOT_SUBNET_THRESHOLD

    def test_different_subnets_not_flagged(self):
        """IP-uri din /24 diferite nu trebuie marcate."""
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
        """4 sau mai multe IP-uri numeric consecutive declanseaza ban."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(10, 15)]

        for ip in ips:
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_sequential_ips(now)
        assert result is not None, "Sequential IPs should be detected."
        assert len(result) >= inspector.BOT_SEQUENTIAL_THRESHOLD

    def test_non_sequential_ips_not_flagged(self):
        """IP-uri nesecventiale nu trebuie marcate."""
        now = time.time()
        ips = ["10.2.0.10", "10.2.0.50", "10.2.0.100", "10.2.0.200"]

        for ip in ips:
            inspector.ip_history[ip].append({"ts": now, "path": "/"})

        result = inspector._check_sequential_ips(now)
        assert result is None, "Non-sequential IPs should NOT trigger."

    def test_synchronized_bursts_detected(self):
        """4 sau mai multe IP-uri cu rafale sincronizate de 500ms declanseaza ban."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 6)]

        for burst_idx in range(4):
            burst_time = now - 20 + burst_idx * 5
            for ip in ips:
                inspector.global_timeline.append({
                    "ts": burst_time + 0.05,
                    "ip": ip,
                    "path": "/",
                })

        inspector.global_timeline.sort(key=lambda x: x["ts"])

        result = inspector._check_synchronized_bursts(now)
        assert result is not None, "Synchronized bursts should be detected."
        assert len(result) >= inspector.BOT_BURST_MIN_IPS

    def test_non_synchronized_requests_not_flagged(self):
        """Cererile distribuite in timp nu trebuie sa declanseze burst."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 6)]

        for i, ip in enumerate(ips):
            inspector.global_timeline.append({
                "ts": now - 60 + i * 10,
                "ip": ip,
                "path": "/",
            })

        result = inspector._check_synchronized_bursts(now)
        assert result is None, "Non-synchronized requests should NOT trigger."

    def test_cross_ip_identical_timing_detected(self):
        """3 sau mai multe IP-uri cu tipare de interval identice declanseaza ban."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 5)]

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
        """IP-uri cu tipare de interval diferite nu trebuie marcate."""
        now = time.time()
        ips = [f"10.2.0.{i}" for i in range(1, 5)]

        intervals_per_ip = [
            [0, 1.5, 4.0, 5.5, 9.0],
            [0, 3.0, 4.0, 8.0, 10.0],
            [0, 0.5, 5.0, 6.0, 12.0],
            [0, 2.0, 2.5, 7.0, 7.5],
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
        """End-to-end: alimentarea evenimentelor prin handle_event declanseaza ban."""
        now = int(time.time())
        ips = [f"10.2.0.{i}" for i in range(10, 15)]

        for ip in ips:
            clear_all_bans(ip)

        for ip in ips:
            for j in range(3):
                evt = make_event(ip, now + j, path="/")
                inspector.handle_event(evt)

        banned_count = sum(1 for ip in ips if is_banned(ip))
        assert banned_count >= 4, \
            f"Expected >=4 IPs banned by sequential detection, got {banned_count}."

        for ip in ips:
            clear_all_bans(ip)

class TestFullPipeline:
    """Teste end-to-end care alimenteaza evenimente prin handle_event."""

    def setup_method(self):
        reset_inspector_state()
        self._test_ips = ["10.9.0.1", "10.9.0.2"]
        clear_all_bans(*self._test_ips)

    def teardown_method(self):
        clear_all_bans(*self._test_ips)

    def test_volume_ban_via_handle_event(self):
        """Flood de cereri prin handle_event declanseaza modulul 1."""
        ip = "10.9.0.1"
        now = int(time.time())

        for i in range(inspector.MAX_REQ + 5):
            evt = make_event(ip, now)
            inspector.handle_event(evt)
            if is_banned(ip):
                break

        assert is_banned(ip), "Volume flood via handle_event should trigger ban."

    def test_frequency_ban_via_handle_event(self):
        """Cereri metronomice prin handle_event declanseaza modulul 2."""
        ip = "10.9.0.1"
        base_ts = time.time()

        for i in range(8):
            ts = base_ts + i * 1.0
            evt = make_event(ip, ts)
            inspector.handle_event(evt)
            if is_banned(ip):
                break

        assert is_banned(ip), \
            "Metronomic requests via handle_event should trigger ban."

    def test_legitimate_traffic_not_banned(self):
        """Trafic normal si variat nu trebuie sa declanseze nici un modul."""
        ip = "10.9.0.2"
        base_ts = time.time()

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
