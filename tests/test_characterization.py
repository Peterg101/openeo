"""Characterization tests: pin the CURRENT behaviour of logic this change must not alter.

Tests marked xfail describe behaviour that looks like a bug; they document it and
are deliberately NOT fixed here (the charger control code is out of scope).
"""
import datetime as real_datetime
import json
import sqlite3
import time
import types

import pytest

from lib.PluginSuperClass import PluginSuperClass


class FrozenClock:
    """Replacement for the `datetime` module attribute inside a lib module."""

    def __init__(self, hh, mm, ss=0, day=(2025, 1, 15)):
        moment = real_datetime.datetime(*day, hh, mm, ss)

        class DT(real_datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(*[getattr(moment, f) for f in ("year", "month", "day", "hour", "minute", "second")])

        self.moment = moment
        self.DT = DT
        self.module = types.SimpleNamespace(datetime=DT, time=real_datetime.time,
                                            timedelta=real_datetime.timedelta)


def freeze(monkeypatch, module, hh, mm, ss=0, day=(2025, 1, 15)):
    fc = FrozenClock(hh, mm, ss, day)
    monkeypatch.setattr(module, "datetime", fc.module)
    return fc


# =============================== PluginSuperClass =============================
class Demo(PluginSuperClass):
    pluginParamSpec = {"b": {"type": "bool", "default": False}, "i": {"type": "int", "default": 5},
                       "f": {"type": "float", "default": 1.5}, "s": {"type": "str", "default": "d"},
                       "j": {"type": "json", "default": "[1]"}}


@pytest.mark.parametrize("raw,expected", [
    ({"b": "true"}, True), ({"b": "True"}, True), ({"b": 1}, True), ({"b": "1"}, True),
    ({"b": "false"}, False), ({"b": 0}, False), ({"b": "yes"}, False),
    ({"i": "7"}, 7), ({"i": "7.9"}, 7), ({"i": 3.2}, 3), ({"i": "abc"}, 5), ({"i": None}, 5),
    ({"f": "2.5"}, 2.5), ({"f": "-1"}, -1.0), ({"f": "x"}, 1.5),
    ({"s": "hello"}, "hello"), ({"s": 5}, "d"),
    ({"j": '[{"a": 1}]'}, [{"a": 1}]), ({"j": "not json"}, [1]), ({}, [1]),
])
def test_type_conversion(raw, expected):
    d = Demo(dict(raw))
    key = list(Demo.pluginParamSpec)[["b", "i", "f", "s", "j"].index(next(iter(raw or {"j": 0})))]
    assert d.pluginConfig[key] == expected


def test_json_value_already_decoded_is_passed_through():
    assert Demo({"j": [2]}).pluginConfig["j"] == [2]


def test_defaults_applied_for_missing_keys_and_name_derived():
    class FooClassPlugin(PluginSuperClass):
        pluginParamSpec = {"x": {"type": "int", "default": 9}}
    p = FooClassPlugin({})
    assert p.pluginConfig == {"x": 9} and str(p) == "Foo"
    assert p.get_config("x") == 9 and p.get_config() == {"x": 9} and p.get_user_settings() == []


def test_mismatched_default_type_gives_none():
    class BadClassPlugin(PluginSuperClass):
        pluginParamSpec = {"x": {"type": "int", "default": "oops"}}
    assert BadClassPlugin({}).pluginConfig["x"] is None


# =============================== scheduler ====================================
@pytest.fixture
def scheduler(gs):
    import lib.scheduler as mod

    def make(schedule):
        return mod.schedulerClassPlugin({"enabled": True, "schedule": json.dumps(schedule)}), mod
    return make


def test_scheduler_parses_schedule(scheduler):
    s, _ = scheduler([{"start": "0130", "end": "0545", "amps": "16"}])
    assert s.parsedSchedule == [{"start": real_datetime.time(1, 30), "end": real_datetime.time(5, 45), "amps": 16}]


def test_scheduler_default_schedule_when_unset(gs):
    import lib.scheduler as mod
    s = mod.schedulerClassPlugin({})
    assert s.parsedSchedule == [{"start": real_datetime.time(0, 30), "end": real_datetime.time(5, 30), "amps": 32}]
    assert s.pluginConfig["scheduler_granularity"] == 5 and s.pluginConfig["enabled"] is True


@pytest.mark.parametrize("hh,mm,ss,expected", [
    (3, 0, 0, 32), (1, 0, 1, 32), (4, 59, 59, 32),
    (0, 59, 59, 0), (5, 0, 0, 0), (12, 0, 0, 0),
    (1, 0, 0, 0),            # start instant itself is EXCLUSIVE
])
def test_scheduler_simple_window(scheduler, monkeypatch, hh, mm, ss, expected):
    s, mod = scheduler([{"start": "0100", "end": "0500", "amps": 32}])
    freeze(monkeypatch, mod, hh, mm, ss)
    assert s.poll() == expected


@pytest.mark.parametrize("hh,mm,expected", [(23, 0, 20), (22, 1, 20), (0, 30, 20), (5, 59, 20),
                                            (6, 0, 0), (12, 0, 0), (21, 59, 0)])
def test_scheduler_window_spanning_midnight(scheduler, monkeypatch, hh, mm, expected):
    s, mod = scheduler([{"start": "2200", "end": "0600", "amps": 20}])
    freeze(monkeypatch, mod, hh, mm, 30)
    assert s.poll() == expected


def test_scheduler_overlapping_windows_take_max(scheduler, monkeypatch):
    s, mod = scheduler([{"start": "0100", "end": "0500", "amps": 10},
                        {"start": "0300", "end": "0700", "amps": 25},
                        {"start": "2300", "end": "0200", "amps": 16}])
    freeze(monkeypatch, mod, 3, 30)
    assert s.poll() == 25
    freeze(monkeypatch, mod, 1, 30)
    assert s.poll() == 16                    # midnight-spanning (16) beats 10
    freeze(monkeypatch, mod, 6, 0)
    assert s.poll() == 25


def test_scheduler_zero_amps_and_empty_and_degenerate(scheduler, monkeypatch):
    s, mod = scheduler([{"start": "0100", "end": "0500", "amps": 0}])
    freeze(monkeypatch, mod, 3, 0)
    assert s.poll() == 0
    s, mod = scheduler([])
    assert s.poll() == 0
    s, mod = scheduler([{"start": "0300", "end": "0300", "amps": 32}])    # start == end: never active
    freeze(monkeypatch, mod, 3, 0, 1)
    assert s.poll() == 0


def test_scheduler_user_settings(scheduler):
    s, _ = scheduler([])
    f = s.get_user_settings()[0]
    assert f["name"] == "scheduler_granularity" and f["range"] == [5, 15] and f["default"] == 5


# =============================== switch =======================================
def test_switch_poll(gs):
    import lib.switch as mod
    assert mod.switchClassPlugin({"on": "true", "amps": "16"}).poll() == 16
    assert mod.switchClassPlugin({"on": "true"}).poll() == 32            # default amps
    assert mod.switchClassPlugin({"on": "false", "amps": "16"}).poll() == 0
    assert mod.switchClassPlugin({}).poll() == 0                          # default off


def test_switch_retain_state_on_startup(gs):
    import lib.switch as mod
    mod.switchClassPlugin({"on": "true", "retain_state_on_startup": "true"})
    assert gs.configDB.data == {}
    mod.switchClassPlugin({"on": "true", "retain_state_on_startup": "false"})
    assert gs.configDB.data["switch"]["on"] is False


def test_switch_user_settings(gs):
    import lib.switch as mod
    f = mod.switchClassPlugin({}).get_user_settings()[0]
    assert f["name"] == "retain_state_on_startup" and f["default"] is True


# =============================== loadmanagement ===============================
@pytest.fixture
def lm(gs, monkeypatch):
    import lib.loadmanagement as mod
    monkeypatch.setattr(mod.loadmanagementClassPlugin, "solar_ct_readings", [0, 0])

    def make(schedule=None, **cfg):
        c = {"solar_enable": "true"}
        if schedule is not None:
            c["schedule"] = json.dumps(schedule)
        c.update(cfg)
        return mod.loadmanagementClassPlugin(c)
    make.mod = mod
    return make


def test_lm_disabled_returns_zero_and_marks_inactive(gs, lm):
    p = lm(solar_enable="false")
    gs.stateDict["eo_current_solar"] = 30
    assert p.poll() == 0
    assert gs.stateDict["eo_solar_active"] is False and gs.stateDict["eo_solar_reservation"] == 0
    assert gs.stateDict["eo_solar_charge_current"] == 0


def test_lm_no_schedule_means_always_active_with_zero_reservation(gs, lm):
    p = lm(schedule=[])
    assert p.get_active_schedule() == 0
    assert gs.stateDict["eo_solar_active"] is True and gs.stateDict["eo_solar_reservation"] == 0


def test_lm_schedule_windows_and_midnight(gs, lm, monkeypatch):
    p = lm(schedule=[{"start": "0900", "end": "1700", "amps": 4}, {"start": "2200", "end": "0600", "amps": 8}])
    mod = lm.mod
    freeze(monkeypatch, mod, 12, 0)
    assert p.get_active_schedule() == 4 and gs.stateDict["eo_solar_reservation"] == 4
    freeze(monkeypatch, mod, 23, 0)
    assert p.get_active_schedule() == 8
    freeze(monkeypatch, mod, 7, 0)
    assert p.get_active_schedule() is None
    assert gs.stateDict["eo_solar_active"] is False


def test_lm_zero_amp_window_is_active_not_none(gs, lm, monkeypatch):
    p = lm(schedule=[{"start": "0900", "end": "1700", "amps": 0}])
    freeze(monkeypatch, lm.mod, 12, 0)
    assert p.get_active_schedule() == 0 and gs.stateDict["eo_solar_active"] is True


def test_lm_threshold_and_hold_levels(gs, lm):
    p = lm(schedule=[], solar_enable_threshold="9")
    gs.stateDict["eo_current_solar"] = 8
    assert p.poll() == 0 and p.solar_active is False         # 8 < 9: not started
    gs.stateDict["eo_current_solar"] = 9
    p.poll()
    assert p.poll() == 9 and p.solar_active is True          # mean(9,9)=9 >= 9
    gs.stateDict["eo_current_solar"] = 6
    p.poll()
    gs.stateDict["eo_current_solar"] = 6
    assert p.poll() == 6                                     # keeps going down to 6
    gs.stateDict["eo_current_solar"] = 5
    p.poll()
    assert p.poll() == 0 and p.solar_active is False         # below 6: stops


def test_lm_reservation_is_subtracted(gs, lm, monkeypatch):
    p = lm(schedule=[{"start": "0000", "end": "2359", "amps": 5}])
    freeze(monkeypatch, lm.mod, 12, 0)
    gs.stateDict["eo_current_solar"] = 14
    p.poll()
    assert p.poll() == 9                                     # 14 - 5
    assert gs.stateDict["eo_solar_charge_current"] == 9


def test_lm_outside_schedule_returns_zero(gs, lm, monkeypatch):
    p = lm(schedule=[{"start": "0900", "end": "1000", "amps": 0}])
    freeze(monkeypatch, lm.mod, 20, 0)
    gs.stateDict["eo_current_solar"] = 30
    p.poll()
    assert p.poll() == 0


def test_lm_defaults_and_user_settings(gs, lm):
    p = lm.mod.loadmanagementClassPlugin({})
    c = p.pluginConfig
    assert (c["site_limit_current"], c["ct_calibration_site"], c["ct_offset_solar"],
            c["solar_enable_threshold"], c["solar_enable"]) == (60, 1.0, 0.0, 7, False)
    assert [f["name"] for f in p.get_user_settings()] == ["solar_enable", "site_limit_current"]


@pytest.mark.xfail(reason="solar_ct_readings is a class-level list shared by every instance "
                          "(and between reconfigure cycles of different instances)", strict=True)
def test_lm_instances_do_not_share_ct_history(gs):
    import lib.loadmanagement as mod
    mod.loadmanagementClassPlugin.solar_ct_readings = [0, 0]
    a = mod.loadmanagementClassPlugin({"solar_enable": "false"})
    b = mod.loadmanagementClassPlugin({"solar_enable": "false"})
    gs.stateDict["eo_current_solar"] = 12
    a.poll()
    assert b.solar_ct_readings == [0, 0]


# =============================== chargeroptions ===============================
def test_chargeroptions_publishes_to_state(gs):
    import lib.chargeroptions as mod
    p = mod.chargeroptionsClassPlugin({"overall_limit_current": "20", "charger_name": "Garage",
                                       "charger_id": "g_1"})
    assert gs.stateDict["eo_overall_limit_current"] == 20
    assert gs.stateDict["charger_name"] == "Garage" and gs.stateDict["charger_id"] == "g_1"
    p.configure({"overall_limit_current": "10"})
    assert gs.stateDict["eo_overall_limit_current"] == 10 and gs.stateDict["charger_name"] == "openeo"


def test_chargeroptions_defaults_and_user_settings(gs):
    import lib.chargeroptions as mod
    p = mod.chargeroptionsClassPlugin({})
    assert (p.pluginConfig["overall_limit_current"], p.pluginConfig["mains_voltage_correction"],
            p.pluginConfig["overall_property_limit_current"]) == (32, 77.8, 60)
    fields = {f["name"]: f for f in p.get_user_settings()}
    assert fields["overall_limit_current"]["range"] == [6, 32]
    assert fields["charger_id"]["pattern"] == "([A-Za-z0-9_])+"
    assert fields["mains_voltage_correction"]["step"] == 0.1


# =============================== chargersession ===============================
@pytest.fixture
def cs(gs, tmp_path, monkeypatch):
    import lib.chargersession as mod
    monkeypatch.setattr(mod.chargersessionClassPlugin, "SESSION_DB_FILE", str(tmp_path / "session.db"))

    def make(**cfg):
        return mod.chargersessionClassPlugin(cfg)
    make.mod = mod
    make.gs = gs
    return make


TARIFF = [{"start": "0000", "end": "0629", "cost": 0.10}, {"start": "0630", "end": "2359", "cost": 0.30}]


def _charging_state(gs, state=9, volts=230.0, amps=10.0):
    gs.stateDict.update({"eo_charger_state_id": state, "eo_live_voltage": volts,
                         "eo_current_vehicle": amps})


def test_session_resets_when_car_not_charging(cs, gs, monkeypatch):
    p = cs(tariff=json.dumps(TARIFF))
    _charging_state(gs, state=2)
    gs.stateDict["eo_session_joules"] = 999
    freeze(monkeypatch, cs.mod, 12, 0)
    assert p.poll() == 0
    assert gs.stateDict["eo_session_joules"] == 0 and gs.stateDict["eo_session_kwh"] == 0
    assert [t["joules"] for t in gs.stateDict["session_tariff"]] == [0, 0]


def test_session_accumulates_energy_cost_and_time(cs, gs, monkeypatch):
    p = cs(tariff=json.dumps(TARIFF))
    _charging_state(gs)
    fc = freeze(monkeypatch, cs.mod, 12, 0, 0)
    p.timestamp_hhmm = lambda ts: "1200"       # tariff lookup uses time.time(), so pin it
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=5)
    p.poll()
    assert gs.stateDict["eo_session_joules"] == 11500            # 230V * 10A * 5s
    assert gs.stateDict["eo_session_seconds_charged"] == 5
    assert gs.stateDict["eo_session_current_tariff"] == 0.30
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=3600)
    p.poll()
    assert gs.stateDict["eo_session_joules"] == 11500 + 8280000
    assert gs.stateDict["eo_session_kwh"] == round((11500 + 8280000) / 3600000, 2) == 2.3
    assert gs.stateDict["eo_session_cost"] == round(0.30 * (8291500 / 3600000), 2)


def test_session_seconds_only_counted_when_vehicle_draws_current(cs, gs, monkeypatch):
    p = cs(tariff=json.dumps(TARIFF))
    _charging_state(gs, amps=1.9)
    p.timestamp_hhmm = lambda ts: "1200"
    fc = freeze(monkeypatch, cs.mod, 12, 0, 0)
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=5)
    p.poll()
    assert gs.stateDict["eo_session_seconds_charged"] == 0
    assert gs.stateDict["eo_session_joules"] == int(230 * 1.9 * 5)


def test_session_cost_splits_across_tariff_periods(cs, gs, monkeypatch):
    p = cs(tariff=json.dumps(TARIFF))
    _charging_state(gs, amps=10)
    fc = freeze(monkeypatch, cs.mod, 6, 0, 0)               # cheap period
    p.timestamp_hhmm = lambda ts: "0600"
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=1800)
    p.poll()
    fc = freeze(monkeypatch, cs.mod, 7, 0, 0)               # expensive period
    p.timestamp_hhmm = lambda ts: "0700"
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=1800)
    p.poll()
    cheap, dear = (t["joules"] for t in gs.stateDict["session_tariff"])
    assert cheap == dear == 4140000
    assert gs.stateDict["eo_session_cost"] == round(0.10 * 1.15 + 0.30 * 1.15, 2)


def test_session_writes_to_db_once_a_minute_and_reads_back(cs, gs, monkeypatch):
    p = cs(tariff=json.dumps(TARIFF))
    _charging_state(gs, amps=32)
    gs.stateDict["eo_session_timestamp"] = int(time.time()) - 100
    p.timestamp_hhmm = lambda ts: "1200"
    fc = freeze(monkeypatch, cs.mod, 12, 5, 0)
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=60)     # previous loop was minute 4
    p.poll()
    rows = p.cursor.execute("SELECT joules, seconds_charged FROM session_v5").fetchall()
    assert rows == [(gs.stateDict["eo_session_joules"], 60)]
    assert any(m.startswith("Sessionlog update") for m in gs.configDB.log)
    p.lastloop = fc.moment                                           # same minute: no new write
    p.poll()
    assert p.cursor.execute("SELECT count(*) FROM session_v5").fetchone() == (1,)


@pytest.mark.xfail(reason="minute comparison `thisloop.minute > lastloop.minute` is False when the "
                          "minute wraps 59 -> 0, so the log write is skipped once an hour", strict=True)
def test_session_write_happens_across_the_hour_boundary(cs, gs, monkeypatch):
    p = cs(tariff=json.dumps(TARIFF))
    _charging_state(gs, amps=32)
    p.timestamp_hhmm = lambda ts: "1300"
    fc = freeze(monkeypatch, cs.mod, 13, 0, 0)
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=5)       # 12:59:55
    p.poll()
    assert p.cursor.execute("SELECT count(*) FROM session_v5").fetchone() == (1,)


def test_session_resets_on_new_day(cs, gs, monkeypatch):
    p = cs(tariff=json.dumps(TARIFF))
    _charging_state(gs)
    gs.stateDict["eo_session_joules"] = 5
    p.today_timestamp = 0                                            # session started "yesterday"
    p.timestamp_hhmm = lambda ts: "0001"
    fc = freeze(monkeypatch, cs.mod, 0, 1, 0)
    p.lastloop = fc.moment - real_datetime.timedelta(seconds=1)
    p.poll()
    assert gs.stateDict["eo_session_joules"] == int(230 * 10 * 1)    # restarted from zero this loop


def test_get_sessions_filters_short_sessions_and_old_ones(cs, gs):
    p = cs(tariff=json.dumps(TARIFF))
    now = int(time.time())
    big, small, old = now - 3600, now - 7200, now - 60 * 60 * 24 * 400
    day = p.timestamp_start_of_today()
    for first, joules in [(big, 4000000), (big, 100), (small, 1000000), (old, 9000000)]:
        p.cursor.execute("REPLACE INTO session_v5 VALUES (?,?,?,?,?,?,?)",
                         (first, day + (joules % 7), now, joules, 10, 1.0, "{}"))
    p.conn.commit()
    got = p.get_sessions()
    assert {r["first_timestamp"] for r in got} == {big}              # <0.5kWh and >6 months dropped
    assert len(got) == 2 and got[0]["cost_by_tariff"] == "{}"


def test_session_helpers_and_user_settings(cs, gs):
    p = cs()
    assert p.timestamp_text(0) == real_datetime.datetime.fromtimestamp(0).strftime("%Y-%m-%d %H:%M:%S")
    assert p.timestamp_hhmm(3600 * 5) == real_datetime.datetime.fromtimestamp(3600 * 5).strftime("%H%M")
    assert p.get_user_settings()[0]["type"] == "tariff"
    assert json.loads(cs.mod.chargersessionClassPlugin.pluginParamSpec["tariff"]["default"])[0]["cost"] == 0.27048


def test_session_migrates_v4_table(gs, tmp_path, monkeypatch):
    import lib.chargersession as mod
    db = tmp_path / "s.db"
    monkeypatch.setattr(mod.chargersessionClassPlugin, "SESSION_DB_FILE", str(db))
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE session_v4 (first_timestamp, day_timestamp, last_timestamp, joules, "
                 "seconds_charged, cost)")
    conn.execute("INSERT INTO session_v4 VALUES (100, 50, 200, 7, 3, 1.5)")
    conn.commit(); conn.close()
    p = mod.chargersessionClassPlugin({})
    assert p.cursor.execute("SELECT first_timestamp,last_timestamp,day_timestamp,joules,seconds_charged,"
                            "cost,cost_by_tariff FROM session_v5").fetchall() == [(100, 200, 50, 7, 3, 1.5, "")]
    assert p.cursor.execute("SELECT name FROM sqlite_master WHERE name='session_v4'").fetchall() == []


# =============================== openeoConfig =====================================
@pytest.fixture
def cfgmod(tmp_path, monkeypatch):
    import openeoConfig
    d = tmp_path / "etc"
    d.mkdir()
    cls = openeoConfig.openeoConfigClass
    monkeypatch.setattr(cls, "CONFIG_DIR", str(d) + "/")
    monkeypatch.setattr(cls, "DB_FILE", str(d / "config.db"))
    monkeypatch.setattr(cls, "JSON_FILE", str(d / "config.json"))
    return openeoConfig, d


def test_config_defaults_only_for_missing_modules(cfgmod):
    mod, d = cfgmod
    db = mod.openeoConfigClass({"switch": {"enabled": True}, "cloud": {"enabled": False}})
    assert db.get("switch", "enabled") == 1 and db.get("cloud", "enabled") == 0
    db.set("switch", "enabled", False)
    db2 = mod.openeoConfigClass({"switch": {"enabled": True}})       # module exists: default NOT reapplied
    assert db2.get("switch", "enabled") == 0
    assert db2.changed is True


def test_config_get_set_dict_exists(cfgmod):
    mod, _ = cfgmod
    db = mod.openeoConfigClass({})
    assert db.get("m") is None and db.get("m", "k") is None and db.get("m", "k", "dflt") == "dflt"
    assert not db.exists("m")
    db.set("m", "a", "1")
    db.set("m", {"b": "2", "c": 3.5})
    assert db.exists("m") and db.get("m") == {"a": "1", "b": "2", "c": 3.5}
    assert db.get("m", "c") == 3.5 and db.dict() == {"m": {"a": "1", "b": "2", "c": 3.5}}
    db.set("m", "a", "9")
    assert db.get("m", "a") == "9"
    db.changed = False
    db.set("m", "z", "1", triggerModuleReonfigure=False)
    assert db.changed is False
    assert "[m] a = 9" in str(db)


def test_config_change_log_hides_secrets_and_private_keys(cfgmod):
    mod, _ = cfgmod
    db = mod.openeoConfigClass({})
    db.set("homeassistant", "mqtt_password", "hunter22")
    db.set("homeassistant", {"authtoken": "TOKEN", "mqtt_host": "h"})
    db.set("configserver", "_admin_password_hash", "scrypt$secrethash")
    db.set("homeassistant", "mqtt_host", "h2")
    log = db.logget()
    assert "hunter22" not in log and "TOKEN" not in log and "secrethash" not in log
    assert "Config update homeassistant:mqtt_password=********" in log
    assert "Config update homeassistant:authtoken=********" in log
    assert "Config update homeassistant:mqtt_host=h2" in log
    assert "_admin_password_hash" not in log


def test_config_log_write_get_purge(cfgmod):
    mod, _ = cfgmod
    db = mod.openeoConfigClass({})
    db.logwrite("hello")
    assert "hello" in db.logget()
    db.cursor.execute("INSERT INTO log VALUES (?, ?)", (int(time.time()) - 10 ** 6, "ancient"))
    db.conn.commit()
    db.logpurge()
    assert "ancient" not in db.logget() and "hello" in db.logget()


def test_config_json_file_loaded_once_and_renamed(cfgmod):
    mod, d = cfgmod
    (d / "config.json").write_text(json.dumps({"switch": {"amps": 20}, "cloud": {"authtoken": "T"}}))
    db = mod.openeoConfigClass({})
    assert db.get("switch", "amps") == 20 and db.get("cloud", "authtoken") == "T"
    assert not (d / "config.json").exists() and (d / "config.json_loaded").exists()
    assert "T" not in db.logget() or "authtoken=********" in db.logget()


def test_config_bad_json_file_is_ignored(cfgmod):
    mod, d = cfgmod
    (d / "config.json").write_text("{not json")
    db = mod.openeoConfigClass({})
    assert db.dict() == {} and (d / "config.json").exists()


def test_config_log_ttl_from_chargeroptions(cfgmod):
    mod, _ = cfgmod
    assert mod.openeoConfigClass({}).LOG_PURGE_TTL == 3600 * 24
    db = mod.openeoConfigClass({"chargeroptions": {"log_purge_ttl": 99}})
    db2 = mod.openeoConfigClass({})
    assert db2.LOG_PURGE_TTL == 99


def test_config_migrates_v1_table(cfgmod):
    mod, d = cfgmod
    conn = sqlite3.connect(str(d / "config.db"))
    conn.execute("CREATE TABLE configuration (module TEXT, key TEXT, value)")
    conn.execute("INSERT INTO configuration VALUES ('switch','amps',16)")
    conn.execute("INSERT INTO configuration VALUES ('switch','note','hi')")
    conn.commit(); conn.close()
    db = mod.openeoConfigClass({})
    assert db.get("switch", "amps") == 16 and db.get("switch", "note") == "hi"
    assert db.cursor.execute("SELECT name FROM sqlite_master WHERE name='configuration'").fetchall() == []


def test_config_creates_missing_directory_owned_by_pi(tmp_path, monkeypatch):
    import openeoConfig
    cls = openeoConfig.openeoConfigClass
    target = tmp_path / "newetc"
    monkeypatch.setattr(cls, "CONFIG_DIR", str(target) + "/")
    monkeypatch.setattr(cls, "DB_FILE", str(target) + "/config.db")
    monkeypatch.setattr(cls, "JSON_FILE", str(target) + "/config.json")
    chowned = []
    monkeypatch.setattr(openeoConfig, "getpwnam", lambda n: (n, "x", 1000))
    monkeypatch.setattr(openeoConfig, "getgrnam", lambda n: (n, "x", 1001))
    monkeypatch.setattr(openeoConfig.os, "chown", lambda p, u, g: chowned.append((p, u, g)))
    cls({})
    assert target.is_dir() and chowned == [(str(target) + "/", 1000, 1001)]


@pytest.mark.xfail(reason="delete() never commits, so the removal is invisible to other connections "
                          "(and is lost if the process stops before the next commit)", strict=True)
def test_config_delete_is_durable(cfgmod):
    mod, d = cfgmod
    db = mod.openeoConfigClass({})
    db.set("m", "k", "v")
    db.delete("m", "k")
    other = sqlite3.connect(str(d / "config.db"))
    assert other.execute("SELECT count(*) FROM configuration_v2 WHERE module='m'").fetchone() == (0,)


def test_config_delete_visible_on_same_connection(cfgmod):
    mod, _ = cfgmod
    db = mod.openeoConfigClass({})
    db.set("m", "k", "v")
    db.delete("m", "k")
    assert db.get("m", "k") is None


# =============================== util ==========================================
def test_restart_python_closes_files_then_execs(monkeypatch):
    import util
    closed, execs = [], []

    class P:
        def open_files(self): return [types.SimpleNamespace(fd=7)]
        def connections(self): return [types.SimpleNamespace(fd=8), types.SimpleNamespace(fd=9)]

    monkeypatch.setattr(util.psutil, "Process", lambda pid: P())
    monkeypatch.setattr(util.os, "close", lambda fd: closed.append(fd) or (_ for _ in ()).throw(OSError("x")) if fd == 8 else closed.append(fd))
    monkeypatch.setattr(util.os, "execl", lambda *a: execs.append(a))
    monkeypatch.setattr(util.sys, "argv", ["openeo.py", "--x"])
    util.restart_python()
    assert closed == [7, 8, 9]                    # a failing close does not stop the restart
    assert execs and execs[0][1:] == (util.sys.executable, "openeo.py", "--x")


def test_restart_python_survives_psutil_failure(monkeypatch):
    import util
    execs = []
    monkeypatch.setattr(util.psutil, "Process", lambda pid: (_ for _ in ()).throw(RuntimeError("no")))
    monkeypatch.setattr(util.os, "execl", lambda *a: execs.append(a))
    util.restart_python()
    assert len(execs) == 1


def _run_result(stdout="", returncode=0, stderr=""):
    return types.SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def test_net_bind_capability_already_set(monkeypatch):
    import util
    calls = []
    monkeypatch.setattr(util.shutil, "which", lambda n: "/usr/bin/python3")
    monkeypatch.setattr(util.os.path, "realpath", lambda p: "/usr/bin/python3.11")
    monkeypatch.setattr(util.subprocess, "run",
                        lambda argv, **k: calls.append(argv) or _run_result("/usr/bin/python3.11 cap_net_bind_service=eip"))
    monkeypatch.setattr(util, "restart_python", lambda: calls.append("restart"))
    util.ensure_net_bind_capability()
    assert calls == [["getcap", "/usr/bin/python3.11"]]


def test_net_bind_capability_applied_then_restarts(monkeypatch):
    import util
    calls = []
    monkeypatch.setattr(util.shutil, "which", lambda n: "/usr/bin/python3")
    monkeypatch.setattr(util.os.path, "realpath", lambda p: "/usr/bin/python3.11")
    monkeypatch.setattr(util.subprocess, "run", lambda argv, **k: calls.append(argv) or _run_result(""))
    monkeypatch.setattr(util, "restart_python", lambda: calls.append("restart"))
    util.ensure_net_bind_capability()
    assert calls[1] == ["sudo", "setcap", "CAP_NET_BIND_SERVICE=+eip", "/usr/bin/python3.11"]
    assert calls[-1] == "restart"


def test_net_bind_capability_failures(monkeypatch):
    import util
    monkeypatch.setattr(util.shutil, "which", lambda n: None)
    with pytest.raises(RuntimeError, match="python3 not found"):
        util.ensure_net_bind_capability()
    monkeypatch.setattr(util.shutil, "which", lambda n: "/usr/bin/python3")
    monkeypatch.setattr(util.os.path, "realpath", lambda p: p)
    results = iter([_run_result(""), _run_result("", 1, "denied\n")])
    monkeypatch.setattr(util.subprocess, "run", lambda argv, **k: next(results))
    with pytest.raises(RuntimeError, match="setcap failed: denied"):
        util.ensure_net_bind_capability()


# =============================== globalState (real file) ===========================
def test_global_state_defaults_cloud_off():
    """globalState.py runs I/O at import, so read its default config statically."""
    import ast
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "globalState.py")
    tree = ast.parse(open(path).read())
    defaults = next(ast.literal_eval(n.value) for n in tree.body
                    if isinstance(n, ast.Assign) and n.targets[0].id == "defaultConfig")
    assert defaults["cloud"] == {"enabled": False}
    assert defaults["configserver"] == {"enabled": True} and defaults["homeassistant"] == {"enabled": False}
