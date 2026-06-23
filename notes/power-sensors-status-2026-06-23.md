# Power, Charging, and Sensors Status

Date: 2026-06-23 Australia/Sydney

Scope: Power/Sensors/Charging subagent. This note uses only read-only evidence
from the current repository logs, workflow docs, kernel config snapshots, and
the external read-only mainline `lmi/HARDWARE_SUPPORT.md`.

## Current Evidence

Current postmarketOS v27 evidence:

- `logs/full-hardware-check-v27-persistent-20260623.redacted.txt` shows
  `/sys/class/power_supply` entries for `battery`, `bms`,
  `bq2597x-standalone`, `dc`, `main`, `pc_port`, `usb`, and `batt_verify`.
- The same log records battery reporting as present and healthy:
  `status=Full`, `capacity=100`, `voltage_now=4389148`,
  `current_now=2929`, `charge_full=4064000`, `temp=245`, `health=Good`,
  `present=1`.
- `logs/post-reboot-stability-v27-20260623.redacted.txt` confirms the same
  power-supply shape after reboot, with battery still `Full`, `100`, `Good`,
  and present.
- Charger-related nodes are visible but not functionally validated:
  `bq2597x-standalone` reports `present=0`, `dc` reports `present=0` and
  `online=0`, `pc_port` reports `online=1`, and `usb` reports `present=1` but
  `online=0` in the captured state.
- Thermal reporting is broad: the full hardware log lists many thermal zones,
  including CPU, GPU, PMIC, WLAN, video, camera, BMS, and battery zones. Battery
  and BMS temperatures are readable at `24500` milli-C in thermal and `245` in
  power_supply units.
- IIO enumeration currently proves PMIC ADC presence only:
  `pm8150l vadc`, `pm8150b vadc`, and `pm8150 vadc`.
- Sensor-adjacent kernel threads and nodes exist (`SENSORS_CNTL`,
  `SENSORS_DATA`, `SENSORS_CMD`, `SENSORS_DCI`, `/dev/subsys_slpi`,
  `soc:qcom,msm-ssc-sensors`, `soc:qmi-ts-sensors`), but there is no evidence
  yet for usable accelerometer, gyroscope, magnetometer, light, or proximity
  sensor devices.

External mainline `HARDWARE_SUPPORT.md` evidence:

- Battery/charging is marked partial support there: PM8150B Type-C/TCPM,
  SMB5 charger, and gen4 fuel gauge expose USB input, battery capacity,
  voltage, current, temperature, and status.
- That external path also mentions `charge_behaviour`, `input_current_limit`,
  `current_max`, and a conservative `lmi-power` service, but those are not yet
  proven in the current postmarketOS v27 logs.
- Sensors are still marked pending there and need SDSP remoteproc, signed SDSP
  firmware, and a sensor userspace stack.

Kernel/config evidence:

- Current config contains `CONFIG_POWER_SUPPLY=y`, `CONFIG_QPNP_SMB5=y`,
  `CONFIG_QPNP_FG_GEN4=y`, `CONFIG_BQ2597X_CHARGE_PUMP=y`,
  `CONFIG_TYPEC=y`, `CONFIG_USB_PD_POLICY=y`, `CONFIG_QPNP_USB_PDPHY=y`,
  `CONFIG_IIO=y`, `CONFIG_QCOM_SPMI_ADC5=y`, and `CONFIG_SENSORS_SSC=y`.
- Current config still has `# CONFIG_REMOTEPROC is not set`, which is a likely
  blocker for the external SDSP/sensors path.

## Verified vs Gaps

Verified in current postmarketOS:

- Battery presence, capacity, voltage, current, charge-full, temperature, and
  health are readable.
- USB/PC-port power-supply nodes are exposed.
- BMS and battery thermal zones are readable.
- PMIC VADC IIO devices are exposed.

Not verified:

- Real charging current negotiation across charger types.
- Whether `online=0` on `usb` with `pc_port online=1` is expected for the
  current gadget/cable state.
- Long-duration capacity/temperature stability.
- `charge_behaviour`, `input_current_limit`, `current_max`, or other limit
  controls in the current postmarketOS image.
- BQ2597x charge pump use; captured state reports not present/disabled.
- 33 W Xiaomi private fast charging.
- Hardware bypass/direct-power behavior.
- Motion/environment sensors via IIO/input/sensor stack.

## Minimal Next Test

Run the new read-only probe over the existing SSH path:

```sh
ssh lmi@172.16.42.1 'sh -s' < scripts/38_power_sensors_probe.sh \
  > logs/power-sensors-probe-v27-20260623.txt
```

Then redact any identifiers before committing a log:

```sh
cp logs/power-sensors-probe-v27-20260623.txt \
  logs/power-sensors-probe-v27-20260623.redacted.txt
```

The probe should answer:

- Which power-supply properties are exposed for each node.
- Whether charge limiting controls exist in current postmarketOS.
- Which Type-C/USB-PD sysfs nodes exist.
- Which IIO channels are readable, not just which IIO devices exist.
- Whether any non-PMIC sensors enumerate through IIO or input.
- Which thermal zones have empty or invalid readings.

## Risks

- Do not write power-supply attributes until their semantics are known on this
  downstream kernel; some charger attributes directly affect charging state.
- Do not claim sensors are supported from `CONFIG_SENSORS_SSC`, SLPI nodes, or
  kernel threads alone.
- Do not import the external `lmi-power` behavior blindly into postmarketOS
  without first proving compatible sysfs controls and failure behavior.
- Do not treat BQ2597x presence in config as functional fast charging; the
  captured runtime state shows `present=0`.

## Files Changed

- Added `scripts/38_power_sensors_probe.sh`, a read-only power, charging,
  IIO, thermal, and sensor evidence collector.
- Added this note.
