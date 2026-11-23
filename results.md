# Evaluation results

- Attacker IP: `192.168.200.130`   Target: `192.168.200.131`
- Clock offset applied: -0.2573 s (round trip 0.0235 s)
- Trials: 18 (12 attack, 6 negative, 0 evasion)   Gap between trials: 90 s
- Alerts in this run's time window: 12

## Detection (attack trials)

| Trial type | Rule | Trials | Detected | Rate | Min s | Median s | Mean s | Max s |
|---|---|---|---|---|---|---|---|---|
| syn_flood | R-03 | 3 | 3 | 100% | 0.0 | 0.0 | 0.1 | 0.3 |
| null_scan | R-05 | 3 | 3 | 100% | 0.0 | 0.0 | 0.0 | 0.1 |
| xmas_scan | R-05 | 3 | 3 | 100% | 0.0 | 0.0 | 0.0 | 0.1 |
| icmp_flood | R-04 | 3 | 3 | 100% | 0.3 | 0.4 | 0.6 | 1.1 |

## False alarms (negative trials)

| Trial type | Trials | Quiet | False alarms | Rules that fired |
|---|---|---|---|---|
| syn_burst | 3 | 3 | 0 | - |
| ping_normal | 3 | 3 | 0 | - |

## Summary

- **Detection rate (true positive rate):** 12/12 attack trials = 100%
- **Missed attacks (false negatives):** 0
- **False-alarm rate:** 0/6 negative trials = 0%
- **Alert precision:** 12 of 12 alerts raised were the expected detection of a real attack = 100%
- **Unexplained alerts** (outside any trial, or from another IP): 0

## Trial sanity checks

- Every timed trial ran for a plausible length.

## Capture health

- 04:42:29  **monitor-stopped**    -> affects trial(s): none of the capture-dependent trials

## Reading these numbers honestly

- Each attack type was run only 3 to 3 times, so a rate of 100% means "detected in every trial run", not "100% accurate".
- Zero misses in 12 trials only shows the true miss rate is probably below about 25% (95% confidence, the "rule of three"). It does not show it is zero.
- Zero false alarms in 6 negative trials likewise only bounds the true false-alarm rate below about 50%.
- Alert times are stored to the whole second, so a latency under one second shows as 0.0. Read it as "under 1 second", not as zero. Longer latencies are accurate to about +/- 1 second.
- Latency runs from the moment the attack command started, not from the first malicious packet. For brute force it is dominated by how fast the attack tool produces failed logins.
- These results describe a quiet, isolated lab network and attacks the rules were designed to catch. They say nothing about false alarms on a busy network or about attackers who adapt.
