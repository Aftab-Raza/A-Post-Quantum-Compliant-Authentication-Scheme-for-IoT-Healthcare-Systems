# SKEBA

Implementation of the IEEE paper:

**A Post-Quantum Compliant Authentication Scheme for IoT Healthcare Systems**

## Project Status

- [x] Environment Setup
- [x] GitHub Repository
- [x] Project Architecture
- [x] Registration Phase
- [x] Login Phase
- [x] Mutual Authentication
- [x] Access Control Phase
- [x] Integration Tests
- [ ] Attack Simulation
- [ ] Performance Evaluation

## Current Progress

- [x] Environment
- [x] Crypto Layer
- [x] Registration
- [x] Login Steps 1-4
- [x] Mutual Authentication
- [x] Access Control
- [x] Integration Test
- [ ] Attack Simulation
- [ ] Performance Evaluation

## Run

```powershell
$env:PYTHONPATH='.'
$env:PYTHONIOENCODING='utf-8'
python tests/test_full_protocol.py
```

On Linux, the wrapper uses `native/libsaber.so` when it can be loaded.
On Windows, the wrapper falls back to a development KEM backend so the
protocol can be tested without a Windows Saber shared library.

## demonstration

Run the interactive demo from the project root:

```powershell
python main.py
```

The demo asks for a live user ID, password, and medical IoT device ID, then
shows:

- Setup phase
- Live user registration
- Smart-card personalization evidence
- Wrong-password rejection
- Live login
- Mutual authentication
- Replay attack rejection
- Access control
- User/device session key agreement

For a quick non-interactive rehearsal, run:

```powershell
python main.py --demo --user-id aftab_raza --device-id icu-monitor-01
```

## Replay Attack Demonstration

Run the standalone replay attack simulation:

```powershell
python attacks\replay.py
```

The simulation performs:

- Register a user
- Login normally
- Capture the `LoginMessage`
- Logout
- Replay the old `LoginMessage`

Expected result:

```text
[OK] Observed: authentication failed
[OK] Server rejection reason: Replay attack detected: login message already used.
[OK] Conclusion: replay attack prevented
```

Regression test:

```powershell
python -m tests.test_replay_attack
```
