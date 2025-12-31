# Entrechat

**Entrechat** is an Android peer-to-peer messaging application focused on synchronous messaging.

## Design choice: strict synchrony

Entrechat is intentionally designed as a **strictly synchronous** messaging system.

Messages are only delivered when both peers are online and explicitly engaged
in a session. There is no message queueing, no deferred delivery, and no
background communication.

This design choice reduces persistent state, limits metadata accumulation,
and makes the exposure surface explicit at the time of communication.


---

## Core properties

- **Transport**: Tor hidden services only
- **Encryption**: OpenPGP end-to-end
- **Identity**: Local keypair generated on first launch
- **Discovery**: Offline QR codes (EC1 / EC2)
- **Storage**: Local encrypted database (Room + SQLCipher)
- **Threat model**: Passive and active network observer
- **Telemetry**: None

---

## Architecture overview

Each device runs:

- A Tor instance in a foreground service
- A local HTTP server bound to `localhost`
- A persistent OpenPGP identity

Messages are:

- Encrypted and signed client-side
- Transported exclusively over Tor hidden services
- Replay-protected using nonces
- Stored locally only

There is **no central infrastructure**.

---

## Repository structure

- `app/` — Android application (Kotlin)
- `torcontrol/` — Embedded Tor control protocol implementation


## Build requirements

- Android Studio Hedgehog or newer
- Android SDK 26+
- Java 17 (tested with OpenJDK 17.0.17)
- Gradle 8.7 (no Gradle wrapper included)

## Build

```bash
./gradlew assembleDebug
```

## Install on a device:

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## Run (development)

1. Launch the app.
2. A local identity and OpenPGP keypair are generated.
3. Tor starts in a foreground service.
4. Exchange contacts using QR codes.
5. Messages are delivered once both peers are reachable over Tor.

---

## Security notes

* Debug builds expose additional audit and diagnostic surfaces.
* Debug builds must not be used for real-world communication.
* Replay protection is enforced at message ingress.
* Private keys are protected using the Android Keystore.

---

## Development status

This codebase is **under active development** and is not production-hardened.

Testing coverage is constrained by the hardware currently available to the developer.
Behavior may vary significantly across devices, ROMs, and Android versions.

---

## Tested devices

* **realme 70T** (RMX5313)
  Build: `RMX5313GDPR_15_A.59`
  Kernel: `5.15.178-android13-8-00006-g0c6055fd2d8b-ab13363910`

* **OnePlus One** (IN2023)
  Build: `13.1.0.591(EX01)`

Other devices and ROMs may require adjustments, particularly regarding Tor integration, background execution limits, and OEM networking behavior.

Tor stability may vary depending on network quality, connectivity changes, device hardware, OEM power management policies, and Android background restrictions.

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

* You may use, modify, and redistribute this software.
* If you run a modified version as a network service, you must provide the corresponding source code.
* See the `LICENSE` file for full terms.

---

## Disclaimer

This project is provided for research and experimentation purposes only.
No warranty is provided.
Use at your own risk.

## Support the project

If you find this project useful and want to support its development, you can contribute via Bitcoin:

**Bitcoin (BTC)**  
`bc1qaj3lcwwgdkz4xpex04n2vhkuwclurkth7waq6r`

Support helps cover development time, testing hardware, and long-term maintenance.


```

