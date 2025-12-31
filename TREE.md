# Repository tree description

## Root

- `A/` — Placeholder or legacy directory.
- `app/` — Android application module.
- `build.gradle.kts` — Root Gradle build configuration.
- `Compilation/` — Build or compilation artifacts.
- `Get/` — Temporary or downloaded resources.
- `gradle/` — Gradle wrapper support files.
- `gradle/wrapper/gradle-wrapper.jar` — Gradle wrapper executable.
- `gradle/wrapper/gradle-wrapper.properties` — Gradle wrapper configuration.
- `gradle.properties` — Global Gradle properties.
- `gradlew` — Unix Gradle wrapper launcher.
- `gradlew.bat` — Windows Gradle wrapper launcher.
- `java_pid*.hprof` — JVM heap dumps (debug artifacts).
- `LICENSE` — GNU Affero General Public License v3.0.
- `README.md` — Project overview and documentation.
- `Run/` — Runtime or execution artifacts.
- `SECURITY.md` — Security disclosure policy.
- `settings.gradle.kts` — Gradle project settings.
- `Task/` — Task notes or working directory.
- `tests/` — Test scripts and audit outputs.
- `torcontrol/` — Embedded Tor control protocol code.

---

## app/

- `app/build.gradle.kts` — Android app module build configuration.

### app/src/debug

- `AndroidManifest.xml` — Debug-only Android manifest.
- `java/.../audit/KeystoreAuditReceiver.kt` — Debug receiver auditing keystore state.

### app/src/main

- `AndroidManifest.xml` — Main application manifest.

#### Core application

- `AppGraph.kt` — Manual dependency graph and service wiring.
- `EntrechatApp.kt` — Application initialization and global state.
- `EntrechatServiceManager.kt` — Orchestration of Tor and messaging services.
- `MainActivity.kt` — Main entry activity.
- `Identity/IdentityManager.kt` — Identity lifecycle and key management.

#### config/

- `HeadersConfig.kt` — Protocol and HTTP header definitions.
- `LimitsConfig.kt` — Security and size limits.
- `NetworkConfig.kt` — Network-related constants.
- `ProtocolConfig.kt` — Messaging protocol parameters.
- `RetryPolicy.kt` — Retry and backoff rules.
- `TorConfig.kt` — Tor runtime configuration.

#### crypto/

- `BlobCryptoImpl.kt` — Binary payload encryption helper.
- `CryptoService.kt` — Cryptographic service interface.
- `CryptoServiceImpl.kt` — Cryptographic service implementation.
- `DbPassphraseProvider.kt` — Database passphrase provider interface.
- `KeystorePinDbPassphraseProvider.kt` — Keystore-backed DB passphrase provider.
- `KeyStoreProvider.kt` — Android keystore abstraction.
- `KeyStoreProviderImpl.kt` — Android keystore implementation.
- `PgpEncryptorBc.kt` — OpenPGP encryption using Bouncy Castle.
- `PgpEngineBc.kt` — OpenPGP engine implementation.
- `PgpKeyGenBc.kt` — OpenPGP key generation.
- `PgpKeyLoader.kt` — OpenPGP key loading utilities.
- `PinKdf.kt` — PIN-based key derivation.

#### db/

- `ContactDao.kt` — Contact database access object.
- `ContactEntity.kt` — Contact table entity.
- `DatabaseFactory.kt` — Database initialization logic.
- `EntrechatDatabase.kt` — Room database definition.
- `IdentityDao.kt` — Identity database access object.
- `IdentityEntity.kt` — Identity table entity.
- `InviteDao.kt` — Invite database access object.
- `InviteEntity.kt` — Invite table entity.
- `MessageDao.kt` — Message database access object.
- `MessageEntity.kt` — Message table entity.

#### debug/

- `RuntimeFile.kt` — Debug-only runtime file access helper.

#### network/

- `CryptoResult.kt` — Cryptographic operation result wrapper.
- `HttpResult.kt` — HTTP request result abstraction.
- `HttpStatuses.kt` — HTTP status constants.
- `IncomingMessageHandler.kt` — Interface for inbound message handling.
- `IncomingMessageHandlerImpl.kt` — Validation and decryption of inbound messages.
- `IncomingMessageResult.kt` — Result of inbound message processing.
- `LocalHttpJsonClient.kt` — Loopback HTTP JSON client.
- `LocalMessageServer.kt` — Local HTTP server for inbound Tor messages.
- `MessageRepository.kt` — Message persistence abstraction.
- `MessageRepositoryRoom.kt` — Room-backed message repository.
- `OutgoingMessageSender.kt` — Outbound message sender.
- `PgpEngine.kt` — Protocol-facing PGP abstraction.
- `RemoteMessageClient.kt` — Client for remote peer communication.
- `ReplayProtection.kt` — Replay attack protection interface.
- `ReplayProtectionImpl.kt` — Nonce-based replay protection.
- `TorHttpClient.kt` — HTTP client routed through Tor.

#### tor/

- `TorForegroundService.kt` — Foreground service keeping Tor alive.
- `TorManager.kt` — Tor lifecycle interface.
- `TorManagerImpl.kt` — Tor process and state management.
- `TorState.kt` — Tor state machine model.
- `TorStatusReceiver.kt` — Tor status broadcast receiver.

#### ui/

##### chat/

- `ChatActivity.kt` — Chat screen controller.
- `ChatAdapter.kt` — RecyclerView adapter for chat messages.
- `ChatRow.kt` — Chat message UI model.

##### common/

- `Ec1QrCodec.kt` — EC1 QR encoding and decoding.
- `Ec2QrCodec.kt` — EC2 QR encoding and decoding.
- `FpFormat.kt` — Fingerprint formatting utilities.
- `Io.kt` — IO helper functions.
- `JsonContactCodec.kt` — JSON contact serialization.

##### contacts/

- `ContactRow.kt` — Contact UI model.
- `ContactsActivity.kt` — Contact list activity.
- `ContactsAdapter.kt` — RecyclerView adapter for contacts.
- `QrContactV1.kt` — QR-based contact exchange format.

##### identity/

- `IdentityActivity.kt` — Identity management UI.

##### options/

- `OptionsActivity.kt` — Application settings UI.

##### qr/

- `QrShowActivity.kt` — QR code display activity.

---

## Resources

- `res/drawable/*.xml` — Vector and shape drawables.
- `res/drawable-nodpi/logo_entrechat.png` — App logo without density scaling.
- `res/layout/*.xml` — Activity and list item layouts.
- `res/mipmap-*/ic_launcher.png` — Launcher icons for all densities.
- `res/themes.xml` — Base theme definition.
- `res/values/colors.xml` — Color definitions.
- `res/values/strings.xml` — Default string resources.
- `res/values/styles.xml` — Style definitions.
- `res/values/themes.xml` — Theme overrides.
- `res/values-fr/strings.xml` — French localization.
- `res/xml/network_security_config.xml` — Android network security policy.

---

## tests/

- `audit_keystore_v1.py` — Automated keystore audit script.
- `audit_out/` — Stored audit outputs and reports.

---

## torcontrol/

- `build.gradle` — Tor control module build configuration.
- `src/main/java/net/freehaven/tor/control/` — Tor control protocol implementation.
