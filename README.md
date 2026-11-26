# TrueBlock

TrueBlock is an advanced, high-performance Android ad-blocking, privacy protection, and traffic routing application powered by a local VpnService, dynamic DNS engine, and optional MITM TLS proxy.

## Key Features

- **Local DNS Sinkhole & Router**: Operates entirely on-device without remote VPN dependencies.
- **DoH / Plain DNS Support**: Configurable upstream DNS (Cloudflare, Google, AdGuard, Quad9, Mullvad, or custom) with fallback and recursive bootstrap resolution.
- **Per-Network Rules**: Separate DNS & DoH configurations for Wi-Fi and Cellular (Mobile Data) interfaces.
- **MITM HTTPS Interception (Optional)**:
  - Deep-packet inspection for full URL blocking.
  - Cosmetic element hiding via CSS injection into HTML streams.
  - Tracker query parameter stripper (`$removeparam` / ClearURLs).
  - WebSocket tracker stubs.
- **Application Routing & Proxy**:
  - Raw TCP & UDP traffic routing via custom user-space IPv4 L3 router (`TunL3Router`).
  - SOCKS5 and HTTP upstream proxy support with per-app granular inclusion.
  - Application bypass whitelist.
- **Live Traffic Activity & Analytics**:
  - Live raw stream, grouped domain view, and intercepted HTTPS URLs view.
  - 24-hour request distribution charts and tracker stripping counters.
- **Quick Settings Tile**: One-tap toggle directly from the Android status bar.

## Tech Stack & Architecture

- **Language**: Kotlin 2.0+
- **UI**: Jetpack Compose & Material 3
- **Storage**: Room (SQLite) with Paging 3
- **Networking & Cryptography**: BouncyCastle (X.509 generation), OkHttp 4
- **Target OS**: Android 15 (API 35), Min SDK 35

## Building

```bash
./gradlew assembleRelease
```

The output APK will be generated at `app/build/outputs/apk/release/app-release.apk`.

## CI / CD

Releases are automatically tested, built, and published using GitHub Actions upon pushing git tags matching `v*`.
