# Changelog

## [Unreleased]

## Added

- Require Cleep auth enabled to start tunnel
- Open the tunnel over HTTPS only, disable request inspection, and keep the agent interface on localhost
- Publish the tunnel public address while it is open
- Show tunnel get-info result with config-table (tunnel fields + connection/duration metrics)

## Changed

- General app improvements
- Defer agent/tunnel bootstrap out of blocking `_on_start` (keeps bus responsive at boot)

### Fixed

- Fix some issues
- Log a useful message when ``ngrok service start`` fails with empty stdout/stderr (journal or returncode)

## [1.1.0] - 2025-11-20

## Added

- Add action to update binary (binary auto update command)

## Updated

- ngrok binary (v3.33.0)

## [1.0.1] - 2024-11-22

## Updated

- ngrok binary (v3.18.0)
- Fix and improve service handling

## [1.0.0] - 2024-10-23

### Added

- First release
