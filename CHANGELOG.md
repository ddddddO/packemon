# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed
- **eureka** Removed custom color settings (black background, white text) from Ethernet form to maintain consistency with other forms in the TUI generator. The form now uses the default blue background like IPv4, TCP, and other forms.
- **eureka** Removed unused tcell import from form_ethernet.go after color settings removal. The package now compiles successfully without any errors.
