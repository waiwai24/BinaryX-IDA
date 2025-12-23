# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

* Fixed missing callback function detection - now detects function addresses passed as parameters (e.g., `lea rsi, func`)
* Fixed missing tail call detection via JMP instructions (e.g., `jmp func`)
* Added support for data cross-references (dr_O, dr_R) to detect callback patterns
* Extended call instruction detection to include JMP, B, and J instructions for tail calls

### Changed

* Refactored `extract_calls` function to handle both code references (calls) and data references (callbacks)
* Added `is_tail_call_jmp` function to validate JMP instructions as tail calls
* Added new call type "callback" for function pointer references

### Added

* Support for detecting LEA, MOV, ADR, ADRP, and LDR instructions that load function addresses
* Improved call relationship detection for callback-heavy code patterns

## [0.1.0] - 2025-12-23

* First release.

## How to Update This Changelog

When making changes to the project:

1. Add new entries under the "Unreleased" section
2. Use appropriate categories: Added, Changed, Deprecated, Removed, Fixed, Security
3. When releasing a version:
   * Move "Unreleased" entries to a new version section
   * Add release date
   * Create a new empty "Unreleased" section
