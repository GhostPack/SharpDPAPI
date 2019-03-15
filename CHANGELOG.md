# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.1.1] - 2019-03-15

### Added
* **SharpDPAPI.cna** Cobalt Strike aggressor script to automate the usage of SharpDPAPI (from @leechristensen)

### Changed
* Wrapped main in try/catch

### Fixed
* Fixed Policy.vpol parsing to handle the "KSSM" (?) format. Thank you @gentilkiwi :)


## [1.1.0] - 2019-03-14

### Added
* **masterkeys** action
    * decrypts currently reachable master keys (current users or all if elevated) and attempts to decrypt them using a passed {GUI}:SHA1 masterkey lookup table, or a /pvk base64 blob representation of the domain DPAPI backup key
* **credentials** action
    * decrypts currently reachable Credential files (current users or all if elevated) and attempts to decrypt them using a passed {GUI}:SHA1 masterkey lookup table, or a /pvk base64 blob representation of the domain DPAPI backup key
* **vaults** action
    * decrypts currently reachable Vault files (current users or all if elevated) and attempts to decrypt them using a passed {GUI}:SHA1 masterkey lookup table, or a /pvk base64 blob representation of the domain DPAPI backup key
* **triage** action
    * performs all triage actions (currently vault and credential)
* CHANGELOG

### Changed
* modified the argument formats for the **backupkey** command
* retructured files so code isn't in a single file
* revamped README


## [1.0.0] - 2018-08-22

* Initial release
