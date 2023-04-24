# Keysas Minifilter

A windows minifilter and application to validate files on USB sticks.

## Minifilter Driver
### Building
The driver can be built with VS 2022.

### Installation
The driver can be installed with a Right click on the INF file in `./minifilter/x64/[Debug|Release]/KeysasDriver`.

To check the installation use:
- `sc.exe query KeysasDriver`
- or `pnputil /enum-drivers | Select-String -Pattern KeysasDriver -Context 2,4`

### Loading/Removing
In a Powershell as Administrator.
Start the driver with `sc.exe start KeysasDriver`.
Stop the driver with `sc.exe stop KeysasDriver`.
Remove it with `sc.exe delete KeysasDriver` and `pnputil -d oem*.inf` with the appropriate number.

## Rust application