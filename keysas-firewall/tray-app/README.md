# Keysas Minifilter

A windows minifilter and application to validate files on USB sticks.

## Minifilter Driver
### Building
The driver can be built with VS 2022.

### Installation
The driver can be installed with a Right click on the INF file in `./minifilter/x64/[Debug|Release]/KeysasMinifilter`.

To check the installation use:
- `sc.exe query KeysasMinifilter`
- or `pnputil /enum-drivers | Select-String -Pattern KeysasMinifilter -Context 2,4`

### Loading/Removing
In a Powershell as Administrator.
Start the driver with `sc.exe start KeysasMinifilter`.
Stop the driver with `sc.exe stop KeysasMinifilter`.
Remove it with `sc.exe delete KeysasMinifilter` and `pnputil -d oem*.inf` with the appropriate number.

## Rust application