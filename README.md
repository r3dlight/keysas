# Keysas - USB virus cleaning station (WIP)

Warning: This is only a work in progress for now.

# Main features
- Retrieve files from USB or over the network
- Perform multiple checks
    - Run anti-virus check (ClamAV)
    - Run Yara rules
    - Run extensions and size checks

## Project architecture

```
+----------------------------+           +----------------------------+            +--------------------------------+
|                            |           |                            |            |                                |
|         Keysas-in          |           |         Keysas-transit     |            |           Keysas-out           |
|                            |           |                            |            |                                |
|   - Open files             +---------->+   - Run checks on files    +----------->+    - Output file and report    |
|   | Compute file digest    |           |                            |            |                                |
|   - Send file to transit   |           |                            |            |                                |
|                            |           |                            |            |                                |
+----------------------------+           +----------------------------+            +--------------------------------+
```

Files are passed between daemons as file descriptors and using abstract sockets.

