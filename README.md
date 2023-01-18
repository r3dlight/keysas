# Keysas - USB virus cleaning station

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

Files are passed between daemon in sockets as file descriptors.
The sockets are located in:
- /run/keysas/sock_in : sockets between keysas-in and keysas-transit
- /run/keysas/sock_out : sockets between keysas-transit and keysas-out

