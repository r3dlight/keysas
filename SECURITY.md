# Reporting a vulnerability

Please report security vulnerabilities to one of the contributors. You will receive a response within a few days. If the vulnerability is confirmed, we will release a patch as soon as possible.


# Security audit for v2.5

  - This code has undergone a security audit conducted by [Amossys](https://www.amossys.fr/) an external company specialized in cybersecurity. Since this audit, all security patches have been applied to the current v2.5.
  
| Component | Technical facts | Patched facts | Unpatched facts |
|-----------------|-----------------|-----------------|----------|
| Keysas-lib   |   10   | 9   | 1 |
| Keysas-core   |   7   | 9   | 1 |
| Keysas-io   |   8   | 8   | 0 |
| Keysas-admin   |   7   | 7   | 0 |

Remaining facts are :
- Keysas-lib: Hybrid signatures stay optionnal in generated reports and must be explicitly set up by the administrator.
- Keysas-core: Landlock and Seccomp sandboxes do not crash the daemons if not supported by the host.
- Required toolchain is nightly (05/2025)