# Firmware Update Advisories / 固件更新机制漏洞通告合集

Security advisories for **firmware update mechanism vulnerabilities** in embedded / IoT
devices — missing signature verification, unsigned update acceptance, update-chain
design flaws, and related exposures discovered during firmware update-graph research.

面向嵌入式 / IoT 设备**固件更新机制漏洞**的安全通告合集：更新链路签名验证缺失、
无签名固件被接受、更新设计缺陷，及相关联暴露面。来源于固件更新图恢复研究。

> Coordinated disclosure: advisories are published here per each report's disclosure
> window after vendor notification. 协调披露：通告按各自披露窗口在厂商通报后发布。

## Advisories

| Date | Product | Vulnerability | CVSS 3.1 | Links |
|---|---|---|---|---|
| 2026-11-17 | D-Link DIR-816 A1 (CN, fw v1.01CNB04) | Missing firmware signature verification → persistent root code execution (CWE-345); factory-default telnet credentials (CWE-798); process-global login state (CWE-668) | 6.8 / 8.0 / 8.8 | [advisory (EN)](D-Link-DIR-816-A1/2026-11-17-D-Link-DIR-816-A1-unsigned-firmware-update-advisory-EN.md) · [PDF](D-Link-DIR-816-A1/2026-11-17-D-Link-DIR-816-A1-unsigned-firmware-update-advisory-EN.pdf) |

## Layout

One directory per product line; each advisory directory is self-contained
(markdown, PDF, evidence screenshots together, so relative image links render).
