# Design decisions

Things eFa-next deliberately does not build, and why.

| Not built | Why |
| --- | --- |
| Headless browser to open links | A full browser on the mail gateway is a large attack surface and costs much memory per check; the link check at the click (2) and the feeds of URLs (12) cover the same risk. |
| VirusTotal | Sends hashes or files to a US service; no EU basis for it, and the free API limits are too low for a gateway. |
| CrowdSec | Shares addresses of the own clients with a central service; the own lockout (B6), address harvesting (9i) and blocklists (9m) do the job locally. |
| OCR of images | Slow, memory-hungry and of little use against current phishing; QR codes are decoded instead (5x). |
| Deep protocol tests of postscreen | They delay every new sender by a retry; pregreet and the weighted blocklists catch most bots without delay. |
| An own sandbox | A sandbox on the mail host itself would run the malware next to the mail; a self-hosted sandbox elsewhere can be connected (14). |
| AI writing style analysis, image content analysis, browser isolation, awareness training, large file transfer, M365/Google APIs | Out of scope of a resource-light, privacy-first gateway (plan 6.0.0.5). |
