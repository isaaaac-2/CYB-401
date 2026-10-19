# CYB-401 ASSIGNMENT
## ISAAC AKINYEMI RUN/CYB/23/15383

## CVE-2014-0160 - HEARTBLEED
### Brief overview
Heartbleed is a security bug in some outdated versions of the OpenSSL cryptography library, which is a widely used implementation of the Transport Layer Security (TLS) protocol. It was introduced into the software in 2012 and publicly disclosed in April 2014. Heartbleed could be exploited regardless of whether the vulnerable OpenSSL instance is running as a TLS server or client. It resulted from improper input validation (due to a missing bounds check) in the implementation of the TLS heartbeat extension. Thus, the bug's name derived from heartbeat. The vulnerability was classified as a buffer over-read,[7] a situation where more data can be read than should be allowed. (Wikipedia contributors, 2026).

### Description
The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug. CVE-2014-0160 does not allow unrestricted access to memory on the targeted host, a successful exploit does leak information from memory locations which have the potential to contain particularly sensitive information, e.g., cryptographic keys and passwords. Theft of this information could enable other attacks on the information system, the impact of which would depend on the sensitivity of the data and functions of that system ((OpenSSL “Heartbleed” Vulnerability (CVE-2014-0160) | CISA, 2014). The CVSS score for this bug came at a concerning 7.5, the vulnerability was a very high 

### KILL CHAIN

| Kill Chain Stage | How Heartbleed Fits | Defensive Break Point |
|---|---|---|
| **1. Reconnaissance** | Attackers scanned the internet for servers running vulnerable OpenSSL versions. | Asset inventory, external attack-surface monitoring |
| **2. Weaponization** | Public proof-of-concept tools made the flaw easy to exploit, so little skill was needed. | Patch management, vulnerability intelligence feeds |
| **3. Delivery** | Crafted heartbeat requests were sent over normal TLS connections on port 443, which blends in with legitimate traffic. | Anomaly detection on heartbeat messages, IDS/IPS signatures |
| **4. Exploitation** | The missing length check let the server leak adjacent memory. | Patching to OpenSSL 1.0.1g or later, or disabling the heartbeat extension |
| **5. Installation** | Heartbleed itself did not install persistence. Stolen credentials or keys could enable later access. | Endpoint monitoring, credential rotation |
| **6. Command & Control** | Leaked session tokens or keys could let attackers authenticate as legitimate users without needing C2 channels. | Session invalidation, anomalous login detection |
| **7. Actions on Objectives** | Attackers could steal data, impersonate services by using stolen private keys, or decrypt past traffic if keys lacked forward secrecy. | Key revocation and reissuance, forward secrecy, data-loss monitoring |

### PATCH
The fix for CVE-2014-0160 (Heartbleed) was the release of **OpenSSL 1.0.1g** on April 7, 2014.

The vulnerability existed because OpenSSL’s implementation of the TLS/DTLS heartbeat extension failed to validate the length of the payload provided by the client. In a valid heartbeat request, the payload length is included in the header. The server was supposed to copy only that many bytes from its memory to the response. However, the code blindly copied the length specified in the header without checking if it exceeded the actual payload size. This allowed an attacker to request more data than was sent, causing the server to leak up to 64 KB of its own memory.

### The Code Patch

The fix was applied to the file `ssl/t1_lib.c` in the OpenSSL source code. Specifically, the function `dtls1_process_heartbeat()` was modified.

#### The Vulnerable Code (Before)
In OpenSSL 1.0.1 through 1.0.1f, the code looked roughly like this:

```c
static int dtls1_process_heartbeat(SSL *s, unsigned int pt, unsigned char *p, unsigned int len)
{
    unsigned char *buffer, *bp;
    unsigned int l = 0, bp_len = 0;
    int ret;

    /* Read type and payload length first */
    if (1 + 2 + 16 > len)
        return -1;
    
    // ... payload type is read ...
    
    /* Payload */
    bp = p + 1;
    bp_len = (p[1] << 8) | p[2]; // <-- This length comes from the client
    
    // ... some checks ...

    /* Allocate memory for the response */
    buffer = OPENSSL_malloc(1 + 2 + bp_len + 16);
    bp = buffer;

    /* Copy the payload into the response */
    memcpy(bp, p, bp_len); // <-- BUG: Copies bp_len bytes, which can be larger than the actual payload sent
    
    /* ... add padding and return ... */
}
```

The critical flaw was that `bp_len` was taken directly from the client's packet header without verifying that the actual data received (`len`) was at least `bp_len` bytes long.

#### The Fixed Code (After, in 1.0.1g)
The fix added a strict check to ensure the payload length in the header does not exceed the actual length of the message received.

```c
static int dtls1_process_heartbeat(SSL *s, unsigned int pt, unsigned char *p, unsigned int len)
{
    unsigned char *buffer, *bp;
    unsigned int l = 0, bp_len = 0;
    int ret;

    /* Read type and payload length first */
    if (1 + 2 + 16 > len)
        return -1;
    
    // ... payload type is read ...
    
    /* Payload */
    bp = p + 1;
    bp_len = (p[1] << 8) | p[2];

    /*
     * Abort if payload length is larger than the message actually
     * received. This is the key fix.
     */
    if (1 + 2 + bp_len + 16 > len)
        return -1; // <-- NEW CHECK ADDED HERE

    /* Allocate memory for the response */
    buffer = OPENSSL_malloc(1 + 2 + bp_len + 16);
    bp = buffer;

    /* Copy the payload into the response */
    memcpy(bp, p, bp_len); 

    /* ... add padding and return ... */
}
```

### Key Changes in OpenSSL 1.0.1g

1.  **Bounds Check:** The primary fix was adding the condition `if (1 + 2 + bp_len + 16 > len) return -1;`. This ensures that the server never attempts to read more data from memory than was actually provided in the heartbeat request.
2.  **No Behavioral Changes:** The fix was minimal and did not change the protocol behavior for valid requests. It only prevented the out-of-bounds read.

### Why Was 1.0.1g the Only Fix?

-   **OpenSSL 1.0.1f and earlier:** Vulnerable.
-   **OpenSSL 1.0.1g:** Fixed.
-   **OpenSSL 1.0.2 and later:** The heartbeat extension was **disabled by default** and later removed entirely in OpenSSL 1.1.0, preventing similar vulnerabilities in that extension.


### References

1. NVD-CVE-2014-0160. (n.d.). https://nvd.nist.gov/vuln/detail/cve-2014-0160
2. Blackduck, Inc. https://www.blackduck.com/. (2025, March 7). Heartbleed bug. https://heartbleed.com/
3. OpenSSL “Heartbleed” vulnerability (CVE-2014-0160) | CISA. (2014, April 8). Cybersecurity and Infrastructure Security Agency CISA. https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160
4. Wikipedia contributors. (2026, September 23). Heartbleed. Wikipedia. https://en.wikipedia.org/wiki/Heartbleed
5. Sragan, & Sragan. (2014, April 11). How to fix the Heartbleed bug. CSO Online. https://www.csoonline.com/article/544892/vulnerabilities-heartbleed-cve-2014-0160-an-overview-of-the-problem-and-the-resources-needed-to.html
6. NVD - Home. (n.d.). https://nvd.nist.gov/vuln/detail/CVE-2014-0160
