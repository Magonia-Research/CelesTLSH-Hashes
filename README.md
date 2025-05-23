# TLSH Hash Datafeed for Open-Source Red Teaming and Pentesting Tools

## Overview

This datafeed leverages the **TLSH (Trend Micro Locality Sensitive Hash)** algorithm to provide a robust similarity-based hashing mechanism for monitoring and analyzing open-source (FOSS) red teaming and penetration testing tools hosted on GitHub.

### What is TLSH?

[TLSH](https://github.com/trendmicro/tlsh) is described by Trend Micro as:

> TLSH is a fuzzy matching library. Given a byte stream with a minimum length of 50 bytes, TLSH generates a hash value which can be used for similarity comparisons. Similar objects will have similar hash values, enabling the detection of similar objects by comparing their hash values.

Unlike traditional hashing algorithms (e.g., SHA256 or MD5) which are designed for exact file matching, TLSH is specifically engineered to measure file similarity. The algorithm computes a "distance" score, where smaller values indicate closer similarity and larger scores signify greater differences. This unique capability makes TLSH particularly valuable for threat detection and hunting, as it allows analysts to identify variations of malicious or suspicious tools.

---

## Datafeed Purpose

The primary goal of this project is to provide an actionable, continuously updated feed of TLSH hashes for prominent FOSS red teaming and penetration testing tools. By sourcing data directly from GitHub repositories, this feed ensures that the information is accurate and up to date. 

### Use Cases

- **Threat Hunting**: Leverage TLSH distances to identify modified or derivative versions of known tools used in adversarial operations.
- **Detection Engineering**: Establish baseline similarity thresholds to reduce false positives while improving detection accuracy for suspicious binaries or scripts.
- **Incident Response**: Quickly assess whether artifacts discovered in an environment are likely variants of known tools.

---

## Advantages of TLSH for Threat Detection

The TLSH algorithm offers several key benefits for cybersecurity practitioners:

- **Similarity-Based Detection**: Enables the identification of tool variations, repackaged binaries, or lightly modified malware.
- **Flexible Distance Thresholds**: Fine-tune detection sensitivity based on acceptable false positive rates, as shown in the reference table below.
- **Lightweight and Scalable**: Designed for fast computation and easy integration into security workflows.

Below is a table illustrating the relationship between TLSH distance and false positive rates, aiding practitioners in selecting appropriate thresholds for their use cases.

| Score  | FP rate    | Detect rate |
|--------|------------|-------------|
| < 300  | 79.30%     | 98.8%       |
| < 250  | 69.06%     | 98.8%       |
| < 200  | 50.10%     | 98.8%       |
| < 150  | 24.33%     | 98.1%       |
| < 100  | 6.43%      | 94.5%       |
| < 90   | 4.49%      | 92.3%       |
| < 80   | 2.93%      | 89.0%       |
| < 70   | 1.84%      | 83.6%       |
| < 60   | 1.09%      | 76.0%       |
| < 50   | 0.52%      | 65.3%       |
| < 40   | 0.07%      | 49.6%       |
| < 30   | 0.00181%   | 32.2%       |
| < 20   | 0.00181%   | 17.3%       |
| < 10   | 0.00181%   | 6.4%        |

---

## Project Scope

This initiative focuses on tracking a wide array of open-source red teaming and pentesting tools, directly sourcing files and release artifacts from their official GitHub repositories. The hash data is continuously updated and made available to assist the cybersecurity community in detection and analysis efforts.

By using TLSH, this project bridges the gap between traditional file hashing techniques and modern fuzzy matching capabilities, providing a powerful resource for security teams and researchers alike.

---

## Get Involved

Contributions and feedback are welcome! If you have suggestions for additional tools to monitor or improvements to the feed, feel free to submit an issue or pull request on the project’s repository.
