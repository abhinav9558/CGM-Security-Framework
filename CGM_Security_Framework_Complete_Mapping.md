# Complete Threat-to-Control Mapping: AI-Enabled CGM Security Framework

> **Supplementary Material** for "A Security Framework for AI-Enabled Continuous Glucose Monitoring: Translating FDA Guidance into Actionable Controls"
>
> Venkata Sai Abhinav Piratla, Sajal Bhatia, and Sahaj Saxena
>
> CyberAI 2026 Conference

---

## Overview

This document provides the **complete mapping artifact** for the five-layer security framework described in the accompanying paper. It contains:

- **27 threats** across five categories (Control-Theoretic, Software, Hardware, Communication, AI-Specific)
- **38 FDA requirements** from the June 2025 Premarket Cybersecurity Guidance (30) and January 2025 AI-DSF Draft Guidance (8)
- **MITRE ATT&CK technique mappings** spanning ICS, Enterprise, and ATLAS matrices
- **NIST SP 800-53 Rev. 5 control mappings** with specific control identifiers
- **Implementation priority scores** using FMEA-adapted Severity × Likelihood × Detectability methodology

### Mapping Rubric

Each threat-to-FDA requirement mapping is scored on a three-point relevance scale:

| Score | Label | Definition |
|-------|-------|------------|
| 2 | Direct | Regulatory text explicitly names or addresses the threat class |
| 1 | Indirect | Requirement addresses a broader category encompassing the threat |
| 0 | None | No meaningful relationship (excluded from mappings below) |

### Priority Scoring

- **Severity (S):** Clinical impact (1-5); 5 = life-threatening
- **Likelihood (L):** Exploitation probability (1-5); 5 = demonstrated in field
- **Detectability (D):** Detection difficulty (1-5); 5 = undetectable
- **RPN:** S × L × D (range: 1–125)
- **Complexity (C):** Implementation effort (1-5); 1 = software-only, 5 = research-grade
- **Quadrant:** Q1 (Quick Win: RPN≥40, C≤3), Q2 (Strategic: RPN≥40, C>3), Q3 (Efficiency: RPN<40, C≤3), Q4 (Long-term: RPN<40, C>3)

---

## 1. Complete Threat Catalog (27 Threats)

### 1.1. Control-Theoretic Threats (4)

#### T-001: Glucose-Insulin Model Manipulation

- **Category:** Control-Theoretic (CT)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 4
- **Description:** Adversary manipulates physiological glucose-insulin model parameters used by closed-loop controllers, causing systematically incorrect insulin delivery calculations.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0836 | Modify Parameter | ICS |
| T0855 | Unauthorized Command Message | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SI-7, SA-11, CA-2, AU-2

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-006 | Security Risk Assessment with Traceability | 2 (Direct) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| AI-003 | AI Risk Assessment | 2 (Direct) | Risk assessment specifically addressing AI/ML threats including data poisoning, ... |
| AI-005 | AI Performance Validation | 1 (Indirect) | Pre-deployment validation of AI model performance across representative patient ... |
| CYB-024 | Cybersecurity Testing Evidence | 1 (Indirect) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |

**Priority:** S=5, L=2, D=3, RPN=30, C=4 → **Q4**

---

#### T-002: MPC Model Inaccuracy

- **Category:** Control-Theoretic (CT)
- **Severity:** High
- **Primary Framework Layer:** Layer 4
- **Description:** Inaccurate glucose-insulin dynamics in Model Predictive Control (MPC) controllers lead to dangerous insulin delivery due to parameter estimation errors or deliberate manipulation.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0836 | Modify Parameter | ICS |
| T0880 | Loss of Safety | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SI-7, SA-11, CA-8, AU-6

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-006 | Security Risk Assessment with Traceability | 2 (Direct) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-019 | Code/Data/Execution Integrity | 1 (Indirect) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| AI-003 | AI Risk Assessment | 2 (Direct) | Risk assessment specifically addressing AI/ML threats including data poisoning, ... |
| AI-005 | AI Performance Validation | 2 (Direct) | Pre-deployment validation of AI model performance across representative patient ... |
| AI-007 | AI Performance Monitoring | 1 (Indirect) | Continuous real-world performance monitoring with defined metrics, alert thresho... |

**Priority:** S=5, L=3, D=3, RPN=45, C=4 → **Q2**

---

#### T-003: Setpoint Manipulation

- **Category:** Control-Theoretic (CT)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 3
- **Description:** Adversary alters target glucose setpoint to unsafe levels, causing the control algorithm to drive blood glucose to hypoglycemic or hyperglycemic ranges.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0836 | Modify Parameter | ICS |
| T0831 | Manipulation of Control | ICS |

**NIST SP 800-53 Rev. 5 Controls:** AC-3, AC-6, SI-7, AU-2, IA-2

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-016 | Authentication Controls | 2 (Direct) | Multi-factor authentication for all user and device interactions, including devi... |
| CYB-017 | Authorization and Access Controls | 2 (Direct) | Role-based access control (RBAC) policies governing patient, clinician, caregive... |
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-024 | Cybersecurity Testing Evidence | 1 (Indirect) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |

**Priority:** S=5, L=3, D=2, RPN=30, C=3 → **Q3**

---

#### T-004: Control Algorithm Exploitation

- **Category:** Control-Theoretic (CT)
- **Severity:** High
- **Primary Framework Layer:** Layer 4
- **Description:** Exploiting vulnerabilities in PID/MPC/RL control algorithms through crafted inputs that cause oscillatory or divergent insulin delivery behavior.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0836 | Modify Parameter | ICS |
| T0882 | Theft of Operational Information | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SA-11, SI-7, CA-8, SC-7

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| AI-003 | AI Risk Assessment | 2 (Direct) | Risk assessment specifically addressing AI/ML threats including data poisoning, ... |
| AI-005 | AI Performance Validation | 2 (Direct) | Pre-deployment validation of AI model performance across representative patient ... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-008 | Security by Design Principles | 1 (Indirect) | Application of defense-in-depth, least privilege, fail-secure, and economy of me... |

**Priority:** S=4, L=2, D=4, RPN=32, C=5 → **Q4**

---

### 1.2. Software Threats (8)

#### T-005: Cloud API Exploitation

- **Category:** Software (SW)
- **Severity:** High
- **Primary Framework Layer:** Layer 2
- **Description:** Exploiting vulnerabilities in cloud service APIs to gain unauthorized access to patient glucose data, modify dosing parameters, or disrupt cloud-based analytics.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1190 | Exploit Public-Facing Application | Enterprise |
| T0883 | Unauthorized Access | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-7, AC-4, SI-3, RA-5, SA-11

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-016 | Authentication Controls | 2 (Direct) | Multi-factor authentication for all user and device interactions, including devi... |
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-024 | Cybersecurity Testing Evidence | 2 (Direct) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |
| CYB-009 | Defense-in-Depth Architecture | 1 (Indirect) | Multiple independent layers of security controls ensuring no single point of fai... |
| CYB-020 | Data Confidentiality and Privacy | 1 (Indirect) | Protection of patient glucose data, device identifiers, and personal health info... |

**Priority:** S=4, L=3, D=3, RPN=36, C=3 → **Q3**

---

#### T-006: Insufficient Authentication

- **Category:** Software (SW)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 3
- **Description:** Unauthorized device connections and command injection due to weak, default, or missing authentication mechanisms, as demonstrated in the 2019 Medtronic MiniMed advisory.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1078 | Valid Accounts | Enterprise |
| T0812 | Default Credentials | ICS |

**NIST SP 800-53 Rev. 5 Controls:** IA-2, IA-5, AC-7, AC-14, IA-3

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-016 | Authentication Controls | 2 (Direct) | Multi-factor authentication for all user and device interactions, including devi... |
| CYB-006 | Security Risk Assessment with Traceability | 2 (Direct) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-024 | Cybersecurity Testing Evidence | 2 (Direct) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |
| CYB-017 | Authorization and Access Controls | 1 (Indirect) | Role-based access control (RBAC) policies governing patient, clinician, caregive... |
| CYB-008 | Security by Design Principles | 1 (Indirect) | Application of defense-in-depth, least privilege, fail-secure, and economy of me... |

**Priority:** S=5, L=5, D=3, RPN=75, C=2 → **Q1**

---

#### T-007: Firmware Code Injection

- **Category:** Software (SW)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 1
- **Description:** Malicious code injection to alter device behavior by replacing or modifying firmware, enabling persistent compromise of insulin pump or CGM controller functionality.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1542 | Pre-OS Boot | Enterprise |
| T0857 | System Firmware | ICS |

**NIST SP 800-53 Rev. 5 Controls:** CM-2, CM-3, SI-7, SA-10, SC-34

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-023 | Vulnerability Patching Capability | 2 (Direct) | Devices must support postmarket software/firmware updates and patches to address... |
| CYB-011 | Software Bill of Materials (SBOM) | 2 (Direct) | Manufacturers must provide an SBOM in machine-readable format (SPDX or CycloneDX... |
| CYB-012 | Secure Firmware Update Mechanism | 2 (Direct) | Authenticated and integrity-verified over-the-air (OTA) firmware update mechanis... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |

**Priority:** S=5, L=3, D=4, RPN=60, C=4 → **Q2**

---

#### T-008: Session Hijacking

- **Category:** Software (SW)
- **Severity:** High
- **Primary Framework Layer:** Layer 3
- **Description:** Hijacking authenticated sessions between CGM system components (sensor-controller, controller-pump, device-cloud) to issue unauthorized commands.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1563 | Remote Service Session Hijacking | Enterprise |
| T0830 | Manipulation of View | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-23, AC-12, IA-11, AU-2

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-016 | Authentication Controls | 2 (Direct) | Multi-factor authentication for all user and device interactions, including devi... |
| CYB-018 | Cryptographic Controls | 1 (Indirect) | Validated cryptographic algorithms for data at rest and in transit, including TL... |
| CYB-019 | Code/Data/Execution Integrity | 1 (Indirect) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-014 | Secure Communication Protocols | 1 (Indirect) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |

**Priority:** S=4, L=3, D=3, RPN=36, C=3 → **Q3**

---

#### T-009: Replay Attacks

- **Category:** Software (SW)
- **Severity:** High
- **Primary Framework Layer:** Layer 2
- **Description:** Retransmitting previously valid CGM readings or insulin commands to cause inappropriate insulin delivery or mask actual glucose levels.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1557 | Adversary-in-the-Middle | Enterprise |
| T0830 | Manipulation of View | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-23, AU-2, SC-13, SC-8

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-018 | Cryptographic Controls | 2 (Direct) | Validated cryptographic algorithms for data at rest and in transit, including TL... |
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-014 | Secure Communication Protocols | 1 (Indirect) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-021 | Event Detection and Logging | 1 (Indirect) | Logging of security-relevant events including authentication attempts, configura... |

**Priority:** S=4, L=4, D=3, RPN=48, C=2 → **Q1**

---

#### T-010: Denial of Service (DoS)

- **Category:** Software (SW)
- **Severity:** High
- **Primary Framework Layer:** Layer 2
- **Description:** Overwhelming device communication channels or cloud resources to disrupt real-time glucose monitoring and insulin delivery control loops.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1498 | Network Denial of Service | Enterprise |
| T0814 | Denial of Service | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-5, CP-7, SI-4, SC-7

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-022 | Resiliency and Recovery | 2 (Direct) | Device ability to maintain essential safety functions (safe-mode insulin deliver... |
| CYB-014 | Secure Communication Protocols | 2 (Direct) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-009 | Defense-in-Depth Architecture | 1 (Indirect) | Multiple independent layers of security controls ensuring no single point of fai... |
| CYB-008 | Security by Design Principles | 1 (Indirect) | Application of defense-in-depth, least privilege, fail-secure, and economy of me... |

**Priority:** S=4, L=4, D=3, RPN=48, C=1 → **Q1**

---

#### T-011: Man-in-the-Middle (MITM) Attacks

- **Category:** Software (SW)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 2
- **Description:** Intercepting and altering data in transit between CGM sensor, controller, insulin pump, and cloud services to modify glucose readings or insulin commands.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1557 | Adversary-in-the-Middle | Enterprise |
| T0830 | Manipulation of View | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-8, SC-12, SC-23, SC-13

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-018 | Cryptographic Controls | 2 (Direct) | Validated cryptographic algorithms for data at rest and in transit, including TL... |
| CYB-014 | Secure Communication Protocols | 2 (Direct) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-021 | Event Detection and Logging | 1 (Indirect) | Logging of security-relevant events including authentication attempts, configura... |

**Priority:** S=5, L=3, D=3, RPN=45, C=4 → **Q2**

---

#### T-012: Privilege Escalation

- **Category:** Software (SW)
- **Severity:** High
- **Primary Framework Layer:** Layer 3
- **Description:** Escalating from limited user access to administrative or clinical-level privileges on the CGM mobile application or cloud management portal.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1068 | Exploitation for Privilege Escalation | Enterprise |
| T0890 | Exploitation for Privilege Escalation | ICS |

**NIST SP 800-53 Rev. 5 Controls:** AC-6, AC-5, AU-2, SI-7, CM-7

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-017 | Authorization and Access Controls | 2 (Direct) | Role-based access control (RBAC) policies governing patient, clinician, caregive... |
| CYB-016 | Authentication Controls | 2 (Direct) | Multi-factor authentication for all user and device interactions, including devi... |
| CYB-024 | Cybersecurity Testing Evidence | 1 (Indirect) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |
| CYB-010 | Least Privilege Implementation | 2 (Direct) | Users, processes, and system components operate with only the minimum privileges... |

**Priority:** S=4, L=3, D=3, RPN=36, C=2 → **Q3**

---

### 1.3. Hardware Threats (5)

#### T-013: CGM Sensor Failures

- **Category:** Hardware (HW)
- **Severity:** High
- **Primary Framework Layer:** Layer 1
- **Description:** Signal loss or calibration drift disrupting closed-loop glucose control, including premature sensor failures leading to loss of glucose monitoring data.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0814 | Denial of Service | ICS |
| T0826 | Loss of Availability | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SI-4, PE-14, CP-2, MA-2

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-022 | Resiliency and Recovery | 2 (Direct) | Device ability to maintain essential safety functions (safe-mode insulin deliver... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-028 | Postmarket Cybersecurity Monitoring | 1 (Indirect) | Active monitoring for new cybersecurity threats, vulnerabilities in third-party ... |
| CYB-024 | Cybersecurity Testing Evidence | 1 (Indirect) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |

**Priority:** S=4, L=4, D=2, RPN=32, C=3 → **Q3**

---

#### T-014: Sensor Calibration Manipulation

- **Category:** Hardware (HW)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 1
- **Description:** Deliberately altering CGM sensor calibration parameters to produce systematically inaccurate glucose readings, leading to incorrect insulin dosing.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0836 | Modify Parameter | ICS |
| T0885 | Loss of Engineering Control | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SI-7, PE-3, AU-2, CM-3

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-015 | Physical Security Controls | 1 (Indirect) | Hardware-level protections including tamper detection, tamper evidence, secure e... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-021 | Event Detection and Logging | 1 (Indirect) | Logging of security-relevant events including authentication attempts, configura... |

**Priority:** S=5, L=2, D=3, RPN=30, C=4 → **Q4**

---

#### T-015: Physical Tampering

- **Category:** Hardware (HW)
- **Severity:** High
- **Primary Framework Layer:** Layer 1
- **Description:** Physical access enables settings modification, data extraction, firmware dumping, or hardware component replacement on CGM/pump devices.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0879 | Damage to Property | ICS |
| T0831 | Manipulation of Control | ICS |

**NIST SP 800-53 Rev. 5 Controls:** PE-3, PE-6, MP-4, PE-4

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-015 | Physical Security Controls | 2 (Direct) | Hardware-level protections including tamper detection, tamper evidence, secure e... |
| CYB-019 | Code/Data/Execution Integrity | 1 (Indirect) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-008 | Security by Design Principles | 1 (Indirect) | Application of defense-in-depth, least privilege, fail-secure, and economy of me... |

**Priority:** S=3, L=2, D=2, RPN=12, C=3 → **Q3**

---

#### T-016: Battery/Power Depletion

- **Category:** Hardware (HW)
- **Severity:** Medium
- **Primary Framework Layer:** Layer 1
- **Description:** Deliberately draining device battery through repeated unnecessary BLE connection requests or computation-intensive operations to disable glucose monitoring.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0826 | Loss of Availability | ICS |
| T0814 | Denial of Service | ICS |

**NIST SP 800-53 Rev. 5 Controls:** PE-11, CP-2, SI-4, SC-5

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-022 | Resiliency and Recovery | 2 (Direct) | Device ability to maintain essential safety functions (safe-mode insulin deliver... |
| CYB-009 | Defense-in-Depth Architecture | 1 (Indirect) | Multiple independent layers of security controls ensuring no single point of fai... |
| CYB-008 | Security by Design Principles | 1 (Indirect) | Application of defense-in-depth, least privilege, fail-secure, and economy of me... |

**Priority:** S=3, L=3, D=2, RPN=18, C=4 → **Q4**

---

#### T-017: Hardware Supply Chain Compromise

- **Category:** Hardware (HW)
- **Severity:** High
- **Primary Framework Layer:** Layer 1
- **Description:** Compromised hardware components introduced during manufacturing or distribution, including counterfeit sensors or tampered microcontrollers with backdoor access.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1195 | Supply Chain Compromise | Enterprise |
| T0862 | Supply Chain Compromise | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SR-3, SR-5, SR-11, SA-12, PE-3

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-005 | Third-Party Component Security | 2 (Direct) | Security assessment and ongoing monitoring of all third-party software, firmware... |
| CYB-011 | Software Bill of Materials (SBOM) | 2 (Direct) | Manufacturers must provide an SBOM in machine-readable format (SPDX or CycloneDX... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-019 | Code/Data/Execution Integrity | 1 (Indirect) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |

**Priority:** S=4, L=2, D=4, RPN=32, C=5 → **Q4**

---

### 1.4. Communication Threats (6)

#### T-018: BLE Eavesdropping

- **Category:** Communication (COM)
- **Severity:** High
- **Primary Framework Layer:** Layer 2
- **Description:** Passive interception of Bluetooth Low Energy communications between CGM sensor and controller to capture glucose readings, device identifiers, and protocol details.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1040 | Network Sniffing | Enterprise |
| T0842 | Network Sniffing | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-8, SC-13, AC-18, SC-40

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-018 | Cryptographic Controls | 2 (Direct) | Validated cryptographic algorithms for data at rest and in transit, including TL... |
| CYB-020 | Data Confidentiality and Privacy | 2 (Direct) | Protection of patient glucose data, device identifiers, and personal health info... |
| CYB-014 | Secure Communication Protocols | 2 (Direct) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-008 | Security by Design Principles | 1 (Indirect) | Application of defense-in-depth, least privilege, fail-secure, and economy of me... |

**Priority:** S=3, L=4, D=2, RPN=24, C=2 → **Q3**

---

#### T-019: BLE Pairing Exploitation

- **Category:** Communication (COM)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 2
- **Description:** Exploiting BLE pairing vulnerabilities (e.g., SweynTooth, KNOB attack) to establish unauthorized connections with CGM devices and inject commands.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0860 | Wireless Compromise | ICS |
| T0812 | Default Credentials | ICS |

**NIST SP 800-53 Rev. 5 Controls:** IA-3, SC-8, AC-18, SC-13

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-016 | Authentication Controls | 2 (Direct) | Multi-factor authentication for all user and device interactions, including devi... |
| CYB-018 | Cryptographic Controls | 2 (Direct) | Validated cryptographic algorithms for data at rest and in transit, including TL... |
| CYB-014 | Secure Communication Protocols | 2 (Direct) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-024 | Cybersecurity Testing Evidence | 1 (Indirect) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |

**Priority:** S=4, L=4, D=3, RPN=48, C=3 → **Q1**

---

#### T-020: Wireless Replay

- **Category:** Communication (COM)
- **Severity:** High
- **Primary Framework Layer:** Layer 2
- **Description:** Capturing and retransmitting valid BLE/RF messages to re-issue previously authorized commands, such as insulin delivery instructions or sensor calibration updates.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1557 | Adversary-in-the-Middle | Enterprise |
| T0887 | Wireless Sniffing | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-23, AU-2, SC-13, SC-8

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-018 | Cryptographic Controls | 2 (Direct) | Validated cryptographic algorithms for data at rest and in transit, including TL... |
| CYB-019 | Code/Data/Execution Integrity | 2 (Direct) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-014 | Secure Communication Protocols | 1 (Indirect) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-021 | Event Detection and Logging | 1 (Indirect) | Logging of security-relevant events including authentication attempts, configura... |

**Priority:** S=4, L=4, D=3, RPN=48, C=2 → **Q1**

---

#### T-021: RF Jamming/Interference

- **Category:** Communication (COM)
- **Severity:** High
- **Primary Framework Layer:** Layer 2
- **Description:** Disrupting wireless BLE or Wi-Fi communications between CGM components through radio frequency jamming, causing loss of real-time glucose data transmission.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T0814 | Denial of Service | ICS |
| T1498 | Network Denial of Service | Enterprise |

**NIST SP 800-53 Rev. 5 Controls:** SC-5, CP-7, SC-40, PE-18

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-022 | Resiliency and Recovery | 2 (Direct) | Device ability to maintain essential safety functions (safe-mode insulin deliver... |
| CYB-014 | Secure Communication Protocols | 2 (Direct) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-009 | Defense-in-Depth Architecture | 1 (Indirect) | Multiple independent layers of security controls ensuring no single point of fai... |

**Priority:** S=3, L=3, D=2, RPN=18, C=4 → **Q4**

---

#### T-022: DNS/Cloud Redirect

- **Category:** Communication (COM)
- **Severity:** Medium
- **Primary Framework Layer:** Layer 2
- **Description:** Redirecting cloud communications to malicious servers through DNS spoofing or ARP poisoning, enabling interception of patient data or injection of false analytics.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1071 | Application Layer Protocol | Enterprise |
| T1584 | Compromise Infrastructure | Enterprise |

**NIST SP 800-53 Rev. 5 Controls:** SC-20, SC-21, SC-22, SI-3

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-018 | Cryptographic Controls | 2 (Direct) | Validated cryptographic algorithms for data at rest and in transit, including TL... |
| CYB-014 | Secure Communication Protocols | 2 (Direct) | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pair... |
| CYB-019 | Code/Data/Execution Integrity | 1 (Indirect) | Mechanisms ensuring integrity of firmware, software, and data including secure b... |
| CYB-020 | Data Confidentiality and Privacy | 1 (Indirect) | Protection of patient glucose data, device identifiers, and personal health info... |

**Priority:** S=3, L=2, D=3, RPN=18, C=3 → **Q3**

---

#### T-023: Cloud Infrastructure Compromise

- **Category:** Communication (COM)
- **Severity:** High
- **Primary Framework Layer:** Layer 2
- **Description:** Compromising the cloud backend services that process CGM analytics, store patient data, and host AI/ML inference models for glucose prediction.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| T1190 | Exploit Public-Facing Application | Enterprise |
| T0883 | Unauthorized Access | ICS |

**NIST SP 800-53 Rev. 5 Controls:** SC-7, AC-4, SI-3, RA-5, CP-2

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| CYB-016 | Authentication Controls | 2 (Direct) | Multi-factor authentication for all user and device interactions, including devi... |
| CYB-022 | Resiliency and Recovery | 2 (Direct) | Device ability to maintain essential safety functions (safe-mode insulin deliver... |
| CYB-024 | Cybersecurity Testing Evidence | 2 (Direct) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |
| CYB-020 | Data Confidentiality and Privacy | 2 (Direct) | Protection of patient glucose data, device identifiers, and personal health info... |
| CYB-009 | Defense-in-Depth Architecture | 1 (Indirect) | Multiple independent layers of security controls ensuring no single point of fai... |

**Priority:** S=4, L=3, D=4, RPN=48, C=4 → **Q2**

---

### 1.5. AI-Specific Threats (4)

#### T-024: Training Data Poisoning

- **Category:** AI-Specific (AI)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 4
- **Description:** Corrupting training datasets for glucose prediction models by injecting malicious data points, causing systematically biased predictions and unsafe insulin dosing recommendations.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| AML.T0020 | Poison Training Data | ATLAS |

**NIST SP 800-53 Rev. 5 Controls:** CA-2, CA-8, AU-2, SA-11, SI-7

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| AI-003 | AI Risk Assessment | 2 (Direct) | Risk assessment specifically addressing AI/ML threats including data poisoning, ... |
| AI-004 | AI Data Management | 2 (Direct) | Policies and procedures for AI training/validation/test data lifecycle managemen... |
| AI-002 | AI Training Data Documentation | 2 (Direct) | Comprehensive documentation of training data sources, collection methodology, pr... |
| AI-005 | AI Performance Validation | 1 (Indirect) | Pre-deployment validation of AI model performance across representative patient ... |
| CYB-006 | Security Risk Assessment with Traceability | 1 (Indirect) | Risk assessment mapping each identified threat to security controls with documen... |

**Priority:** S=5, L=3, D=5, RPN=75, C=4 → **Q2**

---

#### T-025: Adversarial Evasion

- **Category:** AI-Specific (AI)
- **Severity:** Critical
- **Primary Framework Layer:** Layer 4
- **Description:** Crafting perturbations to glucose sensor inputs or model features that cause the AI prediction model to produce incorrect glucose forecasts while appearing normal to monitoring systems.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| AML.T0043 | Craft Adversarial Data | ATLAS |

**NIST SP 800-53 Rev. 5 Controls:** SI-7, CA-8, SA-11, SI-4

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| AI-003 | AI Risk Assessment | 2 (Direct) | Risk assessment specifically addressing AI/ML threats including data poisoning, ... |
| AI-005 | AI Performance Validation | 2 (Direct) | Pre-deployment validation of AI model performance across representative patient ... |
| CYB-006 | Security Risk Assessment with Traceability | 2 (Direct) | Risk assessment mapping each identified threat to security controls with documen... |
| CYB-024 | Cybersecurity Testing Evidence | 2 (Direct) | Comprehensive testing documentation including vulnerability scanning, static/dyn... |

**Priority:** S=5, L=3, D=5, RPN=75, C=4 → **Q2**

---

#### T-026: Model Inversion/Extraction

- **Category:** AI-Specific (AI)
- **Severity:** Medium
- **Primary Framework Layer:** Layer 4
- **Description:** Extracting proprietary model parameters or inferring private patient training data from the glucose prediction model through repeated queries or side-channel analysis.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| AML.T0024 | Infer Training Data Membership | ATLAS |
| AML.T0044 | Full ML Model Access | ATLAS |

**NIST SP 800-53 Rev. 5 Controls:** SC-28, AC-3, MP-4, SA-8

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| AI-003 | AI Risk Assessment | 2 (Direct) | Risk assessment specifically addressing AI/ML threats including data poisoning, ... |
| AI-004 | AI Data Management | 1 (Indirect) | Policies and procedures for AI training/validation/test data lifecycle managemen... |
| CYB-020 | Data Confidentiality and Privacy | 2 (Direct) | Protection of patient glucose data, device identifiers, and personal health info... |
| AI-001 | AI/ML Algorithm Transparency | 1 (Indirect) | Documentation of AI/ML algorithm design decisions, model architecture, training ... |

**Priority:** S=2, L=2, D=4, RPN=16, C=4 → **Q4**

---

#### T-027: Concept Drift

- **Category:** AI-Specific (AI)
- **Severity:** High
- **Primary Framework Layer:** Layer 4
- **Description:** Gradual degradation of glucose prediction model performance due to changes in patient physiology, sensor characteristics, or data distribution over time, leading to increasingly inaccurate predictions.

**MITRE ATT&CK Techniques:**

| Technique ID | Technique Name | Matrix |
|-------------|----------------|--------|
| AML.T0043 | Craft Adversarial Data | ATLAS |
| AML.T0031 | Erode ML Model Integrity | ATLAS |

**NIST SP 800-53 Rev. 5 Controls:** SI-4, CA-7, SA-11, PM-14

**FDA Requirement Mappings:**

| FDA Req ID | Requirement Name | Score | Rationale |
|-----------|-----------------|-------|-----------|
| AI-007 | AI Performance Monitoring | 2 (Direct) | Continuous real-world performance monitoring with defined metrics, alert thresho... |
| AI-003 | AI Risk Assessment | 2 (Direct) | Risk assessment specifically addressing AI/ML threats including data poisoning, ... |
| AI-006 | AI Monitoring and Drift Detection | 2 (Direct) | Ongoing monitoring for model performance degradation, concept drift, and data di... |
| AI-008 | Predetermined Change Control Plan (PCCP) | 1 (Indirect) | Documentation of anticipated AI model modifications, validation requirements for... |
| CYB-028 | Postmarket Cybersecurity Monitoring | 1 (Indirect) | Active monitoring for new cybersecurity threats, vulnerabilities in third-party ... |

**Priority:** S=4, L=4, D=4, RPN=64, C=4 → **Q2**

---

## 2. Complete FDA Requirement Catalog (38 Requirements)

### 2.1. FDORA Section 524B Statutory Requirements (Mandatory)

| Req ID | Requirement | Source | Description |
|--------|------------|--------|-------------|
| CYB-011 | Software Bill of Materials (SBOM) | FDORA 524B(b)(3) | Manufacturers must provide an SBOM in machine-readable format (SPDX or CycloneDX) including commercial, open-source, and off-the-shelf components with version, supplier, and support status. |
| CYB-023 | Vulnerability Patching Capability | FDORA 524B(b)(2) | Devices must support postmarket software/firmware updates and patches to address cybersecurity vulnerabilities on a reasonably justified regular cycle. |
| CYB-026 | Cybersecurity Management Plan | FDORA 524B(b)(1) | Submission must include a plan addressing postmarket cybersecurity monitoring, vulnerability management, coordinated disclosure, and incident response. |

### 2.2. FDA Guidance Recommended Requirements

| Req ID | Requirement | Source | Description |
|--------|------------|--------|-------------|
| CYB-001 | Threat Modeling | Cybersec. Section IV | Systematic identification of threats using structured methodologies (STRIDE, DREAD, attack trees) appropriate to device architecture and intended use. |
| CYB-002 | Secure Product Development Framework (SPDF) | Cybersec. Section IV-A-1 | Integration of cybersecurity activities throughout the product development lifecycle, from concept to decommissioning. |
| CYB-003 | Security Architecture Documentation | Cybersec. Section IV-B | Comprehensive documentation of security architecture including data flow diagrams, trust boundaries, and cryptographic design decisions. |
| CYB-004 | Trust Boundary Definition | Cybersec. Section IV-C | Explicit identification and documentation of all trust boundaries between system components (sensor, controller, pump, cloud, clinician). |
| CYB-005 | Third-Party Component Security | Cybersec. Section IV-D | Security assessment and ongoing monitoring of all third-party software, firmware, and hardware components integrated into the device. |
| CYB-006 | Security Risk Assessment with Traceability | Cybersec. Section V-A | Risk assessment mapping each identified threat to security controls with documented rationale and traceability throughout the TPLC. |
| CYB-007 | Risk-Benefit Analysis | Cybersec. Section V-B | Analysis demonstrating that cybersecurity risks are mitigated to an acceptable level relative to device benefits and intended use. |
| CYB-008 | Security by Design Principles | Cybersec. Section V-C | Application of defense-in-depth, least privilege, fail-secure, and economy of mechanism principles from initial design through deployment. |
| CYB-009 | Defense-in-Depth Architecture | Cybersec. Section V-D | Multiple independent layers of security controls ensuring no single point of failure compromises overall device security. |
| CYB-010 | Least Privilege Implementation | Cybersec. Section V-E | Users, processes, and system components operate with only the minimum privileges necessary for their intended function. |
| CYB-016 | Authentication Controls | Cybersec. Appendix 1-A | Multi-factor authentication for all user and device interactions, including device-to-device, user-to-device, and clinician-to-cloud authentication. |
| CYB-017 | Authorization and Access Controls | Cybersec. Appendix 1-A | Role-based access control (RBAC) policies governing patient, clinician, caregiver, and administrator access to device functions and data. |
| CYB-018 | Cryptographic Controls | Cybersec. Appendix 1-C | Validated cryptographic algorithms for data at rest and in transit, including TLS 1.3 for cloud communications and AES-CCM for BLE, with documented key lifecycle management. |
| CYB-019 | Code/Data/Execution Integrity | Cybersec. Appendix 1-D | Mechanisms ensuring integrity of firmware, software, and data including secure boot, code signing, and runtime integrity verification. |
| CYB-020 | Data Confidentiality and Privacy | Cybersec. Appendix 1-E | Protection of patient glucose data, device identifiers, and personal health information through encryption, access controls, and data minimization. |
| CYB-021 | Event Detection and Logging | Cybersec. Appendix 1-F | Logging of security-relevant events including authentication attempts, configuration changes, firmware updates, and anomalous device behavior. |
| CYB-022 | Resiliency and Recovery | Cybersec. Appendix 1-G | Device ability to maintain essential safety functions (safe-mode insulin delivery, glucose alerting) under cybersecurity compromise and recover to normal operation. |
| CYB-012 | Secure Firmware Update Mechanism | Cybersec. Section VI-A | Authenticated and integrity-verified over-the-air (OTA) firmware update mechanism with rollback capability and version control. |
| CYB-013 | Update Authentication and Verification | Cybersec. Section VI-B | Cryptographic verification of all software and firmware updates before installation, ensuring updates originate from authorized sources. |
| CYB-014 | Secure Communication Protocols | Cybersec. Section VI-C | Use of validated secure communication protocols (TLS 1.3, BLE Secure Simple Pairing) for all inter-component and external communications. |
| CYB-015 | Physical Security Controls | Cybersec. Section VI-D | Hardware-level protections including tamper detection, tamper evidence, secure element storage, and physical access controls. |
| CYB-024 | Cybersecurity Testing Evidence | Cybersec. Section VII-A | Comprehensive testing documentation including vulnerability scanning, static/dynamic analysis, fuzz testing, and penetration testing results. |
| CYB-025 | Penetration Testing | Cybersec. Section VII-B | Independent third-party penetration testing targeting all attack surfaces including BLE, cloud APIs, mobile applications, and firmware. |
| CYB-027 | Coordinated Vulnerability Disclosure | Cybersec. Section VIII-A | Established process for receiving, evaluating, and responding to cybersecurity vulnerability reports from external researchers. |
| CYB-028 | Postmarket Cybersecurity Monitoring | Cybersec. Section VIII-B | Active monitoring for new cybersecurity threats, vulnerabilities in third-party components, and emerging attack techniques relevant to the device. |
| CYB-029 | Incident Response Plan | Cybersec. Section VIII-C | Documented procedures for responding to cybersecurity incidents, including severity classification, containment, remediation, and regulatory notification. |
| CYB-030 | End-of-Life Planning | Cybersec. Section VIII-D | Plan for device end-of-life including continued security support timelines, data migration, and secure decommissioning procedures. |

### 2.3. AI-DSF Draft Guidance Requirements

| Req ID | Requirement | Source | Description |
|--------|------------|--------|-------------|
| AI-001 | AI/ML Algorithm Transparency | AI-DSF Section V | Documentation of AI/ML algorithm design decisions, model architecture, training methodology, and known limitations for regulatory reviewers. |
| AI-002 | AI Training Data Documentation | AI-DSF Section VI | Comprehensive documentation of training data sources, collection methodology, preprocessing steps, annotation procedures, and demographic representation. |
| AI-003 | AI Risk Assessment | AI-DSF Section VII | Risk assessment specifically addressing AI/ML threats including data poisoning, adversarial inputs, model drift, and algorithmic bias. |
| AI-004 | AI Data Management | AI-DSF Section VIII | Policies and procedures for AI training/validation/test data lifecycle management including provenance tracking, quality assurance, and data integrity. |
| AI-005 | AI Performance Validation | AI-DSF Section IX | Pre-deployment validation of AI model performance across representative patient populations, edge cases, and adversarial conditions. |
| AI-006 | AI Monitoring and Drift Detection | AI-DSF Section X | Ongoing monitoring for model performance degradation, concept drift, and data distribution shifts post-deployment. |
| AI-007 | AI Performance Monitoring | AI-DSF Section XI | Continuous real-world performance monitoring with defined metrics, alert thresholds, and corrective action procedures. |
| AI-008 | Predetermined Change Control Plan (PCCP) | AI-DSF Section XII | Documentation of anticipated AI model modifications, validation requirements for each change type, and conditions requiring new regulatory submission. |

## 3. Threat × FDA Requirement Cross-Reference Matrix

This matrix shows which FDA requirements map to each threat (2 = Direct, 1 = Indirect, blank = no mapping).

| Threat | AI-001 | AI-002 | AI-003 | AI-004 | AI-005 | AI-006 | AI-007 | AI-008 | CYB-001 | CYB-002 | CYB-003 | CYB-004 | CYB-005 | CYB-006 | CYB-007 | CYB-008 | CYB-009 | CYB-010 | CYB-011 | CYB-012 | CYB-013 | CYB-014 | CYB-015 | CYB-016 | CYB-017 | CYB-018 | CYB-019 | CYB-020 | CYB-021 | CYB-022 | CYB-023 | CYB-024 | CYB-025 | CYB-026 | CYB-027 | CYB-028 | CYB-029 | CYB-030 |
|--------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|------|
| T-001 |   |   | 2 |   | 1 |   |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   |   | 1 |   |   |   |   |   |   |
| T-002 |   |   | 2 |   | 2 |   | 1 |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   |   |   |   |   |   |
| T-003 |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   |   |   |   | 2 | 2 |   | 2 |   |   |   |   | 1 |   |   |   |   |   |   |
| T-004 |   |   | 2 |   | 2 |   |   |   |   |   |   |   |   | 1 |   | 1 |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |   |   |   |
| T-005 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   | 2 |   |   | 2 | 1 |   |   |   | 2 |   |   |   |   |   |   |
| T-006 |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   | 1 |   |   |   |   |   |   |   | 2 | 1 |   |   |   |   |   |   | 2 |   |   |   |   |   |   |
| T-007 |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   | 2 | 2 |   |   |   |   |   |   | 2 |   |   |   | 2 |   |   |   |   |   |   |   |
| T-008 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   | 2 |   | 1 | 1 |   |   |   |   |   |   |   |   |   |   |   |
| T-009 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   | 2 | 2 |   | 1 |   |   |   |   |   |   |   |   |   |
| T-010 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 | 1 |   |   |   |   | 2 |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |
| T-011 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   | 2 | 2 |   | 1 |   |   |   |   |   |   |   |   |   |
| T-012 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   |   |   | 2 | 2 |   |   |   |   |   |   | 1 |   |   |   |   |   |   |
| T-013 |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   | 1 |   |   |   | 1 |   |   |
| T-014 |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   |   |   | 1 |   |   |   | 2 |   | 1 |   |   |   |   |   |   |   |   |   |
| T-015 |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   | 1 |   |   |   |   |   |   | 2 |   |   |   | 1 |   |   |   |   |   |   |   |   |   |   |   |
| T-016 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 | 1 |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |
| T-017 |   |   |   |   |   |   |   |   |   |   |   |   | 2 | 1 |   |   |   |   | 2 |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   |   |   |   |   |   |
| T-018 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   | 2 |   |   |   | 2 |   | 2 |   |   |   |   |   |   |   |   |   |   |
| T-019 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   | 2 |   | 2 |   |   |   |   |   | 1 |   |   |   |   |   |   |
| T-020 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   | 2 | 2 |   | 1 |   |   |   |   |   |   |   |   |   |
| T-021 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   | 2 |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |
| T-022 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   | 2 | 1 | 1 |   |   |   |   |   |   |   |   |   |   |
| T-023 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   | 2 |   |   |   | 2 |   | 2 |   | 2 |   |   |   |   |   |   |
| T-024 |   | 2 | 2 | 2 | 1 |   |   |   |   |   |   |   |   | 1 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
| T-025 |   |   | 2 |   | 2 |   |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |
| T-026 | 1 |   | 2 | 1 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 2 |   |   |   |   |   |   |   |   |   |   |
| T-027 |   |   | 2 |   |   | 2 | 2 | 1 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | 1 |   |   |

## 4. MITRE ATT&CK Technique Summary

### 4.1. ICS Matrix Techniques

| Technique ID | Technique Name | Associated Threats |
|-------------|----------------|--------------------|
| T0812 | Default Credentials | T-006, T-019 |
| T0814 | Denial of Service | T-010, T-013, T-016, T-021 |
| T0826 | Loss of Availability | T-013, T-016 |
| T0830 | Manipulation of View | T-008, T-009, T-011 |
| T0831 | Manipulation of Control | T-003, T-015 |
| T0836 | Modify Parameter | T-001, T-002, T-003, T-004, T-014 |
| T0842 | Network Sniffing | T-018 |
| T0855 | Unauthorized Command Message | T-001 |
| T0857 | System Firmware | T-007 |
| T0860 | Wireless Compromise | T-019 |
| T0862 | Supply Chain Compromise | T-017 |
| T0879 | Damage to Property | T-015 |
| T0880 | Loss of Safety | T-002 |
| T0882 | Theft of Operational Information | T-004 |
| T0883 | Unauthorized Access | T-005, T-023 |
| T0885 | Loss of Engineering Control | T-014 |
| T0887 | Wireless Sniffing | T-020 |
| T0890 | Exploitation for Privilege Escalation | T-012 |

### 4.2. Enterprise Matrix Techniques

| Technique ID | Technique Name | Associated Threats |
|-------------|----------------|--------------------|
| T1040 | Network Sniffing | T-018 |
| T1068 | Exploitation for Privilege Escalation | T-012 |
| T1071 | Application Layer Protocol | T-022 |
| T1078 | Valid Accounts | T-006 |
| T1190 | Exploit Public-Facing Application | T-005, T-023 |
| T1195 | Supply Chain Compromise | T-017 |
| T1498 | Network Denial of Service | T-010, T-021 |
| T1542 | Pre-OS Boot | T-007 |
| T1557 | Adversary-in-the-Middle | T-009, T-011, T-020 |
| T1563 | Remote Service Session Hijacking | T-008 |
| T1584 | Compromise Infrastructure | T-022 |

### 4.3. ATLAS Matrix Techniques

| Technique ID | Technique Name | Associated Threats |
|-------------|----------------|--------------------|
| AML.T0020 | Poison Training Data | T-024 |
| AML.T0024 | Infer Training Data Membership | T-026 |
| AML.T0031 | Erode ML Model Integrity | T-027 |
| AML.T0043 | Craft Adversarial Data | T-025, T-027 |
| AML.T0044 | Full ML Model Access | T-026 |

## 5. NIST SP 800-53 Rev. 5 Control Summary

| Control Family | Family Name | Associated Threats |
|---------------|------------|--------------------|
| AC | Access Control | T-003, T-005, T-006, T-008, T-012, T-018, T-019, T-023, T-026 |
| AU | Audit and Accountability | T-001, T-002, T-003, T-008, T-009, T-012, T-014, T-020, T-024 |
| CA | Security Assessment | T-001, T-002, T-004, T-024, T-025, T-027 |
| CM | Configuration Management | T-007, T-012, T-014 |
| CP | Contingency Planning | T-010, T-013, T-016, T-021, T-023 |
| IA | Identification and Authentication | T-003, T-006, T-008, T-019 |
| MA | Maintenance | T-013 |
| MP | Media Protection | T-015, T-026 |
| PE | Physical and Environmental Protection | T-013, T-014, T-015, T-016, T-017, T-021 |
| PM | Program Management | T-027 |
| RA | Risk Assessment | T-005, T-023 |
| SA | System and Services Acquisition | T-001, T-002, T-004, T-005, T-007, T-017, T-024, T-025, T-026, T-027 |
| SC | System and Communications Protection | T-004, T-005, T-007, T-008, T-009, T-010, T-011, T-016, T-018, T-019, T-020, T-021, T-022, T-023, T-026 |
| SI | System and Information Integrity | T-001, T-002, T-003, T-004, T-005, T-007, T-010, T-012, T-013, T-014, T-016, T-022, T-023, T-024, T-025, T-027 |
| SR | Supply Chain Risk Management | T-017 |

### Detailed Control Assignments

| NIST Control | Control Name | Associated Threats |
|-------------|-------------|--------------------|
| AC-12 | Access Control | T-008 |
| AC-14 | Access Control | T-006 |
| AC-18 | Access Control | T-018, T-019 |
| AC-3 | Access Control | T-003, T-026 |
| AC-4 | Access Control | T-005, T-023 |
| AC-5 | Access Control | T-012 |
| AC-6 | Access Control | T-003, T-012 |
| AC-7 | Access Control | T-006 |
| AU-2 | Audit and Accountability | T-001, T-003, T-008, T-009, T-012, T-014, T-020, T-024 |
| AU-6 | Audit and Accountability | T-002 |
| CA-2 | Security Assessment | T-001, T-024 |
| CA-7 | Security Assessment | T-027 |
| CA-8 | Security Assessment | T-002, T-004, T-024, T-025 |
| CM-2 | Configuration Management | T-007 |
| CM-3 | Configuration Management | T-007, T-014 |
| CM-7 | Configuration Management | T-012 |
| CP-2 | Contingency Planning | T-013, T-016, T-023 |
| CP-7 | Contingency Planning | T-010, T-021 |
| IA-11 | Identification and Authentication | T-008 |
| IA-2 | Identification and Authentication | T-003, T-006 |
| IA-3 | Identification and Authentication | T-006, T-019 |
| IA-5 | Identification and Authentication | T-006 |
| MA-2 | Maintenance | T-013 |
| MP-4 | Media Protection | T-015, T-026 |
| PE-11 | Physical and Environmental Protection | T-016 |
| PE-14 | Physical and Environmental Protection | T-013 |
| PE-18 | Physical and Environmental Protection | T-021 |
| PE-3 | Physical and Environmental Protection | T-014, T-015, T-017 |
| PE-4 | Physical and Environmental Protection | T-015 |
| PE-6 | Physical and Environmental Protection | T-015 |
| PM-14 | Program Management | T-027 |
| RA-5 | Risk Assessment | T-005, T-023 |
| SA-10 | System and Services Acquisition | T-007 |
| SA-11 | System and Services Acquisition | T-001, T-002, T-004, T-005, T-024, T-025, T-027 |
| SA-12 | System and Services Acquisition | T-017 |
| SA-8 | System and Services Acquisition | T-026 |
| SC-12 | System and Communications Protection | T-011 |
| SC-13 | System and Communications Protection | T-009, T-011, T-018, T-019, T-020 |
| SC-20 | System and Communications Protection | T-022 |
| SC-21 | System and Communications Protection | T-022 |
| SC-22 | System and Communications Protection | T-022 |
| SC-23 | System and Communications Protection | T-008, T-009, T-011, T-020 |
| SC-28 | System and Communications Protection | T-026 |
| SC-34 | System and Communications Protection | T-007 |
| SC-40 | System and Communications Protection | T-018, T-021 |
| SC-5 | System and Communications Protection | T-010, T-016, T-021 |
| SC-7 | System and Communications Protection | T-004, T-005, T-010, T-023 |
| SC-8 | System and Communications Protection | T-009, T-011, T-018, T-019, T-020 |
| SI-3 | System and Information Integrity | T-005, T-022, T-023 |
| SI-4 | System and Information Integrity | T-010, T-013, T-016, T-025, T-027 |
| SI-7 | System and Information Integrity | T-001, T-002, T-003, T-004, T-007, T-012, T-014, T-024, T-025 |
| SR-11 | Supply Chain Risk Management | T-017 |
| SR-3 | Supply Chain Risk Management | T-017 |
| SR-5 | Supply Chain Risk Management | T-017 |

## 6. Implementation Priority Matrix

### Q1: Quick Wins (RPN≥40, C≤3) — 5 threats

| Threat ID | Threat Name | S | L | D | RPN | C | Layer |
|-----------|------------|---|---|---|-----|---|-------|
| T-006 | Insufficient Authentication | 5 | 5 | 3 | 75 | 2 | 3 |
| T-009 | Replay Attacks | 4 | 4 | 3 | 48 | 2 | 2 |
| T-010 | Denial of Service (DoS) | 4 | 4 | 3 | 48 | 1 | 2 |
| T-019 | BLE Pairing Exploitation | 4 | 4 | 3 | 48 | 3 | 2 |
| T-020 | Wireless Replay | 4 | 4 | 3 | 48 | 2 | 2 |

### Q2: Strategic Priorities (RPN≥40, C>3) — 7 threats

| Threat ID | Threat Name | S | L | D | RPN | C | Layer |
|-----------|------------|---|---|---|-----|---|-------|
| T-024 | Training Data Poisoning | 5 | 3 | 5 | 75 | 4 | 4 |
| T-025 | Adversarial Evasion | 5 | 3 | 5 | 75 | 4 | 4 |
| T-027 | Concept Drift | 4 | 4 | 4 | 64 | 4 | 4 |
| T-007 | Firmware Code Injection | 5 | 3 | 4 | 60 | 4 | 1 |
| T-023 | Cloud Infrastructure Compromise | 4 | 3 | 4 | 48 | 4 | 2 |
| T-002 | MPC Model Inaccuracy | 5 | 3 | 3 | 45 | 4 | 4 |
| T-011 | Man-in-the-Middle (MITM) Attacks | 5 | 3 | 3 | 45 | 4 | 2 |

### Q3: Efficiency Gains (RPN<40, C≤3) — 8 threats

| Threat ID | Threat Name | S | L | D | RPN | C | Layer |
|-----------|------------|---|---|---|-----|---|-------|
| T-005 | Cloud API Exploitation | 4 | 3 | 3 | 36 | 3 | 2 |
| T-008 | Session Hijacking | 4 | 3 | 3 | 36 | 3 | 3 |
| T-012 | Privilege Escalation | 4 | 3 | 3 | 36 | 2 | 3 |
| T-013 | CGM Sensor Failures | 4 | 4 | 2 | 32 | 3 | 1 |
| T-003 | Setpoint Manipulation | 5 | 3 | 2 | 30 | 3 | 3 |
| T-018 | BLE Eavesdropping | 3 | 4 | 2 | 24 | 2 | 2 |
| T-022 | DNS/Cloud Redirect | 3 | 2 | 3 | 18 | 3 | 2 |
| T-015 | Physical Tampering | 3 | 2 | 2 | 12 | 3 | 1 |

### Q4: Long-term Initiatives (RPN<40, C>3) — 7 threats

| Threat ID | Threat Name | S | L | D | RPN | C | Layer |
|-----------|------------|---|---|---|-----|---|-------|
| T-004 | Control Algorithm Exploitation | 4 | 2 | 4 | 32 | 5 | 4 |
| T-017 | Hardware Supply Chain Compromise | 4 | 2 | 4 | 32 | 5 | 1 |
| T-001 | Glucose-Insulin Model Manipulation | 5 | 2 | 3 | 30 | 4 | 4 |
| T-014 | Sensor Calibration Manipulation | 5 | 2 | 3 | 30 | 4 | 1 |
| T-016 | Battery/Power Depletion | 3 | 3 | 2 | 18 | 4 | 1 |
| T-021 | RF Jamming/Interference | 3 | 3 | 2 | 18 | 4 | 2 |
| T-026 | Model Inversion/Extraction | 2 | 2 | 4 | 16 | 4 | 4 |

## 7. Framework Layer Coverage Analysis

### Layer 1: Secure Device Foundation — 6 primary threats

| Threat ID | Threat Name | Category | Severity |
|-----------|------------|----------|----------|
| T-007 | Firmware Code Injection | SW | Critical |
| T-013 | CGM Sensor Failures | HW | High |
| T-014 | Sensor Calibration Manipulation | HW | Critical |
| T-015 | Physical Tampering | HW | High |
| T-016 | Battery/Power Depletion | HW | Medium |
| T-017 | Hardware Supply Chain Compromise | HW | High |

### Layer 2: Secure Communications — 10 primary threats

| Threat ID | Threat Name | Category | Severity |
|-----------|------------|----------|----------|
| T-005 | Cloud API Exploitation | SW | High |
| T-009 | Replay Attacks | SW | High |
| T-010 | Denial of Service (DoS) | SW | High |
| T-011 | Man-in-the-Middle (MITM) Attacks | SW | Critical |
| T-018 | BLE Eavesdropping | COM | High |
| T-019 | BLE Pairing Exploitation | COM | Critical |
| T-020 | Wireless Replay | COM | High |
| T-021 | RF Jamming/Interference | COM | High |
| T-022 | DNS/Cloud Redirect | COM | Medium |
| T-023 | Cloud Infrastructure Compromise | COM | High |

### Layer 3: Access Control & Identity — 4 primary threats

| Threat ID | Threat Name | Category | Severity |
|-----------|------------|----------|----------|
| T-003 | Setpoint Manipulation | CT | Critical |
| T-006 | Insufficient Authentication | SW | Critical |
| T-008 | Session Hijacking | SW | High |
| T-012 | Privilege Escalation | SW | High |

### Layer 4: AI Anomaly Detection — 7 primary threats

| Threat ID | Threat Name | Category | Severity |
|-----------|------------|----------|----------|
| T-001 | Glucose-Insulin Model Manipulation | CT | Critical |
| T-002 | MPC Model Inaccuracy | CT | High |
| T-004 | Control Algorithm Exploitation | CT | High |
| T-024 | Training Data Poisoning | AI | Critical |
| T-025 | Adversarial Evasion | AI | Critical |
| T-026 | Model Inversion/Extraction | AI | Medium |
| T-027 | Concept Drift | AI | High |

### Layer 5: Lifecycle Management — 0 primary threats

| Threat ID | Threat Name | Category | Severity |
|-----------|------------|----------|----------|

---

## Citation

If you use this mapping artifact, please cite:

```bibtex
@inproceedings{piratla2026cgmsecurity,
  title     = {A Security Framework for {AI}-Enabled Continuous Glucose Monitoring: Translating {FDA} Guidance into Actionable Controls},
  author    = {Piratla, Venkata Sai Abhinav and Bhatia, Sajal and Saxena, Sahaj},
  booktitle = {Proceedings of the CyberAI 2026 Conference},
  year      = {2026},
  address   = {Morocco}
}
```

## License

This supplementary material is released under the [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) license for academic and community use.
