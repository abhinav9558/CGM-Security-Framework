# CGM-Security-Framework

**A Five-Layer Defense-in-Depth Security Framework for AI-Enabled Continuous Glucose Monitoring Systems**

> Supplementary material for: *"A Security Framework for AI-Enabled Continuous Glucose Monitoring: Translating FDA Guidance into Actionable Controls"*
>
> Accepted at **CyberAI 2026** — International Conference on Cybersecurity and Artificial Intelligence, Morocco, June 25-26, 2026. Published by Taylor & Francis.

---

## Overview

AI-enabled Continuous Glucose Monitoring (CGM) and Artificial Pancreas (AP) systems increasingly rely on wireless connectivity, cloud analytics, and machine learning for closed-loop insulin delivery. As the FDA's June 2025 Premarket Cybersecurity Guidance and January 2025 AI-Enabled Device Software Functions (AI-DSF) draft guidance introduce new security expectations, manufacturers face a critical gap between regulatory language and deployable technical controls.

This repository provides the **complete threat-to-control mapping artifact** accompanying our paper, enabling reproducibility and community review of the proposed five-layer security framework.

### What's Inside

- **27 cataloged threats** across five categories: Control-Theoretic (4), Software (8), Hardware (5), Communication (6), and AI-Specific (4)
- **38 FDA requirements** mapped from the June 2025 Premarket Cybersecurity Guidance (30 requirements) and January 2025 AI-DSF Draft Guidance (8 requirements)
- **MITRE ATT&CK technique mappings** spanning three matrices: ICS (18 techniques), Enterprise (11 techniques), and ATLAS (5 techniques)
- **NIST SP 800-53 Rev. 5 control assignments** with specific control identifiers per threat
- **Scored implementation priority matrix** using FMEA-adapted Severity x Likelihood x Detectability methodology with implementation complexity assessment
- **27 x 38 cross-reference matrix** showing every threat-to-FDA requirement mapping with relevance scores

## Framework Architecture

The framework proposes five defense-in-depth layers:

| Layer | Name | Key Controls | Threat Coverage |
|-------|------|-------------|-----------------|
| 1 | Secure Device Foundation | TPM/HSM, Secure Boot, Firmware Signing, Tamper Detection | 6 threats |
| 2 | Secure Communications | TLS 1.3, BLE SSP + AES-CCM, Replay Protection, DDoS Mitigation | 10 threats (37%) |
| 3 | Access Control & Identity | MFA (FIDO2), RBAC, Parameter Integrity, Audit Logging | 5 threats |
| 4 | AI Anomaly Detection | Model Validation, Adversarial Robustness, Poisoning Detection, Drift Monitoring | 7 threats |
| 5 | Lifecycle Management | SBOM, Vulnerability Management, Incident Response, Security Assessments | All 27 (cross-cutting) |

## Mapping Rubric

Each threat-to-FDA requirement mapping uses a three-point relevance scale:

| Score | Label | Definition |
|-------|-------|------------|
| 2 | Direct | Regulatory text explicitly names or addresses the threat class |
| 1 | Indirect | Requirement addresses a broader category encompassing the threat |
| 0 | None | No meaningful relationship (excluded from mappings) |

## Implementation Priority Quadrants

Threats are prioritized using composite Risk Priority Number (RPN = Severity x Likelihood x Detectability) and Implementation Complexity (C):

| Quadrant | Criteria | Threats | Recommended Timeline |
|----------|----------|---------|---------------------|
| Q1: Quick Wins | RPN >= 40, C <= 3 | 5 | Months 1-3 |
| Q2: Strategic Priorities | RPN >= 40, C > 3 | 7 | Months 4-18 |
| Q3: Efficiency Gains | RPN < 40, C <= 3 | 8 | Months 18-36 |
| Q4: Long-term Initiatives | RPN < 40, C > 3 | 7 | Months 19-36+ |

## Repository Contents

```
.
├── README.md                                           # This file
├── CGM_Security_Framework_Complete_Mapping.md           # Full mapping artifact (Markdown)
├── CGM_Security_Framework_Complete_Mapping.docx         # Full mapping artifact (Word)
├── CGM_Security_Framework_CyberAI2026.pdf               # Paper (preprint)
└── Visuals/
    ├── framework_architecture.png                       # Five-layer framework diagram
    └── priority_matrix.png                              # Implementation priority matrix
```

## Key Regulatory References

- **FDA Premarket Cybersecurity Guidance** (June 2025) — 30 requirements across 8 control categories
- **FDA AI-DSF Draft Guidance** (January 2025) — 8 AI-specific requirements
- **FDORA Section 524B** (December 2022) — 3 mandatory statutory requirements (SBOM, Cybersecurity Management Plan, Vulnerability Patching)
- **NIST SP 800-53 Rev. 5** (September 2020) — Security and privacy controls
- **MITRE ATT&CK for ICS** — Industrial control system techniques applied by analogy to CGM closed-loop control
- **MITRE ATT&CK for Enterprise** — Cloud and application-layer threat techniques
- **MITRE ATLAS** — Adversarial threat landscape for AI/ML systems

## Citation

If you use this framework or mapping artifact in your research, please cite:

```bibtex
@inproceedings{piratla2026cgmsecurity,
  title     = {A Security Framework for {AI}-Enabled Continuous Glucose Monitoring:
               Translating {FDA} Guidance into Actionable Controls},
  author    = {Piratla, Venkata Sai Abhinav and Bhatia, Sajal and Saxena, Sahaj},
  booktitle = {Proceedings of the CyberAI 2026 Conference},
  year      = {2026},
  address   = {Morocco},
  publisher = {Taylor \& Francis}
}
```

## Related Work

- V. S. A. Piratla et al., "Safeguarding the Artificial Pancreas: A Review of Security and Reliability Gaps and AI Driven Resilience," *Proc. ICSC*, 2025. doi: [10.1109/ICSC65596.2025.11140338](https://doi.org/10.1109/ICSC65596.2025.11140338)
- V. S. A. Piratla, S. Bhatia, and S. Saxena, "AP-GUARD: Artificial Pancreas Generalized Unsupervised Anomaly Recognition and Detection," *Proc. IEEE CICN*, 2025.

## Authors

- **Venkata Sai Abhinav Piratla** — School of Computer Science and Engineering, Sacred Heart University, CT, USA — piratlav@mail.sacredheart.edu
- **Sajal Bhatia** — School of Computer Science and Engineering, Sacred Heart University, CT, USA — bhatias@sacredheart.edu
- **Sahaj Saxena** — Department of Electrical and Instrumentation Engineering, Thapar Institute of Engineering and Technology, Punjab, India — sahaj.saxena@thapar.edu

## License

This supplementary material is released under the [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) license for academic and community use. You are free to share and adapt the material with appropriate attribution.

---

*For questions or collaboration inquiries, please contact the corresponding author at piratlav@mail.sacredheart.edu.*
