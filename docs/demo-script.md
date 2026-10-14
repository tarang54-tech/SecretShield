# Classroom demo script

1. Start Compose and create an administrator; sign into the local dashboard.
2. Upload a clean Python file and show a completed scan with zero findings.
3. In another PowerShell window, run `py scripts/make_demo_bundle.py` and upload the printed ZIP file.
4. Show the `secretshield-demo-key` finding, its severity, relative path, and line. Explain that the value itself is not displayed or stored in the finding database.
5. Use the CI workflow or the local policy tests to explain that high and critical findings fail the gate. In GitHub, a test branch containing the fabricated pattern should fail; removing it should make the check pass.
6. Run `py scripts/make_demo_bundle.py --clean` and scan that archive. Use the verification action on the earlier finding, selecting the later clean scan. Explain that acknowledgement records review, while verification records evidence that the finding disappeared from a later scan.
7. Create an incident linked to the finding. Walk through `open → investigating → remediation_pending`, add resolution notes, then resolve it after the finding has been verified. Show the incident timeline and audit events.
8. Remove the temporary ZIP and show the limitations/security model.

The fixture is synthetic and cannot authenticate to any provider.
