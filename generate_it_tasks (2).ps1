# Define base actions
$actions = @(
    "Perform", "Monitor", "Update", "Manage", "Optimize", "Configure", "Test", "Deploy",
    "Troubleshoot", "Investigate", "Automate", "Analyze", "Respond to", "Research", "Audit",
    "Enhance", "Review", "Develop", "Implement", "Assess", "Secure", "Patch", "Debug",
    "Upgrade", "Validate", "Streamline", "Overhaul", "Fine-tune", "Execute", "Reinforce"
)

# Define task categories
$taskCategories = @{
    "System Administration" = @(
        "server performance", "operating system patches", "virtual machine configurations",
        "disk space usage", "scheduled maintenance tasks", "database backups", "log rotation policies",
        "storage performance optimization", "kernel version updates", "process automation scripts"
    )
    "Security Operations" = @(
        "firewall policies", "intrusion detection alerts", "phishing attempts",
        "malware scans", "threat intelligence reports", "security patches", "endpoint security settings",
        "DLP policies", "SIEM event correlation", "SOC incident analysis"
    )
    "Cloud Management" = @(
        "AWS IAM roles", "Azure security groups", "S3 bucket policies", "serverless function performance",
        "cloud compliance monitoring", "Kubernetes cluster security", "cloud access controls",
        "multi-cloud networking policies", "database encryption settings", "cost optimization reports"
    )
    "Network Operations" = @(
        "network traffic anomalies", "VPN configurations", "bandwidth usage",
        "DNS resolution issues", "router and switch logs", "IP address conflicts", "DHCP lease analysis",
        "QoS policy adjustments", "packet loss troubleshooting", "network segmentation policies"
    )
    "User Support & Help Desk" = @(
        "end-user requests", "email access issues", "printer connectivity problems",
        "remote desktop troubleshooting", "software installation requests", "password reset requests",
        "mobile device configuration", "group policy enforcement", "hardware driver updates", "IT asset inventory"
    )
    "Documentation & Compliance" = @(
        "IT security policies", "network architecture diagrams", "system audit logs",
        "compliance checklists", "data retention policies", "incident response reports",
        "internal IT training materials", "cybersecurity awareness reports", "cloud security frameworks",
        "risk management documentation"
    )
    "Research & Development" = @(
        "emerging cybersecurity threats", "new cloud security tools", "automation best practices",
        "AI-driven threat detection", "IoT security risks", "zero-trust architecture",
        "blockchain security applications", "quantum encryption technologies", "machine learning threat models",
        "autonomous response security tools"
    )
    "Meetings & Communication" = @(
        "team sync meetings", "cybersecurity awareness training", "project planning discussions",
        "vendor consultations", "compliance audits", "technical documentation reviews",
        "cross-team collaboration discussions", "executive security briefings", "product roadmap sessions",
        "incident post-mortem meetings"
    )
}

# Define task variations (3x more than before)
$variations = @(
    "Ensure all configurations follow best practices", "Perform a security risk assessment",
    "Generate a detailed report for review", "Coordinate with team members for implementation",
    "Troubleshoot any unexpected issues", "Optimize for better performance and security",
    "Automate the process for efficiency", "Conduct a test run before final deployment",
    "Schedule follow-up checks", "Document findings for future reference",
    "Verify logs for inconsistencies", "Apply industry-standard hardening techniques",
    "Enhance security posture through proactive measures", "Simulate attack scenarios for analysis",
    "Test rollback procedures in case of failure", "Validate system integrity through hashing",
    "Deploy monitoring tools for early detection", "Benchmark against historical data",
    "Assess vendor compliance with security policies", "Improve efficiency through scripting",
    "Reduce downtime by refining configurations", "Implement least privilege access controls",
    "Investigate anomalies for potential security risks", "Apply patches to mitigate vulnerabilities",
    "Test scalability under heavy load", "Analyze trends for predictive threat modeling",
    "Ensure high availability configurations are working", "Validate disaster recovery readiness",
    "Improve log correlation for enhanced insights", "Enhance response times with automation"
)

# Define task contexts (3x more than before)
$contexts = @(
    "as part of routine maintenance", "due to a recent security update",
    "following an incident report", "to enhance system efficiency",
    "as per compliance requirements", "for a high-priority project",
    "to address a recurring issue", "as requested by upper management",
    "as part of a larger infrastructure upgrade", "to support remote workforce needs",
    "in response to an ongoing cybersecurity investigation", "as recommended by an external audit",
    "to improve system resilience against attacks", "to prevent potential downtime risks",
    "as a proactive security measure", "in collaboration with the IT security team",
    "in preparation for an upcoming regulatory audit", "to integrate with newly deployed systems",
    "to test a proof-of-concept solution", "as required by evolving compliance frameworks",
    "in response to increased user-reported issues", "to validate data integrity after migrations",
    "to align with industry security standards", "to support business continuity planning",
    "in response to a rise in attack attempts", "to ensure a smooth transition to new policies",
    "as part of an infrastructure modernization initiative", "for forensic analysis after a breach",
    "to validate cloud cost optimization measures", "to improve end-user experience and efficiency"
)

# Output file
$outputFile = "IT_Specialist_Tasks.txt"
$taskList = @()

# Generate 30,000 unique tasks
for ($i = 1; $i -le 30000; $i++) {
    $action = Get-Random -InputObject $actions
    $category = Get-Random -InputObject ($taskCategories.Keys)
    $task = Get-Random -InputObject $taskCategories[$category]
    $variation = Get-Random -InputObject $variations
    $context = Get-Random -InputObject $contexts

    # Construct task with uniqueness
    $taskList += "$i. $action $task - $variation $context."
}

# Write to file
$taskList | Out-File -Encoding UTF8 -FilePath $outputFile

Write-Host "Task list generated and saved as '$outputFile'."
