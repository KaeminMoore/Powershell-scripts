# Define base actions
$actions = @(
    "Perform", "Monitor", "Update", "Manage", "Optimize",
    "Configure", "Test", "Deploy", "Troubleshoot", "Investigate",
    "Automate", "Analyze", "Respond to", "Research", "Audit"
)

# Define task categories
$taskCategories = @{
    "System Administration" = @(
        "server performance", "operating system patches", "virtual machine configurations",
        "disk space usage", "scheduled maintenance tasks", "database backups"
    )
    "Security Operations" = @(
        "firewall policies", "intrusion detection alerts", "phishing attempts",
        "malware scans", "threat intelligence reports", "security patches"
    )
    "Cloud Management" = @(
        "AWS IAM roles", "Azure security groups", "S3 bucket policies",
        "virtual networking in the cloud", "Kubernetes cluster security", "serverless functions"
    )
    "Network Operations" = @(
        "network traffic anomalies", "VPN configurations", "bandwidth usage",
        "DNS resolution issues", "router and switch logs", "IP address conflicts"
    )
    "User Support & Help Desk" = @(
        "end-user requests", "email access issues", "printer connectivity problems",
        "remote desktop troubleshooting", "software installation requests", "password reset requests"
    )
    "Documentation & Compliance" = @(
        "IT security policies", "network architecture diagrams", "system audit logs",
        "compliance checklists", "data retention policies", "incident response reports"
    )
    "Research & Development" = @(
        "emerging cybersecurity threats", "new cloud security tools", "automation best practices",
        "AI-driven threat detection", "IoT security risks", "zero-trust architecture"
    )
    "Meetings & Communication" = @(
        "team sync meetings", "cybersecurity awareness training", "project planning discussions",
        "vendor consultations", "compliance audits", "technical documentation reviews"
    )
}

# Define task variations
$variations = @(
    "Ensure all configurations follow best practices",
    "Perform a security risk assessment",
    "Generate a detailed report for review",
    "Coordinate with team members for implementation",
    "Troubleshoot any unexpected issues",
    "Optimize for better performance and security",
    "Automate the process for efficiency",
    "Conduct a test run before final deployment",
    "Schedule follow-up checks",
    "Document findings for future reference"
)

# Define task contexts for uniqueness
$contexts = @(
    "as part of routine maintenance",
    "due to a recent security update",
    "following an incident report",
    "to enhance system efficiency",
    "as per compliance requirements",
    "for a high-priority project",
    "to address a recurring issue",
    "as requested by upper management",
    "as part of a larger infrastructure upgrade",
    "to support remote workforce needs"
)

# Output file
$outputFile = "IT_Specialist_Tasks.txt"
$taskList = @()

# Generate 10,000 unique tasks
for ($i = 1; $i -le 10000; $i++) {
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
