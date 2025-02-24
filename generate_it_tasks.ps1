# Define base tasks, sub-tasks, and filler tasks
$tasks = @(
    "Perform system maintenance",
    "Monitor network traffic",
    "Update security patches",
    "Conduct vulnerability assessments",
    "Troubleshoot software issues",
    "Manage cloud resources",
    "Optimize system performance",
    "Backup critical data",
    "Analyze security logs",
    "Assist users with IT issues",
    "Deploy new software updates",
    "Configure firewall rules",
    "Test disaster recovery procedures",
    "Automate repetitive IT tasks",
    "Document system configurations",
    "Audit user permissions",
    "Set up and manage virtual machines",
    "Investigate security alerts",
    "Provide technical support",
    "Research emerging IT threats",
    "Ensure compliance with IT policies",
    "Optimize cloud infrastructure",
    "Respond to security incidents",
    "Evaluate new IT tools"
)

$subTasks = @(
    "Verify system health before starting",
    "Create detailed documentation of the process",
    "Consult IT team for best practices",
    "Perform initial risk assessment",
    "Ensure backup is available before changes",
    "Coordinate with stakeholders before implementation",
    "Test configurations in a sandbox environment",
    "Schedule maintenance during off-peak hours",
    "Review logs after implementation",
    "Provide a report on the findings"
)

$fillerTasks = @(
    "Attend IT team meeting",
    "Respond to emails from management",
    "Update task tracker with recent activities",
    "Check for pending software license renewals",
    "Assist a colleague with an IT issue",
    "Read industry news for latest trends",
    "Participate in cybersecurity awareness training",
    "Document lessons learned from recent incidents",
    "Test a new IT tool in a lab environment",
    "Evaluate feedback from end-users"
)

# Output file
$outputFile = "IT_Specialist_Tasks.txt"
$taskList = @()

# Generate 1,000 tasks
for ($i = 1; $i -le 1000; $i++) {
    $baseTask = Get-Random -InputObject $tasks
    $variation = Get-Random -InputObject ($subTasks + $fillerTasks)
    $taskList += "$i. $baseTask - $variation"
}

# Write to file
$taskList | Out-File -Encoding UTF8 -FilePath $outputFile

Write-Host "Task list generated and saved as '$outputFile'."
