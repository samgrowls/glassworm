// FALSE POSITIVE TEST FIXTURE — Legitimate build script
// This file should produce ZERO findings
// Pattern: Build script using childProcess for developer tooling
// Normal build operations, NO credential theft patterns

const { execSync, spawn } = require('child_process');
const path = require('path');

/**
 * Run build command
 */
function runBuild() {
    console.log('Running build...');
    try {
        execSync('npm run build', { stdio: 'inherit' });
        console.log('Build completed successfully');
    } catch (error) {
        console.error('Build failed:', error.message);
        process.exit(1);
    }
}

/**
 * Run linting
 */
function runLint() {
    console.log('Running linter...');
    try {
        execSync('npm run lint', { stdio: 'inherit' });
        console.log('Linting completed');
    } catch (error) {
        console.error('Linting failed:', error.message);
        process.exit(1);
    }
}

/**
 * Run tests
 */
function runTests() {
    console.log('Running tests...');
    try {
        execSync('npm test', { stdio: 'inherit' });
        console.log('Tests passed');
    } catch (error) {
        console.error('Tests failed:', error.message);
        process.exit(1);
    }
}

/**
 * Run TypeScript compiler
 */
function runTypeScript() {
    console.log('Compiling TypeScript...');
    try {
        execSync('npx tsc', { stdio: 'inherit' });
        console.log('TypeScript compilation completed');
    } catch (error) {
        console.error('TypeScript compilation failed:', error.message);
        process.exit(1);
    }
}

/**
 * Run ESLint
 */
function runEslint() {
    console.log('Running ESLint...');
    try {
        execSync('npx eslint src/', { stdio: 'inherit' });
        console.log('ESLint completed');
    } catch (error) {
        console.error('ESLint failed:', error.message);
        process.exit(1);
    }
}

/**
 * Run Prettier format check
 */
function runPrettier() {
    console.log('Checking formatting with Prettier...');
    try {
        execSync('npx prettier --check src/', { stdio: 'inherit' });
        console.log('Formatting check passed');
    } catch (error) {
        console.error('Formatting check failed:', error.message);
        process.exit(1);
    }
}

/**
 * Clean build artifacts
 */
function cleanBuild() {
    console.log('Cleaning build artifacts...');
    try {
        execSync('rm -rf dist/ build/ .cache/', { stdio: 'inherit' });
        console.log('Clean completed');
    } catch (error) {
        console.error('Clean failed:', error.message);
        process.exit(1);
    }
}

/**
 * Run full CI pipeline
 */
function runCiPipeline() {
    console.log('Running CI pipeline...');
    cleanBuild();
    runTypeScript();
    runLint();
    runPrettier();
    runBuild();
    runTests();
    console.log('CI pipeline completed successfully');
}

// CLI argument handling
const command = process.argv[2];

switch (command) {
    case 'build':
        runBuild();
        break;
    case 'lint':
        runLint();
        break;
    case 'test':
        runTests();
        break;
    case 'tsc':
        runTypeScript();
        break;
    case 'eslint':
        runEslint();
        break;
    case 'prettier':
        runPrettier();
        break;
    case 'clean':
        cleanBuild();
        break;
    case 'ci':
        runCiPipeline();
        break;
    default:
        console.log('Usage: node build_script.js [build|lint|test|tsc|eslint|prettier|clean|ci]');
        process.exit(0);
}

module.exports = {
    runBuild,
    runLint,
    runTests,
    runTypeScript,
    runEslint,
    runPrettier,
    cleanBuild,
    runCiPipeline
};
