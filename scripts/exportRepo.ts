/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { REPO_FILES } from '../src/data/repoFiles';

const repoRoot = path.resolve('six-eyes');

console.log('[*] Exporting Six Eyes repository files to:', repoRoot);

if (fs.existsSync(repoRoot)) {
  fs.rmSync(repoRoot, { recursive: true, force: true });
}
fs.mkdirSync(repoRoot, { recursive: true });

for (const file of REPO_FILES) {
  const targetPath = path.join(repoRoot, file.path);
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(targetPath, file.content, 'utf8');
  console.log(`  + [six-eyes] ${file.path} (${file.size})`);
}

// Initialize git repository in six-eyes/
try {
  execSync('git init', { cwd: repoRoot });
  execSync('git config user.email "daemon@six-eyes.internal"', { cwd: repoRoot });
  execSync('git config user.name "Six Eyes Operator"', { cwd: repoRoot });
  execSync('git add .', { cwd: repoRoot });
  execSync('git commit -m "feat(core): initialize six-eyes v10 autonomous eBPF DPI evasion daemon"', { cwd: repoRoot });
  execSync('git branch -M main', { cwd: repoRoot });
  console.log('[OK] Git repository initialized and committed on main branch in six-eyes/');
} catch (e: any) {
  console.log('[WARN] Git init warning:', e.message);
}
