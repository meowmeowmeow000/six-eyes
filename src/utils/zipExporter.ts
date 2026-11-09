/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import JSZip from 'jszip';
import { REPO_FILES } from '../data/repoFiles';

/**
 * Generates and triggers download of the complete GitHub repository as a .zip
 */
export async function downloadRepoZip(onProgress?: (percent: number) => void): Promise<void> {
  const zip = new JSZip();

  // Root folder in the zip
  const folder = zip.folder('six-eyes-main') || zip;

  for (let i = 0; i < REPO_FILES.length; i++) {
    const file = REPO_FILES[i];
    folder.file(file.path, file.content);
    if (onProgress) {
      onProgress(Math.round(((i + 1) / REPO_FILES.length) * 50));
    }
  }

  // Add standard .gitignore
  folder.file(
    '.gitignore',
    `# Binaries and build artifacts
bin/
*.o
*.so
dist/

# Logs and temp files
*.log
/tmp/

# OS and Editor files
.DS_Store
.idea/
.vscode/
`
  );

  // Add LICENSE file
  folder.file(
    'LICENSE',
    `Dual License: GPL-2.0 / BSD-3-Clause

This software is dual-licensed under either the GNU General Public License version 2 (GPL-2.0)
or the 3-Clause BSD License, at your option.

Copyright (c) 2026 Six Eyes Autonomous DPI Evasion Project Authors.
All rights reserved.
`
  );

  const content = await zip.generateAsync(
    { type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 } },
    (metadata) => {
      if (onProgress) {
        onProgress(50 + Math.round(metadata.percent / 2));
      }
    }
  );

  // Trigger browser download
  const url = URL.createObjectURL(content);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'six-eyes-v10.zip';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
