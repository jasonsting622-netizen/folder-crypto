'use strict';

const crypto = require('crypto');
const obsidian = require('obsidian');

const ENCRYPTION_MARKER = '%% folder-crypto: encrypted %%';
const ENVELOPE_VERSION = 1;
const DEFAULT_SETTINGS = {
  folderPath: '',
  folderLockEnabled: false,
  contentEncryptionEnabled: false,
  includeSubfolders: true,
  extensions: 'md',
  createPlaintextBackup: false,
  filesystemLockEnabled: false,
  lockedFolders: []
};

function normalizeFolderPath(value) {
  return obsidian.normalizePath((value || '').trim().replace(/^\/+|\/+$/g, ''));
}

function normalizeExtensions(value) {
  const items = String(value || 'md')
    .split(',')
    .map((item) => item.trim().replace(/^\./, '').toLowerCase())
    .filter(Boolean);
  return Array.from(new Set(items.length ? items : ['md']));
}

function isEncryptedContent(content) {
  return content.trimStart().startsWith(ENCRYPTION_MARKER);
}

function toBase64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

function fromBase64(value) {
  return Buffer.from(value, 'base64');
}

function buildEncryptedNote(envelope) {
  return `${ENCRYPTION_MARKER}

\`\`\`json
${JSON.stringify(envelope, null, 2)}
\`\`\`
`;
}

function parseEncryptedNote(content) {
  if (!isEncryptedContent(content)) {
    throw new Error('File is not encrypted by Folder Crypto.');
  }
  const match = content.match(/```json\s*([\s\S]*?)\s*```/);
  if (!match) {
    throw new Error('Encrypted envelope is missing.');
  }
  return JSON.parse(match[1]);
}

function deriveKey(password, salt, iterations) {
  return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const iterations = 210000;
  const hash = deriveKey(password, salt, iterations);
  return {
    kdf: 'pbkdf2-sha256',
    iterations,
    salt: toBase64(salt),
    hash: toBase64(hash)
  };
}

function verifyPassword(password, verifier) {
  const expected = fromBase64(verifier.hash);
  const actual = deriveKey(password, fromBase64(verifier.salt), Number(verifier.iterations || 210000));
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function pathIsInsideFolder(path, folderPath) {
  const normalizedPath = obsidian.normalizePath(path || '');
  const normalizedFolder = normalizeFolderPath(folderPath);
  return normalizedPath === normalizedFolder || normalizedPath.startsWith(`${normalizedFolder}/`);
}

function getVaultBasePath(app) {
  const adapter = app.vault.adapter;
  return adapter && typeof adapter.getBasePath === 'function' ? adapter.getBasePath() : null;
}

function getNodeModule(name) {
  try {
    return require(name);
  } catch (error) {
    const nodeRequire = globalThis.window && globalThis.window.require;
    if (typeof nodeRequire !== 'function') {
      return null;
    }
    try {
      return nodeRequire(name);
    } catch (innerError) {
      return null;
    }
  }
}

function encryptText(plaintext, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const iterations = 210000;
  const key = deriveKey(password, salt, iterations);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return buildEncryptedNote({
    version: ENVELOPE_VERSION,
    algorithm: 'aes-256-gcm',
    kdf: 'pbkdf2-sha256',
    iterations,
    salt: toBase64(salt),
    iv: toBase64(iv),
    tag: toBase64(tag),
    data: toBase64(ciphertext)
  });
}

function decryptText(content, password) {
  const envelope = parseEncryptedNote(content);
  if (envelope.version !== ENVELOPE_VERSION || envelope.algorithm !== 'aes-256-gcm') {
    throw new Error('Unsupported encrypted file version.');
  }

  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const tag = fromBase64(envelope.tag);
  const ciphertext = fromBase64(envelope.data);
  const key = deriveKey(password, salt, Number(envelope.iterations || 210000));
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

class PasswordModal extends obsidian.Modal {
  constructor(app, title, confirmText, requireRepeat) {
    super(app);
    this.title = title;
    this.confirmText = confirmText;
    this.requireRepeat = requireRepeat;
    this.password = '';
    this.passwordRepeat = '';
    this.resolved = false;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h2', { text: this.title });

    new obsidian.Setting(contentEl)
      .setName('Password')
      .addText((text) => {
        text.inputEl.type = 'password';
        text.inputEl.autocomplete = 'off';
        text.inputEl.focus();
        text.onChange((value) => {
          this.password = value;
        });
        text.inputEl.addEventListener('keydown', (event) => {
          if (event.key === 'Enter') {
            this.submit();
          }
        });
      });

    if (this.requireRepeat) {
      new obsidian.Setting(contentEl)
        .setName('Repeat password')
        .addText((text) => {
          text.inputEl.type = 'password';
          text.inputEl.autocomplete = 'off';
          text.onChange((value) => {
            this.passwordRepeat = value;
          });
          text.inputEl.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
              this.submit();
            }
          });
        });
    }

    new obsidian.Setting(contentEl)
      .addButton((button) => {
        button
          .setButtonText(this.confirmText)
          .setCta()
          .onClick(() => this.submit());
      })
      .addButton((button) => {
        button
          .setButtonText('Cancel')
          .onClick(() => this.close());
      });
  }

  submit() {
    if (!this.password) {
      new obsidian.Notice('Password is required.');
      return;
    }
    if (this.requireRepeat && this.password !== this.passwordRepeat) {
      new obsidian.Notice('Passwords do not match.');
      return;
    }
    this.resolved = true;
    this.close();
  }

  waitForPassword() {
    return new Promise((resolve) => {
      this.onClose = () => {
        this.contentEl.empty();
        resolve(this.resolved ? this.password : null);
      };
      this.open();
    });
  }
}

class ConfirmModal extends obsidian.Modal {
  constructor(app, title, message, confirmText) {
    super(app);
    this.title = title;
    this.message = message;
    this.confirmText = confirmText;
    this.confirmed = false;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h2', { text: this.title });
    contentEl.createEl('p', { text: this.message });

    new obsidian.Setting(contentEl)
      .addButton((button) => {
        button
          .setButtonText(this.confirmText)
          .setWarning()
          .onClick(() => {
            this.confirmed = true;
            this.close();
          });
      })
      .addButton((button) => {
        button
          .setButtonText('Cancel')
          .onClick(() => this.close());
      });
  }

  waitForConfirm() {
    return new Promise((resolve) => {
      this.onClose = () => {
        this.contentEl.empty();
        resolve(this.confirmed);
      };
      this.open();
    });
  }
}

class FolderCryptoSettingTab extends obsidian.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display() {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl('h3', { text: 'Shared folder target' });

    new obsidian.Setting(containerEl)
      .setName('Folder path')
      .setDesc('Vault-relative folder path, for example Private or things/secret.')
      .addText((text) => {
        text
          .setPlaceholder('Private')
          .setValue(this.plugin.settings.folderPath)
          .onChange(async (value) => {
            this.plugin.settings.folderPath = normalizeFolderPath(value);
            await this.plugin.saveSettings();
          });
      });

    new obsidian.Setting(containerEl)
      .setName('Folder lock')
      .setDesc('Master switch for the Obsidian folder lock.')
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.folderLockEnabled)
          .onChange(async (value) => {
            this.plugin.settings.folderLockEnabled = value;
            await this.plugin.saveSettings();
            if (value) {
              const locked = await this.plugin.lockConfiguredFolder();
              if (!locked) {
                this.plugin.settings.folderLockEnabled = false;
                await this.plugin.saveSettings();
              }
            } else {
              this.plugin.restoreAllFilesystemLocks();
              this.plugin.clearFolderDecorations();
              new obsidian.Notice('Folder lock disabled.');
            }
            this.display();
          });
      });

    new obsidian.Setting(containerEl)
      .setName('Sync Finder folder lock')
      .setDesc('Also hide the underlying Finder folder while Folder lock is on. This does not change read permissions, so Obsidian can still open.')
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.filesystemLockEnabled)
          .onChange(async (value) => {
            this.plugin.settings.filesystemLockEnabled = value;
            if (value) {
              this.plugin.applyFilesystemLocksForLockedFolders();
            } else {
              this.plugin.restoreAllFilesystemLocks();
            }
            await this.plugin.saveSettings();
          });
      });

    new obsidian.Setting(containerEl)
      .setName('Content lock')
      .setDesc('Master switch for content encryption. Turning it off disables new encryption; existing encrypted files stay encrypted.')
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.contentEncryptionEnabled)
          .onChange(async (value) => {
            this.plugin.settings.contentEncryptionEnabled = value;
            await this.plugin.saveSettings();
            if (value) {
              const encrypted = await this.plugin.encryptConfiguredFolder();
              if (!encrypted) {
                this.plugin.settings.contentEncryptionEnabled = false;
                await this.plugin.saveSettings();
              }
            } else {
              new obsidian.Notice('Content lock disabled. Existing encrypted files are unchanged.');
            }
            this.display();
          });
      });
  }
}

module.exports = class FolderCryptoPlugin extends obsidian.Plugin {
  async onload() {
    await this.loadSettings();
    this.unlockedFolders = new Set();
    this.restoreWorkspaceOpeners = null;
    this.fileExplorerObserver = null;
    this.decorationTimer = null;
    this.addSettingTab(new FolderCryptoSettingTab(this.app, this));
    this.safeRun('apply startup filesystem locks', () => this.applyFilesystemLocksForLockedFolders());

    this.addRibbonIcon('lock', 'Encrypt configured folder', () => {
      this.encryptConfiguredFolder();
    });

    this.addCommand({
      id: 'encrypt-configured-folder',
      name: 'Encrypt configured folder',
      callback: () => this.encryptConfiguredFolder()
    });

    this.addCommand({
      id: 'decrypt-configured-folder',
      name: 'Decrypt configured folder',
      callback: () => this.decryptConfiguredFolder()
    });

    this.addCommand({
      id: 'decrypt-all-encrypted-files',
      name: 'Decrypt all Folder Crypto encrypted files in vault',
      callback: () => this.decryptAllEncryptedFiles()
    });

    this.addCommand({
      id: 'lock-configured-folder',
      name: 'Lock configured folder in Obsidian',
      callback: () => this.lockConfiguredFolder()
    });

    this.addCommand({
      id: 'unlock-configured-folder',
      name: 'Unlock configured folder in Obsidian',
      callback: () => this.unlockConfiguredFolder()
    });

    this.addCommand({
      id: 'lock-all-folders',
      name: 'Lock all Folder Crypto folders',
      callback: () => this.lockAllFolders()
    });

    this.addCommand({
      id: 'remove-configured-folder-lock',
      name: 'Remove configured folder lock',
      callback: () => this.removeConfiguredFolderLock()
    });

    this.registerEvent(
      this.app.workspace.on('file-menu', (menu, file) => {
        if (!(file instanceof obsidian.TFolder)) {
          return;
        }
        menu.addSeparator();
        if (this.settings.folderLockEnabled) {
          menu.addItem((item) => {
            item
              .setTitle('Lock folder in Obsidian')
              .setIcon('lock')
              .onClick(() => this.lockFolder(file.path));
          });
          menu.addItem((item) => {
            item
              .setTitle('Unlock folder in Obsidian')
              .setIcon('unlock')
              .onClick(() => this.unlockFolder(file.path));
          });
          menu.addItem((item) => {
            item
              .setTitle('Remove Obsidian folder lock')
              .setIcon('key')
              .onClick(() => this.removeFolderLock(file.path));
          });
        }
        menu.addSeparator();
        if (this.settings.contentEncryptionEnabled) {
          menu.addItem((item) => {
            item
              .setTitle('Encrypt folder with password')
              .setIcon('lock')
              .onClick(() => this.encryptFolder(file.path));
          });
        }
        menu.addItem((item) => {
          item
            .setTitle('Decrypt folder with password')
            .setIcon('unlock')
            .onClick(() => this.decryptFolder(file.path));
        });
      })
    );

    this.safeRun('install workspace gate', () => this.installWorkspaceGate());
    this.safeRun('register file-open gate', () => {
      this.registerEvent(
        this.app.workspace.on('file-open', (file) => {
          if (file && this.isPathLocked(file.path)) {
            this.closeLockedActiveLeaf(file);
          }
        })
      );
    });
    this.safeRun('start folder decorations', () => this.startFolderDecorations());
  }

  onunload() {
    this.safeRun('restore filesystem locks', () => this.restoreAllFilesystemLocks());
    if (this.restoreWorkspaceOpeners) {
      this.restoreWorkspaceOpeners();
      this.restoreWorkspaceOpeners = null;
    }
    if (this.fileExplorerObserver) {
      this.fileExplorerObserver.disconnect();
      this.fileExplorerObserver = null;
    }
    if (this.decorationTimer) {
      window.clearTimeout(this.decorationTimer);
      this.decorationTimer = null;
    }
    this.clearFolderDecorations();
  }

  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    this.settings.folderPath = normalizeFolderPath(this.settings.folderPath);
    this.settings.folderLockEnabled = this.settings.folderLockEnabled !== false;
    this.settings.contentEncryptionEnabled = this.settings.contentEncryptionEnabled !== false;
    this.settings.extensions = normalizeExtensions(this.settings.extensions).join(',');
    this.settings.filesystemLockEnabled = this.settings.filesystemLockEnabled !== false;
    this.settings.lockedFolders = Array.isArray(this.settings.lockedFolders)
      ? this.settings.lockedFolders
          .map((entry) => Object.assign({}, entry, { path: normalizeFolderPath(entry.path) }))
          .filter((entry) => entry.path && entry.hash && entry.salt)
      : [];
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  safeRun(label, fn) {
    try {
      return fn();
    } catch (error) {
      console.warn(`[folder-crypto] ${label} failed`, error);
      return null;
    }
  }

  async encryptConfiguredFolder() {
    if (!this.settings.contentEncryptionEnabled) {
      new obsidian.Notice('Content encryption is disabled.');
      return false;
    }
    if (!this.settings.folderPath) {
      new obsidian.Notice('Set a folder path in Folder Crypto settings first.');
      return false;
    }
    return this.encryptFolder(this.settings.folderPath);
  }

  async decryptConfiguredFolder() {
    if (!this.settings.folderPath) {
      new obsidian.Notice('Set a folder path in Folder Crypto settings first.');
      return;
    }
    await this.decryptFolder(this.settings.folderPath);
  }

  async encryptFolder(folderPath) {
    if (!this.settings.contentEncryptionEnabled) {
      new obsidian.Notice('Content encryption is disabled.');
      return false;
    }
    return this.processFolder(folderPath, 'encrypt');
  }

  async decryptFolder(folderPath) {
    await this.processFolder(folderPath, 'decrypt');
  }

  async decryptAllEncryptedFiles() {
    const encryptedFiles = [];
    const files = this.app.vault.getMarkdownFiles();
    for (const file of files) {
      try {
        const content = await this.app.vault.read(file);
        if (isEncryptedContent(content)) {
          encryptedFiles.push({ file, content });
        }
      } catch (error) {
        console.warn('[folder-crypto] Could not inspect file', file.path, error);
      }
    }

    if (!encryptedFiles.length) {
      new obsidian.Notice('No Folder Crypto encrypted files found.');
      return;
    }

    await this.processEncryptedCandidates(encryptedFiles, {
      mode: 'decrypt',
      title: 'Decrypt all encrypted files',
      message: `Decrypt ${encryptedFiles.length} Folder Crypto encrypted file(s) in this vault?`,
      confirmText: 'Decrypt all'
    });
  }

  async lockConfiguredFolder() {
    if (!this.settings.folderLockEnabled) {
      new obsidian.Notice('Folder lock is disabled.');
      return false;
    }
    if (!this.settings.folderPath) {
      new obsidian.Notice('Set a folder path in Folder Crypto settings first.');
      return false;
    }
    return this.lockFolder(this.settings.folderPath);
  }

  async unlockConfiguredFolder() {
    if (!this.settings.folderPath) {
      new obsidian.Notice('Set a folder path in Folder Crypto settings first.');
      return;
    }
    await this.unlockFolder(this.settings.folderPath);
  }

  lockAllFolders() {
    if (!this.settings.folderLockEnabled) {
      new obsidian.Notice('Folder lock is disabled.');
      return;
    }
    this.unlockedFolders.clear();
    for (const lock of this.settings.lockedFolders) {
      this.applyFilesystemLock(lock);
    }
    this.decorateLockedFolders();
    new obsidian.Notice('All Folder Crypto folders are locked.');
  }

  async removeConfiguredFolderLock() {
    if (!this.settings.folderPath) {
      new obsidian.Notice('Set a folder path in Folder Crypto settings first.');
      return;
    }
    await this.removeFolderLock(this.settings.folderPath);
  }

  getFolderLock(folderPath) {
    const normalized = normalizeFolderPath(folderPath);
    return this.settings.lockedFolders.find((entry) => entry.path === normalized) || null;
  }

  getLockForPath(path) {
    const matches = this.settings.lockedFolders
      .filter((entry) => pathIsInsideFolder(path, entry.path))
      .sort((a, b) => b.path.length - a.path.length);
    return matches[0] || null;
  }

  isPathLocked(path) {
    if (!this.settings.folderLockEnabled) {
      return false;
    }
    const lock = this.getLockForPath(path);
    return Boolean(lock && !this.unlockedFolders.has(lock.path));
  }

  async lockFolder(folderPath) {
    if (!this.settings.folderLockEnabled) {
      new obsidian.Notice('Folder lock is disabled.');
      return false;
    }
    const folder = this.getFolder(folderPath);
    if (!folder) {
      return false;
    }
    let lock = this.getFolderLock(folder.path);
    if (!lock) {
      const password = await new PasswordModal(
        this.app,
        'Set folder lock password',
        'Set password',
        true
      ).waitForPassword();
      if (!password) {
        return false;
      }
      lock = Object.assign({ path: folder.path }, hashPassword(password));
      this.captureFilesystemMode(lock);
      this.settings.lockedFolders.push(lock);
      await this.saveSettings();
    }

    this.unlockedFolders.delete(lock.path);
    this.applyFilesystemLock(lock);
    this.decorateLockedFolders();
    new obsidian.Notice(`Locked: ${folder.path}`);
    return true;
  }

  async unlockFolder(folderPath) {
    const normalized = normalizeFolderPath(folderPath);
    const lock = this.getFolderLock(normalized);
    if (!lock) {
      new obsidian.Notice(`No folder lock exists for: ${normalized}`);
      return false;
    }

    const unlocked = await this.promptUnlock(lock);
    if (unlocked) {
      new obsidian.Notice(`Unlocked for this Obsidian session: ${lock.path}`);
    }
    return unlocked;
  }

  async removeFolderLock(folderPath) {
    const normalized = normalizeFolderPath(folderPath);
    const lock = this.getFolderLock(normalized);
    if (!lock) {
      new obsidian.Notice(`No folder lock exists for: ${normalized}`);
      return;
    }
    const unlocked = this.unlockedFolders.has(lock.path) || await this.promptUnlock(lock);
    if (!unlocked) {
      return;
    }
    this.settings.lockedFolders = this.settings.lockedFolders.filter((entry) => entry.path !== lock.path);
    this.unlockedFolders.delete(lock.path);
    this.restoreFilesystemLock(lock);
    await this.saveSettings();
    this.decorateLockedFolders();
    new obsidian.Notice(`Removed folder lock: ${lock.path}`);
  }

  async promptUnlock(lock) {
    const password = await new PasswordModal(
      this.app,
      `Unlock ${lock.path}`,
      'Unlock',
      false
    ).waitForPassword();
    if (!password) {
      return false;
    }
    if (!verifyPassword(password, lock)) {
      new obsidian.Notice('Wrong password.');
      return false;
    }
    this.restoreFilesystemLock(lock);
    this.unlockedFolders.add(lock.path);
    this.decorateLockedFolders();
    return true;
  }

  getAbsoluteFolderPath(folderPath) {
    const path = getNodeModule('path');
    if (!path) {
      return null;
    }
    const basePath = getVaultBasePath(this.app);
    if (!basePath) {
      return null;
    }
    const absoluteBase = path.resolve(basePath);
    const absoluteFolder = path.resolve(absoluteBase, normalizeFolderPath(folderPath));
    if (absoluteFolder !== absoluteBase && !absoluteFolder.startsWith(`${absoluteBase}${path.sep}`)) {
      return null;
    }
    return absoluteFolder;
  }

  captureFilesystemMode(lock) {
    return lock;
  }

  applyFilesystemLocksForLockedFolders() {
    if (!this.settings.filesystemLockEnabled) {
      return;
    }
    for (const lock of this.settings.lockedFolders) {
      if (!this.unlockedFolders.has(lock.path)) {
        this.applyFilesystemLock(lock);
      }
    }
  }

  restoreAllFilesystemLocks() {
    for (const lock of this.settings.lockedFolders) {
      this.restoreFilesystemLock(lock, { force: true });
    }
  }

  applyFilesystemLock(lock) {
    if (!this.settings.filesystemLockEnabled) {
      return;
    }
    const childProcess = getNodeModule('child_process');
    if (!childProcess) {
      return;
    }
    const absoluteFolder = this.getAbsoluteFolderPath(lock.path);
    if (!absoluteFolder) {
      return;
    }
    try {
      childProcess.execFileSync('chflags', ['hidden', absoluteFolder], { stdio: 'ignore' });
    } catch (error) {
      console.warn('[folder-crypto] Could not hide Finder folder', lock.path, error);
      new obsidian.Notice(`Could not hide Finder folder: ${lock.path}`);
    }
  }

  restoreFilesystemLock(lock, options = {}) {
    if (!this.settings.filesystemLockEnabled && !options.force) {
      return;
    }
    const childProcess = getNodeModule('child_process');
    if (!childProcess) {
      return;
    }
    const absoluteFolder = this.getAbsoluteFolderPath(lock.path);
    if (!absoluteFolder) {
      return;
    }
    try {
      childProcess.execFileSync('chflags', ['nohidden', absoluteFolder], { stdio: 'ignore' });
    } catch (error) {
      console.warn('[folder-crypto] Could not show Finder folder', lock.path, error);
      new obsidian.Notice(`Could not show Finder folder: ${lock.path}`);
    }
  }

  async ensureUnlockedForPath(path) {
    const lock = this.getLockForPath(path);
    if (!lock || this.unlockedFolders.has(lock.path)) {
      return true;
    }
    return this.promptUnlock(lock);
  }

  installWorkspaceGate() {
    const workspace = this.app.workspace;
    const originalOpenFile = workspace.openFile.bind(workspace);
    const originalOpenLinkText = workspace.openLinkText.bind(workspace);

    workspace.openFile = async (file, openState) => {
      if (file instanceof obsidian.TFile && !(await this.ensureUnlockedForPath(file.path))) {
        return null;
      }
      return originalOpenFile(file, openState);
    };

    workspace.openLinkText = async (linktext, sourcePath, newLeaf, openState) => {
      const file = this.app.metadataCache.getFirstLinkpathDest(linktext, sourcePath);
      if (file instanceof obsidian.TFile && !(await this.ensureUnlockedForPath(file.path))) {
        return null;
      }
      return originalOpenLinkText(linktext, sourcePath, newLeaf, openState);
    };

    this.restoreWorkspaceOpeners = () => {
      workspace.openFile = originalOpenFile;
      workspace.openLinkText = originalOpenLinkText;
    };
  }

  closeLockedActiveLeaf(file) {
    window.setTimeout(async () => {
      if (!this.isPathLocked(file.path)) {
        return;
      }
      const lockedLeaf = this.findOpenLeafForFile(file);
      if (lockedLeaf) {
        lockedLeaf.detach();
      }
      const unlocked = await this.ensureUnlockedForPath(file.path);
      if (unlocked) {
        await this.app.workspace.getLeaf(false).openFile(file);
      }
    }, 0);
  }

  findOpenLeafForFile(file) {
    if (typeof this.app.workspace.iterateAllLeaves !== 'function') {
      const view = this.app.workspace.getActiveViewOfType(obsidian.MarkdownView);
      return view?.file?.path === file.path ? view.leaf : null;
    }
    let found = null;
    this.app.workspace.iterateAllLeaves((leaf) => {
      const view = leaf.view;
      if (view instanceof obsidian.MarkdownView && view.file?.path === file.path) {
        found = leaf;
      }
    });
    return found;
  }

  startFolderDecorations() {
    this.decorateLockedFolders();
    this.fileExplorerObserver = new MutationObserver(() => this.scheduleFolderDecorations());
    this.fileExplorerObserver.observe(document.body, { childList: true, subtree: true });
  }

  scheduleFolderDecorations() {
    if (this.decorationTimer) {
      return;
    }
    this.decorationTimer = window.setTimeout(() => {
      this.decorationTimer = null;
      this.decorateLockedFolders();
    }, 100);
  }

  clearFolderDecorations() {
    document.querySelectorAll('.folder-crypto-lock-badge').forEach((el) => el.remove());
  }

  decorateLockedFolders() {
    if (!this.settings.folderLockEnabled) {
      this.clearFolderDecorations();
      return;
    }
    const lockedPaths = new Set(this.settings.lockedFolders.map((entry) => entry.path));
    document.querySelectorAll('.folder-crypto-lock-badge').forEach((badge) => {
      const titleEl = badge.closest('.nav-folder-title[data-path], .tree-item-self[data-path]');
      const path = titleEl ? normalizeFolderPath(titleEl.getAttribute('data-path')) : '';
      if (!lockedPaths.has(path)) {
        badge.remove();
      }
    });
    if (!lockedPaths.size) {
      return;
    }
    document.querySelectorAll('.nav-folder-title[data-path], .tree-item-self[data-path]').forEach((titleEl) => {
      const path = normalizeFolderPath(titleEl.getAttribute('data-path'));
      if (!lockedPaths.has(path)) {
        return;
      }
      const contentEl = titleEl.querySelector('.nav-folder-title-content, .tree-item-inner') || titleEl;
      if (contentEl.querySelector('.folder-crypto-lock-badge')) {
        return;
      }
      const badge = document.createElement('span');
      badge.className = 'folder-crypto-lock-badge';
      badge.textContent = ' 🔒';
      badge.setAttribute('aria-label', 'Folder locked by Folder Crypto');
      contentEl.appendChild(badge);
    });
  }

  getFolder(folderPath) {
    const normalized = normalizeFolderPath(folderPath);
    const folder = this.app.vault.getAbstractFileByPath(normalized);
    if (!(folder instanceof obsidian.TFolder)) {
      new obsidian.Notice(`Folder not found: ${normalized}`);
      return null;
    }
    return folder;
  }

  collectFiles(folder) {
    const extensions = new Set(normalizeExtensions(this.settings.extensions));
    const files = [];
    const walk = (current) => {
      for (const child of current.children) {
        if (child instanceof obsidian.TFile && extensions.has(child.extension.toLowerCase())) {
          files.push(child);
        } else if (child instanceof obsidian.TFolder && this.settings.includeSubfolders) {
          walk(child);
        }
      }
    };
    walk(folder);
    return files;
  }

  async processFolder(folderPath, mode) {
    const folder = this.getFolder(folderPath);
    if (!folder) {
      return false;
    }

    const allFiles = this.collectFiles(folder);
    const candidates = [];
    for (const file of allFiles) {
      const content = await this.app.vault.read(file);
      const encrypted = isEncryptedContent(content);
      if ((mode === 'encrypt' && !encrypted) || (mode === 'decrypt' && encrypted)) {
        candidates.push({ file, content });
      }
    }

    if (!candidates.length) {
      new obsidian.Notice(`No files to ${mode} in ${folder.path}.`);
      return false;
    }

    return this.processEncryptedCandidates(candidates, {
      mode,
      title: mode === 'encrypt' ? 'Encrypt folder' : 'Decrypt folder',
      message: `${mode === 'encrypt' ? 'Encrypt' : 'Decrypt'} ${candidates.length} file(s) in "${folder.path}"?`,
      confirmText: mode === 'encrypt' ? 'Encrypt' : 'Decrypt'
    });
  }

  async processEncryptedCandidates(candidates, options) {
    const { mode, title, message, confirmText } = options;
    const confirmed = await new ConfirmModal(
      this.app,
      title,
      message,
      confirmText
    ).waitForConfirm();
    if (!confirmed) {
      return false;
    }

    const password = await new PasswordModal(
      this.app,
      mode === 'encrypt' ? 'Encryption password' : 'Decryption password',
      mode === 'encrypt' ? 'Encrypt' : 'Decrypt',
      mode === 'encrypt'
    ).waitForPassword();
    if (!password) {
      return false;
    }

    let changed = 0;
    const failures = [];
    for (const { file, content } of candidates) {
      try {
        if (mode === 'encrypt') {
          if (this.settings.createPlaintextBackup) {
            const backupPath = `${file.path}.ofc-backup`;
            if (!(await this.app.vault.adapter.exists(backupPath))) {
              await this.app.vault.adapter.write(backupPath, content);
            }
          }
          await this.app.vault.modify(file, encryptText(content, password));
        } else {
          await this.app.vault.modify(file, decryptText(content, password));
        }
        changed += 1;
      } catch (error) {
        failures.push(`${file.path}: ${error.message || error}`);
      }
    }

    if (failures.length) {
      console.error('[folder-crypto] Failed files:', failures);
      new obsidian.Notice(`${mode} finished: ${changed} changed, ${failures.length} failed. See developer console.`);
      return changed > 0;
    }
    new obsidian.Notice(`${mode} finished: ${changed} file(s).`);
    return true;
  }
};
