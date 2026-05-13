'use strict';

const obsidian = require('obsidian');

const ENCRYPTION_MARKER = '%% folder-crypto: encrypted %%';
const ENVELOPE_VERSION = 1;
const LOCK_BADGE_CLASS = 'folder-crypto-lock-badge';
const HIDDEN_ITEM_CLASS = 'folder-crypto-hidden-item';
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

function toBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

function fromBase64(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomBytes(n) {
  return (globalThis.crypto || window.crypto).getRandomValues(new Uint8Array(n));
}

function buildEncryptedNote(envelope) {
  return `${ENCRYPTION_MARKER}\n\n\`\`\`json\n${JSON.stringify(envelope, null, 2)}\n\`\`\`\n`;
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

function getWebCrypto() {
  return globalThis.crypto || window.crypto;
}

async function importPbkdf2Key(password) {
  return getWebCrypto().subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
}

async function deriveBits(password, salt, iterations) {
  const keyMaterial = await importPbkdf2Key(password);
  const bits = await getWebCrypto().subtle.deriveBits(
    { name: 'PBKDF2', salt: salt instanceof Uint8Array ? salt : fromBase64(salt), iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function deriveAesKey(password, salt, iterations) {
  const keyMaterial = await importPbkdf2Key(password);
  return getWebCrypto().subtle.deriveKey(
    { name: 'PBKDF2', salt: salt instanceof Uint8Array ? salt : fromBase64(salt), iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const iterations = 210000;
  const hash = await deriveBits(password, salt, iterations);
  return {
    kdf: 'pbkdf2-sha256',
    iterations,
    salt: toBase64(salt),
    hash: toBase64(hash)
  };
}

async function verifyPassword(password, verifier) {
  const expected = fromBase64(verifier.hash);
  const actual = await deriveBits(password, fromBase64(verifier.salt), Number(verifier.iterations || 210000));
  if (expected.length !== actual.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ actual[i];
  return diff === 0;
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

async function encryptText(plaintext, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const iterations = 210000;
  const key = await deriveAesKey(password, salt, iterations);
  const encrypted = await getWebCrypto().subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const encryptedBytes = new Uint8Array(encrypted);
  const tagOffset = encryptedBytes.length - 16;
  const data = encryptedBytes.slice(0, tagOffset);
  const tag = encryptedBytes.slice(tagOffset);

  return buildEncryptedNote({
    version: ENVELOPE_VERSION,
    algorithm: 'aes-256-gcm',
    kdf: 'pbkdf2-sha256',
    iterations,
    salt: toBase64(salt),
    iv: toBase64(iv),
    tag: toBase64(tag),
    data: toBase64(data)
  });
}

async function decryptText(content, password) {
  const envelope = parseEncryptedNote(content);
  if (envelope.version !== ENVELOPE_VERSION || envelope.algorithm !== 'aes-256-gcm') {
    throw new Error('Unsupported encrypted file version.');
  }

  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const tag = fromBase64(envelope.tag);
  const data = fromBase64(envelope.data);

  // Web Crypto expects ciphertext + auth tag concatenated
  const ciphertext = new Uint8Array(data.length + tag.length);
  ciphertext.set(data);
  ciphertext.set(tag, data.length);

  const key = await deriveAesKey(password, salt, Number(envelope.iterations || 210000));
  const decrypted = await getWebCrypto().subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
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

    // === Locked Folders ===
    containerEl.createEl('h3', { text: 'Locked folders' });

    if (this.plugin.settings.lockedFolders.length === 0) {
      containerEl.createEl('p', {
        text: 'No folders locked yet. Add a folder below or right-click any folder in the file explorer.',
        cls: 'setting-item-description'
      });
    }

    for (const lock of [...this.plugin.settings.lockedFolders]) {
      const isUnlocked = this.plugin.unlockedFolders.has(lock.path);
      const row = new obsidian.Setting(containerEl)
        .setName(lock.path)
        .setDesc(isUnlocked ? 'Unlocked this session' : 'Locked');

      if (isUnlocked) {
        row.addButton((btn) => {
          btn.setButtonText('Lock').onClick(async () => {
            await this.plugin.lockFolder(lock.path);
            this.display();
          });
        });
      } else {
        row.addButton((btn) => {
          btn.setButtonText('Unlock').onClick(async () => {
            await this.plugin.unlockFolder(lock.path);
            this.display();
          });
        });
      }

      row.addButton((btn) => {
        btn.setButtonText('Remove').setWarning().onClick(async () => {
          await this.plugin.removeFolderLock(lock.path);
          this.display();
        });
      });
    }

    let newFolderPath = '';
    new obsidian.Setting(containerEl)
      .setName('Add folder lock')
      .setDesc('Vault-relative path, e.g. Private or work/secret. Right-click any folder in the file explorer also works.')
      .addText((text) => {
        text.setPlaceholder('FolderName').onChange((value) => {
          newFolderPath = value;
        });
      })
      .addButton((btn) => {
        btn.setButtonText('Lock').setCta().onClick(async () => {
          const path = newFolderPath.trim();
          if (!path) {
            new obsidian.Notice('Enter a folder path first.');
            return;
          }
          if (!this.plugin.settings.folderLockEnabled) {
            new obsidian.Notice('Enable "Folder lock" below first.');
            return;
          }
          await this.plugin.lockFolder(path);
          this.display();
        });
      });

    // === Options ===
    containerEl.createEl('h3', { text: 'Options' });

    new obsidian.Setting(containerEl)
      .setName('Folder lock')
      .setDesc('Master switch for the Obsidian folder lock.')
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.folderLockEnabled)
          .onChange(async (value) => {
            this.plugin.settings.folderLockEnabled = value;
            await this.plugin.saveSettings();
            if (!value) {
              this.plugin.restoreAllFilesystemLocks();
              this.plugin.clearFolderDecorations();
              new obsidian.Notice('Folder lock disabled.');
            }
            this.display();
          });
      });

    if (!obsidian.Platform.isMobile) {
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
    }

    // === Content Encryption ===
    containerEl.createEl('h3', { text: 'Content encryption' });

    new obsidian.Setting(containerEl)
      .setName('Encryption target folder')
      .setDesc('Vault-relative folder used by the encrypt/decrypt commands and ribbon icon.')
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
    this.unlockPromptPaths = new Set();
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
    this.safeRun('install file explorer gate', () => this.installFileExplorerGate());
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
      lock = Object.assign({ path: folder.path }, await hashPassword(password));
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
    if (!await verifyPassword(password, lock)) {
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

  installFileExplorerGate() {
    this.registerDomEvent(document, 'click', (event) => {
      const target = event.target;
      if (!(target instanceof Element)) {
        return;
      }
      const titleEl = target.closest('.nav-folder-title[data-path], .tree-item-self[data-path]');
      if (!titleEl) {
        return;
      }
      const path = normalizeFolderPath(titleEl.getAttribute('data-path'));
      if (!this.isPathLocked(path) || this.unlockPromptPaths.has(path)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      this.unlockPromptPaths.add(path);
      this.ensureUnlockedForPath(path)
        .finally(() => {
          this.unlockPromptPaths.delete(path);
        });
    }, { capture: true });
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
    document.querySelectorAll(`.${LOCK_BADGE_CLASS}`).forEach((el) => el.remove());
    document.querySelectorAll(`.${HIDDEN_ITEM_CLASS}`).forEach((el) => this.showFileExplorerElement(el));
  }

  decorateLockedFolders() {
    if (!this.settings.folderLockEnabled) {
      this.clearFolderDecorations();
      return;
    }
    const lockedPaths = new Set(
      this.settings.lockedFolders
        .filter((entry) => !this.unlockedFolders.has(entry.path))
        .map((entry) => entry.path)
    );
    document.querySelectorAll(`.${LOCK_BADGE_CLASS}`).forEach((badge) => {
      const titleEl = badge.closest('.nav-folder-title[data-path], .tree-item-self[data-path]');
      const path = titleEl ? normalizeFolderPath(titleEl.getAttribute('data-path')) : '';
      if (!lockedPaths.has(path)) {
        badge.remove();
      }
    });
    document.querySelectorAll(`.${HIDDEN_ITEM_CLASS}`).forEach((el) => this.showFileExplorerElement(el));
    if (!lockedPaths.size) {
      return;
    }
    document.querySelectorAll('.nav-folder-title[data-path], .tree-item-self[data-path]').forEach((titleEl) => {
      const path = normalizeFolderPath(titleEl.getAttribute('data-path'));
      if (!lockedPaths.has(path)) {
        return;
      }
      const contentEl = titleEl.querySelector('.nav-folder-title-content, .tree-item-inner') || titleEl;
      if (contentEl.querySelector(`.${LOCK_BADGE_CLASS}`)) {
        return;
      }
      const badge = document.createElement('span');
      badge.className = LOCK_BADGE_CLASS;
      badge.textContent = ' 🔒';
      badge.setAttribute('aria-label', 'Folder locked by Folder Crypto');
      contentEl.appendChild(badge);
    });
    this.hideLockedFolderDescendants(lockedPaths);
  }

  hideLockedFolderDescendants(lockedPaths) {
    document.querySelectorAll('.nav-folder-title[data-path], .tree-item-self[data-path]').forEach((titleEl) => {
      const path = normalizeFolderPath(titleEl.getAttribute('data-path'));
      if (!lockedPaths.has(path)) {
        return;
      }
      const folderEl = titleEl.closest('.nav-folder, .tree-item');
      const childrenEl = folderEl?.querySelector(':scope > .nav-folder-children, :scope > .tree-item-children');
      if (childrenEl) {
        this.hideFileExplorerElement(childrenEl);
      }
    });

    document.querySelectorAll('.nav-file-title[data-path], .nav-folder-title[data-path], .tree-item-self[data-path]').forEach((titleEl) => {
      const path = normalizeFolderPath(titleEl.getAttribute('data-path'));
      const isHiddenDescendant = Array.from(lockedPaths).some((lockedPath) => {
        return path !== lockedPath && pathIsInsideFolder(path, lockedPath);
      });
      if (!isHiddenDescendant) {
        return;
      }
      const itemEl = titleEl.closest('.nav-file, .nav-folder, .tree-item') || titleEl;
      this.hideFileExplorerElement(itemEl);
    });
  }

  hideFileExplorerElement(el) {
    if (el.classList.contains(HIDDEN_ITEM_CLASS)) {
      return;
    }
    el.dataset.folderCryptoPreviousDisplay = el.style.display || '';
    el.classList.add(HIDDEN_ITEM_CLASS);
    el.setAttribute('aria-hidden', 'true');
    el.style.display = 'none';
  }

  showFileExplorerElement(el) {
    el.style.display = el.dataset.folderCryptoPreviousDisplay || '';
    delete el.dataset.folderCryptoPreviousDisplay;
    el.removeAttribute('aria-hidden');
    el.classList.remove(HIDDEN_ITEM_CLASS);
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
          await this.app.vault.modify(file, await encryptText(content, password));
        } else {
          await this.app.vault.modify(file, await decryptText(content, password));
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
