import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { promisify } from 'node:util';

const execute = promisify(execFile);

const manifestUrl = new URL('./qemu-slim-11.1.0.json', import.meta.url);
const usage = 'Usage: node setup/build-slim-qemu.mjs <verified QEMU folder> <new output folder>';

function relativeFile(name) {
  return typeof name === 'string' && name.split('/').every(part =>
    part && part !== '.' && part !== '..' && !/[\\:\x00-\x1f]/.test(part));
}

function under(base, candidate) {
  const relative = path.relative(base, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative.split(path.sep)[0] !== '..');
}

async function localDirectory(value) {
  const absolute = path.resolve(value);
  const root = path.parse(absolute).root;
  if (!/^[A-Za-z]:\\$/.test(root)) {
    throw new Error('Use a local drive for the source and output folders.');
  }
  const windows = process.env.SystemRoot;
  if (!windows || !path.isAbsolute(windows)) throw new Error('The Windows system folder is unavailable.');
  const powershell = path.join(windows, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  try {
    await execute(powershell, [
      '-NoProfile', '-NonInteractive', '-Command',
      "if ([IO.DriveInfo]::new($env:SVM_QEMU_DRIVE).DriveType -notin 'Fixed','Removable','Ram') {exit 1}",
    ], {
      env: { SystemRoot: windows, WINDIR: windows, SVM_QEMU_DRIVE: root },
      timeout: 8000, windowsHide: true,
    });
  } catch {
    throw new Error('Use a local fixed, removable or RAM drive for the source and output.');
  }
  for (let current = absolute; ; current = path.dirname(current)) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error('The source and output folders must be ordinary directories.');
    }
    if (path.dirname(current) === current) break;
  }
  return realpath(absolute);
}

async function fileRecord(root, name) {
  if (!relativeFile(name)) throw new Error('The bundle manifest has an invalid file path.');
  const file = path.join(root, name);
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || path.relative(file, await realpath(file)) !== '') {
    throw new Error('The source has a linked or unexpected file: ' + name);
  }
  const digest = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(file)) {
    digest.update(chunk);
    bytes += chunk.length;
  }
  if (bytes !== info.size) throw new Error('The source changed while reading: ' + name);
  return { name, bytes, sha256: digest.digest('hex') };
}

async function treeFiles(root, name) {
  if (!relativeFile(name)) throw new Error('The bundle manifest has an invalid directory path.');
  const directory = path.join(root, name);
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || !under(root, await realpath(directory))) {
    throw new Error('The source has a linked or unexpected folder: ' + name);
  }
  const records = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const child = name + '/' + entry.name;
    if (entry.isDirectory()) records.push(...await treeFiles(root, child));
    else records.push(await fileRecord(root, child));
  }
  return records;
}

function treeReceipt(records) {
  const digest = createHash('sha256');
  let bytes = 0;
  for (const file of records) {
    digest.update(JSON.stringify([file.name, file.bytes, file.sha256]) + '\n');
    bytes += file.bytes;
  }
  return { count: records.length, bytes, sha256: digest.digest('hex') };
}

function matchReceipt(actual, expected, name) {
  if (actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256
      || (actual.count !== undefined && actual.count !== expected.count)) {
    throw new Error('The verified QEMU files differ at ' + name + '. Use the original verified package.');
  }
}

async function refuseExisting(destination) {
  try {
    await lstat(destination);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  throw new Error('Choose a new output folder.');
}

async function build(sourceArg, destArg) {
  const manifest = JSON.parse(await readFile(manifestUrl, 'utf8'));
  const source = await localDirectory(sourceArg);
  const destPath = path.resolve(destArg);
  const parent = await localDirectory(path.dirname(destPath));
  const destination = path.join(parent, path.basename(destPath));
  if (under(source, destination) || under(destination, source)) {
    throw new Error('The source and output folders must be separate.');
  }
  await refuseExisting(destination);

  const records = [];
  for (const expected of manifest.files) {
    const file = await fileRecord(source, expected.name);
    matchReceipt(file, expected, file.name);
    records.push(file);
  }
  for (const expected of manifest.trees) {
    const files = await treeFiles(source, expected.name);
    matchReceipt(treeReceipt(files), expected, expected.name);
    records.push(...files);
  }
  if (new Set(records.map(file => file.name.toLowerCase())).size !== records.length) {
    throw new Error('The manifest selects a file more than once.');
  }

  const stage = await mkdtemp(path.join(parent, '.svm-slim-qemu-'));
  let published = false;
  try {
    for (const file of records) {
      const target = path.join(stage, file.name);
      await mkdir(path.dirname(target), { recursive: true });
      await pipeline(createReadStream(path.join(source, file.name)), createWriteStream(target, { flags: 'wx' }));
      matchReceipt(await fileRecord(stage, file.name), file, file.name);
    }
    const integrity = treeReceipt(records);
    const receipt = { release: manifest.release, source: manifest.source, ...integrity };
    await writeFile(path.join(stage, 'svm-qemu-receipt.json'), JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
    await refuseExisting(destination);
    await rename(stage, destination);
    published = true;
    console.log('Slim QEMU ' + receipt.release + ' contains ' + receipt.count + ' runtime files and ' + receipt.bytes + ' bytes.');
  } finally {
    if (!published && path.dirname(stage) === parent && path.basename(stage).startsWith('.svm-slim-qemu-')) {
      const held = await realpath(stage).catch(() => null);
      if (held === stage) await rm(stage, { recursive: true, force: true, maxRetries: 2 });
    }
  }
}

try {
  const args = process.argv.slice(2);
  if (args.length !== 2) throw new Error(usage);
  if (process.platform !== 'win32') throw new Error('This script builds the Windows QEMU folder.');
  await build(...args);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
