import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";

export function writeJsonAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tempFile = `${file}.${process.pid}.${Date.now()}.${randomBytes(6).toString("hex")}.tmp`;
  const data = JSON.stringify(value, null, 2);
  const fd = fs.openSync(tempFile, "w", 0o600);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tempFile, file);
  const directoryFd = fs.openSync(path.dirname(file), "r");
  try {
    fs.fsyncSync(directoryFd);
  } finally {
    fs.closeSync(directoryFd);
  }
}
