import { closeSync, openSync, readSync } from 'fs';
import { decodeBlock } from 'uf2';
import { RP2040 } from 'rp2040js';

const FLASH_START_ADDRESS = 268435456;
const CIRCUITPYTHON_FS_FLASH_START = 0x100000;
const CIRCUITPYTHON_FS_BLOCKSIZE = 4096;

export function loadFlashImage(filename: string, rp2040: RP2040) {
    const flashStart = CIRCUITPYTHON_FS_FLASH_START;
    const blockSize = CIRCUITPYTHON_FS_BLOCKSIZE;

    const file = openSync(filename, 'r');
    const buffer = new Uint8Array(blockSize);
    let flashAddress = flashStart;
    while (readSync(file, buffer) === buffer.length) {
        rp2040.flash.set(buffer, flashAddress);
        flashAddress += buffer.length;
    }
    closeSync(file);
}

export function loadUF2(filename: string, rp2040: RP2040) {
    const file = openSync(filename, 'r');
    const buffer = new Uint8Array(512);
    while (readSync(file, buffer) === buffer.length) {
        const block = decodeBlock(buffer);
        const { flashAddress, payload } = block;
        rp2040.flash.set(payload, flashAddress - FLASH_START_ADDRESS);
    }
    closeSync(file);
}