package dev.logiclabs.remotekey

import java.io.InputStream

/** Read one byte beyond the partition limit so the caller can reject oversized
 * input without loading an arbitrarily large file from a document provider. */
internal object FirmwareImageReader {
    const val MAX_IMAGE_SIZE = 0x1e0000

    fun read(input: InputStream): ByteArray {
        val buffer = ByteArray(MAX_IMAGE_SIZE + 1)
        var size = 0
        while (size < buffer.size) {
            val count = input.read(buffer, size, buffer.size - size)
            if (count < 0) break
            if (count == 0) {
                val next = input.read()
                if (next < 0) break
                buffer[size++] = next.toByte()
            } else size += count
        }
        return buffer.copyOf(size)
    }
}
