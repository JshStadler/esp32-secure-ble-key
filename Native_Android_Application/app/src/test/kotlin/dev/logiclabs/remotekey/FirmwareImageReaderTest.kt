package dev.logiclabs.remotekey

import java.io.ByteArrayInputStream
import java.io.InputStream
import org.junit.Assert.*
import org.junit.Test

class FirmwareImageReaderTest {
    @Test fun acceptsFirmwareAtThePartitionLimitWithoutChangingBytes() {
        val bytes = ByteArray(FirmwareImageReader.MAX_IMAGE_SIZE) { it.toByte() }
        assertArrayEquals(bytes, FirmwareImageReader.read(ByteArrayInputStream(bytes)))
    }

    @Test fun oversizedOrEndlessInputStopsAtOneByteBeyondTheLimit() {
        var consumed = 0
        val endless = object : InputStream() {
            override fun read(): Int { consumed++; return 42 }
            override fun read(bytes: ByteArray, offset: Int, count: Int): Int {
                bytes.fill(42, offset, offset + count)
                consumed += count
                return count
            }
        }
        val image = FirmwareImageReader.read(endless)
        assertEquals(FirmwareImageReader.MAX_IMAGE_SIZE + 1, consumed)
        assertEquals(consumed, image.size)
        assertTrue(image.size > FirmwareImageReader.MAX_IMAGE_SIZE)
    }

    @Test fun handlesEmptyAndShortReads() {
        assertTrue(FirmwareImageReader.read(ByteArrayInputStream(byteArrayOf())).isEmpty())
        val fragmented = object : ByteArrayInputStream(byteArrayOf(1, 2, 3)) {
            override fun read(bytes: ByteArray, offset: Int, count: Int) = super.read(bytes, offset, minOf(1, count))
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), FirmwareImageReader.read(fragmented))
    }

    @Test fun zeroLengthProviderReadCannotCauseAnInfiniteLoop() {
        val input = object : ByteArrayInputStream(byteArrayOf(4, 5)) {
            override fun read(bytes: ByteArray, offset: Int, count: Int) = 0
        }
        assertArrayEquals(byteArrayOf(4, 5), FirmwareImageReader.read(input))
    }
}
