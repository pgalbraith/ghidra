/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.processors.sleigh;

import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeMap;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.stl.Pair;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.ManualEntry;
import ghidra.util.task.TaskMonitor;

public class SleighLanguageManualIndexTest extends AbstractGenericTest {

	private SleighLanguage language;

	@Before
	public void setUp() throws Exception {
		ResourceFile x86LdefsFile =
			Application.findDataFileInAnyModule("languages/x86.ldefs");
		SleighLanguageProvider provider = new SleighLanguageProvider(x86LdefsFile);
		language = provider.getLanguage(new LanguageID("x86:LE:32:default"), TaskMonitor.DUMMY);
		loadTestIndex(
			"@test.pdf [Test Manual]",
			"!0b11101101, 42",
			"!0b11111101, 43",
			"!0b0000_1111_0000_1111, 44",
			"LD, 85");
	}

	private static final Comparator<String> CASE_INSENSITIVE = (o1, o2) -> {
		if (o1 == null) {
			return o2 == null ? 0 : -1;
		}
		if (o2 == null) {
			return 1;
		}
		return o1.compareToIgnoreCase(o2);
	};

	private void loadTestIndex(String... lines) throws Exception {
		File tempDir = Files.createTempDirectory("manual-index-test").toFile();
		tempDir.deleteOnExit();
		File pdf = new File(tempDir, "test.pdf");
		assertTrue(pdf.createNewFile());

		File idxFile = new File(tempDir, "test.idx");
		Files.write(idxFile.toPath(), List.of(lines));

		setInstanceField("manual", language, new TreeMap<>(CASE_INSENSITIVE));
		setInstanceField("instructionMaskManual", language, new ArrayList<>());
		language.loadIndex(new ResourceFile(idxFile));
	}

	private void assertInstructionMaskMatch(String bitMask, byte[] instructionBytes,
			String expectedPage) throws Exception {
		loadTestIndex("@test.pdf [Test Manual]", "!" + bitMask + ", " + expectedPage);
		ManualEntry entry = language.getManualEntry(null, instructionBytes);
		assertNotNull(entry);
		assertEquals(expectedPage, entry.getPageNumber());
	}

	@Test
	public void testExactSingleByteMatch() throws Exception {
		ManualEntry entry = language.getManualEntry(null, new byte[] { (byte) 0xED });
		assertNotNull(entry);
		assertEquals("42", entry.getPageNumber());
	}

	@Test
	public void testExactSingleByteMatchCommaSyntax() throws Exception {
		ManualEntry entry = language.getManualEntry(null, new byte[] { (byte) 0xFD });
		assertNotNull(entry);
		assertEquals("43", entry.getPageNumber());
	}

	@Test
	public void testMultiByteExactMatch() throws Exception {
		ManualEntry entry = language.getManualEntry(null, new byte[] { 0x0F, 0x0F });
		assertNotNull(entry);
		assertEquals("44", entry.getPageNumber());
	}

	@Test
	public void testMostSpecifiedBitsWins() throws Exception {
		loadTestIndex(
			"@test.pdf [Test Manual]",
			"!0b01xx_xxxx, 10",
			"!0b01xx_x110, 20",
			"LD, 85");
		ManualEntry entry = language.getManualEntry(null, new byte[] { 0x46 });
		assertEquals("20", entry.getPageNumber());
	}

	@Test
	public void testMoreSpecifiedBitsWinsOverLongerMask() throws Exception {
		loadTestIndex(
			"@test.pdf [Test Manual]",
			"!0b11101101, 10",
			"!0b11101101_10100000, 20",
			"LD, 85");
		ManualEntry entry = language.getManualEntry(null, new byte[] { (byte) 0xED, (byte) 0xA0 });
		assertEquals("20", entry.getPageNumber());
	}

	@Test
	public void testEqualSpecifiedBitsFallsBackToMnemonic() throws Exception {
		loadTestIndex(
			"@test.pdf [Test Manual]",
			"!0b1111, 10",
			"!0b1111xxxx, 20",
			"NOP, 99");
		ManualEntry entry = language.getManualEntry("NOP", new byte[] { (byte) 0xF0 });
		assertEquals("99", entry.getPageNumber());
	}

	@Test
	public void testMaskTieFallsBackToMnemonic() throws Exception {
		loadTestIndex(
			"@test.pdf [Test Manual]",
			"!0b0100_0110, 10",
			"!0b0100_0110, 20",
			"LD, 85");
		ManualEntry entry = language.getManualEntry("LD", new byte[] { 0x46 });
		assertEquals("85", entry.getPageNumber());
	}

	@Test
	public void testThreeWayMaskTieFallsBackToMnemonic() throws Exception {
		loadTestIndex(
			"@test.pdf [Test Manual]",
			"!0b0100_0110, 10",
			"!0b0100_0110, 20",
			"!0b0100_0110, 30",
			"LD, 85");
		ManualEntry entry = language.getManualEntry("LD", new byte[] { 0x46 });
		assertEquals("85", entry.getPageNumber());
	}

	@Test
	public void testWildcardBits() throws Exception {
		assertInstructionMaskMatch("0b1110xxxx", new byte[] { (byte) 0xED }, "50");
		assertInstructionMaskMatch("0b1110xxxx", new byte[] { (byte) 0xE0 }, "50");
		loadTestIndex("@test.pdf [Test Manual]", "!0b1110xxxx, 50", "CALL, 95");
		ManualEntry entry = language.getManualEntry("CALL", new byte[] { (byte) 0xCD });
		assertEquals("95", entry.getPageNumber());
	}

	@Test
	public void testWildcardCharactersAndSeparators() throws Exception {
		// 16-bit mask: wildcards and x/X/? scattered through both bytes (not only at the end)
		assertInstructionMaskMatch("0b0000_xxX?_01?0_x1X1",
			new byte[] { 0x01, 0x45 }, "60");
	}

	@Test
	public void testMidMaskWildcards() throws Exception {
		// Under 0b, "_0x" is just bits/separators — not a hex prefix
		assertInstructionMaskMatch("0b01??_0xX1", new byte[] { 0x43 }, "100");
		assertInstructionMaskMatch("0x?E?D", new byte[] { (byte) 0xAE, (byte) 0xAD }, "101");
		assertInstructionMaskMatch("$?1?0", new byte[] { 0x01, 0x50 }, "103");

		loadTestIndex("@test.pdf [Test Manual]", "!0b01??_0xX1, 100");
		assertNull(language.getManualEntry(null, new byte[] { 0x59 }).getPageNumber());
	}

	@Test
	public void testFallbackToMnemonicWhenMaskDoesNotMatch() throws Exception {
		ManualEntry entry = language.getManualEntry("LD", new byte[] { 0x00 });
		assertNotNull(entry);
		assertEquals("85", entry.getPageNumber());
	}

	@Test
	public void testMaskTakesPriorityOverMnemonic() throws Exception {
		ManualEntry entry = language.getManualEntry("LD", new byte[] { (byte) 0xED });
		assertNotNull(entry);
		assertEquals("42", entry.getPageNumber());
	}

	@Test
	public void testCommentsAndCommaSyntax() throws Exception {
		loadTestIndex(
			"# full line comment",
			"",
			"@test.pdf [Test Manual] // manual selector",
			"; another comment",
			"!0b11111110, 60",
			"LD, 90 ; inline comment",
			"CALL, 95");

		assertEquals("60", language.getManualEntry(null, new byte[] { (byte) 0xFE }).getPageNumber());
		assertEquals("90", language.getManualEntry("LD", null).getPageNumber());
		assertEquals("95", language.getManualEntry("CALL", null).getPageNumber());
	}

	@Test
	public void testHexInstructionMask() throws Exception {
		assertInstructionMaskMatch("0xED", new byte[] { (byte) 0xED }, "70");
		assertInstructionMaskMatch("0xEx", new byte[] { (byte) 0xE0 }, "71");
		assertInstructionMaskMatch("0xED_A0", new byte[] { (byte) 0xED, (byte) 0xA0 }, "72");
	}

	@Test
	public void testHexByteLiteralMatchesExactByte() throws Exception {
		assertInstructionMaskMatch("$30", new byte[] { 0x30 }, "80");
		assertInstructionMaskMatch("$2A", new byte[] { (byte) 0x2A }, "81");
		loadTestIndex("@test.pdf [Test Manual]", "!$30, 10", "!%00xx0001, 20");
		assertEquals("10", language.getManualEntry(null, new byte[] { 0x30 }).getPageNumber());
		assertEquals("20", language.getManualEntry(null, new byte[] { 0x01 }).getPageNumber());
	}

	@Test
	public void testShorterInstructionDoesNotMatchLongerMask() throws Exception {
		loadTestIndex("@test.pdf [Test Manual]", "!0xED_A0, 99");
		ManualEntry entry = language.getManualEntry(null, new byte[] { (byte) 0xED });
		assertNotNull(entry);
		assertNull(entry.getPageNumber());
		ManualEntry fullEntry =
			language.getManualEntry(null, new byte[] { (byte) 0xED, (byte) 0xA0 });
		assertEquals("99", fullEntry.getPageNumber());
	}

	@Test
	public void testAlternateRadixFormats() throws Exception {
		assertInstructionMaskMatch("$ED", new byte[] { (byte) 0xED }, "90");
		assertInstructionMaskMatch("%11101101", new byte[] { (byte) 0xED }, "92");
		assertInstructionMaskMatch("EDh", new byte[] { (byte) 0xED }, "93");
		assertInstructionMaskMatch("11101101b", new byte[] { (byte) 0xED }, "95");
		assertInstructionMaskMatch("$E_x", new byte[] { (byte) 0xE0 }, "96");
	}

	@Test
	public void testMnemonicOnlyLookup() throws Exception {
		ManualEntry entry = language.getManualEntry("LD", null);
		assertNotNull(entry);
		assertEquals("85", entry.getPageNumber());
	}

	@Test
	public void testUnprefixedRadixInference() throws Exception {
		assertInstructionMaskMatch("11101101", new byte[] { (byte) 0xED }, "40");
		assertInstructionMaskMatch("00001010", new byte[] { 0x0A }, "41");
		assertInstructionMaskMatch("ED", new byte[] { (byte) 0xED }, "42");
		assertInstructionMaskMatch("30", new byte[] { 0x30 }, "43");
		assertInstructionMaskMatch("E_D", new byte[] { (byte) 0xED }, "44");
		assertInstructionMaskMatch("0B11101101", new byte[] { (byte) 0xED }, "45");
		assertInstructionMaskMatch("0XED", new byte[] { (byte) 0xED }, "46");
		assertInstructionMaskMatch("0xE_D", new byte[] { (byte) 0xED }, "47");
	}

	@Test
	public void testOctalMasksAreRejected() throws Exception {
		loadTestIndex(
			"@test.pdf [Test Manual]",
			"!0o377, 10",
			"!&FF, 11",
			"!377o, 12",
			"!0b11101101, 42");
		assertEquals("42",
			language.getManualEntry(null, new byte[] { (byte) 0xED }).getPageNumber());
		ManualEntry ffEntry = language.getManualEntry(null, new byte[] { (byte) 0xFF });
		assertTrue(ffEntry == null || ffEntry.getPageNumber() == null);
		@SuppressWarnings("unchecked")
		List<Pair<?, ?>> maskEntries =
			(List<Pair<?, ?>>) getInstanceField("instructionMaskManual", language);
		assertEquals(1, maskEntries.size());
	}

	@Test
	public void testExtendedCommentSyntax() throws Exception {
		loadTestIndex(
			"// standalone full-line comment",
			"# another standalone comment",
			"@test.pdf [Test Manual]",
			"!0b11111110, 60 // mask inline slash comment",
			"!0b11111111, 61 # mask inline hash comment",
			"LD, 90 # mnemonic inline hash comment",
			"CALL, 95 // mnemonic inline slash comment");

		assertEquals("60",
			language.getManualEntry(null, new byte[] { (byte) 0xFE }).getPageNumber());
		assertEquals("61",
			language.getManualEntry(null, new byte[] { (byte) 0xFF }).getPageNumber());
		assertEquals("90", language.getManualEntry("LD", null).getPageNumber());
		assertEquals("95", language.getManualEntry("CALL", null).getPageNumber());
	}

}
