package rsaencryption;
import java.io.IOException;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class TestRSA 
{	
	@Test
	public void testPadUnPadBytes()
	{
		System.out.println("\ntestPadUnPadBytes");
		byte[] in = new byte[] {0b01010, (byte) 0b10000001, 0b01111, 0b01100, 0b01001, 0b01011, 0b01111, 0b00001,
								0b01010, 0b01101, 0b01111, 0b01100, 0b01001, 0b01011, 0b01111, 0b00001};
		
		byte[] out1 = RSA.padBytes(in);
		
		System.out.println("original:");
		printBytes(in);
		System.out.println("padded:");
		printBytes(out1);
		
		byte[] out2 = RSA.unpadBytes(out1);
		
		System.out.println("unpadded:");
		printBytes(out2);
		
		assertArrayEquals(out2, in);
	}
	@Test 
	public void testLongsToBytesToLongs()
	{
		try {
			System.out.println("\ntestLongsToBytesToLongs");
			BigInteger[] longs = new BigInteger[] {
					BigInteger.valueOf(0b0101101001011010010110100101101001011010010110100101101001011010L)
					};
			/** Convert long to bytes and pad **/
			byte[] bytes = RSA.longsToBytes(longs);
			byte[] bytes_padded = RSA.padBytes(bytes);
			/** Convert back into a long and encrypt **/
			BigInteger[] longs2A  = RSA.bytesToLongs(bytes_padded);
			BigInteger[] longs2B = RSA.performRSA(longs2A, "publicKey.ser");
			/** Convert into bytes **/
			byte[] bytes_padded2 = RSA.longsToBytes(longs2B);
			/** Convert into a long and decrypt **/
			BigInteger[] longs3A  = RSA.bytesToLongs(bytes_padded2);
			BigInteger[] longs3B = RSA.performRSA(longs3A, "privateKey.ser");
			/** Convert into bytes **/
			byte[] bytes_padded3 = RSA.longsToBytes(longs3B);
			/** remove byte padding **/
			byte[] bytes3 = RSA.unpadBytes(bytes_padded3);
			/** to longs **/
			BigInteger[] longs4 = RSA.bytesToLongs(bytes3);
			
			System.out.println("longs:");
			printBigIntegers(longs);
			System.out.println("bytes:");
			printBytes(bytes);
			System.out.println("bytes padded:");
			printBytes(bytes_padded);
			System.out.println("longs2A: (before encryption)");
			printBigIntegers(longs2A);
			System.out.println("longs2B: (post encryption)");
			printBigIntegers(longs2B);
			System.out.println("bytes padded2:");
			printBytes(bytes_padded2);
			System.out.println("longs3A: (before decryption)");
			printBigIntegers(longs3A);
			System.out.println("longs3B: (post decryption)");
			printBigIntegers(longs3B);
			System.out.println("bytes padded3:");
			printBytes(bytes_padded3);
			System.out.println("bytes3:");
			printBytes(bytes3);
			System.out.println("longs4:");
			printBigIntegers(longs4);
			
			assertEquals(longs[0].equals(longs4[0]), true);
		} catch (Exception ex) {}
	}
	@Test
	public void testFileToFileEncryptionDecryption()
	{
		try {
			System.out.println("\ntestFileToFileEncryptionDecryption");
			
			byte[] fileBytes = RSA.readInput("test.txt");
			// Encrypt
			fileBytes = RSA.padBytes(fileBytes);
			BigInteger[] fileData1 = RSA.bytesToLongs(fileBytes);
			BigInteger[] encrypted = RSA.performRSA(fileData1, "publicKey.ser");
			byte[] encryptedBytes = RSA.longsToBytes(encrypted);
			// Decrypt
			BigInteger[] fileData2 = RSA.bytesToLongs(encryptedBytes);
			BigInteger[] decrypted = RSA.performRSA(fileData2, "privateKey.ser");
			byte[] decryptedBytes = RSA.longsToBytes(decrypted);
			byte[] fileBytes2 = RSA.unpadBytes(decryptedBytes);
			
			System.out.println("Input (padded):");
			printBytes(fileBytes);
			System.out.println("Input (longs):");
			printBigIntegers(fileData1);
			System.out.println("encrypted (longs):");
			printBigIntegers(encrypted);
			System.out.println("encrypted (bytes):");
			printBytes(encryptedBytes);
			System.out.println("encrypted (longs):");
			printBigIntegers(fileData2);
			System.out.println("decrypted (longs):");
			printBigIntegers(decrypted);
			System.out.println("decrypted (bytes):");
			printBytes(decryptedBytes);
			System.out.println("fileBytes2 (bytes):");
			printBytes(fileBytes2);
			
		} catch (IOException e) {} catch (ClassNotFoundException e) {}
	}
	@Test
	public void testBytesToLongsToBytes()
	{
		System.out.println("\ntestBytesToLongsToBytes");
		byte[] X = new byte[] {0b01010101, (byte) 0b10000001, 0b01010101, 0b01010101};
		X = RSA.padBytes(X);
		
		BigInteger[] Y = RSA.bytesToLongs(X);
		byte[] Z = RSA.longsToBytes(Y);
		BigInteger[] Y2 = RSA.bytesToLongs(Z);
		
		System.out.println(" X:"); printBytes(X);
		System.out.println(" Y:"); printBigIntegers(Y);
		System.out.println(" Z:"); printBytes(Z);
		System.out.println("Y2:"); printBigIntegers(Y2);
	}
	@Test
	public void testModularExponentiationLargeLongs()
	{
		System.out.println("\ntestModularExponentiationLargeLongs");
		try {
			BigInteger[] public_key_data = RSA.readSerialisedKey("publicKey.ser");
			BigInteger[] private_key_data = RSA.readSerialisedKey("privateKey.ser");
			BigInteger testInput1 = BigInteger.valueOf(512L);
			//long testOutput1 = RSA.modularExponentiation(testInput1, public_key_data[0], public_key_data[1]);
			BigInteger testOutput1 = testInput1.modPow(public_key_data[0], public_key_data[1]);
			BigInteger testOutput2 = testOutput1.modPow(private_key_data[0], private_key_data[1]);
			
			System.out.println("Private key: " + private_key_data[0].longValue());
			System.out.println("Public key: " + public_key_data[0].longValue());
			System.out.println("testInput1: " + testInput1.longValue());
			System.out.println("testOutput1: " + testOutput1.longValue());
			System.out.println("testOutput2: " + testOutput2.longValue());
			boolean equals = false;
			if(testOutput2.equals(testInput1))
				equals = true;
			assertEquals(equals, true);
		} catch (ClassNotFoundException | IOException e) {}
	}
	@Test
	public void testModularExponentiationSmallLongs()
	{
		System.out.println("\ntestModularExponentiationSmallLongs");
		try {
			BigInteger[] public_key_data = RSA.readSerialisedKey("publicKey.ser");
			BigInteger[] private_key_data = RSA.readSerialisedKey("privateKey.ser");
			BigInteger testInput1 = BigInteger.valueOf(5L);
			//long testOutput1 = RSA.modularExponentiation(testInput1, public_key_data[0], public_key_data[1]);
			BigInteger testOutput1 = testInput1.modPow(public_key_data[0], public_key_data[1]);
			BigInteger testOutput2 = testOutput1.modPow(private_key_data[0], private_key_data[1]);
			
			System.out.println("Private key: " + private_key_data[0].longValue());
			System.out.println("Public key: " + public_key_data[0].longValue());
			System.out.println("testInput1: " + testInput1.longValue());
			System.out.println("testOutput1: " + testOutput1.longValue());
			System.out.println("testOutput2: " + testOutput2.longValue());
			boolean equals = false;
			if(testOutput2.equals(testInput1))
				equals = true;
			assertEquals(equals, true);
		} catch (ClassNotFoundException | IOException e) {}
	}
	@Test
	public void testRSAEncryptionDecryptionSmallLongs()
	{
		try {
			BigInteger[] testInput1 = new BigInteger[4];
			testInput1[0] = BigInteger.valueOf(99L);
			testInput1[1] = BigInteger.valueOf(42L);
			testInput1[2] = BigInteger.valueOf(53L);
			testInput1[3] = BigInteger.valueOf(00L);

			BigInteger[] testOutput1 = RSA.performRSA(testInput1, "publicKey.ser");
			BigInteger[] testOutput2 = RSA.performRSA(testOutput1, "privateKey.ser");
					
			System.out.println("\ntestRSAEncryptionDecryptionSmallLongs");
			
			System.out.println("testInput1");
			printBigIntegers(testInput1);
			System.out.println("testOutput1");
			printBigIntegers(testOutput1);
			System.out.println("testOutput2");
			printBigIntegers(testOutput2);
			
			boolean equals = false;
			if(	testOutput2[0].equals(testInput1[0]) 
				&& testOutput2[1].equals(testInput1[1])
				&& testOutput2[2].equals(testInput1[2])
				&& testOutput2[3].equals(testInput1[3]))
				equals = true;
			assertEquals(equals, true);
		} catch (IOException | ClassNotFoundException e) {}
	}
	@Test
	public void testRSAEncryptionDecryptionLargeLongs()
	{
		try {
			BigInteger[] testInput1 = new BigInteger[4];
			testInput1[0] = BigInteger.valueOf(9981L);
			testInput1[1] = BigInteger.valueOf(4233L);
			testInput1[2] = BigInteger.valueOf(5311L);
			testInput1[3] = BigInteger.valueOf(0033L);

			BigInteger[] testOutput1 = RSA.performRSA(testInput1, "publicKey.ser");
			BigInteger[] testOutput2 = RSA.performRSA(testOutput1, "privateKey.ser");
					
			System.out.println("\ntestRSAEncryptionDecryptionSmallLongs");
			
			printBigIntegers(testInput1);
			System.out.println("testOutput1");
			printBigIntegers(testOutput1);
			System.out.println("testOutput2");
			printBigIntegers(testOutput2);
			
			boolean equals = false;
			if(testOutput2[0].equals(testInput1[0]) 
					&& testOutput2[1].equals(testInput1[1])
					&& testOutput2[2].equals(testInput1[2])
					&& testOutput2[3].equals(testInput1[3]))
				equals = true;
			assertEquals(equals, true);
		} catch (IOException | ClassNotFoundException e) {}
	}
	@Test
	public void testReadWriteFile()
	{
		try {
			byte[] fileData1 = RSA.readInput("test.txt");
			RSA.writeOutput("test_out.txt", fileData1);
			byte[] fileData2 = RSA.readInput("test_out.txt");
			
			assertArrayEquals(fileData1, fileData2);
		} catch (IOException e) {}
	}
	
	@Test
	public void testLoadSerialisedKey()
	{
		System.out.println("\ntestLoadSerialisedKey");
		try {
			BigInteger[] public_key_data = RSA.readSerialisedKey("publicKey.ser");
			BigInteger[] private_key_data = RSA.readSerialisedKey("privateKey.ser");
			
			System.out.println("priv: " + private_key_data[0].longValue() + ", " + private_key_data[1].longValue());
			System.out.println("publ: " + public_key_data[0].longValue() + ", " + public_key_data[1].longValue());
		} catch (ClassNotFoundException | IOException e) {}
	}
	
	public void printByte(byte in)
	{
		System.out.print(Long.toBinaryString(Byte.toUnsignedLong(in)));
	}
	
	public void printlnByte(byte in)
	{
		System.out.println(Long.toBinaryString(Byte.toUnsignedLong(in)));
	}
	
	public void printBytes(byte[] in)
	{
		for(int i = 0; i < in.length; i++)
			System.out.print(Long.toBinaryString(Byte.toUnsignedLong(in[i])) + ", ");
		System.out.println();
	}
	
	public void printBigIntegers(BigInteger[] in)
	{
		for(int i = 0; i < in.length; i++)
			System.out.print(in[i].toString(2) + ", ");
		System.out.println();
	}
	
}
