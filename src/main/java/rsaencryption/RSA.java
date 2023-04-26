package rsaencryption;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.io.File;
import java.nio.file.Files;
import java.io.IOException;
/**
 * Binary RSA encryption of files in JAVA
 * @author Ryan N May
 */
public class RSA 
{
	private static final int LONG_BYTE_DIVISION = 8;
	public static void main(String[] argvs)
	{	// argvs = {-e/-d public/privateKey.ser, input.txt, output.txt}
		try {
			if(argvs.length == 4)
			{
				byte[] fileBytes = readInput(argvs[2]); // padding
				if(argvs[0] == "-e")
				{
					fileBytes = padBytes(fileBytes);
					BigInteger[] fileData = bytesToLongs(fileBytes);
					BigInteger[] encrypted = performRSA(fileData, argvs[1]);
					fileBytes = longsToBytes(encrypted);
					writeOutput(argvs[3], fileBytes);
				}
				if(argvs[0] == "-d")
				{
					BigInteger[] fileData = bytesToLongs(fileBytes);
					BigInteger[] decrypted = performRSA(fileData, argvs[1]);
					fileBytes = longsToBytes(decrypted);
					fileBytes = unpadBytes(fileBytes);
					writeOutput(argvs[3], fileBytes);
				}	
			}
			else
				System.out.println("Correct use of RSA: RSA key.ser input.file output.file");
		}catch(Exception ex) {
			System.out.println("An error occured in the execution of RSA: \n" + ex.getMessage());
		}
	}
	/**
	 * This method performs RSA encryption and decryption
	 * @param data_in (long [])
	 * @param keyFilePath
	 * @return data_out (long[])
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	public static BigInteger[] performRSA(BigInteger[] data_in, String keyFilePath) throws ClassNotFoundException, IOException
	{
		BigInteger[] data_out = new BigInteger[data_in.length];
		BigInteger[] key = readSerialisedKey(keyFilePath);
		for(int i = 0; i < data_in.length; i++) {
			data_out[i] = data_in[i].modPow(key[0], key[1]);
		}
		return data_out;
	}
	/**
	 * This method reads the serialised key class and extracts the two key elements from the class structure.
	 * @param keyFilePath
	 * @return ret (long[])
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public static BigInteger[] readSerialisedKey(String keyFilePath) throws IOException, ClassNotFoundException
	{
		FileInputStream keyFileIn = new FileInputStream(keyFilePath);
		ObjectInputStream keyObjectIn = new ObjectInputStream(keyFileIn);
		Key key = (Key) keyObjectIn.readObject();
		keyFileIn.close();
		keyObjectIn.close();
		BigInteger[] ret = {key.element1, key.element2};
		return ret;
	}
	/**
	 * padBytes pads every 4 bytes with 4 blank bytes to prevent RSA long overflow
	 * @param in
	 * @return
	 */
	public static byte[] padBytes(byte[] in)
	{
		byte[] padding = new byte[LONG_BYTE_DIVISION/2];
		byte[] out = in;
        for (int i = 0; i < padding.length; i++) 
            padding[i] = 0;
        for(int i = 0; i < out.length; i+=8)
		{
			byte[] LHS = sliceBytes(out, 0, i);
			byte[] RHS = sliceBytes(out, i, out.length);
			LHS = combineBytes(LHS, padding);
			out = combineBytes(LHS, RHS);
		}
		return out;
	}
	/**
	 * Undoes the work of padBytes
	 * @param in
	 * @return
	 */
	public static byte[] unpadBytes(byte[] in)
	{
		byte[] padding = new byte[LONG_BYTE_DIVISION/2];
		byte[] out = in;
        for (int i = 0; i < padding.length; i++) 
            padding[i] = 0;
        for(int i = 0; i < out.length; i+=4)
		{
			byte[] LHS = sliceBytes(out, 0, i);
			byte[] RHS = sliceBytes(out, i+4, out.length);
			out = combineBytes(LHS, RHS);
		}
		return out;
	}
	/**
	 * WriteOutputFile operates by converting a long array into a byte array. 
	 * Each element of the long array is converted into a 8 bytes. 
	 * @param filePath
	 * @param outputData (long[])
	 * @throws IOException
	 */
	public static void writeOutput(String filePath, byte[] outputData) throws IOException
	{
		File outputFile = new File(filePath);
		FileOutputStream outputFileStream = new FileOutputStream(outputFile);       
        outputFileStream.write(outputData);
        outputFileStream.close();
	}
	/**
	 * ReadInputFile operates by reading a file of bytes, and concatenating them into an array of longs.
	 * Each long array element contains 8 bytes. 	
	 * @param filePath
	 * @return longData (long[])
	 * @throws IOException
	 */
	public static byte[] readInput(String filePath) throws IOException
	{
		File inputFile = new File(filePath);
		byte[] bytes = new byte[(int) inputFile.length()];
		bytes = Files.readAllBytes(inputFile.toPath());
		return bytes;
	}
	/**
	 * Combining byte arrays
	 * @param buffer1
	 * @param buffer2
	 * @return
	 */
	public static byte[] combineBytes(byte[] buffer1, byte[] buffer2) 
	{
        byte[] concatedArray = new byte[buffer1.length + buffer2.length];
        System.arraycopy(buffer1, 0, concatedArray, 0, buffer1.length);
        System.arraycopy(buffer2, 0, concatedArray, buffer1.length,
                buffer2.length);
        return concatedArray;
    }
	/**
	 * Slicing byte array into segments 
	 * @param buffer1
	 * @param l
	 * @param h
	 * @return
	 */
	public static byte[] sliceBytes(byte[] buffer1, int l, int h) 
	{
		
        byte[] slice = new byte[h-l];
        System.arraycopy(buffer1, l, slice, 0, h-l);
        return slice;
    }
	/**
	 * This method converts input longs to bytes (longs are seperated into 8 bytes). 
	 * @param longs
	 * @return
	 */
	public static byte[] longsToBytes(BigInteger[] longs)
	{
		byte[] bytes = new byte[] {};
		for(int i = 0; i < longs.length; i++)
		{
			byte[] b = longs[i].toByteArray();
			byte[] f = new byte[Math.abs(8 - b.length)];
			b = combineBytes(f, b);
			bytes = combineBytes(b, bytes);
		}
		return bytes;
	}
	/**
	 * this method converts a byte array to a long array (8 bytes to a long)
	 * @param bytes
	 * @return longData (long[])
	 */
	public static BigInteger[] bytesToLongs(byte[] bytes)
	{
		BigInteger[] longData = new BigInteger[(int)Math.ceil((float)bytes.length/LONG_BYTE_DIVISION)];
		
		int differential = Math.abs(bytes.length - (int)Math.ceil((float)bytes.length/LONG_BYTE_DIVISION)*LONG_BYTE_DIVISION);
		byte[] filler = new byte[differential];
		byte[] filledBytes = new byte[bytes.length + differential];
		System.arraycopy(bytes, 0, filledBytes, 0, bytes.length);
		System.arraycopy(filler, 0, filledBytes, bytes.length, filler.length);
		bytes = filledBytes;
		
		int longDataLength = longData.length;
		for(int j = 0; j < longDataLength; j++) 
			longData[j] = convert8Bytes(bytes, j);
		return longData;
	}
	/**
	 * Convert 8 bytes into 1 long
	 * @param bytes
	 * @param round
	 * @return
	 */
	private static BigInteger convert8Bytes(byte[] bytes, int round)
	{
		long longBytes = 0b0L;
		byte[] selectedBytes = sliceBytes(bytes, (round*8), (round+1)*8);
		for(int i = 0; i < 8; i++)
			longBytes = longBytes | (((long)selectedBytes[i] & 0b011111111) << (56-i*8));
		return BigInteger.valueOf(longBytes);
	}
}
