package rsaencryption;

import java.util.Random;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.io.IOException;

/**
 * This class generates RSA public and private key sets
 * @author Ryan N May
 * @since 2023-04-24
 */
public class KeySet 
{
	private static final int BITSPACE_HIGH = 32;
	private static final int BITSPACE_LOW = 2;
	private static final int BITSPACE_e = 5;
	
	public static void main(String[] args)
	{
		if(args.length == 2)
			CreateKeys(args[0], args[1]);
		else
			System.out.println("Usage: KeyGen publicKeyPath.ser PrivateKeyPath.ser");
	}
	/**
	 * This method creates the private and public keys, serializes the key objects, and 
	 * updates a progress bar to the user. 
	 * 
	 * @param publicKeyFileLocation (String)
	 * @param privateKeyFileLocation (String)
	 * @return (void)
	 */
	public static void CreateKeys(String publicKeyFileLocation, String privateKeyFileLocation)
	{
		BigInteger U = BigInteger.valueOf(1L);
		BigInteger A = BigInteger.valueOf(2L);
		BigInteger q, p, n, n_phi, e, d;
		do
		{
			// Generating prime q
			q = BigInteger.valueOf(generatePrime());
			// Generating prime p
			p = BigInteger.valueOf(generatePrime());
			// Generating n
			n = p.multiply(q);
			// Generating n_phi
			n_phi = BigInteger.valueOf(p.longValue()-1).multiply(BigInteger.valueOf(q.longValue()-1));
			// Generating e
			Random rand = new Random();
			do { 
				e = BigInteger.valueOf((rand.nextLong() + (long)Math.pow(2, 0)) % (long)Math.pow(2, BITSPACE_e));				
			}while(gcd(e, n_phi) != 1);
			// Generating d
			d = BigInteger.valueOf(extendedEuclidean(e, n_phi)[1]);
			if(d.longValue() < 0)
				d.add(n_phi);
		}while(	!(e.multiply(d).mod(n_phi).equals(U)) 
					|| (e.longValue() < 0) || (d.longValue() < 0)
					|| (d.equals(U)) || (e.equals(U))
 					|| (e.equals(d))
					|| !BigInteger.valueOf(2L).modPow(e, n).modPow(d, n).equals(A));
		Key publicKey = new Key(e, n);
		Key privateKey = new Key(d, n);
			
		try {
			if(!publicKeyFileLocation.contains(".ser"))
				publicKeyFileLocation += ".ser";
			if(!privateKeyFileLocation.contains(".ser"))
				privateKeyFileLocation += ".ser";
				
			FileOutputStream publicKeyFile = new FileOutputStream(publicKeyFileLocation);
			FileOutputStream privateKeyFile = new FileOutputStream(privateKeyFileLocation);
				
			ObjectOutputStream publicKeyObj = new ObjectOutputStream(publicKeyFile);
			ObjectOutputStream privateKeyObj = new ObjectOutputStream(privateKeyFile);
				
			publicKeyObj.writeObject(publicKey);
			privateKeyObj.writeObject(privateKey);
				
			publicKeyFile.close();
			privateKeyFile.close();	
		} catch (IOException ex) {
			ex.printStackTrace();
		}	
	}
	/**
	 * This method generates primes via RNG plus fermats primality theorum.   
	 * @param (void)
	 * @return coprime (long)
	 */
	public static long generatePrime()
	{
		Random rand = new Random();
		long prime;
		BigInteger PRIME;
		BigInteger A = BigInteger.valueOf(2L);
		BigInteger U = BigInteger.valueOf(1L);
		do
		{	// Generate random number (hopefully prime)
			prime = (rand.nextLong() + (long)Math.pow(2,  BITSPACE_LOW)) % (long)Math.pow(2, BITSPACE_HIGH);
			PRIME = BigInteger.valueOf(prime);
		}while(prime < 0 || (A.modPow(PRIME.subtract(U), PRIME).equals(U)) != true);
		return prime; // returns prime that may be inclusive of pseudo-primes. 
	}
	/**
	 * This method performs the extended Euclidean or extended GCD algorithm. 
	 * @param a (long)
	 * @param b (long)
	 * @return ret (long[])
	 */
	public static long[] extendedEuclidean(BigInteger A, BigInteger B)
	{
		long a = A.longValue();
		long b = B.longValue();
		long[] ret;
		if(b == 0)
			ret = new long[] {a, 1, 0};
		else
		{
			long[] small = extendedEuclidean(B,  BigInteger.valueOf(a%b));
			ret = new long[] {small[0], small[2], small[1]-((a/b)*small[2])};
		}
		return ret;
	}
	/**
	 * Simple GCD algorithm, optimized by assuming that b is a power of 2.
	 * @param a (long)
	 * @param b (long)
	 * @return b (long)
	 */
	public static long gcd(BigInteger A, BigInteger B) // only applicable if b = 2^x
	{	// a % b = a % 2^power = a & (2^power - 1)
		long a = A.longValue();
		long b = B.longValue();
		try {
			if(a != 0 && b != 0)
			{
				long r = a & (b-1);
				a = b;
				b = r;
					while((a % b) != 0)
					{
						r = a % b;
						a = b;
						b = r;
					}
			}
		} catch(ArithmeticException ex) {
			return 0;
		}
		return b;
	}
}
