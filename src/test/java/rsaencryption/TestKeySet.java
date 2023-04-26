package rsaencryption;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;;

public class TestKeySet 
{
	@Test
	public void testPrivatePublicKeyInverseModularExponentiation()
	{
		try {
			System.out.println("\nTesting private and public key inversion");
			KeySet.CreateKeys("publicKey.ser", "privateKey.ser");
			BigInteger[] pub = RSA.readSerialisedKey("publicKey.ser");
			BigInteger[] pri = RSA.readSerialisedKey("privateKey.ser");
			
			System.out.println("Private key: " + pri[0].longValue());
			System.out.println("Public key: " + pub[0].longValue());
			
			BigInteger testInput1 = BigInteger.valueOf(99L);
			BigInteger testOutput1 = testInput1.modPow(pub[0], pub[1]);
			BigInteger testOutput2 = testOutput1.modPow(pri[0], pri[1]);
			
			System.out.println("testInput1: " + testInput1.longValue());
			System.out.println("testOutput1: " + testOutput1.longValue());
			System.out.println("testOutput2: " + testOutput2.longValue());
			boolean equals = false;
			if(testOutput2.equals(testInput1))
				equals = true;
			assertEquals(equals, true);
		} catch (IOException | ClassNotFoundException e) {}
	}
}
