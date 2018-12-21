package com.gs.mysqlCrypt;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.Arrays;


/**
 * <p><b>MySQL Crypt Function in java</b></p> this code translation of mysql source
 * code x64 <br>
 * <br>
 * and if mysql is compile in x86 ,you need modify MyNumbersUtils.WORD_SIZE = 4
 * ({@link ins.platform.handregit.service.spring.MyNumbersUtils} i don't know
 * what's the diff) & chartName = gbk in java environment (because in mysql x86
 * chinese characters size is 2-bit but in x64 it's 3-bit )<br>
 * <br>
 * I haven't done any optimization , this means it like source code<br>
 * <br>
 * in mysql use unsigned int, it's 32-bit 0 ~ 4294967295. <br>
 * I use int in java , although the rang is -2147483648~2147483647,i think this
 * has not effect in use
 * 
 * @author xl
 *
 */
public class MysqlCrypt {

	private static final int DES_BLOCK_SIZE = 8;
	private final static String chartName = "utf8";// in mysql-des x64 chinese characters size is 3-bit

	/*
	 * ******************************** mysql des method
	 * ********************************************* *
	 */
	// encrypt des-ede only for mysql
	public static byte[] des_encrypt(String text, String key) throws Exception {
		if (strIsEmpty(text) ||strIsEmpty(text))
			return null;
		byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };// in mysql this value not use
		byte[] keyBytes = getMd5Key(key.getBytes(chartName), iv);

		// result iv&keybytes is eq mysql method
		MysqlCrypt ded = new MysqlCrypt();
		Mode_Basic mb = ded.new Mode_Basic();
		mb.setKey(keyBytes, 24, "ENCRYPTION");
		String tmgText = appendStr(text);
		int[] ivi = new int[] { 0, 0, 0, 0, 0, 0, 0, 0 };
		byte[] strTmgtextByte = tmgText.getBytes(chartName);
		strTmgtextByte[strTmgtextByte.length - 1] = (byte) Integer.parseInt("" + tmgText.charAt(tmgText.length() - 1));
		int[] sti = new int[strTmgtextByte.length];
		for (int i = 0; i < strTmgtextByte.length; i++)
			sti[i] = strTmgtextByte[i] & 0xff;
		int[] encOut = new int[strTmgtextByte.length];
		// encrypt
		mb.CBC_Encrypt(encOut, sti, sti.length, ivi);
		byte[] out = new byte[encOut.length + 1];
		for (int i = 1; i < out.length; i++)
			out[i] = (byte) encOut[i - 1];
		out[0] = (byte) (128 | 127);
		return out;
	}

	public static byte[] des_decrypt(byte[] crypt, String key) throws Exception {
		if (crypt == null || crypt.length == 0 || strIsEmpty(key))
			return null;
		byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };// in mysql this value not use
		byte[] keyBytes = getMd5Key(key.getBytes(chartName), iv);

		MysqlCrypt ded = new MysqlCrypt();
		Mode_Basic mb = ded.new Mode_Basic();
		mb.setKey(keyBytes, 24, "DECRYPTION");
		int[] sti = new int[crypt.length - 1];// decrypt don't need first bit
		for (int i = 1; i < crypt.length; i++)
			sti[i - 1] = crypt[i] & 0xff;

		int[] encOut = new int[sti.length];
		int[] ivi = new int[] { 0, 0, 0, 0, 0, 0, 0, 0 };
		mb.CBC_Decrypt(encOut, sti, sti.length, ivi);

		int tail = (int) encOut[encOut.length - 1];// append str length * delete this characters

		byte[] out = new byte[encOut.length - tail];
		for (int i = 0; i < out.length; i++)
			out[i] = (byte) (encOut[i] & 0xff);

		return out;
	}

	// get the key only for mysql des
	private static byte[] getMd5Key(byte[] key, byte[] iv) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] resKey = new byte[24];
		int digestSz = 16;
		byte[] digest = new byte[20];
		int keyLeft = 24;
		int ivLeft = 8;
		int keyOutput = 0;
		int keyLen = 24;
		int ivLen = 8;
		while (keyOutput < (keyLen + ivLen)) {
			int digestLeft = digestSz;
			if (keyOutput != 0)
				md.update(digest);
			// data
			md.update(key);
			digest = md.digest();
			if (keyLeft != 0) {
				int store = min(keyLeft, digestSz);
				System.arraycopy(digest, 0, resKey, keyLen - keyLeft, store);
				keyOutput += store;
				keyLeft -= store;
				digestLeft -= store;
			}
			if (ivLeft != 0 && digestLeft != 0) {
				int store = min(ivLeft, digestLeft);
				if (iv != null)
					System.arraycopy(digest, digestSz - digestLeft, iv, ivLen - ivLeft, store);
				keyOutput += store;
				ivLeft -= store;
			}
		}
		return resKey;
	}

	// append string only for mysql des encrypt
	// !!! the last chart is a number and only a number not a string because a
	// string num byte value unequal actual value
	private static String appendStr(String str) throws UnsupportedEncodingException {
		String append_str = "********";
		int tail = 8 - (str.getBytes(chartName).length % 8);
		String newStr = str + append_str.substring(0, tail - 1) + tail;
		return newStr;
	}

	// compare number return min
	private final static int min(int a, int b) {
		return a < b ? a : b;
	}

	class Mode_Basic {
		private MysqlBasicDES des1_ = new MysqlBasicDES();
		private MysqlBasicDES des2_ = new MysqlBasicDES();
		private MysqlBasicDES des3_ = new MysqlBasicDES();

		private void setKey(byte[] key, int length, String dir) {
			// this set is no problem
			des1_.setKey("ENCRYPTION".equals(dir) ? key : Arrays.copyOfRange(key, 16, 24), 24, dir);
			des2_.setKey(Arrays.copyOfRange(key, 8, 16), 24, "ENCRYPTION".equals(dir) ? "DECRYPTION" : "ENCRYPTION");
			des3_.setKey("ENCRYPTION".equals(dir) ? Arrays.copyOfRange(key, 16, 24) : key, 24, dir);
		}

		private void ProcessAndXorBlock(int[] in, int xOr, int[] out) {

			int l, r;
			int[] getVal = getFromIn(in);
			l = getVal[0];
			r = getVal[1];
			int[] ipAI = MyNumbersUtils.IPERM(l, r);

			l = ipAI[0];
			r = ipAI[1];
			int[] rpb1 = des1_.RawProcessBlock(l, r);
			l = rpb1[0];
			r = rpb1[1];
			int[] rpb2 = des2_.RawProcessBlock(r, l);
			r = rpb2[0];
			l = rpb2[1];
			int[] rpb3 = des3_.RawProcessBlock(l, r);
			l = rpb3[0];
			r = rpb3[1];

			int[] fpAI = MyNumbersUtils.FPERM(l, r);
			l = fpAI[0];
			r = fpAI[1];
			putInOut(out, r, l);

		}

		public final void CBC_Encrypt(int[] out, int[] in, int sz, int[] reg_) {
			int blocks = sz / DES_BLOCK_SIZE;

			if (reg_ == null)
				reg_ = new int[8];// in this array only low 8-bit ,this mean data need &0xff
			int posOut = 0;
			int posIn = 0;
			while (blocks-- > 0) {
				MyNumbersUtils.xorbuf(reg_, Arrays.copyOfRange(in, posIn, posIn + DES_BLOCK_SIZE), DES_BLOCK_SIZE);
				// for(int i=0;i<reg_.length;i++)
				// reg_[i]=reg_[i]&0xff;
				ProcessAndXorBlock(reg_, 0, reg_);
				System.arraycopy(reg_, 0, out, posOut, DES_BLOCK_SIZE);
				posOut += DES_BLOCK_SIZE;
				posIn += DES_BLOCK_SIZE;
			}
		}

		public final void CBC_Decrypt(int[] out, int[] in, int sz, int[] reg_) {
			int blocks = sz / DES_BLOCK_SIZE;
			int[] hold = new int[16];
			int[] tmp_ = new int[16];
			if (reg_ == null)
				reg_ = new int[8];// in this array only low 8-bit ,this mean data need &0xff
			int posOut = 0;
			int posIn = 0;
			while (blocks-- > 0) {
				int[] out_t = new int[8];
				tmp_ = Arrays.copyOfRange(in, posIn, posIn + DES_BLOCK_SIZE);
				ProcessAndXorBlock(tmp_, 0, out_t);
				MyNumbersUtils.xorbuf(out_t, reg_, DES_BLOCK_SIZE);

				System.arraycopy(reg_, 0, hold, 0, DES_BLOCK_SIZE);
				System.arraycopy(tmp_, 0, reg_, 0, DES_BLOCK_SIZE);
				System.arraycopy(hold, 0, tmp_, 0, DES_BLOCK_SIZE);
				System.arraycopy(out_t, 0, out, posOut, DES_BLOCK_SIZE);
				posOut += DES_BLOCK_SIZE;
				posIn += DES_BLOCK_SIZE;
			}
		}

		public final int[] getFromIn(int[] block) {
			int a = block[3] | (block[2] << 8) | (block[1] << 16) | (block[0] << 24);
			int b = block[3 + 4] | (block[2 + 4] << 8) | (block[1 + 4] << 16) | (block[0 + 4] << 24);
			return new int[] { a, b };
		}

		public void putInOut(int[] block, int r, int l) {

			block[0] = GETBYTE(r, 3);
			block[1] = GETBYTE(r, 2);
			block[2] = GETBYTE(r, 1);
			block[3] = GETBYTE(r, 0);

			block[0 + 4] = GETBYTE(l, 3);
			block[1 + 4] = GETBYTE(l, 2);
			block[2 + 4] = GETBYTE(l, 1);
			block[3 + 4] = GETBYTE(l, 0);
		}

		// this mean only need 8-bit
		public final int GETBYTE(int x, int y) {
			return ((x) >> (8 * (y))) & 0xff;
		}
	}
	 private  static boolean strIsEmpty(final CharSequence cs) {
	        return cs == null || cs.length() == 0;
	    }
}
