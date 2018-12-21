package com.gs.mysqlCrypt;

public class MyNumbersUtils {

	private static final int WORD_SIZE = 8;

	public static final int rotlFixed(int x, int y) {
		return y != 0 ? _rotl(x, y) : x;
	}

	public static final int rotrFixed(int x, int y) {
		return y != 0 ? _rotr(x, y) : x;
	}

	public static final int _rotl(int x, int y) {
		
		//为了和c标准库的32位旋转方法保持一致
		return ((x << y) & (-1 >>> 32)) | (x >>> ( 32-y));
	}

	public static final int _rotr(int x, int y) {
		//为了和c标准库的32位旋转方法保持一致
		int lyx = ((1 << y) - 1) & x;
		return (x >>> y) | (lyx << (32 - y));
	}

	public static void xorbuf(int[] buf, int[] mask, int count) {
		if ((buf.length | mask.length | count) % WORD_SIZE == 0)
			XorWords(buf, mask, count / WORD_SIZE);
		else {
			for (int i = 0; i < count; i++)
				for (int s = 0; s < WORD_SIZE + i * WORD_SIZE; s++)
					buf[s] ^= mask[s];
		}
	}

	public static final void XorWords(int[] r, int[] a, int n) {
		for (int i = 0; i < n; i++)
			for (int s = i*WORD_SIZE; s < WORD_SIZE + i * WORD_SIZE; s++)
				r[s] ^= a[s];
	}

	public static int[] IPERM(int left, int right) {
		int work;

		right = MyNumbersUtils.rotlFixed(right, 4);
		work = (left ^ right) & 0xf0f0f0f0;
		left ^= work;

		right = MyNumbersUtils.rotrFixed(right ^ work, 20);
		work = (left ^ right) & 0xffff0000;
		left ^= work;

		right = MyNumbersUtils.rotrFixed(right ^ work, 18);
		work = (left ^ right) & 0x33333333;
		left ^= work;

		right = MyNumbersUtils.rotrFixed(right ^ work, 6);
		work = (left ^ right) & 0x00ff00ff;
		left ^= work;

		right = MyNumbersUtils.rotlFixed(right ^ work, 9);
		work = (left ^ right) & 0xaaaaaaaa;
		left = MyNumbersUtils.rotlFixed(left ^ work, 1);
		right ^= work;

		return new int[] { left, right };
	}

	public static int[] FPERM(int left, int right) {
		int work;

		right = MyNumbersUtils.rotrFixed(right, 1);
		work = (left ^ right) & 0xaaaaaaaa;
		right ^= work;
		left = MyNumbersUtils.rotrFixed(left ^ work, 9);
		work = (left ^ right) & 0x00ff00ff;
		right ^= work;
		left = MyNumbersUtils.rotlFixed(left ^ work, 6);
		work = (left ^ right) & 0x33333333;
		right ^= work;
		left = MyNumbersUtils.rotlFixed(left ^ work, 18);
		work = (left ^ right) & 0xffff0000;
		right ^= work;
		left = MyNumbersUtils.rotlFixed(left ^ work, 20);
		work = (left ^ right) & 0xf0f0f0f0;
		right ^= work;
		left = MyNumbersUtils.rotrFixed(left ^ work, 4);

		return new int[] { left, right };
	}

}
