package com.gs.mysqlCrypt;

import java.util.Arrays;

public class MysqlBasicDES extends MyDesBox {

	private int[] k_ = new int[32];

	public int[] getK_() {
		return k_;
	}

	public void setK_(int[] k_) {
		this.k_ = k_;
	}

	public void setKey(byte[] key, int length, String dir) {

		byte buffer[] = new byte[56 + 56 + 8];

		byte[] pc1m = buffer; /* place to modify pc1 into */
		byte[] pcr = Arrays.copyOfRange(pc1m, 56, pc1m.length); /* place to rotate pc1 into */
		byte[] ks = Arrays.copyOfRange(pcr, 56, pcr.length);
		int i, j, l;
		int m;
		for (j = 0; j < 56; j++) { /* convert pc1 to bits of key */
			l = pc1[j] - 1; /* integer bit location */
			m = l & 07; /* find bit */
			pc1m[j] = (byte) ((key[l >> 3] & /* find which key byte l is in */
					bytebit[m]) != 0 /* and which bit of that byte */
							? 1
							: 0); /* and store 1-bit result */
		}

		for (i = 0; i < 16; i++) { /* key chunk for each iteration */
			ks=new byte[8];
			for (j = 0; j < 56; j++) /* rotate pc1 the right amount */
				pcr[j] = pc1m[(l = j + totrot[i]) < (j < 28 ? 28 : 56) ? l : l - 28];
			/* rotate left and right halves independently */
			for (j = 0; j < 48; j++) { /* select bits individually */
				/* check bit that goes to ks[j] */
				if (pcr[pc2[j] - 1] != 0) {
					/* mask it in if it's there */
					l = j % 6;
					ks[j / 6] |= bytebit[l] >> 2;
				}
			}
			/* Now convert to odd/even interleaved form for use in F */
			k_[2 * i] = ((int) ks[0] << 24) | ((int) ks[2] << 16) | ((int) ks[4] << 8) | ((int) ks[6]);
			k_[2 * i + 1] = ((int) ks[1] << 24) | ((int) ks[3] << 16) | ((int) ks[5] << 8) | ((int) ks[7]);
		}

		if ("DECRYPTION".equals(dir))
			for (i = 0; i < 16; i += 2) {
				swap(k_[i], i, k_[32 - 2 - i], 32 - 2 - i);
				swap(k_[i + 1], i + 1, k_[32 - 1 - i], 32 - 1 - i);
			}
	}

	public int[] RawProcessBlock(int lIn, int rIn) {
		int l = lIn, r = rIn;
		int[] kptr = k_;

		for (int i = 0; i < 8; i++) {
			int work = MyNumbersUtils.rotrFixed(r, 4) ^ kptr[4 * i + 0];
			l ^= Spbox[6][((work) & 0x3f)] ^ Spbox[4][ ((work >> 8) & 0x3f)] ^ Spbox[2][ ((work >> 16) & 0x3f)]
					^ Spbox[0][((work >> 24) & 0x3f)];
			work = r ^ kptr[4 * i + 1];
			l ^= Spbox[7][((work) & 0x3f)] ^ Spbox[5][ ((work >> 8) & 0x3f)] ^ Spbox[3][ ((work >> 16) & 0x3f)]
					^ Spbox[1][ ((work >> 24) & 0x3f)];

			work = MyNumbersUtils.rotrFixed(l, 4) ^ kptr[4 * i + 2];
			r ^= Spbox[6][ ((work) & 0x3f)] ^ Spbox[4][ ((work >> 8) & 0x3f)] ^ Spbox[2][ ((work >> 16) & 0x3f)]
					^ Spbox[0][ ((work >> 24) & 0x3f)];
			work = l ^ kptr[4 * i + 3];
			r ^= Spbox[7][ ((work) & 0x3f)] ^ Spbox[5][((work >> 8) & 0x3f)] ^ Spbox[3][((work >> 16) & 0x3f)]
					^ Spbox[1][ ((work >> 24) & 0x3f)];
		}

		// lIn = l;
		// rIn = r;
		return new int[] { l, r };
	}

	private final void swap(int a, int aPos, int b, int bPos) {
		k_[aPos] = b;
		k_[bPos] = a;
	}

}
