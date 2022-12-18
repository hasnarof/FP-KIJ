# matriks yang diperlukan
# dictionary s_box
sbox = {
    1 : [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

	2 :	[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

	3 :	[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

	4 : [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

	5 :	[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

	6 :	[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

	7 :	[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

	8 :	[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        }

# matriks untuk permutasi awal (IP)
ip = [58, 50, 42, 34, 26, 18, 10, 2, 
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# matriks untuk ekspansi di fungsi f
exp = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1]

# matriks p_box yang digunakan setelah penggabungan hasil s_box
p_box = [16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25]

# matriks inverse ip yang digunakan pada proses terakhir
inv_ip = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# matriks untuk permutasi pertama di key
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# matriks banyak pergeseran tiap round pada generator kunci internal
shift_mat = [1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1]

# matriks untuk mengkompresi nilai key yang sebelumnya 56 bit menjadi 48 bit
compress_key = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

# fungsi-fungsi pendukung

# fungsi untuk mengubah input string hexadecimal ke binary 
def hex_to_bin(str_hex):
    str_hex = str(str_hex)
    return format(int(str_hex, 16), '0>64b')

# fungsi untuk mengubah input string binary ke hexadecimal 
def bin_to_hex(str_bin):
    return format(int(str_bin, 2), 'x')

# fungsi untuk mengubah input string binary ke decimal 
def bin_to_dec(binary):
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal

# fungsi untuk mengubah input string decimal ke binary 
def dec_to_bin(num):
    res = bin(num).replace("0b", "")
    if(len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

# fungsi untuk mengubah input string biasa ke hexadecimal 
def str_to_hex(str):
    hexs = []
    for c in str:
      hex = format(ord(c), "x")
      hexs.append(hex)
    return "".join(hexs)

# fungsi untuk mengubah input string hexadecimal ke string biasa
def hex_to_str(hex):
    return bytes.fromhex(hex).decode("latin-1")

# fungsi untuk melakukan permutasi (pengacakan nilai sesuai urutan matriks permutasi)
# old merupakan array yang akan diacak, new adalah matriks permutasi yang berisi index untuk mengacak old
def permutation(old, new):
    res = ''.join([old[new[i]-1] for i in range(len(new))])
    return res

# fungsi untuk subtitusi dengan sbox, s_num adalah sbox berapa 
def s_box_substitution(s_num, str_six_bits):
  # ambil bit awal dan akhir
	bin_row = str_six_bits[0] + str_six_bits[-1]
  # ambil bit tengah
	bin_col = str_six_bits[1:-1]
	dec_row = bin_to_dec(int(bin_row))
	dec_col = bin_to_dec(int(bin_col))
	s_box_val = sbox[s_num][dec_row][dec_col]
	return dec_to_bin(s_box_val)

def xor(val1, val2):
    return "".join(["0" if val1[i] == val2[i] else "1" for i in range(len(val1))])

# fungsi untuk melakukan left shift, str adalah array yang mau digeser, num_shift jumlah pergeseran
def left_circular_shift(str, num_shift):
    str = list(str)
    o = []
    for i in range(len(str)):
        idx = i+num_shift
        if len(str) <= idx:
            idx = idx-len(str)
        o.append(str[idx])
    return ''.join(o)

# Key generation
def key_generation(key):
    key = hex_to_bin(key)
    p1 = permutation(key, keyp)
    # pisah hasil permutasi jadi kiri dan kanan (c dan d)
    c = p1[0:28]
    d = p1[28:56]
    ki = []
    ki_hex = []
    # lakukan left shift sebanyak nilai pada matriks pergeseran setiap round-nya
    for i in range(16):
        c = left_circular_shift(c, shift_mat[i])
        d = left_circular_shift(d, shift_mat[i])
        concat_cd = c+d
        k = permutation(concat_cd, compress_key)
        ki.append(k)
        ki_hex.append(bin_to_hex(k))
    return ki, ki_hex

def feistel(l, r, ki,i):
    # lakukan permutasi untuk mengekspansi nilai r menjadi 48 bit
    r_expand = permutation(r, exp)
    # xor nilai r yang baru dengan key (ki)
    r_xor = xor(r_expand, ki)
    # pecah menjadi 8 bagian yang berisi 6 bit untuk disubstitusi dengan sbox
    list_r_xor = [r_xor[6*k:6*k+6] for k in range(8)]
    # substitusi setiap 6 bit menjadi 4 bit nilai baru sesuai sbox
    # dan di-join semua sehingga menjadi 32 bit
    r_sbox = ''
    for j in range(0, 8):
        r_sbox = r_sbox + s_box_substitution(j+1, list_r_xor[j])
    # lakukan permutasi hasil sbox dengan matriks pbox
    r_pbox = permutation(r_sbox, p_box)
    # xor nilai l dan r_pbox 
    r_new = xor(l, r_pbox)
    l = r_new
    # swap nilai l dan r
    if(i!=15):
        l, r = r, l
    # hasil r yang baru akan dijadikan nilai l untuk round berikutnya
    return l, r

def encrypt(plaintext, ki, ki_hex):
    plaintext = hex_to_bin(plaintext)
    # melakukan permutasi awal
    plaintext = permutation(plaintext, ip)
    # print("setelah dilakukan IP:", bin_to_hex(plaintext))
    l = plaintext[0:32]
    r = plaintext[32:64]
    for i in range(16):
        l, r = feistel(l, r, ki[i],i)
        # print("Round ", i + 1, " ", bin_to_hex(l)," ", bin_to_hex(r), " ", ki_hex[i])
    concat = l + r
    return permutation(concat, inv_ip)

def decrypt(ciphertext, ki, ki_hex):
    ki_d = ki[::-1]
    ki_hex_d = ki_hex[::-1]
    return bin_to_hex(encrypt(ciphertext, ki_d, ki_hex_d))

def blocks_plaintext(plaintext):
    num_bit = 16
    blocks = []
    len_blocks = int(len(plaintext)/num_bit)
    # print(len_blocks)
    # print(len(plaintext))
    if len(plaintext)%num_bit != 0:
      num_pad = len_blocks*num_bit + num_bit - len(plaintext)
      # print(num_pad)
      for i in range(num_pad):
        plaintext += " "
      len_blocks+=1
    blocks = [plaintext[num_bit*k:num_bit*k+num_bit] for k in range(len_blocks)]
    return blocks

def main():
    print("DES ECB Encryption-Decryption\n")
    print("\nPilih jenis plaintext-mu:\n1. Hex\n2. Karakter Teks")
    type_pt = input()

    print("\nMasukkan plaintext-mu!")
    plaintext = str(input())
    key = 0

    # jika input yang dipilih bertipe hex
    if type_pt == "1":
      print("\nMasukkan key yang panjangnya 16 karakter!")
      key = input()

    # jika input yang dipilih bertipe karakter
    elif type_pt == "2":
      print("\nMasukkan key yang panjangnya 8 karakter!")
      key = input()
      # konversi plaintext dan key ke hexadecimal dulu 
      print("\nKonversi Plaintext dan Key ke Hex")
      print("Plaintext: ", plaintext, " -> ", " Hasil Konversi Hex: ", str_to_hex(plaintext))
      print("Key: ", key, " -> ", " Hasil Konversi Hex: ", str_to_hex(key))
      plaintext = str_to_hex(plaintext)
      key = str_to_hex(key)

    # pemecahan plaintext menjadi blok-blok sekaligus menambahkan padding jika panjangnya tidak kelipatan 16
    blocks_enc = blocks_plaintext(plaintext)

    # generate key
    key_internal, key_hexa = key_generation(key)

    # proses enkripsi sebanyak jumlah block data
    print("\nEncryption")
    ciphertext = ''
    i=0
    for b in blocks_enc:
      # print(i)
      cp = bin_to_hex(encrypt(b, key_internal, key_hexa))
      ciphertext = ciphertext + cp
      # print("Ciphertext Hex", str(i), " ", cp)
      i+=1
    print("Ciphertext Akhir (dalam Hex): ", ciphertext)
    if type_pt == '2':
      print("Ciphertext Akhir (dalam Karakter Teks): ", hex_to_str(ciphertext))

    print("\nDecryption")
    blocks_dec = blocks_plaintext(ciphertext)
    text = ''
    i=0
    for b in blocks_dec:
      pt = decrypt(b, key_internal, key_hexa)
      text = text + pt
      # print("Plaintext ", str(i), " ", pt)
      i+=1
    print("Plaintext Asli (dalam Hex): ", text)
    if type_pt == '2':
      print("Plaintext Asli (dalam Karakter Teks): ", hex_to_str(text))
    

if __name__ == "__main__":
    main()