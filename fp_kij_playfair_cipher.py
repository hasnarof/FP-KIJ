# -*- coding: utf-8 -*-
"""FP KIJ - PlayFair Cipher

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1scJxbMgyPoWznjVFdyGbot_Z97DpcEoX
"""

# Function to get the index at matrix that had been generated
def find_index(stringArr, keyString):
	result = []
	for i in range(len(stringArr)):
		for j in range(len(stringArr[i])):
			if stringArr[i][j] == keyString:
				result.append(i)
				result.append(j)
				return result
	result.append(0)
	result.append(0)
	return result

#For a more appealing display of matrix
def make_prettier(table):    

    # to get the index of letter I or J
    index_i = find_index(table, "I")
    index_j = find_index(table, "J")

    # to make the appealing of index I or J to I/J
    if index_i:
      table[index_i[0]][index_i[1]]= "I/J"
    elif index_j:
      table[index_j[0]][index_j[1]]= "I/J"

    res1 = '[ {}]\n'.format('   '.join(table[0]))
    res2 = ''
    for i in range(1,len(table)-1,1):
        res2 = res2 + '| {}|\n'.format('   '.join(table[i]))
    res3 = '[ {}]\n'.format('   '.join(table[len(table)-1]))
    res = res1 + res2 + res3
    return res

# Function to generate matrix from key
def generate_key_matrix(key):
    key_letters = []
    alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    key = ''.join(key.split(' ')) #remove spaces from given key and PF cipher is only for letters. 

    # convert keyword to upper case
    for i in key.upper():
        if i not in key_letters:
            key_letters.append(i)
 
    temp_matrix = []

    # to check if there's a letter of I or J, that must be the one of them only
    # first, input the keyword letters to the matrix from index (0,0)
    for i in key_letters:
        if i=="J" and "I" in temp_matrix: 
          continue
        if i=="I" and "J" in temp_matrix:
          continue
        if i not in temp_matrix: # checking if there's a same letter
          temp_matrix.append(i)

    # second, input the alphabet letters to the matrix from the first unfilled index 
    for i in alphabets:
        if i=="J" and "I" in temp_matrix:
          continue
        if i=="I" and "J" in temp_matrix:
          continue
        if i not in temp_matrix: # checking if there's a same letter
          temp_matrix.append(i)
 
    matrix = []
    while temp_matrix != []:
        # get the first 5 letters in the array
        matrix.append(temp_matrix[:5])
        # get all array list except first 5 letters
        temp_matrix = temp_matrix[5:]
 
    return matrix

#Add fillers if the same letter is in a pair
def filler_letter(message):
    index = 0
    message = ''.join(message.split(' ')) #remove spaces from given key and PF cipher is only for letters. 
    while (index<len(message)):
        letter_1 = message[index]

        # cek apakah jumlah message ganjil, jika ya tambah 'Z' diakhir
        if index == len(message)-1:
            message = message + 'Z'
            index += 2
            continue

        letter_2 = message[index+1]

        #cek letter yang berpasangan apakah sama, jika ya tambah 'X' antara kedua huruf
        if letter_1==letter_2:
            message = message[:index+1] + 'X' + message[index+1:]
        index +=2   
    return message

# make the key to pair of letter
def split_to_pair(message):
    result = []
    pair= 0
    for i in range(2, len(message), 2):
        result.append(message[pair:i])
        pair = i
    result.append(message[pair:]) # get next pair letter
    return result

def at_same_row(matrix, index1_row, index1_col, index2_row, index2_col):
    
    # to save pair letter
    letter1 = ''
    letter2 = ''

    if index1_col == 4: # amount of the maksimum col
        letter1 = matrix[index1_row][0]
    else:
        letter1 = matrix[index1_row][index1_col+1]
 

    if index2_col == 4: # amount of the maksimum col
        letter2 = matrix[index2_row][0]
    else:
        letter2 = matrix[index2_row][index2_col+1]
 
    return letter1, letter2
 

def at_same_column(matrix, index1_row, index1_col, index2_row, index2_col):

    # to save pair letter
    letter1 = ''
    letter2 = ''

    if index1_row == 4: # amount of the maksimum row
        letter1 = matrix[0][index1_col]
    else:
        letter1 = matrix[index1_row+1][index1_col]
 
    
    if index2_row == 4: # amount of the maksimum row
        letter2 = matrix[0][index2_col]
    else:
        letter2 = matrix[index2_row+1][index2_col]
 
    return letter1, letter2

 
def at_same_rectangle(matrix, index1_row, index1_col, index2_row, index2_col):

    # to save pair letter
    letter1 = ''
    letter2 = ''

    # swap the index of each column of letter
    letter1 = matrix[index1_row][index2_col]
    letter2 = matrix[index2_row][index1_col]
 
    return letter1, letter2

def playfair_encryption(matrix, message):
    message = message.upper()
    message = filler_letter(message)
    message = split_to_pair(message)
    print("\nSplitting your message into the following pairs:\n{}".format(' '.join(message)))

    cipher_text = []

    for i in range(0, len(message)):
        # to save pair letter of encription result
        letter1 = 0
        letter2 = 0

        # find index or location of every pair from message
        index1_x, index1_y = find_index(matrix, message[i][0])
        index2_x, index2_y = find_index(matrix, message[i][1])
 
        # if a pair of letter in one row
        if index1_x == index2_x:
            letter1, letter2 = at_same_row(matrix, index1_x, index1_y, index2_x, index2_y)

        # if a pair of letter one column
        elif index1_y == index2_y:
            letter1, letter2 = at_same_column(matrix, index1_x, index1_y, index2_x, index2_y)

        # if rectangle
        else:
            letter1, letter2 = at_same_rectangle(matrix, index1_x, index1_y, index2_x, index2_y)
 
        cipher_text.append(letter1 + letter2)
    return cipher_text

if __name__=='__main__':

    print("Welcome to Playfair Cipher.\n")
    key=input("Please input the key:\n")
    matrix = generate_key_matrix(key)
    print("\nThe cipher matrix based on your key:\n{}".format(make_prettier([row[:] for row in matrix])))
    
    message = input("\nPlease input the message:\n")
    print("\nEncrypting the message:\n{}".format(message.upper()))
    print("\nHere is the encrypted text:\n{}".format(''.join(playfair_encryption(matrix, message))))