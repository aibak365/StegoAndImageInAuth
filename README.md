# StegoAndImageInAuth
Here i suggest an algorthim to authnticate a user by images and Stegangoraphy using LSB

# Algorithm:

## 1-Register
First we get 3 images from the user and a password
We calculate the hash of password and hide it in the first image
after that we calcualte the hash of the first stego_image (That will help us to make the image unique so the attacker can not find it publicily on the internet)
then we hide the hash result of the stego_image_1 and hide in the image2
then we calculate the hash of the stego_image_2 and encrypted by a random AES key 
then we hide the result cipher of AES in the image3 using LSB
then we make XOR of the hashed password with the image_stego_3 digest
and then save the result hashed with salt in the database

## 2-Login

For login:
the user should send the image that we have provided to him/her and a correct password
we calculate the hash of each of them and Xor between them and compare what we have in the database