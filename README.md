#Stego for Auth

I have designed an algorthim depending on Stegangoraphy and password to create a 2FA process, in a way that is easy to use and effective against different attacks with a unique imaeg.

The general idea is:
We have 3 images and password
Calculate the has of the password
hide it inside the first image
then hide the hash of the first image inside the second one
then hide the hash of the second image inside the third one with a random key of 16 bytes
then calculate the xor results between the hash of the password and the hash of the third image and save the hash of the xor result in the database and the hidden key also.

Now in the login:
The user provide the password and the the Stego image
Caculate the hash for each one of them and extract the hidden key from the image
then compare with the one in the database

## WHY is it working?
The strong hash algorthim such as SHA256 supoused to give a unique value for each different input even if a 1 bit has been changed, so why we don`t connect 3 images using a very light-way which is hash by calculate the hash of each one of the image and hide in the other image
Saving a hash value in the database better than saving the image because in simple word is light, the attacker can't get the image from the server and very easy to implement

#END
