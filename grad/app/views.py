import base64
import binascii
import imghdr
from django.shortcuts import render,redirect
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.hashers import make_password,check_password
from django.contrib import messages
from PIL import Image
import io
import hashlib
from PIL import Image
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from app.models import User
from .form import RegistrationForm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from django.contrib.auth import logout

#Aes encryption
def encrypt_aes(plain_text):
    # Convert the plain text from string to bytes
    plain_text_bytes = plain_text.encode('utf-8')

    # Generate a random 256-bit key
    key = os.urandom(32)

    # Create a new AES cipher object with the key and AES.MODE_CBC mode
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=backend)
    encryptor = cipher.encryptor()

    # Make sure the plain text is a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text_bytes) + padder.finalize()

    # Encrypt the plain text
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the ciphertext and the key to base64 strings
    cipher_text_str = base64.b64encode(cipher_text).decode('utf-8')

    return cipher_text_str
#Xor between 2 hashes
def xor_hashes(hash1, hash2):
    # Convert the hashes from hexadecimal to bytes
    hash1_bytes = bytes.fromhex(hash1)
    hash2_bytes = bytes.fromhex(hash2)

    # XOR the two hashes and return the result
    xor_result = bytes(a ^ b for a, b in zip(hash1_bytes, hash2_bytes))
    return binascii.hexlify(xor_result).decode()

#Compute the digeest of a string
def hash_string(input_string):
    # Create a new sha256 hash object
    sha_signature = hashlib.sha256(input_string.encode()).hexdigest()
    return sha_signature

#Calculate the digest of the imgae
def image_digest(image_data):
    # Read the image data
    data = image_data.tobytes()
    # Calculate the hash
    hash_object = hashlib.sha256(data)
    hex_dig = hash_object.hexdigest()
    return hex_dig

def is_image(file):
    image_types = [ 'jpeg', 'png']
    return imghdr.what(file) in image_types

#Hiding data into img by LSB
def LSB(request,image, msg):
            # Convert the message to binary
            binary_message = ''.join(format(ord(i), '08b') for i in msg)

            # Ensure the message will fit in the image
            if len(binary_message) > image.width * image.height:
                messages.info(request,"Please pick a better image")

            # Create a new image to hold the output
            output_image = Image.new(image.mode, image.size)
            output_pixels = output_image.load()

            # Iterate over the pixels in the image
            message_index = 0
            for y in range(image.height):
                for x in range(image.width):
                    # Get the current pixel
                    pixel = list(image.getpixel((x, y)))

                    # Modify the pixel to contain the message
                    for n in range(len(pixel)):
                        if message_index < len(binary_message):
                            # Change the least significant bit of each color component
                            pixel[n] = pixel[n] & ~1 | int(binary_message[message_index])
                            message_index += 1

                    # Write the modified pixel to the output image
                    output_pixels[x, y] = tuple(pixel)

            # Return the output image
            return output_image

#Caluclate the hash of the file
def calculate_hash(file_path):
    # Open the file in binary mode
    with open(file_path, 'rb') as file:
        bytes = file.read()  # Read the entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest()  # Calculate the SHA-256 hash
    return readable_hash



def check_image_size(image):
    size = image.size
    size_in_MB = size / (1024 * 1024)  # Convert size to MB
    return size_in_MB
     
#Here is the register process
def register(request):
    if request.method == 'POST':
        email=request.POST['email']
        if User.objects.filter(email=email).exists():
                    messages.info(request, 'Email already has been used!')
                    return redirect('register')
        password=request.POST['password']
        confirm=request.POST['confirm']

        if password != confirm:
            messages.info(request, 'Unmatch passwords')
            return redirect('register')
        
        form = RegistrationForm(request.POST) 
        if form.is_valid():
            user = form.save(commit=False)
            password_hash = hash_string(password)

            #Checking Image
            if 'image1' in request.FILES :
                image1 = request.FILES['image1']
            else:
                messages.info(request,"Please enter a correct imgae1")
                return redirect('register')
            if 'image2' in request.FILES :
                image2 = request.FILES['image2']
            else:
                messages.info(request,"Please enter a correct imgae2")
                return redirect('register')
            if 'image3' in request.FILES:
                image3 = request.FILES['image3']
            else:
                messages.info(request,"Please enter a correct imgae3")
                return redirect(request,'register')
            if not is_image(image1) or check_image_size(image1)>8:
                messages.info(request,"Please enter a correct imgae1")
                return redirect('register')
            if not is_image(image2) or check_image_size(image2)>8:
                messages.info("Please enter a correct imgae2")
                return redirect(request,'register')
            if not is_image(image3) or check_image_size(image3)>8:
                messages.info(request,"Please enter a correct imgae3")
                return redirect('register')
            
            #Checking password
            cnt_strength_password_capital = True
            cnt_strength_password_lower = True
            cnt_strength_password_special = True
            cnt_strength_password_number = True
            cnt_strength_password_len = 0
            for i in password:
                if i>='A' and i<='Z':
                    cnt_strength_password_capital = False
                elif i>='a' and i<='z':
                    cnt_strength_password_lower = False
                elif i in ['!','@','#','$','%','^','&','*','(',')','-','_','+','=']:
                    cnt_strength_password_special = False
                elif i>='0' and i<='9':
                    cnt_strength_password_number = False
                cnt_strength_password_len+=1

            if cnt_strength_password_len<8 or ( cnt_strength_password_capital or  cnt_strength_password_lower or  cnt_strength_password_special or cnt_strength_password_number):
                messages.info(request,"Please pick a better password contains: 8 chars, lower, capital, special and a number")
                return redirect('register')
        
        
            # Read the images into memory
            image1_data = Image.open(io.BytesIO(image1.read()))
            image2_data = Image.open(io.BytesIO(image2.read()))
            image3_data = Image.open(io.BytesIO(image3.read()))

            #Hiding by LSB R1
            stego_image1_R1 = LSB(request,image1_data,password_hash)
            #calculating the digest R1
            stego_digest1_R1 = image_digest(stego_image1_R1)

            #Hiding by LSB R2
            stego_image2_R2 = LSB(request,image2_data,stego_digest1_R1)
            #calculating the digest R2
            stego_digest2_R2 = encrypt_aes(image_digest(stego_image2_R2))
            

            stego_image3_R3 = LSB(request,image3_data,stego_digest2_R2)
            stego_digest3_R3 = image_digest(stego_image3_R3)
                        
            #Saving the user in the database
                
            xor=xor_hashes(stego_digest3_R3,password_hash)
            user.email = email
            user.set_password(hash_string(xor))
            user.save() 
            image_io = io.BytesIO()
            stego_image3_R3.save(image_io, format='PNG')

            # Create a base64 string of the image data
            image_str = base64.b64encode(image_io.getvalue()).decode('utf-8')

            # Create a data URL of the image
            data_url = 'data:image/png;base64,' + image_str

            # Pass the data URL to the template
            return render(request, 'yourStego.html', {'image_data_url': data_url})
            
    else:
        form = RegistrationForm()

    return render(request, 'register.html', {'form': form})

#Here is the login process, note (we made the function called log_in to avoid overload, pls keep it like that)
def log_in(request):
    
    if request.method == 'POST':
            email = request.POST['email']
            password = request.POST['password']            
            if 'image1' in request.FILES:
                image1 = request.FILES['image1']
                if is_image(image1):
                    image1_data = Image.open(io.BytesIO(image1.read()))
                    password_hash = hash_string(password)
                    image1_digest = image_digest(image1_data)
                    xor_hash = hash_string(xor_hashes(image1_digest,password_hash))
                    user = authenticate(request, username=email, password=xor_hash) 
                    if user is not None:
                        login(request,user)
                        return redirect('hello') 
                    else:
                        messages.info(request,"Invalid emair or credetinals")
                        return redirect('log_in')             
                else:
                    messages.info("Please upload jpg or png image only")
                    return redirect('log_in')
            else:
                messages.info(request,'No image file uploaded')
                return redirect('log_in')
    
    return render(request, 'log_in.html')



@login_required
def yourStego(request):
    logout(request)
    return render(request, 'yourStego.html')
def index(request):
    return render(request, "index.html")

def hello(request):
    return render(request, 'hello.html')

